#include "util.h"
#include "memory.h"
#include "codesign.h"
#include "loader.h"
#include "memory.h"
#include "basebin_hook.h"
#include "ppl.h"
#include "trustcache.h"
#include "jbserver.h"

static xpc_object_t (*xpc_serializer_unpack_orig)(void *, void *, void *) = NULL;
static int (*xpc_receive_mach_msg_orig)(void *a1, void *a2, void *a3, void *a4, xpc_object_t *output) = NULL;
static xpc_object_t (*xpc_dictionary_get_value_orig)(xpc_object_t dict, const char *key) = NULL;
static int (*MISValidateSignatureAndCopyInfo)(CFStringRef File, CFDictionaryRef Opts, void **Info);
pthread_mutex_t fakesigned_lock = PTHREAD_MUTEX_INITIALIZER;
xpc_object_t fakesigned_dict = NULL;

static sandbox_ext_t sb_ext[] = {
    {SANDBOX_READ, "/private/var/mobile"},
    {SANDBOX_READ, "/amethyst"},
    {SANDBOX_READ_WRITE, "/private/var/mobile/Library/Preferences"},
    {SANDBOX_READ_WRITE, "/private/var/cache"},
    {SANDBOX_READ_WRITE, "/Library"},
    {SANDBOX_EXECUTABLE, "/Library"},
    {SANDBOX_EXECUTABLE, "/private/var"},
    {SANDBOX_EXECUTABLE, "/amethyst"},
    {NULL, NULL}
};

static pid_t jbserver_getpid(xpc_object_t request) {
    pid_t pid = (pid_t)xpc_dictionary_get_int64(request, "pid");
    if (pid > 0) return pid;

    audit_token_t token = {0};
    xpc_dictionary_get_audit_token(request, &token);
    pid = get_audit_token_pid(token);
    return (pid <= 1) ? -1 : pid;
}

static uid_t jbserver_getuid(xpc_object_t request) {
    audit_token_t token = {0};
    xpc_dictionary_get_audit_token(request, &token);
    return get_audit_token_uid(token);
}

static uid_t jbserver_getruid(xpc_object_t request) {
    audit_token_t token = {0};
    xpc_dictionary_get_audit_token(request, &token);
    return get_audit_token_ruid(token);
}

static gid_t jbserver_getgid(xpc_object_t request) {
    audit_token_t token = {0};
    xpc_dictionary_get_audit_token(request, &token);
    return get_audit_token_gid(token);
}

static gid_t jbserver_getrgid(xpc_object_t request) {
    audit_token_t token = {0};
    xpc_dictionary_get_audit_token(request, &token);
    return get_audit_token_rgid(token);
}

static jbserver_err_t jbserver_trustcache(xpc_object_t request, xpc_object_t reply) {
    xpc_object_t hash_list = xpc_dictionary_get_array(request, "hashes");
    if (hash_list == NULL || xpc_get_type(hash_list) != XPC_TYPE_ARRAY) return JBSERVER_ERR_INVALID_CD_HASH;
    xpc_object_t type_list = xpc_dictionary_get_array(request, "types");

    size_t count = xpc_array_get_count(hash_list);
    for (int i = 0; i < count; i++) {
        xpc_object_t value = xpc_array_get_value(hash_list, i);
        if (value == NULL) continue;
        uint8_t hash[20] = {0};
        uint8_t type = 0;

        __unused size_t size = xpc_data_get_bytes(value, &hash[0], 0, 20);
        if (type_list != NULL) type = (uint8_t)(xpc_array_get_uint64(type_list, i) & 0xff);
        if (!trustcache_check(hash)) {
            trustcache_lock_add_hash(hash, type);
        }
    }
    return JBSERVER_ERR_SUCCESS;
}

static jbserver_err_t jbserver_sign_binary(xpc_object_t request, xpc_object_t reply) {
    const char *path = xpc_dictionary_get_string(request, "path");
    if (path == NULL) return JBSERVER_ERR_INVALID_PATH;
    
    uint32_t le_offset = (uint32_t)xpc_dictionary_get_uint64(request, "le_offset");
    uint32_t le_size = (uint32_t)xpc_dictionary_get_uint64(request, "le_size");
    uint32_t slice_offset = (uint32_t)xpc_dictionary_get_uint64(request, "slice_offset");
    uint32_t file_type = (uint32_t)xpc_dictionary_get_uint64(request, "file_type");
    
    int status = sign_binary((char *)path, le_offset, le_size, slice_offset, file_type);
    return (status == 0) ? JBSERVER_ERR_SUCCESS : JBSERVER_ERR_UNKNOWN_FAILURE;
}

static jbserver_err_t jbserver_preload_binary(xpc_object_t request, xpc_object_t reply) {
    const char *path = xpc_dictionary_get_string(request, "path");
    if (path == NULL) return JBSERVER_ERR_INVALID_PATH;
    
    int fd = open(path, O_RDONLY);
    if (fd < 0) return JBSERVER_ERR_INVALID_PATH;

    uint64_t vnode = vnode_for_fd(fd);
    if (vnode == 0) {
        close(fd);
        return JBSERVER_ERR_INVALID_PATH;
    }

    uint64_t ubc_info = kread64(vnode + koffsetof(vnode, ubcinfo));
    if (!KADDR_VALID(ubc_info)) {
        close(fd);
        return JBSERVER_ERR_INVALID_PATH;
    }

    uint64_t cs_blob = kread64(ubc_info + koffsetof(ubc_info, cs_blob));
    if (!KADDR_VALID(cs_blob)) {
        close(fd);
        return JBSERVER_ERR_INVALID_PATH;
    }

    while (KADDR_VALID(cs_blob)) {
        if (kread32(cs_blob + offsetof(cs_blob_t, csb_cpu_type)) == CPU_TYPE_ANY) {
            cs_blob_t blob_data = {0};
            kread_buf(cs_blob, &blob_data, sizeof(cs_blob_t));

            blob_data.csb_flags |= (CS_VALID|CS_GET_TASK_ALLOW|CS_ENTITLEMENTS_VALIDATED|CS_PLATFORM_BINARY|CS_SIGNED|CS_DEBUGGED);
            blob_data.csb_cpu_type = CPU_TYPE_ARM64;
            blob_data.csb_reconstituted = 1;
            if (blob_data.csb_platform.binary == 0) {
                blob_data.csb_platform.binary = 1;
            }

            kwrite_buf(cs_blob, &blob_data, sizeof(cs_blob_t));
        }
        
#if defined(__arm64e__)
        uint64_t pmap_cs_entry = kread64(cs_blob + 0xb0);
        if (KADDR_VALID(pmap_cs_entry)) {
            uint32_t current_trustlevel = kread32(pmap_cs_entry + koffsetof(pmap_cs_code_directory, trust));
            if (current_trustlevel != 1) {
                uint64_t trustlevel_pa = kvtophys(pmap_cs_entry + koffsetof(pmap_cs_code_directory, trust));
                if (trustlevel_pa != 0) {
                    ppl_write32(trustlevel_pa, 1);
                    usleep(1000);

                    current_trustlevel = kread32(pmap_cs_entry + koffsetof(pmap_cs_code_directory, trust));
                    if (current_trustlevel != 1) ppl_write32(trustlevel_pa, 1);
                }
            }
        }
#endif
        cs_blob = kread64(cs_blob); // cs_blob->csb_next
    }

    close(fd);
    return JBSERVER_ERR_SUCCESS;
}

static jbserver_err_t jbserver_init_process(xpc_object_t request, xpc_object_t reply) {
    pid_t pid = jbserver_getpid(request);
    if (pid <= 0) return JBSERVER_ERR_INVALID_PROCESS;

    uint64_t proc = 0;
    uint64_t task = 0;
    if (get_process_info(pid, &proc, &task) != 0) return JBSERVER_ERR_INVALID_PROCESS;

    uint64_t ucred = kread64(proc + koffsetof(proc, ucred));
    if (!KADDR_VALID(ucred)) return JBSERVER_ERR_INVALID_PROCESS;
    add_task_flag(-1, task, TF_PLATFORM);
    fixup_cs_flags(proc);

  	uint32_t proc_flags = kread32(proc + koffsetof(proc, p_flag));
    if ((proc_flags & P_SUGID) == P_SUGID) {
        kwrite32(proc + koffsetof(proc, p_flag), proc_flags & ~P_SUGID);
    }

    xpc_object_t xpc_target_uid = xpc_dictionary_get_value_orig(request, "target_uid");
    if (xpc_target_uid != NULL && xpc_get_type(xpc_target_uid) && XPC_TYPE_INT64) {
        uid_t target_uid = (uid_t)xpc_int64_get_value(xpc_target_uid);
        kwrite32(proc + koffsetof(proc, p_svuid), target_uid);
        kwrite32(ucred + koffsetof(ucred, cr_svuid), target_uid);
        kwrite32(ucred + koffsetof(ucred, cr_uid), target_uid);
    }

    xpc_object_t xpc_target_gid = xpc_dictionary_get_value_orig(request, "target_gid");
    if (xpc_target_gid != NULL && xpc_get_type(xpc_target_uid) && XPC_TYPE_INT64) {
        uid_t target_gid = (uid_t)xpc_int64_get_value(xpc_target_gid);
        kwrite32(proc + koffsetof(proc, p_svgid), target_gid);
        kwrite32(ucred + koffsetof(ucred, cr_svgid), target_gid);
        kwrite32(ucred + koffsetof(ucred, cr_groups), target_gid);
    }

    jbserver_unsandbox_t unsandbox_type = (uint32_t)xpc_dictionary_get_uint64(request, "unsandbox_type");
    if (unsandbox_type == JBSERVER_UNSANDBOX_EXTENSIONS) {
        xpc_object_t extensions = xpc_array_create(NULL, 0);
        if (extensions == NULL) return JBSERVER_ERR_UNKNOWN_FAILURE;

        for (int i = 0; sb_ext[i].cls; i++) {
            char *ext = sandbox_extension_issue_file(sb_ext[i].cls, sb_ext[i].path, 0);
            if (ext == NULL) continue;

            xpc_object_t str = xpc_string_create(ext);
            if (str != NULL) {
                xpc_array_append_value(extensions, str);
                xpc_release(str);
            }
            free(ext);
        }

        if (xpc_array_get_count(extensions) > 0) {
            xpc_dictionary_set_value(reply, "extensions", extensions);
        }
        xpc_release(extensions);
    } else if (unsandbox_type == JBSERVER_UNSANDBOX_FULL) {
        set_mac_slot(-1, proc, 1, 0);
    }

#if defined(__arm64e__)
    uint64_t vm_map = kread64(task + koffsetof(task, vm_map));
    if (!KADDR_VALID(vm_map)) return JBSERVER_ERR_INVALID_PROCESS;

    uint64_t pmap = kread64(vm_map + koffsetof(vm_map, pmap));
    if (!KADDR_VALID(pmap)) return JBSERVER_ERR_INVALID_PROCESS;

    if (kread8(pmap + koffsetof(pmap, cs_enforced)) == 1) {
        uint64_t pa = kvtophys(pmap + koffsetof(pmap, cs_enforced));
        if (pa != 0) {
            ppl_write8(pa, 0);
            usleep(1000);

            if (kread8(pmap + koffsetof(pmap, cs_enforced)) == 1) {
                ppl_write8(pa, 0);
            }
        }

        uint64_t pmap_cs_entry = proc_get_pmap_cs_entry(proc);
        if (pmap_cs_entry != 0) {
            uint32_t current_trustlevel = kread32(pmap_cs_entry + koffsetof(pmap_cs_code_directory, trust));
            if (current_trustlevel != 1) {
                uint64_t trustlevel_pa = kvtophys(pmap_cs_entry + koffsetof(pmap_cs_code_directory, trust));
                if (trustlevel_pa != 0) ppl_write32(trustlevel_pa, 1);
            }
        }
        if (kread8(pmap + koffsetof(pmap, cs_enforced)) == 1) return JBSERVER_ERR_UNKNOWN_FAILURE;
    }
#endif
    return JBSERVER_ERR_SUCCESS;
}

static jbserver_err_t jbserver_platformize(xpc_object_t request, xpc_object_t reply) {
    pid_t pid = jbserver_getpid(request);
    if (pid <= 0) return JBSERVER_ERR_INVALID_PROCESS;

    uint64_t proc = 0;
    uint64_t task = 0;
    if (get_process_info(pid, &proc, &task) != 0) return JBSERVER_ERR_INVALID_PROCESS;

    add_cs_flag(-1, proc, CS_PLATFORM_BINARY);
    add_task_flag(-1, task, TF_PLATFORM);
    return JBSERVER_ERR_SUCCESS;
}

static jbserver_err_t jbserver_unsandbox(xpc_object_t request, xpc_object_t reply) {
    pid_t pid = jbserver_getpid(request);
    if (pid <= 0) return JBSERVER_ERR_INVALID_PROCESS;
    jbserver_unsandbox_t unsandbox_type = (uint32_t)xpc_dictionary_get_uint64(request, "unsandbox_type");
    
    if (unsandbox_type == JBSERVER_UNSANDBOX_EXTENSIONS) {
        xpc_object_t extensions = xpc_array_create(NULL, 0);
        if (extensions == NULL) return JBSERVER_ERR_UNKNOWN_FAILURE;

        for (int i = 0; sb_ext[i].cls; i++) {
            char *ext = sandbox_extension_issue_file(sb_ext[i].cls, sb_ext[i].path, 0);
            if (ext == NULL) continue;

            xpc_object_t str = xpc_string_create(ext);
            if (str != NULL) {
                xpc_array_append_value(extensions, str);
                xpc_release(str);
            }
            free(ext);
        }

        if (xpc_array_get_count(extensions) > 0) {
            xpc_dictionary_set_value(reply, "extensions", extensions);
        }
        xpc_release(extensions);
    } else if (unsandbox_type == JBSERVER_UNSANDBOX_FULL) {
        set_mac_slot(pid, 0, 1, 0);
    }
    return JBSERVER_ERR_SUCCESS;
}

static jbserver_err_t jbserver_patch_setuid(xpc_object_t request, xpc_object_t reply) {
    pid_t pid = jbserver_getpid(request);
    if (pid <= 0) return JBSERVER_ERR_INVALID_PROCESS;

    uint64_t proc = find_proc_for_pid(pid);
    if (!KADDR_VALID(proc)) return JBSERVER_ERR_INVALID_PROCESS;

    uint64_t ucred = kread64(proc + koffsetof(proc, ucred));
    if (!KADDR_VALID(ucred)) return JBSERVER_ERR_INVALID_PROCESS;

    uint32_t proc_flags = kread32(proc + koffsetof(proc, p_flag));
    if ((proc_flags & P_SUGID) == P_SUGID) {
        kwrite32(proc + koffsetof(proc, p_flag), proc_flags & ~P_SUGID);
    }

    kwrite32(proc + koffsetof(proc, p_svuid), 0);
    kwrite32(ucred + koffsetof(ucred, cr_svuid), 0);
    kwrite32(ucred + koffsetof(ucred, cr_uid), 0);
    return JBSERVER_ERR_SUCCESS;
}

static jbserver_err_t jbserver_patch_setgid(xpc_object_t request, xpc_object_t reply) {
    pid_t pid = jbserver_getpid(request);
    if (pid <= 0) return JBSERVER_ERR_INVALID_PROCESS;

    uint64_t proc = find_proc_for_pid(pid);
    if (!KADDR_VALID(proc)) return JBSERVER_ERR_INVALID_PROCESS;

    uint64_t ucred = kread64(proc + koffsetof(proc, ucred));
    if (!KADDR_VALID(ucred)) return JBSERVER_ERR_INVALID_PROCESS;

    uint32_t proc_flags = kread32(proc + koffsetof(proc, p_flag));
    if ((proc_flags & P_SUGID) == P_SUGID) {
        kwrite32(proc + koffsetof(proc, p_flag), proc_flags & ~P_SUGID);
    }

    kwrite32(proc + koffsetof(proc, p_svgid), 0);
    kwrite32(ucred + koffsetof(ucred, cr_svgid), 0);
    kwrite32(ucred + koffsetof(ucred, cr_groups), 0);
    return JBSERVER_ERR_SUCCESS;
}

static jbserver_err_t jbserver_check_fakesigned(xpc_object_t request, xpc_object_t reply) {
    const char *path = xpc_dictionary_get_string(request, "path");
    if (path == NULL) return JBSERVER_ERR_INVALID_PATH;
    
    pthread_mutex_lock(&fakesigned_lock);
    bool result = xpc_dictionary_get_bool(fakesigned_dict, path);
    pthread_mutex_unlock(&fakesigned_lock);
    xpc_dictionary_set_bool(reply, "result", result);
    return JBSERVER_ERR_SUCCESS;
}

static jbserver_err_t jbserver_add_fakesigned(xpc_object_t request, xpc_object_t reply) {
    const char *path = xpc_dictionary_get_string(request, "path");
    if (path == NULL) return JBSERVER_ERR_INVALID_PATH;
    
    pthread_mutex_lock(&fakesigned_lock);
    xpc_dictionary_set_bool(fakesigned_dict, path, true);
    pthread_mutex_unlock(&fakesigned_lock);
    return JBSERVER_ERR_SUCCESS;
}

static jbserver_err_t jbserver_heartbeat(xpc_object_t request, xpc_object_t reply) {
    return 0x1337;
}

static void jbserver_handle_request(xpc_object_t request) {
    jbserver_cmd_t cmd = (jbserver_cmd_t)xpc_dictionary_get_uint64(request, "cmd");
    jbserver_err_t err = JBSERVER_ERR_UNKNOWN_FAILURE;
    xpc_object_t reply = xpc_dictionary_create_reply(request);

    switch (cmd) {
        case JBSERVER_CMD_TRUSTCACHE: err = jbserver_trustcache(request, reply); break;
        case JBSERVER_CMD_SIGN_BINARY: err = jbserver_sign_binary(request, reply); break;
        case JBSERVER_CMD_PRELOAD_BINARY: err = jbserver_preload_binary(request, reply); break;
        case JBSERVER_CMD_INIT_PROCESS: err = jbserver_init_process(request, reply); break;
        case JBSERVER_CMD_PLATFORMIZE: err = jbserver_platformize(request, reply); break;
        case JBSERVER_CMD_UNSANDBOX: err = jbserver_unsandbox(request, reply); break;
        case JBSERVER_CMD_PATCH_SETUID: err = jbserver_patch_setuid(request, reply); break;
        case JBSERVER_CMD_PATCH_SETGID: err = jbserver_patch_setgid(request, reply); break;
        case JBSERVER_CMD_CHECK_FAKESIGNED: err = jbserver_check_fakesigned(request, reply); break;
        case JBSERVER_CMD_ADD_FAKESIGNED: err = jbserver_add_fakesigned(request, reply); break;
        case JBSERVER_CMD_HEARTBEAT: err = jbserver_heartbeat(request, reply); break;
        default: err = JBSERVER_ERR_UNKNOWN_CMD; break;
    }

    xpc_dictionary_set_int64(reply, "error", err);
    xpc_pipe_routine_reply(reply);
    xpc_release(reply);
}

static void jbserver_prepare_reboot(void) {
    kinfo->userspace_rebooting = 1;
    draw_splash_screen();
    usleep(100000);

    update_jailbreak();
    unlink("/var/db/sysstatuscheck_should_check");
    unlink("/var/db/mmaintenanced");
    unlink("/tmp/mmaintenanced");
    sync();

    sync_volume_np("/private/var", SYNC_VOLUME_FULLSYNC);
    sync_volume_np("/", SYNC_VOLUME_FULLSYNC);

    unmount("/Developer", MNT_FORCE);
    usleep(100000);
    sync();
}

static xpc_object_t jbserver_handle_xpc_message(xpc_object_t message) {
    if (message == NULL || xpc_get_type(message) != XPC_TYPE_DICTIONARY) return message;
    uint64_t subsystem = xpc_dictionary_get_uint64(message, "subsystem");
    uint64_t routine = xpc_dictionary_get_uint64(message, "routine");

    if (subsystem == 3 && routine == 821) {
        uint64_t type = xpc_dictionary_get_uint64(message, "type");
        uint64_t handle = xpc_dictionary_get_uint64(message, "handle");

        if (type == 1 && handle == 0) {
            uint64_t flags = xpc_dictionary_get_uint64(message, "flags");
            if ((flags & RB2_USERREBOOT) == RB2_USERREBOOT) {
                jbserver_prepare_reboot();
                return message;
            }
        }
    }

    const char *name = xpc_dictionary_get_string(message, "name");
    if (name != NULL && strcmp(name, "com.staturnz.jbserver") == 0) {
        jbserver_handle_request(message);
        xpc_release(message);
        return NULL;
    }
    return message;
}

static xpc_object_t xpc_serializer_unpack_hook(void *a1, void *a2, void *a3) {
    xpc_object_t message = xpc_serializer_unpack_orig(a1, a2, a3);
    if (message == NULL || kinfo->initialized == 0 || kinfo->userspace_rebooting == 1) {
        return message;
    }
    return jbserver_handle_xpc_message(message);
}

static int xpc_receive_mach_msg_hook(void *a1, void *a2, void *a3, void *a4, xpc_object_t *out) {
    xpc_object_t message = NULL;
    int status = xpc_receive_mach_msg_orig(a1, a2, a3, a4, &message);
    if (message == NULL || kinfo->initialized == 0 || kinfo->userspace_rebooting == 1) {
        if (out != NULL) *out = message;
        return status;
    }

    xpc_object_t output = jbserver_handle_xpc_message(message);
    if (message != NULL && output != NULL && out != NULL) *out = output;
    return (output == NULL) ? 22 : status;
}

static xpc_object_t xpc_dictionary_get_value_hook(xpc_object_t dict, const char *key) {
    if (dict == NULL || key == NULL) return NULL;
    xpc_object_t value = xpc_dictionary_get_value_orig(dict, key);
    if (value == NULL) return NULL;

    if (strcmp(key, "LaunchDaemons") == 0 && xpc_get_type(value) == XPC_TYPE_DICTIONARY) {
        DIR *dir = opendir("/Library/LaunchDaemons");
        if (dir != NULL) {
            struct dirent *entry = NULL;
            char plist_path[PATH_MAX] = {0};

            while ((entry = readdir(dir)) != NULL) {
                char *item = (char *)entry->d_name;
                if (strstr(item, ".plist") == NULL || strstr(item, "jailbreakd") != NULL) continue;
                bzero(plist_path, PATH_MAX);
                snprintf(plist_path, PATH_MAX-1, "/Library/LaunchDaemons/%s", item);

                xpc_object_t plist = xpc_open_plist(plist_path);
                if (plist != NULL) {
                    xpc_dictionary_set_value(value, plist_path, plist);
                    xpc_release(plist);
                }
            }
            closedir(dir);
        }

        xpc_object_t misd_dict = xpc_dictionary_get_value_orig(value, "/System/Library/LaunchDaemons/com.apple.MobileInternetSharing.plist");
        if (misd_dict != NULL && xpc_get_type(misd_dict) == XPC_TYPE_DICTIONARY) {
            xpc_dictionary_set_bool(misd_dict, "KeepAlive", true);
        }
    } else if (strcmp(key, "Paths") == 0 && xpc_get_type(value) == XPC_TYPE_ARRAY) {
        xpc_object_t path_str = xpc_string_create("/Library/LaunchDaemons");
        if (path_str != NULL) {
            xpc_array_append_value(value, path_str);
            xpc_release(path_str);
        }
    }
    return value;
}

int init_server(void) {
    void *handle = dlopen("/usr/lib/system/libxpc.dylib", RTLD_NOW);
    if (handle == NULL) handle = RTLD_DEFAULT;
    if ((fakesigned_dict = xpc_dictionary_create(NULL, NULL, 0)) == NULL) return -1;

    if (kinfo->version[0] <= 12) {
        void *symbol = dlsym(handle, "_xpc_serializer_unpack");
        if (symbol == NULL) return -1;

        int status = hook_function(symbol, (void *)xpc_serializer_unpack_hook, (void **)&xpc_serializer_unpack_orig);
        if (status != 0 || xpc_serializer_unpack_orig == NULL) return -1;
    } else {
        void *symbol = dlsym(handle, "xpc_receive_mach_msg");
        if (symbol == NULL) return -1;

        int status = hook_function(symbol, (void *)xpc_receive_mach_msg_hook, (void **)&xpc_receive_mach_msg_orig);
        if (status != 0 || xpc_receive_mach_msg_orig == NULL) return -1;
    }

    int status = hook_function(xpc_dictionary_get_value, (void *)xpc_dictionary_get_value_hook, (void **)&xpc_dictionary_get_value_orig);
    return (status == 0 && xpc_dictionary_get_value_orig != NULL) ? 0 : -1;
}
