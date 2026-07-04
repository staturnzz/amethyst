#include "basebin_util.h"
#include "basebin_macho.h"
#include "basebin_jbserver.h"

static jbserver_err_t jbserver_send_msg_with_reply(xpc_object_t request, xpc_object_t *output) {
    struct xpc_global_data *global = NULL;
    if (_os_alloc_once_table[1].once == -1) {
        global = _os_alloc_once_table[1].ptr;
    } else {
        uint32_t num = (get_ios_version() == 13) ? 448 : 472;
        global = _os_alloc_once(&_os_alloc_once_table[1], num, NULL);
        if (global != NULL) _os_alloc_once_table[1].once = -1;
    }

    if (global == NULL) return JBSERVER_ERR_CLIENT_FAILURE;
    if (global->xpc_bootstrap_pipe == NULL) {
        mach_port_t *ports = NULL;
        mach_msg_type_number_t count = 0;
        if (mach_ports_lookup(mach_task_self(), &ports, &count) == 0) {
            global->task_bootstrap_port = ports[0];
            global->xpc_bootstrap_pipe = xpc_pipe_create_from_port(global->task_bootstrap_port, 0);
        }
    }

    if (global->xpc_bootstrap_pipe == NULL) return JBSERVER_ERR_CLIENT_FAILURE;
    if (!MACH_PORT_VALID(global->task_bootstrap_port)) {
        global->task_bootstrap_port = MACH_PORT_NULL;
        return JBSERVER_ERR_CLIENT_FAILURE;
    }

    xpc_object_t xpc_pipe = global->xpc_bootstrap_pipe;
    xpc_object_t reply = NULL;
    xpc_pipe_routine(xpc_pipe, request, &reply);
    
    if (reply == NULL) return JBSERVER_ERR_UNKNOWN_FAILURE;
    jbserver_err_t err = (jbserver_err_t)xpc_dictionary_get_int64(reply, "error");
    if (output != NULL) *output = reply;
    else xpc_release(reply);
    return err;
}

static jbserver_err_t jbserver_send_msg(xpc_object_t request) {
    return jbserver_send_msg_with_reply(request, NULL);
}

static xpc_object_t jbserver_init_msg(jbserver_cmd_t cmd) {
    xpc_object_t request = xpc_dictionary_create(NULL, NULL, 0);
    xpc_dictionary_set_uint64(request, "cmd", cmd);
    xpc_dictionary_set_string(request, "name", "com.staturnz.jbserver");    
    return request;
}

jbserver_err_t jbserver_trustcache(xpc_object_t hash_list, xpc_object_t type_list) {
    if (hash_list == NULL) return JBSERVER_ERR_INVALID_REQUEST;
    if (xpc_array_get_count(hash_list) == 0) {
        return JBSERVER_ERR_SUCCESS;
    }
    
    xpc_object_t request = jbserver_init_msg(JBSERVER_CMD_TRUSTCACHE);
    xpc_dictionary_set_value(request, "hashes", hash_list);
    if (type_list != NULL) xpc_dictionary_set_value(request, "types", type_list);

    jbserver_err_t err = jbserver_send_msg(request);
    xpc_release(request);
    return err;
}

jbserver_err_t jbserver_sign_binary(const char *path, uint32_t le_offset, uint32_t le_size, uint32_t slice_offset, uint32_t file_type) {
    if (path == NULL || le_size == 0) return JBSERVER_ERR_CLIENT_FAILURE;
    xpc_object_t request = jbserver_init_msg(JBSERVER_CMD_SIGN_BINARY);

    xpc_object_t target_path = xpc_string_create(path);
    xpc_dictionary_set_value(request, "path", target_path);
    xpc_release(target_path);

    xpc_dictionary_set_uint64(request, "le_offset", (uint64_t)le_offset);
    xpc_dictionary_set_uint64(request, "le_size", (uint64_t)le_size);
    xpc_dictionary_set_uint64(request, "slice_offset", (uint64_t)slice_offset);
    xpc_dictionary_set_uint64(request, "file_type", (uint64_t)file_type);

    jbserver_err_t err = jbserver_send_msg(request);
    xpc_release(request);
    return err;
}

jbserver_err_t jbserver_init_process(pid_t pid, uid_t target_uid, gid_t target_gid, jbserver_unsandbox_t unsandbox_type) {
    xpc_object_t request = jbserver_init_msg(JBSERVER_CMD_INIT_PROCESS);
    if (pid != getpid()) xpc_dictionary_set_int64(request, "pid", (int64_t)pid);
    if (target_uid != getuid()) xpc_dictionary_set_int64(request, "target_uid", (int64_t)target_uid);
    if (target_gid != getgid()) xpc_dictionary_set_int64(request, "target_gid", (int64_t)target_uid);
    xpc_dictionary_set_uint64(request, "unsandbox_type", unsandbox_type);

    xpc_object_t reply = NULL;
    jbserver_err_t err = jbserver_send_msg_with_reply(request, &reply);
    xpc_release(request);
    
    if (err != JBSERVER_ERR_SUCCESS || reply == NULL) {
        if (reply != NULL) xpc_release(reply);
        return err;
    }

    if (unsandbox_type == JBSERVER_UNSANDBOX_EXTENSIONS) {
        xpc_object_t extensions = xpc_dictionary_get_array(reply, "extensions");
        if (extensions == NULL || xpc_get_type(extensions) != XPC_TYPE_ARRAY) {
            xpc_release(reply);
            return JBSERVER_ERR_UNKNOWN_FAILURE;
        }

        size_t count = xpc_array_get_count(extensions);
        for (int i = 0; i < count; i++) {
            const char *ext = xpc_array_get_string(extensions, i);
            if (ext != NULL) sandbox_extension_consume(ext);
        }
    }

    xpc_release(reply);
    return err;
}

jbserver_err_t jbserver_preload_binary(const char *path) {
    if (path == NULL) return JBSERVER_ERR_INVALID_PATH;
    int fd = open(path, O_RDONLY);
    if (fd < 0) return JBSERVER_ERR_INVALID_PATH;

    macho_ctx_t *macho = macho_load(path);
    if (macho == NULL) {
        close(fd);
        return JBSERVER_ERR_INVALID_PATH;
    }

    for (uint32_t i = 0; i < macho->slice_count; i++) {
        macho_signature_t *signature = macho_get_signature(&macho->slice_list[i]);
        if (signature == NULL) continue;

        fsignatures_t fsignature = {0};
        fsignature.fs_file_start = macho->slice_list[i].offset;
        fsignature.fs_blob_start = (void *)((uint64_t)signature->offset);
        fsignature.fs_blob_size = signature->size;
        
        fcntl(fd, F_ADDFILESIGS, &fsignature);
        macho_release_signature(signature);
    }

    macho_release(macho);
    xpc_object_t request = jbserver_init_msg(JBSERVER_CMD_PRELOAD_BINARY);
    xpc_object_t target_path = xpc_string_create(path);
    xpc_dictionary_set_value(request, "path", target_path);
    xpc_release(target_path);

    jbserver_err_t err = jbserver_send_msg(request);
    xpc_release(request);
    close(fd);
    return err;
}

jbserver_err_t jbserver_platformize(pid_t pid) {
    xpc_object_t request = jbserver_init_msg(JBSERVER_CMD_PLATFORMIZE);
    if (pid != getpid()) xpc_dictionary_set_int64(request, "pid", (int64_t)pid);

    jbserver_err_t err = jbserver_send_msg(request);
    xpc_release(request);
    return err;
}

jbserver_err_t jbserver_unsandbox(pid_t pid, jbserver_unsandbox_t unsandbox_type) {
    xpc_object_t request = jbserver_init_msg(JBSERVER_CMD_UNSANDBOX);
    if (pid != getpid()) xpc_dictionary_set_int64(request, "pid", (int64_t)pid);
    xpc_dictionary_set_uint64(request, "unsandbox_type", unsandbox_type);

    xpc_object_t reply = NULL;
    jbserver_err_t err = jbserver_send_msg_with_reply(request, &reply);
    xpc_release(request);
    
    if (err != JBSERVER_ERR_SUCCESS || reply == NULL) {
        if (reply != NULL) xpc_release(reply);
        return err;
    }

    if (unsandbox_type == JBSERVER_UNSANDBOX_EXTENSIONS) {
        xpc_object_t extensions = xpc_dictionary_get_array(reply, "extensions");
        if (extensions == NULL || xpc_get_type(extensions) != XPC_TYPE_ARRAY) {
            xpc_release(reply);
            return JBSERVER_ERR_UNKNOWN_FAILURE;
        }

        size_t count = xpc_array_get_count(extensions);
        for (int i = 0; i < count; i++) {
            const char *ext = xpc_array_get_string(extensions, i);
            if (ext != NULL) sandbox_extension_consume(ext);
        }
    }

    xpc_release(reply);
    return err;
}

jbserver_err_t jbserver_patch_setuid(pid_t pid) {
    xpc_object_t request = jbserver_init_msg(JBSERVER_CMD_PATCH_SETUID);
    if (pid != getpid()) xpc_dictionary_set_int64(request, "pid", (int64_t)pid);

    jbserver_err_t err = jbserver_send_msg(request);
    xpc_release(request);
    return err;
}

jbserver_err_t jbserver_patch_setgid(pid_t pid) {
    xpc_object_t request = jbserver_init_msg(JBSERVER_CMD_PATCH_SETGID);
    if (pid != getpid()) xpc_dictionary_set_int64(request, "pid", (int64_t)pid);

    jbserver_err_t err = jbserver_send_msg(request);
    xpc_release(request);
    return err;
}

jbserver_err_t jbserver_check_fakesigned(char *path, int32_t *result) {
    if (path == NULL || result == NULL) return JBSERVER_ERR_INVALID_REQUEST;
    xpc_object_t request = jbserver_init_msg(JBSERVER_CMD_CHECK_FAKESIGNED);
    *result = -1;

    xpc_object_t target_path = xpc_string_create(path);
    xpc_dictionary_set_value(request, "path", target_path);
    xpc_release(target_path);

    xpc_object_t reply = NULL;
    jbserver_err_t err = jbserver_send_msg_with_reply(request, &reply);
    xpc_release(request);
    
    if (err != JBSERVER_ERR_SUCCESS || reply == NULL) {
        if (reply != NULL) xpc_release(reply);
        return err;
    }

    *result = (xpc_dictionary_get_bool(reply, "result") ? 1 : 0);
    xpc_release(reply);
    return JBSERVER_ERR_SUCCESS;
}

jbserver_err_t jbserver_add_fakesigned(char *path) {
    if (path == NULL) return JBSERVER_ERR_INVALID_PATH;
    xpc_object_t request = jbserver_init_msg(JBSERVER_CMD_ADD_FAKESIGNED);

    xpc_object_t target_path = xpc_string_create(path);
    xpc_dictionary_set_value(request, "path", target_path);
    xpc_release(target_path);

    jbserver_err_t err = jbserver_send_msg(request);
    xpc_release(request);
    return err;
}

jbserver_err_t jbserver_heartbeat(void) {
    xpc_object_t request = jbserver_init_msg(JBSERVER_CMD_HEARTBEAT);
    jbserver_err_t err = jbserver_send_msg(request);
    xpc_release(request);
    return (err == 0x1337) ? JBSERVER_ERR_SUCCESS : JBSERVER_ERR_SERVER_FAILURE;
}

jbserver_err_t jbserver_process_binary(const char *path, bool *external_libswift) {
    if (path == NULL) return JBSERVER_ERR_INVALID_PATH;
    macho_ctx_t *macho = macho_load(path);
    if (macho == NULL) return JBSERVER_ERR_INVALID_PATH;

    if (!macho_should_process(macho)) {
        macho_release(macho);
        return JBSERVER_ERR_SUCCESS;
    }
    
    macho_rpaths_t *rpaths = macho_resolve_rpaths(macho);
    if (rpaths == NULL) {
        macho_release(macho);
        return JBSERVER_ERR_INVALID_PATH;
    }

    macho_deps_t *deps = macho_resolve_deps(macho, rpaths);
    macho_release_rpaths(rpaths);
    macho_release(macho);

    if (deps == NULL) return JBSERVER_ERR_INVALID_PATH;
    if (external_libswift != NULL && soc_is_arm64e()) {
        *external_libswift = macho_uses_external_libswift(deps);
    }

    xpc_object_t hash_list = xpc_array_create(NULL, 0);
    xpc_object_t type_list = xpc_array_create(NULL, 0);

    for (uint32_t i = 0; i < deps->count; i++) {
        macho_ctx_t *current_macho = macho_load(deps->list[i]);
        if (current_macho == NULL) continue;

        for (uint32_t j = 0; j < current_macho->slice_count; j++) {
            macho_signature_t *signature = macho_get_signature(&current_macho->slice_list[j]);
            if (signature == NULL) continue;
            
            uint32_t offset = current_macho->slice_list[j].offset;
            uint32_t file_type = current_macho->slice_list[j].file_type;
            bool add_hash = true;

            if (signature->is_fakesigned || (signature->version <= 0x20001 && signature->hash_type == CS_HASHTYPE_SHA1)) {
                if (jbserver_sign_binary(deps->list[i], signature->offset, signature->size, offset, file_type) != JBSERVER_ERR_SUCCESS) {
                    add_hash = false;
                }
            }

            if (add_hash) {
                xpc_object_t xpc_hash = xpc_data_create(signature->hash, 20);
                if (xpc_hash != NULL) {
                    if (get_ios_version() >= 13) {
                        xpc_object_t hash_type = xpc_uint64_create((uint64_t)signature->hash_type);
                        xpc_array_append_value(type_list, hash_type);
                        xpc_release(hash_type);
                    }
                    
                    xpc_array_append_value(hash_list, xpc_hash);
                    xpc_release(xpc_hash);
                }
            }
            macho_release_signature(signature);
        }
        macho_release(current_macho);
    }

    macho_release_deps(deps);
    if (xpc_array_get_count(hash_list) == 0) {
        xpc_release(hash_list);
        xpc_release(type_list);
        return JBSERVER_ERR_SUCCESS;
    }

    if (xpc_array_get_count(type_list) == 0) {
        xpc_release(type_list);
        type_list = NULL;
    }
    
    jbserver_err_t err = jbserver_trustcache(hash_list, type_list);
    if (type_list != NULL) xpc_release(type_list);
    xpc_release(hash_list);
    return err;
}

jbserver_unsandbox_t jbserver_unsandbox_type(const char *exec_path) {
   //return JBSERVER_UNSANDBOX_FULL;

    if (exec_path == NULL || sandbox_check(getpid(), NULL, 0, NULL) == 0) return JBSERVER_UNSANDBOX_NONE;
    if (strstr(exec_path, "PluginKitPlugin") != NULL || strstr(exec_path, ".appex") != NULL || strstr(exec_path, "XPCServices") != NULL) {
        return JBSERVER_UNSANDBOX_NONE;
    }

    for (int i = 0; sb_ext_override_list[i]; i++) {
        if (strcmp(exec_path, sb_ext_override_list[i]) == 0) {
            return JBSERVER_UNSANDBOX_EXTENSIONS;
        }
    }

    if (strstr(exec_path, "WebKit") != NULL || strstr(exec_path, "WebContent") != NULL) {
        return JBSERVER_UNSANDBOX_EXTENSIONS;
    }

    for (int i = 0; sb_full_override_list[i]; i++) {
        if (strcmp(exec_path, sb_full_override_list[i]) == 0) {
            return JBSERVER_UNSANDBOX_FULL;
        }
    }

    xpc_object_t ents = xpc_load_entitlements(getpid());
    if (ents != NULL) {
        if (dict_get_bool(ents, "com.apple.private.security.sandbox") == 0 || 
            dict_get_bool(ents, "com.apple.private.security.no-sandbox") == 1 ||
            dict_get_bool(ents, "com.apple.private.security.container-required") == 0 ||
            dict_get_bool(ents, "com.apple.private.security.no-container") == 1) {
            xpc_release(ents);
            return JBSERVER_UNSANDBOX_FULL;
        }

        xpc_object_t rw_list = dict_get_array(ents, "com.apple.security.exception.files.absolute-path.read-write");
        if (rw_list != NULL) {
            uint32_t count = xpc_array_get_count(rw_list);
            for (uint32_t i = 0; i < count; i++) {
                xpc_object_t value = xpc_array_get_value(rw_list, i);
                if (value == NULL || xpc_get_type(value) != XPC_TYPE_STRING) continue;

                const char *value_str = xpc_string_get_string_ptr(value);
                if (value_str == NULL) continue;
                
                if (strcmp(value_str, "/") == 0) {
                    xpc_release(ents);
                    return JBSERVER_UNSANDBOX_FULL;
                }
            }
        }

        xpc_object_t ro_list = dict_get_array(ents, "com.apple.security.exception.files.absolute-path.read-only");
        if (ro_list != NULL ) {
            uint32_t count = xpc_array_get_count(ro_list);
            for (uint32_t i = 0; i < count; i++) {
                xpc_object_t value = xpc_array_get_value(ro_list, i);
                if (value == NULL || xpc_get_type(value) != XPC_TYPE_STRING) continue;

                const char *value_str = xpc_string_get_string_ptr(value);
                if (value_str == NULL) continue;
                
                if (strcmp(value_str, "/") == 0) {
                    xpc_release(ents);
                    return JBSERVER_UNSANDBOX_FULL;
                }
            }
        }
        xpc_release(ents);
    }

    if (strncmp(exec_path, "/usr", strlen("/usr")) == 0 || strncmp(exec_path, "/Library", strlen("/Library")) == 0) {
        return JBSERVER_UNSANDBOX_FULL;
    }

    struct stat st = {0};
    if (lstat(exec_path, &st) == 0) {
        if (S_ISREG(st.st_mode) == 1) {
            if ((st.st_mode & S_ISUID) == S_ISUID || (st.st_mode & S_ISGID) == S_ISGID) {
                if (st.st_uid == 0 || st.st_gid == 0) return JBSERVER_UNSANDBOX_FULL;
            }
        }
    }
    return JBSERVER_UNSANDBOX_EXTENSIONS;
}
