#include "basebin_hook.h"
#include "basebin_macho.h"
#include "util.h"
#include "jbserver.h"
#include "memory.h"
#include "trustcache.h"
#include "codesign.h"
#include "loader.h"

static orig_spawn_t orig_posix_spawn = NULL;
static orig_spawn_t orig_posix_spawnp = NULL;

static bool loader_blocked(const char *path, char **argv, posix_spawnattr_t *attr) {
    if (path == NULL || path[0] == '\0' || access("/usr/lib/base_hook.dylib", F_OK) != 0) return true;
    if (kinfo->initialized == 0 || kinfo->userspace_rebooting == 1) return true;
    if (strcmp(path, "/Developer/usr/bin/debugserver") == 0) return true;

    if (attr != NULL && *attr != NULL) {
        int proc_type = -1;
        posix_spawnattr_getprocesstype_np(attr, &proc_type);
        if (proc_type == POSIX_SPAWN_PROC_TYPE_DRIVER) return true;
    }

    if (strcmp(path, "/usr/libexec/xpcproxy") == 0) {
        if (argv != NULL && argv[0] != NULL && argv[1] != NULL) {
            char *bundle = argv[1];
            if (strstr(bundle, "debugserver") != NULL) return true;
            if (strstr(bundle, "com.apple") == NULL) return false;

            for (uint32_t i = 0; xpc_block_list[i] != NULL; i++) {
                if (strstr(bundle, xpc_block_list[i]) != NULL) return true;
            }
        }
    } else {
        for (uint32_t i = 0; path_block_list[i] != NULL; i++) {
            if (strcmp(path, path_block_list[i]) == 0) return true;
        }
    }
    return false;
}

int process_binary(const char *path) {
    if (strcmp(path, "/usr/libexec/xpcproxy") == 0) return 0;
    macho_ctx_t *macho = macho_load(path);
    if (macho == NULL) return -1;

    macho_slice_t *best_slice = macho_get_best_slice(macho);
    if (best_slice == NULL) {
        macho_release(macho);
        return -1;
    }

    macho_signature_t *signature = macho_get_signature(best_slice);
    if (signature != NULL) {
        if (trustcache_static_check(signature->hash)) {
            macho_release_signature(signature);
            macho_release(macho);
            return 0;
        }
        macho_release_signature(signature);
    }

    macho_rpaths_t *rpaths = macho_resolve_rpaths(macho);
    if (rpaths == NULL) {
        macho_release(macho);
        return -1;
    }

    macho_deps_t *deps = macho_resolve_deps(macho, rpaths);
    macho_release_rpaths(rpaths);
    macho_release(macho);

    if (deps == NULL) return -1;
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
                if (sign_binary(deps->list[i], signature->offset, signature->size, offset, file_type) != 0) {
                    add_hash = false;
                }
            }

            if (add_hash) trustcache_lock_add_hash(signature->hash, signature->hash_type);
            macho_release_signature(signature);
        }
        macho_release(current_macho);
    }
    
    macho_release_deps(deps);
    return 0;
}

static int spawn_handler(pid_t *pid, const char *path, posix_spawn_file_actions_t *file_actions, posix_spawnattr_t *attr, char **argv, char **env, orig_spawn_t orig_spawn) {
    if (orig_spawn == NULL) return -1;
    if (path != NULL && strcmp(path, "/sbin/launchd") == 0) {
        setenv("DYLD_INSERT_LIBRARIES", "/amethyst/launchd_hook.dylib", 1);
        setenv("AMETHYST", "1", 1);
        usleep(100000);
        return orig_spawn(pid, path, file_actions, attr, argv, environ);
    }

    if (kinfo->initialized == 0 && path != NULL && strcmp(path, "/usr/libexec/xpcproxy") == 0) {
        kinfo->initialized = 1;
    }

    if (loader_blocked(path, argv, attr)) {
        return orig_spawn(pid, path, file_actions, attr, argv, env);
    }

    posix_spawnattr_t target_attr = NULL;
    bool release_attr = false;
    if (attr != NULL && *attr != NULL) {
        target_attr = *attr;
    } else {
        posix_spawnattr_init(&target_attr);
        release_attr = true;
    }

    int16_t attr_flags = 0;
    posix_spawnattr_getflags(&target_attr, &attr_flags);
    attr_flags &= ~POSIX_SPAWN_SETEXEC;
    posix_spawnattr_setflags(&target_attr, attr_flags | POSIX_SPAWN_START_SUSPENDED);

    process_binary(path);
    char **target_env = env_copy(env, 3);
    env_set(target_env, "DYLD_INSERT_LIBRARIES", "/usr/lib/base_hook.dylib", false);
    if (access("/amethyst/.disable_tweaks", F_OK) == 0) env_set(target_env, "DISABLE_TWEAKS", "1", false);

    if (target_attr != NULL) {
        ps_attr_t *ps_attr = (ps_attr_t *)target_attr;
        uint32_t multiplier = 2;

        if ((ps_attr->psa_jetsam_flags & POSIX_SPAWN_JETSAM_SET) != 0) {
            for (uint32_t i = 0; jetsam_list[i] != NULL; i++) {
                if (strstr(path, jetsam_list[i]) != NULL) {
                    multiplier = 3;
                    break;
                }
            }
            
            if (ps_attr->psa_memlimit_active != -1) {
                ps_attr->psa_memlimit_active = (ps_attr->psa_memlimit_active * multiplier);
            }

            if (ps_attr->psa_memlimit_inactive != -1) {
                ps_attr->psa_memlimit_inactive = (ps_attr->psa_memlimit_inactive * multiplier);
            }
        }
    }

    int status = orig_spawn(pid, path, file_actions, &target_attr, argv, target_env);
    if (pid != NULL && *pid > 0) {
        if (status == 0) {
            uint64_t proc = 0;
            uint64_t task = 0;
            struct stat st = {0};

            if (get_process_info(*pid, &proc, &task) == 0) {
                if (lstat(path, &st) == 0 && S_ISREG(st.st_mode) == 1) {
                    if (((st.st_mode & S_ISUID) == S_ISUID) || ((st.st_mode & S_ISGID) == S_ISGID)) {
                        uint64_t ucred = kread64(proc + koffsetof(proc, ucred));
                        if (KADDR_VALID(ucred)) {
                            if ((st.st_mode & S_ISUID) == S_ISUID) kwrite32(ucred + koffsetof(ucred, cr_svuid), st.st_uid);
                            if ((st.st_mode & S_ISGID) == S_ISGID) kwrite32(ucred + koffsetof(ucred, cr_svgid), st.st_gid);
                        }
                    
                    }
                }
        
                add_task_flag(-1, task, TF_PLATFORM);
                fixup_cs_flags(proc);
            }
        }
        kill(*pid, SIGCONT);
    }

    if (release_attr) posix_spawnattr_destroy(&target_attr);
    env_release(target_env);
    return status;
}

static int posix_spawn_hook(pid_t *pid, const char *path, posix_spawn_file_actions_t *file_actions, posix_spawnattr_t *attr, char **argv, char **env) {
    return spawn_handler(pid, path, file_actions, attr, argv, env, orig_posix_spawn);
}

static int posix_spawnp_hook(pid_t *pid, const char *path, posix_spawn_file_actions_t *file_actions, posix_spawnattr_t *attr, char **argv, char **env) {
    return spawn_handler(pid, path, file_actions, attr, argv, env, orig_posix_spawnp);
}

int init_loader(void) {
    hook_function((void *)posix_spawn, (void *)posix_spawn_hook, (void **)&orig_posix_spawn);
    hook_function((void *)posix_spawnp, (void *)posix_spawnp_hook, (void **)&orig_posix_spawnp);
    return 0;
}
