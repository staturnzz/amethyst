#include "basebin_hook.h"
#include "basebin_util.h"
#include "basebin_jbserver.h"
#include "loader.h"

static orig_spawn_t orig_posix_spawn = NULL;
static orig_spawn_t orig_posix_spawnp = NULL;

static bool is_interpreted_script(const char *path) {
    if (path == NULL) return false;
    char data[2] = {0};
    int fd = open(path, O_RDONLY);
    if (fd < 0) return false;

    read(fd, data, 2);
    close(fd);
    return (data[0] == '#' && data[1] == '!');
}

__attribute__((naked)) static int sys_execve(char *path, char **argv, char **env) {
    asm("mov x16, #59");
    asm("svc #0x80");
    asm("b.cc 0f");
    asm("stp x29, x30, [sp, #-0x10]!");
    asm("mov x29, sp");
    asm("bl _cerror_nocancel");
    asm("mov sp, x29");
    asm("ldp x29, x30, [sp], #0x10");
    asm("0:");
    asm("ret");
}

static bool loader_blocked(const char *path, char **argv, posix_spawnattr_t *attr) {
    if (path == NULL || path[0] == '\0' || access("/usr/lib/base_hook.dylib", F_OK) != 0) return true;
    if (attr != NULL && *attr != NULL) {
        ps_attr_t *ps_attr = (ps_attr_t *)(*attr);
        int proc_type = (ps_attr->psa_apptype & POSIX_SPAWN_PROC_TYPE_MASK);
        if (proc_type == POSIX_SPAWN_PROC_TYPE_DRIVER) return true;
    }
    
    for (uint32_t i = 0; path_block_list[i] != NULL; i++) {
        if (strcmp(path, path_block_list[i]) == 0) return true;
    }
    return false;
}

static int spawn_handler(pid_t *pid, const char *path, posix_spawn_file_actions_t *file_actions, posix_spawnattr_t *attr, char **argv, char **env, bool is_exec, orig_spawn_t orig_spawn) {
    if (orig_spawn == NULL) return -1;
    if (!is_exec) {
        if (pid == NULL) {
            is_exec = true;
        } else {
            if (attr != NULL && *attr != NULL) {
                int16_t attr_flags = 0;
                posix_spawnattr_getflags(attr, &attr_flags);
                if ((attr_flags & POSIX_SPAWN_SETEXEC) != 0) is_exec = true;
            }
        }
    }
    
    char *target_path = NULL;
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
    if (is_exec) {
        attr_flags &= ~POSIX_SPAWN_START_SUSPENDED;
        posix_spawnattr_setflags(&target_attr, attr_flags | POSIX_SPAWN_SETEXEC);
    } else {
        attr_flags &= ~POSIX_SPAWN_SETEXEC;
        posix_spawnattr_setflags(&target_attr, attr_flags);
    }
    
    if (loader_blocked(path, argv, attr) || ((target_path = resolve_executable(path)) == NULL)) {
        if (is_exec) {
            int status = orig_spawn(NULL, path, NULL, &target_attr, argv, env);
            if (release_attr) posix_spawnattr_destroy(&target_attr);
            if (status == EINVAL) status = sys_execve((char *)path, argv, env);
            return status;
        } else {
            int status = orig_spawn(pid, path, file_actions, &target_attr, argv, env);
            if (release_attr) posix_spawnattr_destroy(&target_attr);
            return status;
        }
    }

    char **target_env = env_copy(env, 5);
    char **dyld_insert = env_get(target_env, "DYLD_INSERT_LIBRARIES");
    bool inject_hook = true;

    if (dyld_insert != NULL && *dyld_insert != NULL) {
        char *copy = strdup((*dyld_insert) + strlen("DYLD_INSERT_LIBRARIES="));
        char *current = NULL;

        if (copy != NULL) {
            char *temp = copy;
            while ((current = strsep(&temp, ":")) != NULL) {
                if (current[0] == '\0') continue;
                if (strcmp(current, "/usr/lib/base_hook.dylib") == 0) {
                    inject_hook = false;
                    continue;
                }

                char *resolved_lib = resolve_library(current);
                if (resolved_lib != NULL) {
                    jbserver_process_binary(resolved_lib, NULL);
                    free(resolved_lib);
                }
            }
            free(copy);
        }
    }

    if (getenv("DISABLE_TWEAKS") != NULL) env_set(target_env, "DISABLE_TWEAKS", "1", false);
    if (inject_hook) env_set(target_env, "DYLD_INSERT_LIBRARIES", "/usr/lib/base_hook.dylib", true);
    char **target_argv = argv;
    bool release_argv = false;
    bool external_libswift = false;

    if (is_interpreted_script(target_path)) {
        char *interpreter_path = NULL;
        char **interpreter_argv = NULL;
        uint32_t interpreter_argc = 0;

        if (resolve_interpreter(target_path, &interpreter_path, &interpreter_argv, &interpreter_argc) == 0) {
            jbserver_process_binary(interpreter_path, &external_libswift);
            uint32_t arg_count = interpreter_argc + 2;
            if (argv != NULL) {
                for (uint32_t i = 0; argv[i] != NULL; i++) arg_count++;
            }

            target_argv = calloc(1, sizeof(char *) * (arg_count + 1));
            if (target_argv != NULL) {
                target_argv[0] = strdup(interpreter_path);
                for (uint32_t i = 0; i < interpreter_argc; i++) {
                    target_argv[i+1] = interpreter_argv[i];
                }

                target_argv[interpreter_argc+1] = target_path;
                if (argv != NULL) {
                    for (int i = 1; argv[i] != NULL; i++) {
                        target_argv[i+interpreter_argc+1] = strdup(argv[i]);
                    }
                }

                target_path = interpreter_path;
                release_argv = true;
            }
        }
    } else {
        jbserver_process_binary(target_path, &external_libswift);
    }

    if (external_libswift) {
        jbserver_preload_binary(target_path);
        env_set(target_env, "DYLD_FALLBACK_LIBRARY_PATH", "/usr/lib:/usr/local/lib:/lib:/Library:/usr/lib/libswift/stable", true);
    }
    
    if (target_attr != NULL) {
        ps_attr_t *ps_attr = (ps_attr_t *)target_attr;
        uint32_t multiplier = 2;

        if ((ps_attr->psa_jetsam_flags & POSIX_SPAWN_JETSAM_SET) != 0) {
            for (uint32_t i = 0; jetsam_list[i] != NULL; i++) {
                if (strstr(target_path, jetsam_list[i]) != NULL) {
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

    int status = orig_spawn(pid, target_path, file_actions, &target_attr, target_argv, target_env);
    if (release_attr) posix_spawnattr_destroy(&target_attr);
    if (is_exec && status == EINVAL) {
        status = sys_execve(target_path, target_argv, target_env);
    }

    if (!is_exec && status == 0 && pid != NULL && (attr_flags & POSIX_SPAWN_START_SUSPENDED) != 0) {
        pid_t target_pid = *pid;
        if (target_pid > 1 || target_pid != getpid()) {
            jbserver_unsandbox_t unsandbox_type = jbserver_unsandbox_type(target_path);
            uid_t target_uid = getuid();
            uid_t target_gid = getgid();

            struct stat st = {0};
            if (lstat(target_path, &st) == 0) {
                if (S_ISREG(st.st_mode) == 1) {
                    if ((st.st_mode & S_ISUID) == S_ISUID) target_uid = st.st_uid;
                    if ((st.st_mode & S_ISGID) == S_ISGID) target_gid = st.st_gid;
                }
            }
            jbserver_init_process(target_pid, target_uid, target_gid, unsandbox_type);
        }
    }

    if (release_argv) {
        if (target_argv != NULL) {
            for (uint32_t i = 0; target_argv[i] != NULL; i++) {
                free(target_argv[i]);
            }
            free(target_argv);
        }
    } 

    env_release(target_env);
    free(target_path);
    return status;
}

static int execve_hook(const char *path, char **argv, char **envp) {
    return spawn_handler(NULL, path, NULL, NULL, argv, envp, true, orig_posix_spawn);
}

static int posix_spawn_hook(pid_t *pid, const char *path, posix_spawn_file_actions_t *file_actions, posix_spawnattr_t *attr, char **argv, char **env) {
    return spawn_handler(pid, path, file_actions, attr, argv, env, false, orig_posix_spawn);
}

static int posix_spawnp_hook(pid_t *pid, const char *path, posix_spawn_file_actions_t *file_actions, posix_spawnattr_t *attr, char **argv, char **env) {
    return spawn_handler(pid, path, file_actions, attr, argv, env, false, orig_posix_spawnp);
}

void init_loader(void) {
    hook_function((void *)posix_spawn, (void *)posix_spawn_hook, (void **)&orig_posix_spawn);
    hook_function((void *)posix_spawnp, (void *)posix_spawnp_hook, (void **)&orig_posix_spawnp);
    hook_function((void *)execve, (void *)execve_hook, NULL);
}
