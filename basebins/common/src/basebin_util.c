#include "basebin_macho.h"
#include "basebin_memory.h"
#include "basebin_util.h"

static uint32_t ios_version = -1;
static uint32_t is_arm64e = -1;
static uint32_t stock_libswift = -1;
static uint32_t runtime_page_size = -1;

char **env_copy(char **env, uint32_t addtional) {
    uint32_t count = addtional + 1;
    if (env == NULL) return calloc(1, count * sizeof(char *));

    if (env != NULL) {
        for (int i = 0; env[i]; i++) count++;
    }

    for (int i = 0; env[i] != NULL; i++) count++;
    char **new_env = calloc(1, count * sizeof(char *));
    if (new_env == NULL) return NULL;

    for (int i = 0; env[i] != NULL; i++) {
        if (env[i][0] == '\0') {
            new_env[i] = strdup("");
        } else {
            new_env[i] = strdup(env[i]);
        }
    }
    return new_env;
}

void env_release(char **env) {
    if (env == NULL) return;
    for (int i = 0; env[i] != NULL; i++) {
        free(env[i]);
        env[i] = NULL;
    }
    free(env);
}

char **env_get(char **env, const char *key) {
    if (env == NULL || key == NULL) return NULL;
    size_t key_len = strlen(key);

    for (int i = 0; env[i] != NULL; i++) {
        if (strncmp(env[i], key, key_len) == 0) {
            return &env[i];
        }
    }
    return NULL;
}

void env_set(char **env, const char *key, const char *value, bool append) {
    char **current = env_get(env, key);
    if (current != NULL) {
        char *old_value = *current;
        char *new_value = NULL;

        if (append) {
            if (strstr(old_value, value) != NULL) return;
            asprintf(&new_value, "%s:%s", old_value, value);
        } else {
            asprintf(&new_value, "%s=%s", key, value);
        }

        free(old_value);
        *current = new_value;
    } else {
        for (int i = 0; env[i] != NULL; i++) {
            if (env[i+1] == NULL) {
                asprintf(&env[i+1], "%s=%s", key, value);
                break;
            }
        }
    }
}

bool env_exists(char **env, const char *key, const char *value) {
    if (env == NULL || key == NULL) return false;
    char **ptr = env_get(env, key);
    if (ptr == NULL) return false;

    if (value == NULL) return true;
    return (*ptr != NULL && strcmp(*ptr, value) == 0);
}

void *map_file(const char *path, uint32_t *size, bool write) {
    if (path == NULL || size == NULL) return NULL;
    int fd = open(path, O_RDONLY);
    if (fd < 0) return NULL;

    struct stat st = {0};
    if (fstat(fd, &st) != 0 || st.st_size <= 0) {
        close(fd);
        return NULL;
    }

    uint32_t prot = PROT_READ | (write ? PROT_WRITE : PROT_NONE);
    void *data = mmap(NULL, st.st_size, prot, MAP_PRIVATE, fd, 0);
    close(fd);

    if (data == MAP_FAILED) return NULL;
    *size = (uint32_t)st.st_size;
    return data;
}

void unmap_file(void *data, uint32_t size) {
    if (data == NULL || size == 0) return;
    munmap(data, size);
}

xpc_object_t xpc_open_plist(const char *path) {
    uint32_t file_size = 0;
    uint8_t *file_data = map_file(path, &file_size, false);
    if (file_data == NULL) return NULL;

    xpc_object_t plist = xpc_create_from_plist(file_data, file_size);
    unmap_file(file_data, file_size);

    if (plist == NULL || xpc_get_type(plist) != XPC_TYPE_DICTIONARY) {
        xpc_release(plist);
        return NULL;
    }
    return plist;
}

xpc_object_t xpc_load_entitlements(pid_t pid) {
    cs_header_t hdr = {0};
    int rv = csops(pid, CS_OPS_ENTITLEMENTS_BLOB, &hdr, sizeof(cs_header_t));
    if (rv != -1 || errno != ERANGE) return NULL;
    
    uint32_t size = ntohl(hdr.length);
    if (size > 0x100000 || size < sizeof(cs_header_t)) return NULL;
        
    uint8_t *ents_data = calloc(1, size);
    if (csops(pid, CS_OPS_ENTITLEMENTS_BLOB, ents_data, size) != 0) {
        free(ents_data);
        return NULL;
    }
    
    xpc_object_t ents = xpc_create_from_plist(ents_data+sizeof(cs_header_t), size-sizeof(cs_header_t));
    free(ents_data);
    return ents;
}

uint64_t dict_get_u64(xpc_object_t dict, const char *key) {
    xpc_object_t value = xpc_dictionary_get_value(dict, key);
    if (value == NULL) return 0;

    if (xpc_get_type(value) == XPC_TYPE_STRING) {
        const char *str = xpc_string_get_string_ptr(value);
        if (str == NULL) return 0;

        if (strlen(str) >= 3 && str[0] == '0' && str[1] == 'x') {
            return (uint64_t)strtoull(str, (char **)&str, 16);
        } else {
            return (uint64_t)strtoull(str, (char **)&str, 10);
        }
    } else if (xpc_get_type(value) == XPC_TYPE_UINT64) {
        return xpc_uint64_get_value(value);
    }
    return 0;
}

int dict_get_bool(xpc_object_t dict, const char *key) {
    xpc_object_t value = xpc_dictionary_get_value(dict, key);
    if (value == NULL || xpc_get_type(value) != XPC_TYPE_BOOL) return -1;
    return (value == XPC_BOOL_TRUE) ? 1 : 0;
}

xpc_object_t dict_get_array(xpc_object_t dict, const char *key) {
    xpc_object_t value = xpc_dictionary_get_value(dict, key);
    if (value == NULL || xpc_get_type(value) != XPC_TYPE_ARRAY) return NULL;
    return value;
}

char *resolve_working_dir(void) {
    char path[PATH_MAX] = {0};
    if (getcwd(path, PATH_MAX-1) == NULL || path[0] == '\0') return NULL;
    return strdup(path);
}

char *resolve_home_dir(void) {
    struct passwd *pw = getpwuid(getuid());
    if (pw == NULL || pw->pw_dir == NULL) return NULL;
    return strdup(pw->pw_dir);
}

char *resolve_file_at_path(char *path, const char *file) {
    if (path == NULL || file == NULL || path[0] == '\0' || file[0] == '\0') return NULL;
    size_t path_len = strnlen(path, PATH_MAX);
    size_t file_len = strnlen(file, PATH_MAX);
    if (path_len + file_len + 2 > PATH_MAX) return NULL;
    
    uint32_t file_offset = 0;
    char path_buf[PATH_MAX] = {0};
    if (file[0] == '.' && file[1] == '/') file_offset = 2;
    snprintf(path_buf, PATH_MAX, "%s/%s", path, file + file_offset);
    
    if (access(path_buf, F_OK) == 0) {
        char resolve_buf[PATH_MAX] = {0};
        char *resolved = realpath(path_buf, resolve_buf);

        if (resolved != NULL) {
            struct stat st = {0};
            stat(resolved, &st);
            if (S_ISREG(st.st_mode)) return strdup(resolved);
        }
    }
    return NULL;
}

char *resolve_path(char *path) {
    if (path == NULL || path[0] == '\0') return NULL;
    char path_buf[PATH_MAX] = {0};

    char *resolved = realpath(path, path_buf);
    if (resolved != NULL) return strdup(resolved);
    return NULL;
}

char *resolve_library(const char *library) {
    if (library == NULL || library[0] == '\0') return NULL;
    char path_buf[PATH_MAX] = {0};

    char *resolved = realpath(library, path_buf);
    if (resolved != NULL) return strdup(resolved);
    char *search_paths[] = {
        "/usr/lib",
        "/usr/local/lib",
        "/Library/Frameworks",
        "/System/Library/Frameworks",
        "/System/Library/PrivateFrameworks",
        "/Library",
        "/System/Library",
        "/lib",
        NULL
    };

    for (uint32_t i = 0; search_paths[i] != NULL; i++) {
        if (access(search_paths[i], F_OK) == 0) {
            char *resolved = resolve_file_at_path(search_paths[i], library);
            if (resolved != NULL) return resolved;
        }
    }

    if (!use_stock_libswift() && access("/usr/lib/libswift/stable", F_OK) == 0) {
        char *resolved = resolve_file_at_path("/usr/lib/libswift/stable", library);
        if (resolved != NULL) return resolved;
    }
    return NULL;
}

char *resolve_executable(const char *executable) {
    if (executable == NULL || executable[0] == '\0') return NULL;
    char path_buf[PATH_MAX] = {0};

    char *resolved = realpath(executable, path_buf);
    if (resolved != NULL) return strdup(resolved);
    char *search_paths[] = {
        "/bin",
        "/usr/bin",
        "/sbin",
        "/usr/sbin",
        "/usr/local/bin",
        "/usr/local/sbin",
        "/usr/libexec",
        NULL
    };

    for (uint32_t i = 0; search_paths[i] != NULL; i++) {
        if (access(search_paths[i], F_OK) == 0) {
            char *resolved = resolve_file_at_path(search_paths[i], executable);
            if (resolved != NULL) return resolved;
        }
    }
    return NULL;
}

const char *resolve_binary_name(const char *path) {
    if (path == NULL || path[0] == '\0') return NULL;
    size_t path_len = strlen(path);
    if (path_len <= 1 || path_len > PATH_MAX) return NULL;

    uint32_t idx = (uint32_t)path_len;
    for (; path[idx] != '/' && idx > 0; idx--);
    
    if (idx == 0 || idx == path_len) return NULL;
    return (const char *)&path[idx+1];
}

static char *resolve_next_arg(char **input) {
    if (input == NULL || *input == NULL) return NULL;
    char *str = *input;

    while (str[0] == ' ') str++;
    if (str[0] == '\0') {
        *input = NULL;
        return NULL;
    }
    
    char *start = str;
    char quote = 0;

    while (str[0] != '\0') {
        if ((quote == 0) && (str[0] == '"' || str[0] == '\'')) {
            quote = str[0];
            memmove(str, str + 1, strlen(str));
            continue;
        }

        if ((quote != 0) && (str[0] == quote)) {
            quote = 0;
            memmove(str, str + 1, strlen(str));
            continue;
        }

        if ((quote == 0) && (str[0] == ' ')) {
            str[0] = '\0';
            *input = str + 1;
            return start;
        }
        str++;
    }

    *input = NULL;
    return start;
}

static uint32_t resolve_arg_count(char *input, uint32_t len) {
    if (input == NULL || len == 0) return 0;
    char *copy = strndup(input, len);
    if (copy == NULL) return 0;
    
    char *current = NULL;
    char *temp = copy;
    uint32_t count = 0;
    while ((current = resolve_next_arg(&temp)) != NULL) {
        if (current[0] == '\0') continue;
        count++;
    }
    
    free(copy);
    return count;
}

int resolve_interpreter(const char *path, char **output_path, char ***output_argv, uint32_t *output_argc) {
    if (path == NULL || output_path == NULL || output_argv == NULL || output_argc == NULL) return -1;
    uint32_t file_size = 0;
    char *file_data = map_file(path, &file_size, false);
    if (file_data == NULL) return -1;
    
    char *temp = file_data;
    uint32_t cmd_len = -1;
    uint32_t cmd_offset = -1;
    
    if (file_size < 4 || temp[0] != '#' || temp[1] != '!') {
        unmap_file(file_data, file_size);
        return -1;
    }

    for (uint32_t i = 0; i < file_size; i++) {
        if (temp[i] == '\0') break;
        if (i >= 2 && cmd_offset == -1) {
            if (isalpha(temp[i]) || temp[i] == '/' || temp[i] == '.') {
                cmd_offset = i;
            }
        }
        
        if (temp[i] == '\n') {
            if (i == 0) break;
            cmd_len = i;

            if (temp[i-1] == '\r') cmd_len--;
            break;
        }
    }

    if (cmd_len == -1 || cmd_offset == -1 || (cmd_len <= cmd_offset)) {
        unmap_file(file_data, file_size);
        return -1;
    }
    
    cmd_len -= cmd_offset;
    char *interpreter_cmd = calloc(1, cmd_len+1);
    if (interpreter_cmd == NULL) {
        unmap_file(file_data, file_size);
        return -1;
    }

    memcpy(interpreter_cmd, file_data+cmd_offset, cmd_len);
    char *interpreter_bin = NULL;
    char *interpreter_arg_str = NULL;
    int32_t arg_len = -1;
    
    uint32_t env_len = (uint32_t)strlen("/usr/bin/env");
    if (strncmp(interpreter_cmd, "/usr/bin/env", env_len) == 0) {
        char *temp = interpreter_cmd + env_len;
        uint32_t offset = -1;
        uint32_t len = -1;

        for (uint32_t i = 0; i < (cmd_len - env_len); i++) {
            if (offset == -1 && isalpha(temp[i])) {
                offset = i;
                continue;
            }
            
            if (offset != -1) {
                int32_t end = -1;
                if (temp[i] == '\0' || temp[i] == ' ' || temp[i] == '\r') {
                    end = i;
                } else if (temp[i] == '\n') {
                    end = i;
                    if (temp[i-1] == '\r') end--;
                } else {
                    if ((i + 1) == (cmd_len - env_len)) {
                        len = i + 1 - offset;
                    }
                    continue;
                }
                
                if (end != -1) len = end - offset;
                break;
            }
        }

        if (len != -1 && offset != -1) {
            interpreter_bin = strndup(temp + offset, len);
            if ((env_len + offset + len + 1) < cmd_len) {
                interpreter_arg_str = temp + offset + len;
                arg_len = cmd_len - (env_len + offset + len);
            }
        }
    } else {
        char *temp = interpreter_cmd;
        int32_t len = -1;

        for (uint32_t i = 0; i < cmd_len; i++) {
            if (temp[i] == '\0' || temp[i] == ' ' || temp[i] == '\r'  || temp[i] == '\n') break;
            if (len == -1) {
                len = 1;
            } else {
                len++;
            }
        }
        
        if (len >= 1) {
            interpreter_bin = strndup(temp, len);
            if ((len + 1) < cmd_len) {
                interpreter_arg_str = temp + len;
                arg_len = cmd_len - len;
            }
        }
    }

    if (interpreter_bin == NULL) {
        unmap_file(file_data, file_size);
        free(interpreter_cmd);
        return -1;
    }
    
    char **interpreter_argv = NULL;
    uint32_t interpreter_argc = 0;

    char *interpreter_path = resolve_executable(interpreter_bin);
    free(interpreter_bin);
    
    if (interpreter_path == NULL) {
        unmap_file(file_data, file_size);
        free(interpreter_cmd);
        return -1;
    }

    if (interpreter_arg_str != NULL && arg_len >= 1) {
        if (interpreter_arg_str[0] == ' ') {
            if (arg_len == 1) {
                interpreter_arg_str = NULL;
                arg_len = -1;
            } else {
                interpreter_arg_str++;
                arg_len--;
            }
        }
        
        if (interpreter_arg_str != NULL) {
            uint32_t count = resolve_arg_count(interpreter_arg_str, arg_len);
            if (count >= 1) {
                char *copy = strndup(interpreter_arg_str, arg_len);
                if (copy != NULL) {
                    char **temp_argv = calloc(1, sizeof(char *) * (count + 1));
                    if (temp_argv != NULL) {
                        char *current = NULL;
                        char *temp = copy;
                        uint32_t temp_argc = 0;
                        
                        while ((current = resolve_next_arg(&temp)) != NULL) {
                            if (current[0] == '\0') continue;
                            temp_argv[temp_argc] = strdup(current);
                            if (temp_argv[temp_argc] == NULL) break;
                            temp_argc++;
                        }
                        
                        if (temp_argc != count) {
                            for (uint32_t i = 0; i < count; i++) {
                                if (temp_argv[i] != NULL) free(temp_argv[i]);
                            }
                            free(temp_argv);
                        } else {
                            interpreter_argv = temp_argv;
                            interpreter_argc = temp_argc;
                        }
                    }
                    free(copy);
                }
            }
        }
    }

    free(interpreter_cmd);
    unmap_file(file_data, file_size);

    *output_path = interpreter_path;
    *output_argv = interpreter_argv;
    *output_argc = interpreter_argc;
    return 0;
}

char *resolve_app_path(char *path) {
    if (path == NULL || strstr(path, ".app/") == NULL) return NULL;
    char *copy = strdup(path);
    if (copy == NULL) return NULL;

    char *app_end = strstr(copy, ".app/");
    if (app_end == NULL) {
        free(copy);
        return NULL;
    }
    
    app_end += strlen(".app");
    app_end[0] = '\0';

    char *resolved = resolve_path(copy);
    free(copy);
    return resolved;
}

uint32_t get_ios_version(void) {
    if (ios_version != -1) return ios_version;
    char version_str[64] = {0};
    size_t version_size = sizeof(version_str)-1;
    
    sysctlbyname("kern.osproductversion", version_str, &version_size, 0, 0);
    if (version_str[0] != '\0') {
        uint32_t version[3] = {0};
        sscanf(version_str, "%u.%u.%u", &version[0], &version[1], &version[2]);

        if (version[0] != 0) {
            ios_version = version[0];
            return ios_version;
        }
    }

    bzero(version_str, sizeof(version_str));
    version_size = sizeof(version_str)-1;
    sysctlbyname("kern.osrelease", version_str, &version_size, 0, 0);
    if (version_str[0] != '\0') {
        uint32_t version[3] = {0};
        sscanf(version_str, "%u.%u.%u", &version[0], &version[1], &version[2]);

        switch (version[0]) {
            case 19: ios_version = 13; break;
            case 18: ios_version = 12; break;
            default: ios_version = 0; break;
        }
        return ios_version;
    }

    ios_version = 0;
    return 0;
}

uint32_t get_page_size(void) {
    if (runtime_page_size == -1) {
        uint32_t cpu_family = 0;
        size_t size = sizeof(cpu_family);
        sysctlbyname("hw.cpufamily", &cpu_family, &size, NULL, 0);
    
        switch (cpu_family) {
            case CPUFAMILY_ARM_CYCLONE:
            case CPUFAMILY_ARM_TYPHOON:
                runtime_page_size = 0x1000;
                break;
            default:
                runtime_page_size = 0x4000;
                break;
        }
    }
    return runtime_page_size;
}

bool soc_is_arm64e(void) {
    if (is_arm64e == -1) {
        uint32_t cpu_family = 0;
        size_t size = sizeof(cpu_family);
        sysctlbyname("hw.cpufamily", &cpu_family, &size, NULL, 0);
    
        if (cpu_family == CPUFAMILY_ARM_VORTEX_TEMPEST || cpu_family == CPUFAMILY_ARM_LIGHTNING_THUNDER) {
            is_arm64e = 1;
        } else {
            is_arm64e = 0;
        }
    }
    return (is_arm64e == 1);
}

bool use_stock_libswift(void) {
    if (stock_libswift == -1) {
        char version_str[64] = {0};
        size_t version_size = sizeof(version_str)-1;
        uint32_t version[3] = {0};

        sysctlbyname("kern.osproductversion", version_str, &version_size, 0, 0);
        if (version_str[0] != '\0') {
            sscanf(version_str, "%u.%u.%u", &version[0], &version[1], &version[2]);
        }

        if (version[0] < 12 || (version[0] == 12 && version[1] < 2)) {
            stock_libswift = 0;
        } else {
            stock_libswift = 1;
        }
    }
    return (stock_libswift == 1);
}
