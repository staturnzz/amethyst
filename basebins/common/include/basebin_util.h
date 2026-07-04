#ifndef basebins_util_h
#define basebins_util_h

#include "basebin_common.h"

#define POSIX_SPAWN_PROC_TYPE_DRIVER 0x700
#define POSIX_SPAWN_PROC_TYPE_MASK 0x00000F00
#define POSIX_SPAWN_JETSAM_SET 0x8000
#define POSIX_SPAWN_JETSAM_USE_EFFECTIVE_PRIORITY 0x01
#define POSIX_SPAWN_JETSAM_HIWATER_BACKGROUND 0x02
#define JETSAM_PRIORITY_MAX 21
#define JETSAM_PRIORITY_DEFAULT 18
#define CS_OPS_ENTITLEMENTS_BLOB 7

typedef struct {
    short psa_flags;
    short flags_padding;
    sigset_t psa_sigdefault;
    sigset_t psa_sigmask;
    pid_t psa_pgroup;
    cpu_type_t psa_binprefs[4];
    int psa_pcontrol;
    int psa_apptype;
    uint64_t psa_cpumonitor_percent;
    uint64_t psa_cpumonitor_interval;
    uint64_t psa_reserved;
    short psa_jetsam_flags;
    short short_padding;
    int psa_priority;
    int psa_memlimit_active;
    int psa_memlimit_inactive;
    uint64_t psa_qos_clamp;
    uint64_t psa_darwin_role;
    int psa_thread_limit;
    uint64_t psa_max_addr;
} ps_attr_t;

char **env_copy(char **env, uint32_t addtional);
void env_release(char **env);
char **env_get(char **env, const char *key);
void env_set(char **env, const char *key, const char *value, bool append);
bool env_exists(char **env, const char *key, const char *value);

void *map_file(const char *path, uint32_t *size, bool write);
void unmap_file(void *data, uint32_t size);

xpc_object_t xpc_open_plist(const char *path);
xpc_object_t xpc_load_entitlements(pid_t pid);
uint64_t dict_get_u64(xpc_object_t plist, const char *key);
int dict_get_bool(xpc_object_t dict, const char *key);
xpc_object_t dict_get_array(xpc_object_t dict, const char *key);

char *resolve_working_dir(void);
char *resolve_home_dir(void);
char *resolve_file_at_path(char *path, const char *file);
char *resolve_path(char *path);
char *resolve_library(const char *library);
char *resolve_executable(const char *executable);
const char *resolve_binary_name(const char *path);
int resolve_interpreter(const char *path, char **output_path, char ***output_argv, uint32_t *output_argc);
char *resolve_app_path(char *path);
uint32_t get_ios_version(void);
uint32_t get_page_size(void);
bool soc_is_arm64e(void);
bool use_stock_libswift(void);

#endif /* basebins_util_h */
