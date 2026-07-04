#include "basebin_common.h"
#include "basebin_util.h"
#include "basebin_hook.h"
#include "basebin_jbserver.h"
#include "basebin_macho.h"
#include "basebin_memory.h"
#include "loader.h"
#include "hooks.h"

static const char *get_tweak_loader(void) {
    if (access("/usr/lib/libsonar.dylib", F_OK) == 0) {
        if (access(SONAR_LOADER, R_OK) == 0) return SONAR_LOADER;
    } else if (access("/etc/rc.d/libhooker", F_OK) == 0) {
        if (access(LIBHOOKER_LOADER, R_OK) == 0) return LIBHOOKER_LOADER;
    } else if (access("/etc/rc.d/substitute-launcher", F_OK) == 0) {
        if (access(SUBSTITUTE_LOADER, R_OK) == 0) return SUBSTITUTE_LOADER;
    } else if (access("/etc/rc.d/ellekit-loader", F_OK) == 0) {
        if (access(ELLEKIT_LOADER, R_OK) == 0) return ELLEKIT_LOADER;
    }

    if (access(GENERIC_LOADER, F_OK) == 0) return GENERIC_LOADER;
    return NULL;
}

int init_tweaks(char *exec_path) {
    if (strcmp(exec_path, "/usr/libexec/xpcproxy") == 0) return 0;
    if (access("/.disable_tweakinject", F_OK) == 0 || getenv("DISABLE_TWEAKS") != NULL) return 0;
    if (access("/amethyst/.disable_tweaks", F_OK) == 0 || access("/var/mobile/.tweaks_disabled", F_OK) == 0) return 0;

    if (strstr(exec_path, "SpringBoard.app/SpringBoard") == NULL) {
        if (getenv("_SafeMode") || getenv("_MSSafeMode") || getenv("_LHSafeMode")) return 0;
        if (access("/var/mobile/.safemode", F_OK) == 0 || access("/var/mobile/.eksafemode", F_OK) == 0) return 0;
    }

    const char *loader_path = get_tweak_loader();
    if (loader_path == NULL) return -1;

    if (strcmp(loader_path, SONAR_LOADER) == 0) {
        setenv("SONAR_LOADER", "1", 1);
    }

    void *handle = dlopen(loader_path, RTLD_NOW);
    if (handle == NULL) {
        jbserver_process_binary(loader_path, NULL);
        handle = dlopen(loader_path, RTLD_NOW);
    }
    return (handle == NULL) ? -1 : 0;
}

__attribute__((constructor)) static void ctor(int argc, char **argv, char **envp, char **apple) {
    if (env_exists(envp, "JBUTIL_SPAWN", "1")) {
        char ppid_path[PATH_MAX] = {0};
        proc_name(getppid(), ppid_path, PATH_MAX);

        if (strcmp(ppid_path, "/usr/bin/jbutil") == 0) {
            jbserver_init_process(getpid(), 0, 0, JBSERVER_UNSANDBOX_FULL);
            setuid(0);
            setgid(0);
            
            init_loader();
            init_hooks("/usr/bin/jbutil");
            return;
        }
    }
    
    char *exec_path = apple[0] + strlen("executable_path=");
    if (getenv("PATH") == NULL) {
        setenv("PATH", "/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/bin:/usr/local/sbin", 1);
    }

    if (env_exists(envp, "DYLD_INSERT_LIBRARIES", "/usr/lib/base_hook.dylib")) {
        unsetenv("DYLD_INSERT_LIBRARIES");
    }

#ifndef __arm64e__
    if (strcmp(exec_path, "/usr/libexec/xpcproxy") == 0) {
        init_loader();
        return;
    }
#endif

    jbserver_unsandbox_t unsandbox_type = jbserver_unsandbox_type(exec_path);
    uid_t target_uid = getuid();
    uid_t target_gid = getgid();

    struct stat st = {0};
    if (lstat(exec_path, &st) == 0) {
        if (S_ISREG(st.st_mode) == 1) {
            if ((st.st_mode & S_ISUID) == S_ISUID) target_uid = st.st_uid;
            if ((st.st_mode & S_ISGID) == S_ISGID) target_gid = st.st_gid;
        }
    }

    if (jbserver_init_process(getpid(), target_uid, target_gid, unsandbox_type) == 0) {
#ifdef __arm64e__
        if (strcmp(exec_path, "/usr/libexec/xpcproxy") == 0) {
            init_loader();
            jbserver_init_process(getpid(), target_uid, target_gid, unsandbox_type);
            return;
        }
#endif
        
        if (init_hooks(exec_path) != 0) return;
        init_loader();
        init_tweaks(exec_path);
    }
}
