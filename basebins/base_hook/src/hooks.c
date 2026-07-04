#include "basebin_hook.h"
#include "basebin_util.h"
#include "basebin_jbserver.h"
#include "basebin_memory.h"
#include "basebin_dyld.h"
#include "hooks.h"

static void *(*dyld2_dlopen_internal)(const char *, int, void *) = NULL;
static bool (*dyld2_dlopen_preflight_internal)(const char *, void *) = NULL;
static void *(*dyld3_dlopen_internal)(const char *, int, void *) = NULL;
static bool (*dyld3_dlopen_preflight_internal)(const char *) = NULL;
static bool use_dyld3 = false;

__attribute__((naked)) static int sys_csops(pid_t pid, unsigned int ops, void *useraddr, size_t usersize) {
    asm("mov x16, #169");
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

__attribute__((naked)) static int sys_csops_audittoken(pid_t pid, unsigned int ops, void *useraddr, size_t usersize, audit_token_t *token) {
    asm("mov x16, #169");
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

static void *dlopen_hook(const char *path, int mode) {
    if (path == NULL) return ((mode & RTLD_FIRST) != 0) ? RTLD_MAIN_ONLY : RTLD_DEFAULT;
    void *caller = xpaci(__builtin_return_address(0));
    void *handle = NULL;

    if (path != NULL && use_stock_libswift() && strstr(path, "/usr/lib/libswift/stable/") != NULL) {
        char *new_path = calloc(1, PATH_MAX);
        if (new_path != NULL) {
            snprintf(new_path, PATH_MAX-1, "/usr/lib/swift/%s", path + strlen("/usr/lib/libswift/stable/"));

            if (use_dyld3) {
                handle = dyld3_dlopen_internal(new_path, mode, caller);
                asm volatile ("");
            } else {
                handle = dyld2_dlopen_internal(new_path, mode, caller);
                asm volatile ("");
            }

            free(new_path);
            return handle;
        }
    }

    if (path != NULL && strstr(path, "/var/containers") == NULL) {
        if (use_dyld3) {
            handle = dyld3_dlopen_internal(path, mode, caller);
            asm volatile ("");
        } else {
            handle = dyld2_dlopen_internal(path, mode, caller);
            asm volatile ("");
        }
    }

    if (handle != NULL || path == NULL || (mode & RTLD_NOLOAD)) return handle;
    char *resolved = resolve_library(path);

    if (resolved != NULL) {
        jbserver_process_binary(resolved, NULL);
        free(resolved);

        if (use_dyld3) {
            handle = dyld3_dlopen_internal(path, mode, caller);
            asm volatile ("");
        } else {
            handle = dyld2_dlopen_internal(path, mode, caller);
            asm volatile ("");
        }
    }
    return handle;
}

static bool dlopen_preflight_hook(const char *path) {
    if (path == NULL) return false;
    void *caller = xpaci(__builtin_return_address(0));
    bool result = false;

    if (use_stock_libswift() && strstr(path, "/usr/lib/libswift/stable/") != NULL) {
        char *new_path = calloc(1, PATH_MAX);
        if (new_path != NULL) {
            snprintf(new_path, PATH_MAX-1, "/usr/lib/swift/%s", path + strlen("/usr/lib/libswift/stable/"));

            if (use_dyld3) {
                result = dyld3_dlopen_preflight_internal(new_path);
            } else {
                result = dyld2_dlopen_preflight_internal(new_path, caller);
                asm volatile ("");
            }

            free(new_path);
            return result;
        }
    }

    if (path != NULL && strstr(path, "/var/containers") == NULL) {
        if (use_dyld3) {
            result = dyld3_dlopen_preflight_internal(path);
        } else {
            result = dyld2_dlopen_preflight_internal(path, caller);
            asm volatile ("");
        }
    }

    if (result) return result;
    char *resolved = resolve_library(path);

    if (resolved != NULL) {
        jbserver_process_binary(resolved, NULL);
        free(resolved);

        if (use_dyld3) {
            result = dyld3_dlopen_preflight_internal(path);
        } else {
            result = dyld2_dlopen_preflight_internal(path, caller);
            asm volatile ("");
        }
    }
    return result;
}

static int csops_hook(pid_t pid, unsigned int ops, void *useraddr, size_t usersize) {
    int status = sys_csops(pid, ops, useraddr, usersize);
    if (status != 0 || ops != CS_OPS_STATUS || useraddr == NULL || usersize != 4) return status;

    uint32_t cs_flags = *(uint32_t *)useraddr;
    cs_flags |= CS_VALID | CS_DEBUGGED;
    *(uint32_t *)useraddr = cs_flags;
    return status;
}

static int csops_audittoken_hook(pid_t pid, unsigned int ops, void *useraddr, size_t usersize, audit_token_t *token) {
    int status = sys_csops_audittoken(pid, ops, useraddr, usersize, token);
    if (status != 0 || ops != CS_OPS_STATUS || useraddr == NULL || usersize != 4) return status;

    uint32_t cs_flags = *(uint32_t *)useraddr;
    cs_flags |= CS_VALID | CS_DEBUGGED;
    *(uint32_t *)useraddr = cs_flags;
    return status;
}

int init_hooks(char *exec_path) {
    if (dyld_init() != 0) return -1;
    void *gUseDyld3 = dyld_cache_find_symbol("/usr/lib/system/libdyld.dylib", "_gUseDyld3");
    if (gUseDyld3 != NULL && *(uint32_t *)gUseDyld3 != 0) use_dyld3 = true;
    
    // preload CoreFoundation and Foundation in dyld3 mode
    if (use_dyld3) {
        dlopen("/usr/lib/libobjc.A.dylib", RTLD_NOW);
        dlopen("/System/Library/Frameworks/Foundation.framework/Foundation", RTLD_NOW);
        dlopen("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation", RTLD_NOW);
    }

    if (use_dyld3) {
        dyld3_dlopen_internal = dyld_cache_find_symbol("/usr/lib/system/libdyld.dylib", "__ZN5dyld315dlopen_internalEPKciPv");
        dyld3_dlopen_preflight_internal = dyld_cache_find_symbol("/usr/lib/system/libdyld.dylib", "__ZN5dyld325dlopen_preflight_internalEPKc");
    } else {
        dyld2_dlopen_internal = dyld_find_symbol("_dlopen_internal");
        if (dyld2_dlopen_internal == NULL) dyld2_dlopen_internal = dyld_find_symbol("_dlopen");
        dyld2_dlopen_preflight_internal = dyld_find_symbol("_dlopen_preflight_internal");
        if (dyld2_dlopen_preflight_internal == NULL) dyld2_dlopen_preflight_internal = dyld_find_symbol("_dlopen_preflight");
    }

    if (use_dyld3) {
        if (dyld3_dlopen_internal == NULL || dyld3_dlopen_preflight_internal == NULL) {
            dyld_deinit();
            return -1;
        }
        dyld3_dlopen_internal = ptrauth_ia(dyld3_dlopen_internal, NULL);
        dyld3_dlopen_preflight_internal = ptrauth_ia(dyld3_dlopen_preflight_internal, NULL);
    } else {
        if (dyld2_dlopen_internal == NULL || dyld2_dlopen_preflight_internal == NULL) {
            dyld_deinit();
            return -1;
        }
        dyld2_dlopen_internal = ptrauth_ia(dyld2_dlopen_internal, NULL);
        dyld2_dlopen_preflight_internal = ptrauth_ia(dyld2_dlopen_preflight_internal, NULL);
    }

    hook_function((void *)csops, (void *)csops_hook, NULL);
    hook_function((void *)csops_audittoken, (void *)csops_audittoken_hook, NULL);
    hook_function((void *)dlopen, (void *)dlopen_hook, NULL);
    hook_function((void *)dlopen_preflight, (void *)dlopen_preflight_hook, NULL);

    // fix issue where Foundation doesn't initialize correctly in dyld3 mode
    if (use_dyld3) {
        void (*NSInitializePlatform)(void) = dyld_cache_find_symbol("/System/Library/Frameworks/Foundation.framework/Foundation", "__NSInitializePlatform");
        if (NSInitializePlatform != NULL) {
            NSInitializePlatform = ptrauth_ia(NSInitializePlatform, NULL);
            NSInitializePlatform();
        }
    }
    
    dyld_deinit();
    return 0;
}
