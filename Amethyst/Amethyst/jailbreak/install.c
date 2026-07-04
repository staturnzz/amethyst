#include "jailbreak.h"
#include "utils.h"
#include "trustcache.h"
#include "install.h"

int install_deb(char *path) {
    if (path == NULL) return -1;
    return run_jbutil("--install-deb", path, true);
}

int install_tnsv2_support(void) {
    if (access("/chimera/.tnsv2_amethyst", F_OK) == 0) {
        char *path = (char *)bundle_path("tnsv2_updater_stub.deb");
        if (path != NULL) install_deb(path);
        vnode_hide_path("/chimera");
        return 0;
    }
    
    remove_at_path("/chimera");
    mkdir("/chimera", 0777);
    chown("/chimera", 501, 501);
    
    symlink("/amethyst/jbutil", "/chimera/launchctl");
    symlink("/amethyst/launchd_hook.dylib", "/chimera/pspawn_payload.dylib");
    symlink("/usr/lib/base_hook.dylib", "/chimera/pspawn_payload-stg2.dylib");
    
    uint64_t current_proc = kinfo->kern_proc_addr;
    uint64_t all_proc = 0;
    
    while (current_proc != 0) {
        if (kread64(kread64(current_proc + 0x8)) != current_proc) {
            if (current_proc > kinfo->kernel_base && current_proc <= (kinfo->kernel_base + 0x4000000)) {
                all_proc = current_proc;
                break;
            }
        }
        current_proc = kread64(current_proc + 0x8);
    }
    
    if (all_proc == 0) return -1;
    CFMutableDictionaryRef plist = CFDictionaryCreateMutable(NULL, 0, NULL, NULL);
    CFMutableDictionaryRef chimera_env = CFDictionaryCreateMutable(NULL, 0, NULL, NULL);
    
    CFStringRef kbase_str = CFStringCreateWithFormat(NULL, NULL, CFSTR("0x%llx"), kinfo->kernel_base);
    CFDictionaryAddValue(chimera_env, CFSTR("KernelBase"), kbase_str);
    
    CFStringRef all_proc_str = CFStringCreateWithFormat(NULL, NULL, CFSTR("0x%llx"), all_proc);
    CFDictionaryAddValue(chimera_env, CFSTR("AllProc"), all_proc_str);
    
    CFDictionaryAddValue(chimera_env, CFSTR("KernelSignpost"), CFSTR("0x0"));
    CFDictionaryAddValue(plist, CFSTR("EnvironmentVariables"), chimera_env);
    
    int status = write_plist("/chimera/jailbreakd.plist", plist);
    if (status == 0) {
        chmod("/chimera/jailbreakd.plist", 0777);
        chown("/chimera/jailbreakd.plist", 501, 501);
        
        int fd = open("/chimera/.tnsv2_amethyst", O_CREAT | O_RDWR);
        if (fd >= 0) close(fd);
        
        vnode_hide_path("/chimera");
        char *path = (char *)bundle_path("tnsv2_updater.deb");
        install_deb(path);
    }
    return status;
}

static void show_non_default_apps(void) {
    CFMutableDictionaryRef plist = load_plist("/var/mobile/Library/Preferences/com.apple.springboard.plist");
    if (plist != NULL) {
        CFTypeRef current = CFDictionaryGetValue(plist, CFSTR("SBShowNonDefaultSystemApps"));
        if (current == NULL || CFGetTypeID(current) != CFBooleanGetTypeID() || !CFBooleanGetValue(current)) {
            CFDictionaryAddValue(plist, CFSTR("SBShowNonDefaultSystemApps"), kCFBooleanTrue);
            write_plist("/var/mobile/Library/Preferences/com.apple.springboard.plist", plist);
            chmod("/var/mobile/Library/Preferences/com.apple.springboard.plist", 0644);
            chown("/var/mobile/Library/Preferences/com.apple.springboard.plist", 501, 501);
        }
        plist = NULL;
    }
    
    char hw_model[128] = {0};
    size_t size = sizeof(hw_model)-1;
    sysctlbyname("hw.model", hw_model, &size, NULL, 0);
    
    char plist_path[PATH_MAX] = {0};
    snprintf(plist_path, PATH_MAX-1, "/System/Library/CoreServices/SpringBoard.app/%s.plist", hw_model);
    plist = load_plist(plist_path);
    
    if (plist != NULL) {
        CFMutableDictionaryRef capabilities = (CFMutableDictionaryRef)CFDictionaryGetValue(plist, CFSTR("capabilities"));
        if (capabilities == NULL) {
            CFDictionaryAddValue(capabilities, CFSTR("hide-non-default-apps"), kCFBooleanFalse);
            write_plist(plist_path, plist);
            chmod(plist_path, 0700);
            chown(plist_path, 501, 501);
        }
        plist = NULL;
    }
    
    pid_t cfprefsd_pid = find_pid_for_name("cfprefsd");
    pid_t installd_pid = find_pid_for_name("installd");
    if (cfprefsd_pid != -1) kill(cfprefsd_pid, SIGKILL);
    if (installd_pid != -1) kill(installd_pid, SIGKILL);
    usleep(100000);
    sync();
}

int install_bootstrap(void) {
    const char *tar_path = NULL;
    if (kinfo->version[0] == 12) {
        tar_path = bundle_path("bootstrap-1500.tar.lzfse");
    } else {
        tar_path = bundle_path("bootstrap-1600.tar.lzfse");
    }
    
    if (tar_path == NULL || access(tar_path, F_OK) != 0) return -1;
    run_jbutil("--install-bootstrap", (char *)tar_path, true);
    
    if (access("/Library/dpkg", F_OK) != 0 || access("/usr/bin/apt-get", F_OK) != 0) return -1;
    return 0;
}

void migrate_install(void) {
    for (uint32_t i = 0; other_jailbreak_leftovers[i] != NULL; i++) {
        remove_at_path(other_jailbreak_leftovers[i]);
    }
    
    if (access("/chimera/.tnsv2_amethyst", F_OK) != 0) {
        remove_at_path("/chimera");
    }
    
    int fd = open("/.installed_amethyst", O_CREAT | O_RDWR);
    if (fd >= 0) {
        close(fd);
        chmod("/.installed_amethyst", 0644);
        chown("/.installed_amethyst", 0, 0);
        sync();
    }
    
    bool add_sonar = true;
    uint32_t status_size = 0;
    char *status_data = (char *)map_file("/var/lib/dpkg/status", &status_size, false);
    if (status_data != NULL) {
        if (strnstr(status_data, "Package: org.coolstar.libhooker", status_size) != NULL) add_sonar = false;
        munmap(status_data, status_size);
    }
    
    if (access(AMETHYST_SOURCES_FILE, F_OK) != 0) {
        FILE *sources = fopen(AMETHYST_SOURCES_FILE, "w+");
        if (sources != NULL) {
            fprintf(sources, APT_AMETHYST_REPO);
            if (add_sonar) fprintf(sources, APT_SONAR_REPO);
            fflush(sources);
            fclose(sources);

            chmod(AMETHYST_SOURCES_FILE, 0644);
            chown(AMETHYST_SOURCES_FILE, 0, 0);
            sync();
        }
    }
    
    if (access(ZEBRA_SOURCES_FILE, F_OK) == 0) {
        FILE *sources = fopen(ZEBRA_SOURCES_FILE, "a");
        if (sources != NULL) {
            fprintf(sources, ZEBRA_AMETHYST_REPO);
            if (add_sonar) fprintf(sources, ZEBRA_SONAR_REPO);
            fflush(sources);
            fclose(sources);
            sync();
        }
    }
}

void restore_cleanup(void) {
    for (uint32_t i = 0; restore_rootfs_leftovers[i] != NULL; i++) {
        remove_at_path(restore_rootfs_leftovers[i]);
    }
    
    sync_volume_np("/private/var", SYNC_VOLUME_FULLSYNC);
    sync_volume_np("/", SYNC_VOLUME_FULLSYNC);
}

bool is_bootstrap_installed(void) {
    return (access("/Library/dpkg", F_OK) == 0 && access("/usr/bin/apt-get", F_OK) == 0);
}

bool is_procursus_installed(void) {
    return (access("/.procursus_strapped", F_OK) == 0 || access("/etc/apt/sources.list.d/procursus.sources", F_OK) == 0);
}

bool is_amethyst_installed(void) {
    if (!is_bootstrap_installed()) return false;
    return (access("/.installed_amethyst", F_OK) == 0);
}

int register_app(const char *path) {
    if (path == NULL || access(path, F_OK) != 0) return -1;
    return run_jbutil("--register-app", (char *)path, true);
}

void verify_install(void) {
    chown("/usr", 0, 0);
    chown("/usr/lib", 0, 0);
    chown("/usr/libexec", 0, 0);
    chmod("/usr", 0755);
    chmod("/usr/lib", 0755);
    chmod("/usr/libexec", 0755);
    
    if (access("/etc/shells", F_OK) != 0) {
        FILE *shells = fopen("/etc/shells", "w+");
        if (shells != NULL) {
            fprintf(shells, "# /etc/shells: valid login shells\n");
            fprintf(shells, "/bin/sh\n");
            fprintf(shells, "/usr/bin/sh\n");
            fprintf(shells, "/usr/bin/dash\n");
            fprintf(shells, "/bin/zsh\n");
            fprintf(shells, "/usr/bin/zsh\n");
            fprintf(shells, "/bin/bash\n");
            fprintf(shells, "/usr/bin/bash\n");

            fflush(shells);
            fclose(shells);

            chmod("/etc/shells", 0644);
            chown("/etc/shells", 0, 0);
            sync();
        }
    }
    
    unlink("/.DS_Store");
    show_non_default_apps();
    sync();
}
