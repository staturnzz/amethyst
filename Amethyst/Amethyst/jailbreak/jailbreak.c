#include "jailbreak.h"
#include "../exploit/hemlock/hemlock.h"
#include "../exploit/trigon/trigon.h"
#include "utils.h"
#include "patchfinder.h"
#include "remount.h"
#include "handoff.h"
#include "dyld.h"
#include "macho.h"
#include "trustcache.h"
#include "install.h"
#include "dma.h"
#include "ppl.h"
#include "nvram.h"

kinfo_t *kinfo = NULL;

static int init_device(void) {
    if (kinfo != NULL) return 0;
    kinfo = calloc(1, sizeof(kinfo_t));
    if (kinfo == NULL) return -1;
    
    char str[32] = {0};
    CFDictionaryRef dict = _CFCopySystemVersionDictionary();
    CFStringRef version = CFDictionaryGetValue(dict, CFSTR("ProductVersion"));
    CFStringGetCString(version, str, 32, kCFStringEncodingUTF8);
    
    sscanf(str, "%d.%d.%d", &kinfo->version[0], &kinfo->version[1], &kinfo->version[2]);
    CFRelease(dict);
    
    uint32_t cpu_family = 0;
    size_t size = sizeof(cpu_family);
    sysctlbyname("hw.cpufamily", &cpu_family, &size, NULL, 0);
    
    switch (cpu_family) {
        case CPUFAMILY_ARM_CYCLONE: // A7
            kinfo->page_size = 0x1000;
            kinfo->protections.kpp = true;
            kinfo->tnsv2_supported = (kinfo->version[0] == 12);
            break;
        case CPUFAMILY_ARM_TYPHOON: // A8
            kinfo->page_size = 0x1000;
            kinfo->protections.kpp = true;
            kinfo->tnsv2_supported = (kinfo->version[0] == 12);
            break;
        case CPUFAMILY_ARM_TWISTER: // A9
            kinfo->page_size = 0x4000;
            kinfo->protections.kpp = true;
            kinfo->tnsv2_supported = (kinfo->version[0] == 12);
            break;
        case CPUFAMILY_ARM_HURRICANE: // A10
            kinfo->page_size = 0x4000;
            kinfo->protections.ktrr = true;
            kinfo->protections.pan = true;
            kinfo->tnsv2_supported = (kinfo->version[0] == 12);
            break;
        case CPUFAMILY_ARM_MONSOON_MISTRAL: // A11
            kinfo->page_size = 0x4000;
            kinfo->protections.ktrr = true;
            kinfo->protections.pan = true;
            break;
        case CPUFAMILY_ARM_VORTEX_TEMPEST: // A12
            kinfo->page_size = 0x4000;
            kinfo->protections.ktrr = true;
            kinfo->protections.pan = true;
            kinfo->protections.pac = true;
            kinfo->protections.ppl = true;
            break;
        case CPUFAMILY_ARM_LIGHTNING_THUNDER: // A13
            kinfo->page_size = 0x4000;
            kinfo->protections.ktrr = true;
            kinfo->protections.pan = true;
            kinfo->protections.pac = true;
            kinfo->protections.ppl = true;
            break;
        default: return -1;
    }
    
    kinfo->offsets.task.vm_map = (kinfo->version[0] <= 12) ? 0x20 : 0x28;
    kinfo->offsets.task.next = (kinfo->version[0] <= 12) ? 0x28 : 0x30;
    kinfo->offsets.ucred.cr_uid = 0x18;
    kinfo->offsets.ucred.cr_ruid = 0x1c;
    kinfo->offsets.ucred.cr_svuid = 0x20;
    kinfo->offsets.ucred.cr_groups = 0x28;
    kinfo->offsets.ucred.cr_rgid = 0x68;
    kinfo->offsets.ucred.cr_svgid = 0x6c;
    kinfo->offsets.ucred.cr_label = 0x78;
    kinfo->offsets.label.slots = 0x8;
    kinfo->offsets.filedesc.fd_ofiles = 0x0;
    kinfo->offsets.fileproc.f_fglob = (kinfo->version[0] <= 12) ? 0x8 : 0x10;
    kinfo->offsets.fileglob.fg_data = 0x38;
    kinfo->offsets.ipc_port.ip_bits = 0x0;
    kinfo->offsets.ipc_port.ip_receiver = 0x60;
    kinfo->offsets.ipc_port.ip_kobject = 0x68;
    kinfo->offsets.ipc_space.is_table_size = 0x14;
    kinfo->offsets.ipc_space.is_table = 0x20;
    kinfo->offsets.mount.mnt_next = 0x0;
    kinfo->offsets.mount.vnodelist = 0x40;
    kinfo->offsets.mount.flag = 0x70;
    kinfo->offsets.mount.devvp = 0x980;
    kinfo->offsets.vm_map.pmap = 0x48;
    kinfo->offsets.pmap.ttep = 0x8;
    kinfo->offsets.pmap_cs_code_directory.trust = 0x54;
    kinfo->offsets.vnode.ubcinfo = 0x78;
    kinfo->offsets.vnode.specinfo = 0x78;
    kinfo->offsets.specinfo.flags = 0x10;
    kinfo->offsets.vnode.namecache = 0x40;
    kinfo->offsets.vnode.v_flag = 0x54;
    kinfo->offsets.vnode.v_kusecount = 0x5c;
    kinfo->offsets.vnode.v_usecount = 0x60;
    kinfo->offsets.vnode.v_name = 0xb8;
    kinfo->offsets.vnode.v_parent = 0xc0;
    kinfo->offsets.vnode.v_mount = 0xd8;
    kinfo->offsets.vnode.v_data = 0xe0;
    kinfo->offsets.vnode.v_data_flag = 0x31;
    kinfo->offsets.ubc_info.cs_blob = 0x50;
    kinfo->offsets.namecache.vnode = 0x48;
    kinfo->offsets.proc.p_svuid = 0x32;
    kinfo->offsets.proc.p_svgid = 0x36;
    
    if (kinfo->version[0] == 12) {
        kinfo->offsets.pmap.cs_enforced = (kinfo->version[1] >= 1) ? 0x119 : 0x111;
        kinfo->offsets.task.bsd_info = (kinfo->protections.pac ? 0x368 : 0x358);
        kinfo->offsets.task.t_flags = (kinfo->protections.pac ? 0x3a0 : 0x390);
        kinfo->offsets.task.itk_space = 0x300;
        kinfo->offsets.proc.pid = 0x60;
        kinfo->offsets.proc.p_fd = 0x100;
        kinfo->offsets.proc.p_flag = 0x13c;
        kinfo->offsets.proc.ucred = 0xf8;
        kinfo->offsets.proc.csflags = 0x290;
        kinfo->offsets.proc.p_textvp = 0x230;
    } else if (kinfo->version[0] == 13) {
        kinfo->offsets.pmap.cs_enforced = 0x108;
        kinfo->offsets.task.bsd_info = (kinfo->protections.pac ? 0x388 : 0x380);
        kinfo->offsets.task.t_flags = (kinfo->protections.pac ? 0x3c0 : 0x3b8);
        kinfo->offsets.task.itk_space = 0x320;
        kinfo->offsets.proc.pid = 0x68;
        kinfo->offsets.proc.p_fd = 0x108;
        kinfo->offsets.proc.p_flag = 0x144;
        kinfo->offsets.proc.ucred = 0x100;
        kinfo->offsets.proc.csflags = 0x298;
        kinfo->offsets.proc.p_textvp = 0x238;
    }
    return 0;
}

static int init_permissions(void) {
    uint64_t self_ucred = kread64(kinfo->self_proc_addr + koffsetof(proc, ucred));
    if (self_ucred == 0) return -1;
    
    kwrite32(kinfo->self_proc_addr + koffsetof(proc, p_svuid), 0);
    kwrite32(self_ucred + koffsetof(ucred, cr_svuid), 0);
    kwrite32(self_ucred + koffsetof(ucred, cr_uid), 0);
    kwrite32(kinfo->self_proc_addr + koffsetof(proc, p_svgid), 0);
    kwrite32(self_ucred + koffsetof(ucred, cr_svgid), 0);
    kwrite32(self_ucred + koffsetof(ucred, cr_groups), 0);
    setuid(0);
    setgid(0);
    
    if (getuid() != 0 || getgid() != 0) return -1;
    set_mac_slot(getpid(), 1, 0);
    add_task_flag(getpid(), TF_PLATFORM);
    add_cs_flag(getpid(), CS_PLATFORM_PATH|CS_DEBUGGED|CS_INVALID_ALLOWED);
    remove_cs_flag(getpid(), CS_KILL|CS_HARD|CS_RESTRICT);
    remove_proc_flag(getpid(), P_SUGID);
    return access("/", R_OK);
}

static void reset_permissions(void) {
    uint64_t self_ucred = kread64(kinfo->self_proc_addr + koffsetof(proc, ucred));
    if (self_ucred == 0) return;
    
    kwrite32(kinfo->self_proc_addr + koffsetof(proc, p_svuid), 501);
    kwrite32(self_ucred + koffsetof(ucred, cr_svuid), 501);
    kwrite32(self_ucred + koffsetof(ucred, cr_uid), 501);
    kwrite32(kinfo->self_proc_addr + koffsetof(proc, p_svgid), 501);
    kwrite32(self_ucred + koffsetof(ucred, cr_svgid), 501);
    kwrite32(self_ucred + koffsetof(ucred, cr_groups), 501);
    setuid(501);
    setgid(501);
    seteuid(501);
    setegid(501);
    setruid(501);
    setrgid(501);
    
    remove_task_flag(getpid(), TF_PLATFORM);
    remove_cs_flag(getpid(), CS_PLATFORM_PATH);
    remove_proc_flag(getpid(), P_SUGID);
}

static int run_exploit(uint32_t flags) {
    if (MACH_PORT_VALID(kinfo->tfp0)) return 0;
    if (flags & JB_FLAG_EXPLOIT_TRIGON) {
        int err = run_trigon();
        if (err == 0) {
            kinfo->self_task_addr = trigon->self_task_addr;
            kinfo->self_proc_addr = trigon->self_proc_addr;
            kinfo->self_port_addr = trigon->self_port_addr;
            kinfo->kern_task_addr = trigon->kern_task_addr;
            kinfo->kern_proc_addr = trigon->kern_proc_addr;
            kinfo->host_port_addr = trigon->host_port_addr;
            kinfo->realhost_addr = trigon->realhost_addr;
            kinfo->ipc_space_kernel = trigon->ipc_space_kernel;
            kinfo->kernel_base = trigon->kernel_base;
            kinfo->kernel_slide = trigon->kernel_slide;
            kinfo->page_size = trigon->page_size;
            kinfo->tfp0 = trigon->tfp0;
            return 0;
        } else if (err == 0x1337) {
            flags &= ~JB_FLAG_EXPLOIT_TRIGON;
            flags |= JB_FLAG_EXPLOIT_HEMLOCK;
        } else {
            return -1;
        }
    }
    
    if (flags & JB_FLAG_EXPLOIT_HEMLOCK) {
        if (run_hemlock() != 0) return -1;
        kinfo->self_task_addr = hemlock->self_task_addr;
        kinfo->self_proc_addr = hemlock->self_proc_addr;
        kinfo->self_port_addr = hemlock->self_port_addr;
        kinfo->kern_task_addr = hemlock->kern_task_addr;
        kinfo->kern_proc_addr = hemlock->kern_proc_addr;
        kinfo->host_port_addr = hemlock->host_port_addr;
        kinfo->realhost_addr = hemlock->realhost_addr;
        kinfo->ipc_space_kernel = hemlock->ipc_space_kernel;
        kinfo->kernel_base = hemlock->kernel_base;
        kinfo->kernel_slide = hemlock->kernel_slide;
        kinfo->page_size = hemlock->page_size;
        kinfo->tfp0 = hemlock->tfp0;
        return 0;
    }
    return -1;
}

static int run_kpf(void) {
    if (kpf_init() != 0) return -1;
    uint64_t pe_state = kpf_find_pe_state();
    if (pe_state == 0) goto err;
    
    uint64_t bootargs = kread64(pe_state + 0xa0);
    if (bootargs == 0) goto err;
    
    if (((kinfo->patches.gVirtBase = kread64(bootargs + 0x8)) & 0xffff000000000000) != 0xffff000000000000) goto err;
    if (((kinfo->patches.gPhysBase = kread64(bootargs + 0x10)) & 0x800000000) != 0x800000000) goto err;
    if ((kinfo->patches.gPhysSize = kread64(bootargs + 0x18)) == 0) goto err;

    if ((kinfo->patches.dynamic_trustcache = kpf_find_dynamic_trustcache()) == 0) goto err;
    kinfo->patches.static_trustcache = kpf_find_static_trustcache();
    if ((kinfo->patches.ptov_table = kpf_find_ptov_table()) == 0) goto err;

    uint64_t self_vm_map = kread64(kinfo->self_task_addr + koffsetof(task, vm_map));
    if (self_vm_map == 0) goto err;
    uint64_t self_pmap = kread64(self_vm_map + koffsetof(vm_map, pmap));
    if (self_pmap == 0) goto err;
    if ((kinfo->self_ttep = kread64(self_pmap + koffsetof(pmap, ttep))) == 0) goto err;

    uint64_t kern_vm_map = kread64(kinfo->kern_task_addr + koffsetof(task, vm_map));
    if (kern_vm_map == 0) goto err;
    uint64_t kern_pmap = kread64(kern_vm_map + koffsetof(vm_map, pmap));
    if (kern_pmap == 0) goto err;
    if ((kinfo->cpu_ttep = kread64(kern_pmap + koffsetof(pmap, ttep))) == 0) goto err;

    if (!kinfo->protections.ppl && !trigon_cache_get_bool("trigon_init")) {
        uint64_t cpu_ttep_ptr = kpf_find_cpu_ttep_ptr();
        uint64_t all_proc = kpf_find_all_proc();
        uint64_t mapping_base = kpf_find_gfx_mapping_base();
        uint64_t kernel_phys_base = kvtophys(kinfo->kernel_base);
        uint64_t pv_head_table_ptr = kpf_find_pv_head_table_ptr();

        if (cpu_ttep_ptr != 0 && all_proc != 0 && mapping_base != 0 && kernel_phys_base != 0 && pv_head_table_ptr != 0) {
            if (kinfo->page_size == 0x1000) {
                trigon_cache_set_u64("kernel_phys_base", kernel_phys_base);
            }
            
            trigon_cache_set_u64("mapping_base", mapping_base);
            trigon_cache_set_u64("all_proc", all_proc - kinfo->kernel_slide);
            trigon_cache_set_u64("cpu_ttep_ptr", cpu_ttep_ptr - kinfo->kernel_slide);
            trigon_cache_set_u64("pe_state", pe_state - kinfo->kernel_slide);
            trigon_cache_set_u64("pv_head_table_ptr", pv_head_table_ptr - kinfo->kernel_slide);
            trigon_cache_set_u64("ptov_table", kinfo->patches.ptov_table - kinfo->kernel_slide);
            trigon_cache_set_bool("trigon_init", true);
            trigon_cache_sync();
        }
    }
    kpf_deinit();
    return 0;

err:
    kpf_deinit();
    return -1;
}

jb_error_t run_jailbreak(uint32_t flags, char *generator) {
    ProgressLog(0.1f, "Running Exploit");
    if (init_device() != 0) return JB_ERROR_UNKNOWN;
    if (run_exploit(flags) != 0) return JB_ERROR_EXPLOIT;
    if (init_permissions() != 0) return JB_ERROR_PERMISSION;

    if (is_bootstrap_installed() && !is_amethyst_installed()) {
        if ((flags & JB_FLAG_RESTORE_ROOTFS) == 0 && !is_procursus_installed()) {
            reset_permissions();
            return JB_ERROR_UNSUPPORTED_INSTALL;
        }
    }
    
    ProgressLog(0.3f, "Finding Offsets");
    if (run_kpf() != 0) {
        reset_permissions();
        return JB_ERROR_PATCHFINDER;
    }
    
    mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &kinfo->host_priv);
    mach_port_insert_right(mach_task_self(), kinfo->host_priv, kinfo->host_priv, MACH_MSG_TYPE_MAKE_SEND);
    uint64_t port_addr = find_ipc_port(kinfo->host_priv);

    kwrite32(port_addr + koffsetof(ipc_port, ip_bits), IO_BITS_ACTIVE | IKOT_HOST_PRIV);
    kwrite64(port_addr + koffsetof(ipc_port, ip_receiver), kinfo->ipc_space_kernel);
    kwrite64(port_addr + koffsetof(ipc_port, ip_kobject), kinfo->realhost_addr);
    
    if (kinfo->protections.ppl) {
        if (dma_init() != 0) {
            reset_permissions();
            return JB_ERROR_PPL;
        }
        
        if (ppl_init() != 0) {
            reset_permissions();
            return JB_ERROR_PPL;
        }
    }
        
    if (trustcache_init() != 0) {
        reset_permissions();
        return JB_ERROR_TRUSTCACHE;
    }
    
    remount_err_t remount_err = REMOUNT_SUCCESS;
    if ((flags & JB_FLAG_RESTORE_ROOTFS) != 0) {
        ProgressLog(0.5f, "Restoring RootFS");
        remount_err = restore_rootfs();
        restore_cleanup();
    } else {
        ProgressLog(0.5f, "Remounting RootFS");
        remount_err = remount_rootfs();
    }
    
    if (remount_err != REMOUNT_SUCCESS) {
        if (remount_err != REMOUNT_NEED_REBOOT && remount_err != RESTORE_NEED_REBOOT) {
            reset_permissions();
        }
        
        switch (remount_err) {
            case REMOUNT_FAILURE: return JB_ERROR_REMOUNT;
            case RESTORE_FAILURE: return JB_ERROR_RESTORE;
            case OTA_IS_MOUNTED: return JB_ERROR_OTA;
            case REMOUNT_NEED_REBOOT: return JB_ERROR_REMOUNT_REBOOT;
            case RESTORE_NEED_REBOOT: return JB_ERROR_RESTORE_REBOOT;
            default: return JB_ERROR_REMOUNT;
        }
    }
    
    ProgressLog(0.6f, "Applying Patches");
    if (jailbreak_handoff() != 0) {
        reset_permissions();
        return JB_ERROR_HANDOFF;
    }
    
    if (flags & JB_FLAG_ENABLE_TWEAKS) {
        unlink("/amethyst/.disable_tweaks");
    } else {
        FILE *file = fopen("/amethyst/.disable_tweaks", "w+");
        fflush(file);
        fclose(file);
    }
    
    if (patch_dyld() != 0) {
        reset_permissions();
        return JB_ERROR_DYLD;
    }
    
    if (is_bootstrap_installed()) {
        if (!is_amethyst_installed()) {
            migrate_install();
        }
    } else {
        flags |= get_install_options();
        if ((flags & JB_FLAG_INSTALL_SILEO) != 0) {
            if (kinfo->version[0] == 12 && kinfo->version[1] < 2) {
                flags |= JB_FLAG_INSTALL_LIBSWIFT;
            }
        }

        uint32_t deb_count = 0;
        if ((flags & JB_FLAG_INSTALL_SILEO) != 0) deb_count++;
        if ((flags & JB_FLAG_INSTALL_ZEBRA) != 0) deb_count++;
        if ((flags & JB_FLAG_INSTALL_LIBSWIFT) != 0) deb_count++;

        ProgressLog(0.7f, "Installing Bootstrap");
        if (install_bootstrap() != 0) return JB_ERROR_BOOTSTRAP;

        if ((flags & JB_FLAG_INSTALL_LIBSWIFT) != 0) {
            ProgressLog(0.8 + (0.1 / deb_count--), "Installing libswift");
            char *path = (char *)bundle_path("libswift.deb");
            if (install_deb(path) != 0) return JB_ERROR_LIBSWIFT;
        }

        if ((flags & JB_FLAG_INSTALL_SILEO) != 0) {
            ProgressLog(0.8 + (0.1 / deb_count--), "Installing Sileo");
            char *path = (char *)bundle_path("sileo.deb");
            install_deb(path);

            if (access("/Applications/Sileo.app/Sileo", F_OK) != 0) return JB_ERROR_SILEO;
            register_app("/Applications/Sileo.app");
        }

        if ((flags & JB_FLAG_INSTALL_ZEBRA) != 0) {
            ProgressLog(0.8 + (0.1 / deb_count--), "Installing Zebra");
            char *path = (char *)bundle_path("zebra.deb");
            install_deb(path);

            if (access("/Applications/Zebra.app/Zebra", F_OK) != 0) return JB_ERROR_ZEBRA;
            register_app("/Applications/Zebra.app");
        }
    }
    
    ProgressLog(0.95f, "Finalizing");
    nvram_set_generator(generator);
    if (kinfo->tnsv2_supported) {
        install_tnsv2_support();
    }
    
    verify_install();
    ProgressLog(1.0f, "Done");
    FadeDisplay();

    usleep(1000000);
    userspace_reboot();
    reset_permissions();
    return 0;
}
