#include "info.h"
#include "util.h"
#include "memory.h"
#include "loader.h"
#include "jbserver.h"
#include "codesign.h"
#include "ppl.h"
#include "trustcache.h"

kinfo_t *kinfo = NULL;
static bool using_tnsv2 = false;

static int init_info(void) {
    kinfo = calloc(1, sizeof(kinfo_t));
    if (kinfo == NULL) return -1;
    kinfo->initialized = 0;
    kinfo->userspace_rebooting = 0;
    kinfo->shutting_down = 0;
    kinfo->first_run = 0;
    kinfo->using_tnsv2 = 0;

    host_get_special_port(mach_host_self(), HOST_LOCAL_NODE, 4, &kinfo->tfp0);
    if (!MACH_PORT_VALID(kinfo->tfp0)) return -1;

    char str[64] = {0};
    CFDictionaryRef dict = _CFCopySystemVersionDictionary();
    CFStringRef version = CFDictionaryGetValue(dict, CFSTR("ProductVersion"));
    CFStringGetCString(version, str, sizeof(str)-1, kCFStringEncodingUTF8);

    sscanf(str, "%d.%d.%d", &kinfo->version[0], &kinfo->version[1], &kinfo->version[2]);
    CFRelease(dict);

    uint32_t cpu_family = 0;
    size_t size = sizeof(cpu_family);
    sysctlbyname("hw.cpufamily", &cpu_family, &size, NULL, 0);

    switch (cpu_family) {
        case CPUFAMILY_ARM_CYCLONE: // A7
            kinfo->page_size = 0x1000;
            kinfo->protections.kpp = true;
            break;
        case CPUFAMILY_ARM_TYPHOON: // A8
            kinfo->page_size = 0x1000;
            kinfo->protections.kpp = true;
            break;
        case CPUFAMILY_ARM_TWISTER: // A9
            kinfo->page_size = 0x4000;
            kinfo->protections.kpp = true;
            break;
        case CPUFAMILY_ARM_HURRICANE: // A10
            kinfo->page_size = 0x4000;
            kinfo->protections.ktrr = true;
            kinfo->protections.pan = true;
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
    kinfo->offsets.task.transfer_memory_ownership = 0x570;
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
    kinfo->offsets.vm_map.pmap = 0x48;
    kinfo->offsets.vm_map.flags = 0x114;
    kinfo->offsets.pmap.ttep = 0x8;
    kinfo->offsets.pmap_cs_code_directory.trust = 0x54;
    kinfo->offsets.vnode.ubcinfo = 0x78;
    kinfo->offsets.specinfo.flags = 0x10;

    if (kinfo->version[0] == 12 && kinfo->version[1] == 0) {
        kinfo->offsets.vm_map.flags = 0x10c;
    }

    if (kinfo->version[0] == 12) {
        kinfo->offsets.pmap.cs_enforced = (kinfo->version[1] >= 1) ? 0x119 : 0x111;
        kinfo->offsets.task.bsd_info = (kinfo->protections.pac ? 0x368 : 0x358);
        kinfo->offsets.task.t_flags = (kinfo->protections.pac ? 0x3a0 : 0x390);
        kinfo->offsets.task.itk_space = 0x300;
        kinfo->offsets.proc.pid = 0x60;
        kinfo->offsets.proc.p_fd = 0x100;
        kinfo->offsets.proc.p_flag = 0x13c;
        kinfo->offsets.proc.p_svuid = 0x32;
        kinfo->offsets.proc.p_svgid = 0x36;
        kinfo->offsets.proc.ucred = 0xf8;
        kinfo->offsets.proc.csflags = 0x290;
        kinfo->offsets.proc.p_textvp = 0x230;
        kinfo->offsets.vnode.namecache = 0x40;
        kinfo->offsets.ubc_info.cs_blob = 0x50;
        kinfo->offsets.namecache.vnode = 0x48;
    } else if (kinfo->version[0] == 13) {
        kinfo->offsets.pmap.cs_enforced = 0x108;
        kinfo->offsets.task.bsd_info = (kinfo->protections.pac ? 0x388 : 0x380);
        kinfo->offsets.task.t_flags = (kinfo->protections.pac ? 0x3c0 : 0x3b8);
        kinfo->offsets.task.itk_space = 0x320;
        kinfo->offsets.proc.pid = 0x68;
        kinfo->offsets.proc.p_fd = 0x108;
        kinfo->offsets.proc.p_flag = 0x144;
        kinfo->offsets.proc.p_svuid = 0x32;
        kinfo->offsets.proc.p_svgid = 0x36;
        kinfo->offsets.proc.ucred = 0x100;
        kinfo->offsets.proc.csflags = 0x298;
        kinfo->offsets.proc.p_textvp = 0x238;
        kinfo->offsets.vnode.namecache = 0x40;
        kinfo->offsets.ubc_info.cs_blob = 0x50;
        kinfo->offsets.namecache.vnode = 0x48;
    }

    xpc_object_t plist = xpc_open_plist("/amethyst/handoff.plist");
    if (plist == NULL) return -1;

    kinfo->kern_proc_addr = dict_get_u64(plist, "kern_proc_addr");
    kinfo->kern_task_addr = dict_get_u64(plist, "kern_task_addr");
    kinfo->kernel_base = dict_get_u64(plist, "kernel_base");
    kinfo->kernel_slide = dict_get_u64(plist, "kernel_slide");
    kinfo->cpu_ttep = dict_get_u64(plist, "cpu_ttep");
    kinfo->patches.dynamic_trustcache = dict_get_u64(plist, "dynamic_trustcache");
    kinfo->patches.static_trustcache = dict_get_u64(plist, "static_trustcache");
    kinfo->patches.ptov_table = dict_get_u64(plist, "ptov_table");
    kinfo->patches.gPhysBase = dict_get_u64(plist, "gPhysBase");
    kinfo->patches.gVirtBase = dict_get_u64(plist, "gVirtBase");
    kinfo->patches.pplrw_entry = dict_get_u64(plist, "pplrw_entry");
    kinfo->patches.pplrw_mapping_va = dict_get_u64(plist, "pplrw_mapping_va");
    kinfo->patches.pplrw_mapping_pa = dict_get_u64(plist, "pplrw_mapping_pa");

    if (dict_get_u64(plist, "tnsv2") == 0x4141) {
        kinfo->using_tnsv2 = 1;
    }

    if (getenv("AMETHYST") == NULL) {
        kinfo->first_run = 1;
    }
    return 0;
}

__attribute__((constructor)) void ctor(void) {
    if (init_info() != 0) return;
    if ((kinfo->self_proc_addr = find_proc_for_pid(getpid())) == 0) return;
    if ((kinfo->self_task_addr = find_task_for_pid(getpid())) == 0) return;
    if ((kinfo->self_port_addr = find_ipc_port(mach_task_self())) == 0) return;

    set_mac_slot(-1, kinfo->self_proc_addr, 1, 0);
    add_cs_flag(-1, kinfo->self_proc_addr, CS_PLATFORM_PATH|CS_DEBUGGED|CS_INVALID_ALLOWED|CS_GET_TASK_ALLOW|CS_VALID);
    remove_cs_flag(-1, kinfo->self_proc_addr, CS_KILL|CS_HARD|CS_RESTRICT|CS_ENFORCEMENT|CS_REQUIRE_LV);

#ifdef __arm64e__
    uint64_t self_vm_map = kread64(kinfo->self_task_addr + koffsetof(task, vm_map));
    if (!KADDR_VALID(self_vm_map)) return;

    uint64_t self_pmap = kread64(self_vm_map + koffsetof(vm_map, pmap));
    if (!KADDR_VALID(self_pmap)) return;

    kinfo->self_ttep = kread64(self_pmap + koffsetof(pmap, ttep));
    if (kinfo->self_ttep == 0) return;

    if (kinfo->first_run == 0) {
        if (kread8(self_pmap + koffsetof(pmap, cs_enforced)) == 1) {
            uint64_t pa = kvtophys(self_pmap + koffsetof(pmap, cs_enforced));
            if (pa != 0) ppl_write8(pa, 0);

            uint64_t pmap_cs_entry = proc_get_pmap_cs_entry(kinfo->self_proc_addr);
            if (pmap_cs_entry != 0) {
                uint32_t current_trustlevel = kread32(pmap_cs_entry + koffsetof(pmap_cs_code_directory, trust));
                if (current_trustlevel != 1) {
                    uint64_t trustlevel_pa = kvtophys(pmap_cs_entry + koffsetof(pmap_cs_code_directory, trust));
                    if (trustlevel_pa != 0) ppl_write32(trustlevel_pa, 1);
                } 
            }    
        }
    }
#endif

    if (trustcache_init() != 0) return;
#ifndef __arm64e__
    if (kinfo->first_run == 1 && kinfo->using_tnsv2 == 1) {
        trustcache_lock_add_binary("/usr/lib/dyld_patch");
    }
#endif

    init_server();
    init_loader();

    if (kinfo->first_run == 1) {
        kinfo->initialized = 1;
    } else {
        draw_splash_screen();
    }
}
