#include "info.h"
#include "memory.h"
#include "trustcache.h"
#include "ppl.h"
#include "util.h"

extern int IOMobileFramebufferGetMainDisplay(void**);
extern int IOMobileFramebufferGetLayerDefaultSurface(void*, int, void **);
extern int IOMobileFramebufferGetDisplaySize(void *pointer, CGSize *size);
extern void *IOSurfaceCreate(CFDictionaryRef properties);
extern int IOSurfaceLock(void *buffer, uint32_t options, uint32_t *seed);
extern int IOSurfaceUnlock(void *buffer, uint32_t options, uint32_t *seed);
extern int IOMobileFramebufferSwapBegin(void *, int *);
extern int IOMobileFramebufferSwapSetLayer(void *, int, void *, CGRect, CGRect, int);
extern int IOMobileFramebufferSwapEnd(void *);
extern void *IOSurfaceGetBaseAddress(void *buffer);
extern size_t IOSurfaceGetBytesPerRow(void *buffer);
extern size_t IOSurfaceAlignProperty(CFStringRef property, size_t value);
extern const CFStringRef kIOSurfaceBytesPerRow;

static pthread_mutex_t process_lock = PTHREAD_MUTEX_INITIALIZER;
static pid_t self_pid = -1;
static bool io_init_done = false;

int get_process_info(pid_t pid, uint64_t *proc_addr, uint64_t *task_addr) {
    if (pid < 0 || pid > 0xfffff) return -1;
    if (self_pid == -1) self_pid = getpid();

    if (pid == self_pid) {
        if (kinfo->self_proc_addr != 0 && kinfo->self_task_addr != 0) {
            *proc_addr = kinfo->self_proc_addr;
            *task_addr = kinfo->self_task_addr;
            return 0;
        }
    } else if (pid == 0) {
        if (kinfo->kern_proc_addr != 0 && kinfo->kern_task_addr != 0) {
            *proc_addr = kinfo->kern_proc_addr;
            *task_addr = kinfo->kern_task_addr;
            return 0;
        }
        return -1;
    }

    pthread_mutex_lock(&process_lock);
    uint64_t current_task = kinfo->kern_task_addr;
    uint64_t current_proc = 0;
    pid_t current_pid = -1;
    uint32_t search_count = 0;

    while (current_task != 0) {
        current_proc = kread64(current_task + koffsetof(task, bsd_info));
        if (KADDR_VALID(current_proc)) {
            current_pid = kread32(current_proc + koffsetof(proc, pid));
            if (current_pid == pid) {
                *proc_addr = current_proc;
                *task_addr = current_task;
                break;
            }
        }

        current_task = kread64(current_task + koffsetof(task, next));
        if (!KADDR_VALID(current_task) || current_task == kinfo->kern_task_addr) break;
        if (++search_count >= 500) break;
    }

    pthread_mutex_unlock(&process_lock);
    return (*proc_addr != 0 && *task_addr != 0) ? 0 : -1;
}

uint64_t find_proc_for_pid(pid_t pid) {
    uint64_t proc = 0;
    uint64_t task = 0;

    if (get_process_info(pid, &proc, &task) != 0) return 0;
    return proc;
}

uint64_t find_task_for_pid(pid_t pid) {
    uint64_t proc = 0;
    uint64_t task = 0;

    if (get_process_info(pid, &proc, &task) != 0) return 0;
    return task;
}

pid_t find_pid_for_name(const char *name) {
    int count = proc_listpids(PROC_ALL_PIDS, 0, NULL, 0) + 100;
    if (count <= 0) return -1;

    pid_t *pids = calloc(1, sizeof(pid_t) * count);
    count = proc_listpids(PROC_ALL_PIDS, 0, pids, sizeof(pid_t) * count);
    if (count <= 0) {
        free(pids);
        return -1;
    }

    char *current_name = calloc(1, PROC_PIDPATHINFO_MAXSIZE+1);
    if (current_name == NULL) {
        free(pids);
        return -1;
    }

    pid_t target_pid = -1;
    for (uint32_t i = 0; i < count; i++) {
        bzero(current_name, PROC_PIDPATHINFO_MAXSIZE+1);
        if (proc_name(pids[i], current_name, PROC_PIDPATHINFO_MAXSIZE) <= 0) continue;
        if (strncmp((const char *)current_name, name, PROC_PIDPATHINFO_MAXSIZE) == 0) {
            target_pid = pids[i];
            break;
        }
    }

    free(current_name);
    free(pids);
    return target_pid;
}

uint64_t find_ipc_port(mach_port_t port) {
    if (!MACH_PORT_VALID(port)) return 0;
    uint64_t itk_space = kread64(kinfo->self_task_addr + koffsetof(task, itk_space));
    if (!KADDR_VALID(itk_space)) return 0;

    uint64_t is_table = kread64(itk_space + koffsetof(ipc_space, is_table));
    if (!KADDR_VALID(is_table)) return 0;

    uint64_t port_addr = kread64(is_table + ((port >> 8) * 0x18));
    if (!KADDR_VALID(port_addr)) return 0;
    return port_addr;
}

uint64_t get_mac_slot(pid_t pid, uint64_t proc, int slot) {
    if (proc == 0) {
        uint64_t task = 0;
        if (get_process_info(pid, &proc, &task) != 0) return 0;
    }

    uint64_t ucred = kread64(proc + koffsetof(proc, ucred));
    if (!KADDR_VALID(ucred)) return 0;

    uint64_t cr_label = kread64(ucred + koffsetof(ucred, cr_label));
    if (!KADDR_VALID(cr_label)) return 0;

    uint64_t slot_addr = kread64(cr_label + koffsetof(label, slots) + (slot*0x8));
    if (!KADDR_VALID(slot_addr)) return 0;
    return slot_addr;
}

void set_mac_slot(pid_t pid, uint64_t proc, int slot, uint64_t value) {
    if (proc == 0) {
        uint64_t task = 0;
        if (get_process_info(pid, &proc, &task) != 0) return;
    }

    uint64_t ucred = kread64(proc + koffsetof(proc, ucred));
    if (!KADDR_VALID(ucred)) return;

    uint64_t cr_label = kread64(ucred + koffsetof(ucred, cr_label));
    if (!KADDR_VALID(cr_label)) return;

    kwrite64(cr_label + koffsetof(label, slots) + (slot*0x8), value);
}

uint32_t get_task_flags(pid_t pid, uint64_t task) {
    if (task == 0) {
        uint64_t proc = 0;
        if (get_process_info(pid, &proc, &task) != 0) return 0;
    }
    return kread32(task + koffsetof(task, t_flags));
}

void set_task_flags(pid_t pid, uint64_t task, int flags) {
    if (task == 0) {
        uint64_t proc = 0;
        if (get_process_info(pid, &proc, &task) != 0) return;
    }
    kwrite32(task + koffsetof(task, t_flags), flags);
}

void add_task_flag(pid_t pid, uint64_t task, int flag) {
    if (task == 0) {
        uint64_t proc = 0;
        if (get_process_info(pid, &proc, &task) != 0) return;
    }

    uint32_t t_flags = kread32(task + koffsetof(task, t_flags));
    kwrite32(task + koffsetof(task, t_flags), t_flags | flag);
}

void remove_task_flag(pid_t pid, uint64_t task, int flag) {
    if (task == 0) {
        uint64_t proc = 0;
        if (get_process_info(pid, &proc, &task) != 0) return;
    }

    uint32_t t_flags = kread32(task + koffsetof(task, t_flags));
    kwrite32(task + koffsetof(task, t_flags), t_flags & ~flag);
}

uint32_t get_cs_flags(pid_t pid, uint64_t proc) {
    if (proc == 0) {
        uint64_t task = 0;
        if (get_process_info(pid, &proc, &task) != 0) return 0;
    }
    return kread32(proc + koffsetof(proc, csflags));
}

void set_cs_flags(pid_t pid, uint64_t proc, int flags) {
    if (proc == 0) {
        uint64_t task = 0;
        if (get_process_info(pid, &proc, &task) != 0) return;
    }
    kwrite32(proc + koffsetof(proc, csflags), flags);
}

void add_cs_flag(pid_t pid, uint64_t proc, int flag) {
   if (proc == 0) {
        uint64_t task = 0;
        if (get_process_info(pid, &proc, &task) != 0) return;
    }

    uint32_t cs_flags = kread32(proc + koffsetof(proc, csflags));
    kwrite32(proc + koffsetof(proc, csflags), cs_flags | flag);
}

void remove_cs_flag(pid_t pid, uint64_t proc, int flag) {
   if (proc == 0) {
        uint64_t task = 0;
        if (get_process_info(pid, &proc, &task) != 0) return;
    }

    uint32_t cs_flags = kread32(proc + koffsetof(proc, csflags));
    kwrite32(proc + koffsetof(proc, csflags), cs_flags & ~flag);
}

uint64_t vnode_for_fd(int fd) {
    if (fd < 0) return 0;
    uint64_t p_fd = kread64(kinfo->self_proc_addr + koffsetof(proc, p_fd));
    if (!KADDR_VALID(p_fd)) return 0;

    uint64_t fd_ofiles = kread64(p_fd + koffsetof(filedesc, fd_ofiles));
    if (!KADDR_VALID(fd_ofiles)) return 0;

    uint64_t fproc = kread64(fd_ofiles + (fd * 8));
    if (!KADDR_VALID(fproc)) return 0;
    
    uint64_t f_fglob = kread64(fproc + koffsetof(fileproc, f_fglob));
    if (!KADDR_VALID(f_fglob)) return 0;

    uint64_t vnode = kread64(f_fglob + koffsetof(fileglob, fg_data));
    if (!KADDR_VALID(vnode)) return 0;
    return vnode;
}

uint64_t proc_get_pmap_cs_entry(uint64_t proc) {
#ifdef __arm64e__
    if (!KADDR_VALID(proc)) return 0;
    uint64_t vnode = kread64(proc + koffsetof(proc, p_textvp));
    if (!KADDR_VALID(vnode)) return 0;

    uint64_t ubc_info = kread64(vnode + koffsetof(vnode, ubcinfo));
    if (!KADDR_VALID(ubc_info)) return 0;

    uint64_t cs_blob = kread64(ubc_info + koffsetof(ubc_info, cs_blob));
    if (!KADDR_VALID(cs_blob)) return 0;

    uint64_t pmap_cs_entry = kread64(cs_blob + 0xb0);
    if (!KADDR_VALID(pmap_cs_entry)) return 0;
    return pmap_cs_entry;
#else
    return 0;
#endif
}

int draw_splash_screen(void) {
    void *display = NULL;
    CGSize display_size = CGSizeMake(0, 0);
    __block void *surface = NULL;
    CFMutableDictionaryRef dict = NULL;
    CFDataRef image_data = NULL;
    CGImageSourceRef image_src = NULL;
    CGImageRef cg_image = NULL;
    CGContextRef ctx = NULL;
    uint8_t *jp2_data = NULL;
    uint32_t jp2_size = 0;
    int status = -1;

    struct mach_header_64 *hdr = NULL;
    uint32_t count = _dyld_image_count();

    for (uint32_t i = 0; i < count; i++) {
        const char *name = _dyld_get_image_name(i);
        if (name != NULL && strstr(name, "launchd_hook.dylib") != NULL) {
            hdr = (struct mach_header_64 *)_dyld_get_image_header(i);
            break;
        }
    }

    if (hdr == NULL) return -1;
    struct load_command *load_cmd = (struct load_command *)(hdr + 1);
    for (uint32_t i = 0; i < hdr->ncmds; i++) {
        if (load_cmd->cmd == LC_SEGMENT_64) {
            struct segment_command_64 *segment = (struct segment_command_64 *)load_cmd;
            if (strcmp(segment->segname, "__DATA") == 0) {
                struct section_64 *section = (struct section_64 *)(segment + 1);

                for (uint32_t j = 0; j < segment->nsects; j++) {
                    if (strcmp(section[j].sectname, "__splashscreen") == 0) {
                        jp2_size = (uint32_t)section[j].size;
                        jp2_data = (uint8_t *)hdr + section[j].offset;
                        break;
                    }
                }
            }
        }

        if (jp2_data != NULL) break;
        load_cmd = (struct load_command *)((uint64_t)load_cmd + load_cmd->cmdsize);
    }

    if (jp2_data == NULL) return -1;
    if (IOMobileFramebufferGetMainDisplay(&display) != 0) goto done;
    if (IOMobileFramebufferGetDisplaySize(display, &display_size) != 0) goto done;
    if ((dict = CFDictionaryCreateMutable(NULL, 0, NULL, NULL)) == NULL) goto done;

    CFDictionarySetValue(dict, CFSTR("IOSurfaceIsGlobal"), kCFBooleanFalse);
    CFDictionarySetValue(dict, CFSTR("IOSurfaceWidth"), CFNUM(display_size.width));
    CFDictionarySetValue(dict, CFSTR("IOSurfaceHeight"), CFNUM(display_size.height));
    CFDictionarySetValue(dict, CFSTR("IOSurfacePixelFormat"), CFNUM(0x42475241));
    CFDictionarySetValue(dict, CFSTR("IOSurfaceBytesPerElement"), CFNUM(4));

    int token = 0;
    CGRect frame = CGRectMake(0, 0, display_size.width, display_size.height);
    if ((surface = IOSurfaceCreate(dict)) == NULL) goto done;
    IOSurfaceLock(surface, 0, 0);

  //  if (kinfo->first_run == 1) {
        pid_t backboardd_pid = find_pid_for_name("backboardd");
        if (backboardd_pid != -1) kill(backboardd_pid, SIGTERM);
  //  }

    if (IOMobileFramebufferSwapBegin(display, &token) != 0) goto done;
    if (IOMobileFramebufferSwapSetLayer(display, 0, surface, frame, frame, 0) != 0) goto done;
    if (IOMobileFramebufferSwapEnd(display) != 0) goto done;

    if ((image_data = CFDataCreateWithBytesNoCopy(NULL, jp2_data, jp2_size, kCFAllocatorNull)) == NULL) goto done;
    if ((image_src = CGImageSourceCreateWithData(image_data, NULL)) == NULL) goto done;
    if ((cg_image = CGImageSourceCreateImageAtIndex(image_src, 0, NULL)) == NULL) goto done;

    CGSize image_size = CGSizeMake(1000.0f, 2000.0f);
    CGRect final_frame = CGRectZero;
    
    if ((display_size.width / image_size.width) > (display_size.height / image_size.height)) {
        final_frame.size.width = (display_size.width / image_size.width) * image_size.width;
        final_frame.size.height = (display_size.width / image_size.width) * image_size.height;
        final_frame.origin.y = (display_size.height - final_frame.size.height) / 2;
    } else {
        final_frame.size.width = (display_size.height / image_size.height) * image_size.width;
        final_frame.size.height = (display_size.height / image_size.height) * image_size.height;
        final_frame.origin.x = (display_size.width - final_frame.size.width) / 2;
    }

    uint32_t flags = (kCGImageAlphaPremultipliedFirst | kCGImageByteOrder32Little);
    void *base = IOSurfaceGetBaseAddress(surface);
    size_t bytes = IOSurfaceGetBytesPerRow(surface);
    CGColorSpaceRef colorspace = CGColorSpaceCreateDeviceRGB();

    if ((ctx = CGBitmapContextCreate(base, display_size.width, display_size.height, 8, bytes, colorspace, flags)) == NULL) goto done;
    CGContextDrawImage(ctx, final_frame, cg_image);
    CGColorSpaceRelease(colorspace);
    status = 0;    

done:
    if (dict != NULL) CFRelease(dict);
    if (ctx != NULL) CGContextRelease(ctx);
    if (cg_image != NULL) CGImageRelease(cg_image);
    if (image_src != NULL) CFRelease(image_src);
    if (surface != NULL) CFRelease(surface);
    return status;
}

int update_jailbreak(void) {
    if (access("/amethyst/update", F_OK) != 0) return 0;
    if (kinfo->using_tnsv2 != 1) {
        remove("/amethyst/update/jbutil");
        remove("/amethyst/update/base_hook.dylib");
        remove("/amethyst/update/libjailbreak.dylib");
        rmdir("/amethyst/update");
        sync();
        return 0;
    }

    remove("/amethyst/jbutil");
    remove("/usr/lib/base_hook.dylib");
    remove("/usr/lib/libjailbreak.dylib");
    sync();

    rename("/amethyst/update/jbutil", "/amethyst/jbutil");
    rename("/amethyst/update/base_hook.dylib", "/usr/lib/base_hook.dylib");
    rename("/amethyst/update/libjailbreak.dylib", "/usr/lib/libjailbreak.dylib");

    chown("/amethyst/jbutil", 0, 0);
    chmod("/amethyst/jbutil", 0755);
    chown("/usr/lib/base_hook.dylib", 0, 0);
    chmod("/usr/lib/base_hook.dylib", 0755);
    chown("/usr/lib/libjailbreak.dylib", 0, 0);
    chmod("/usr/lib/libjailbreak.dylib", 0755);

    trustcache_lock_add_binary("/amethyst/launchd_hook.dylib");
    trustcache_lock_add_binary("/amethyst/jbutil");
    trustcache_lock_add_binary("/usr/lib/base_hook.dylib");
    trustcache_lock_add_binary("/usr/lib/libjailbreak.dylib");

    rmdir("/amethyst/update");
    chown("/amethyst", 0, 0);
    chmod("/amethyst", 0777);
    return 0;
}