#ifndef launchd_hook_utils_h
#define launchd_hook_utils_h

#include "info.h"
#include "basebin_util.h"
#include <CoreGraphics/CoreGraphics.h>
#include <CoreFoundation/CoreFoundation.h>
#include <ImageIO/ImageIO.h>

#define CFNUM(val) CFNumberCreate(NULL, kCFNumberIntType, &(int){val})
#define KADDR_VALID(addr) (((addr) & 0xffff000000000000) == 0xffff000000000000)

int get_process_info(pid_t pid, uint64_t *proc_addr, uint64_t *task_addr);
uint64_t find_proc_for_pid(pid_t pid);
uint64_t find_task_for_pid(pid_t pid);
pid_t find_pid_for_name(const char *name);
uint64_t find_ipc_port(mach_port_t port);
uint64_t get_mac_slot(pid_t pid, uint64_t proc, int slot);
void set_mac_slot(pid_t pid, uint64_t proc, int slot, uint64_t value);
uint32_t get_task_flags(pid_t pid, uint64_t task);
void set_task_flags(pid_t pid, uint64_t task, int flags);
void add_task_flag(pid_t pid, uint64_t task, int flag);
void remove_task_flag(pid_t pid, uint64_t task, int flag);
uint32_t get_cs_flags(pid_t pid, uint64_t proc);
void set_cs_flags(pid_t pid, uint64_t proc, int flags);
void add_cs_flag(pid_t pid, uint64_t proc, int flag);
void remove_cs_flag(pid_t pid, uint64_t proc, int flag);
uint64_t vnode_for_fd(int fd);
uint64_t proc_get_pmap_cs_entry(uint64_t proc);
int draw_splash_screen(void);
int update_jailbreak(void);

#endif /* launchd_hook_utils_h */
