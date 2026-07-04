#ifndef handoff_h
#define handoff_h

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <xpc/xpc.h>

typedef enum {
    JBSERVER_CMD_UNKNOWN = 0,
    JBSERVER_CMD_TRUSTCACHE,
    JBSERVER_CMD_SIGN_BINARY,
    JBSERVER_CMD_PRELOAD_BINARY,
    JBSERVER_CMD_INIT_PROCESS,
    JBSERVER_CMD_PLATFORMIZE,
    JBSERVER_CMD_UNSANDBOX,
    JBSERVER_CMD_PATCH_SETUID,
    JBSERVER_CMD_PATCH_SETGID,
    JBSERVER_CMD_CHECK_FAKESIGNED,
    JBSERVER_CMD_ADD_FAKESIGNED,
    JBSERVER_CMD_HEARTBEAT
} jbserver_cmd_t;

typedef enum {
    JBSERVER_ERR_SUCCESS = 0,
    JBSERVER_ERR_INVALID_PROCESS,
    JBSERVER_ERR_INVALID_CD_HASH,
    JBSERVER_ERR_INVALID_PATH,
    JBSERVER_ERR_INVALID_REQUEST,
    JBSERVER_ERR_UNKNOWN_CMD,
    JBSERVER_ERR_TRUSTCACHE_FAILURE,
    JBSERVER_ERR_CLIENT_FAILURE,
    JBSERVER_ERR_SERVER_FAILURE,
    JBSERVER_ERR_UNKNOWN_FAILURE
} jbserver_err_t;

struct _os_alloc_once_s {
    long once;
    void *ptr;
};

struct xpc_global_data {
    uint64_t a;
    uint64_t xpc_flags;
    mach_port_t task_bootstrap_port;
#ifndef _64
    uint32_t padding;
#endif
    xpc_object_t xpc_bootstrap_pipe;
};

#if __has_feature(objc_arc)
extern int xpc_pipe_routine(xpc_object_t pipe, xpc_object_t message, XPC_GIVES_REFERENCE xpc_object_t *reply);
extern int xpc_pipe_receive(mach_port_t port, XPC_GIVES_REFERENCE xpc_object_t *message);
#else
extern int xpc_pipe_routine(xpc_object_t pipe, xpc_object_t message, xpc_object_t *reply);
extern int xpc_pipe_receive(mach_port_t port, xpc_object_t *message);
#endif

typedef void *xpc_pipe_t;
extern struct _os_alloc_once_s _os_alloc_once_table[];
extern void* _os_alloc_once(struct _os_alloc_once_s *slot, size_t sz, os_function_t init);
extern int xpc_pipe_routine_reply(xpc_object_t reply);
extern xpc_pipe_t xpc_pipe_create_from_port(mach_port_t port, uint32_t flags);
extern const char *xpc_strerror(int64_t err);
extern int xpc_pipe_routine_with_flags(xpc_object_t xpc_pipe, xpc_object_t inDict, XPC_GIVES_REFERENCE xpc_object_t *reply, uint32_t flags);

int init_launchd_offsets(void);
int jailbreak_handoff(void);
int userspace_reboot(void);

#endif /* handoff_h */
