#ifndef launchd_hook_jbserver_h
#define launchd_hook_jbserver_h

#include "info.h"
#include "codesign.h"

#define SANDBOX_READ "com.apple.app-sandbox.read"
#define SANDBOX_READ_WRITE "com.apple.app-sandbox.read-write"
#define SANDBOX_EXECUTABLE "com.apple.sandbox.executable"
#define SANDBOX_MACH "com.apple.app-sandbox.mach"
#define P_SUGID 0x00000100

#define get_audit_token_pid(token) ((pid_t)(token.val[5]))
#define get_audit_token_uid(token) ((uid_t)(token.val[1]))
#define get_audit_token_ruid(token) ((uid_t)(token.val[3]))
#define get_audit_token_gid(token) ((gid_t)(token.val[2]))
#define get_audit_token_rgid(token) ((gid_t)(token.val[4]))

typedef struct {
    const char *cls;
    const char *path;
} sandbox_ext_t;

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

typedef enum {
    JBSERVER_UNSANDBOX_FULL = 0,
    JBSERVER_UNSANDBOX_EXTENSIONS,
    JBSERVER_UNSANDBOX_NONE
} jbserver_unsandbox_t;

extern char *sandbox_extension_issue_mach_to_process_by_pid(const char *extension_class, const char *name, uint32_t flags, pid_t);
extern char *sandbox_extension_issue_file(const char *extension_class, const char *path, uint32_t flags);
extern char *sandbox_extension_issue_file_to_process_by_pid(const char *extension_class, const char *path, uint32_t flags, pid_t);
extern char *sandbox_extension_issue_file_to_process(const char *extension_class, const char *path, uint32_t flags, audit_token_t);
extern void xpc_dictionary_get_audit_token(xpc_object_t xdict, audit_token_t *token);

extern xpc_object_t _xpc_serializer_unpack(void *a1, void *a2, void *a3);
extern int xpc_receive_mach_msg(void *msg, void *a2, void *a3, void *a4, xpc_object_t *output);
extern int xpc_pipe_routine_reply(xpc_object_t reply);
extern char *xpc_strerror(int err);

int init_server(void);

#endif /* launchd_hook_jbserver_h */
