#ifndef basebins_macho_h
#define basebins_macho_h

#include "basebin_common.h"

#define CS_CDHASH_LEN                           0x00000014
#define CS_HASHTYPE_SHA1                        0x00000001
#define CS_HASHTYPE_SHA256                      0x00000002
#define CS_HASHTYPE_SHA256_TRUNCATED            0x00000003
#define CS_HASHTYPE_SHA384                      0x00000004

#define CSSLOT_CODEDIRECTORY                    0x00000000
#define CSSLOT_INFOSLOT                         0x00000001
#define CSSLOT_REQUIREMENTS                     0x00000002
#define CSSLOT_RESOURCEDIR                      0x00000003
#define CSSLOT_APPLICATION                      0x00000004
#define CSSLOT_ENTITLEMENTS                     0x00000005
#define CSSLOT_DER_ENTITLEMENTS                 0x00000007
#define CSSLOT_LAUNCH_CONSTRAINT_SELF           0x00000008
#define CSSLOT_LAUNCH_CONSTRAINT_PARENT         0x00000009
#define CSSLOT_LAUNCH_CONSTRAINT_RESPONSIBLE    0x0000000a
#define CSSLOT_LIBRARY_CONSTRAINT               0x0000000b
#define CSSLOT_SIGNATURESLOT                    0x00010000
#define CSSLOT_IDENTIFICATIONSLOT               0x00010001
#define CSSLOT_TICKETSLOT                       0x00010002
#define CSSLOT_ALTERNATE_CODEDIRECTORIES        0x00001000
#define CSSLOT_ALTERNATE_CODEDIRECTORY_MAX      0x00000005
#define CSSLOT_ALTERNATE_CODEDIRECTORY_LIMIT    0x00001005

#define CS_SIGNER_TYPE_UNKNOWN                  0x00000000
#define CSMAGIC_EMBEDDED_SIGNATURE              0xfade0cc0
#define CSSLOT_ENTITLEMENTS                     0x00000005
#define CSMAGIC_EMBEDDED_ENTITLEMENTS           0xfade7171
#define CSMAGIC_CODEDIRECTORY                   0xfade0c02

#define MACHO_VALID(m) (m==MH_MAGIC_64||m==MH_CIGAM_64||m==MH_MAGIC||m==MH_CIGAM||m==FAT_MAGIC_64||m==FAT_CIGAM_64||m==FAT_MAGIC||m==FAT_CIGAM)
#define MACHO_REQUIRES_SWAP(m) (m==MH_CIGAM_64||m==MH_CIGAM||m==FAT_CIGAM_64||m==FAT_CIGAM)
#define MACHO_FAT(m) (m==FAT_MAGIC_64||m==FAT_CIGAM_64||m==FAT_MAGIC||m==FAT_CIGAM)
#define MACHO_32BIT(m) (m==MH_MAGIC||m==MH_CIGAM)
#define DYLIB_LOADCMD(c) (c==LC_LOAD_DYLIB||c==LC_LOAD_WEAK_DYLIB||c==LC_REEXPORT_DYLIB||c==LC_LOAD_UPWARD_DYLIB)

#ifndef CPU_SUBTYPE_MASK
#define CPU_SUBTYPE_MASK 0xff000000
#endif

#ifndef CPU_SUBTYPE_LIB64
#define CPU_SUBTYPE_LIB64 0x80000000
#endif

#ifndef CPU_SUBTYPE_PTRAUTH_ABI
#define CPU_SUBTYPE_PTRAUTH_ABI 0x80000000
#endif

typedef struct __attribute__((packed)) {
    uint32_t magic;
    uint32_t length;
    uint32_t version;
    uint32_t flags;
    uint32_t hashOffset;
    uint32_t identOffset;
    uint32_t nSpecialSlots;
    uint32_t nCodeSlots;
    uint32_t codeLimit;
    uint8_t hashSize;
    uint8_t hashType;
    uint8_t platform;
    uint8_t pageSize;
    uint32_t spare2;
    char end_earliest[0];
    uint32_t scatterOffset;
    char end_withScatter[0];
    uint32_t teamOffset;
    char end_withTeam[0];
    uint32_t spare3;
    uint64_t codeLimit64;
    char end_withCodeLimit64[0];
    uint64_t execSegBase;
    uint64_t execSegLimit;
    uint64_t execSegFlags;
    char end_withExecSeg[0];
} CS_CodeDirectory;

typedef struct __attribute__((packed)) {
    uint32_t magic;
    uint32_t length;
    uint32_t version;
    uint32_t flags;
    uint32_t hashOffset;
    uint32_t identOffset;
    uint32_t nSpecialSlots;
    uint32_t nCodeSlots;
    uint32_t codeLimit;
    uint8_t hashSize;
    uint8_t hashType;
    uint8_t platform;
    uint8_t pageSize;
    uint32_t spare2;
    char end_earliest[0];
} CS_CodeDirectory_legacy;

typedef struct __attribute__((packed)) {
    uint32_t type;
    uint32_t offset;
} CS_BlobIndex;

typedef struct __attribute__((packed)) {
    uint32_t magic;
    uint32_t length;
    uint32_t count;
    CS_BlobIndex index[];
} CS_SuperBlob;

typedef struct {
    uint32_t magic;
    uint32_t length;
    char data[];
} CS_GenericBlob;

typedef struct {
    uint32_t count;
    uint32_t base;
    uint64_t targetOffset;
    uint64_t spare;
} SC_Scatter;

typedef struct {
    uint32_t magic;
    uint32_t length;
} cs_header_t;

typedef struct {
    struct mach_header_64 *hdr;
    struct load_command *load_cmd;
    cpu_type_t cpu_type;
    cpu_subtype_t cpu_subtype;
    uint32_t file_type;
    uint32_t cmd_count;
    uint32_t offset;
    uint32_t size;
    uint8_t *file_data;
    uint32_t file_size;
    bool has_ptrauth;
    char *path;
} macho_slice_t;

typedef struct {
    macho_slice_t *slice_list;
    uint32_t slice_count;
    uint8_t *file_data;
    uint32_t file_size;
    char *path;
} macho_ctx_t;

typedef struct {
    uint32_t max;
    uint32_t count;
    uint32_t resolved;
    char **list;
} macho_deps_t;
 
typedef struct {
    char *relative_path;
    uint32_t count;
    char **list;
} macho_rpaths_t;

typedef struct {
    uint32_t type;
    uint32_t size;
    uint8_t *data;
    uint32_t offset;
} macho_generic_blob_t;

typedef struct {
    macho_generic_blob_t entries[8];
    uint32_t entry_count;
} macho_super_blob_t;

typedef struct {
    uint8_t hash[20];
    uint8_t hash_type;
    bool is_adhoc;
    bool is_fakesigned;
    uint32_t version;
    CS_CodeDirectory *code_dir;
    uint32_t offset;
    uint32_t size;
} macho_signature_t;

static char *default_lib_paths[] = {
    "/usr/lib",
    "/usr/local/lib",
    "/Library/Frameworks",
    "/Library",
    "/System/Library",
    "/System/Library/Frameworks",
    "/System/Library/PrivateFrameworks",
    "/lib",
    NULL
};

void macho_release(macho_ctx_t *ctx);
macho_ctx_t *macho_load(const char *path);
void macho_release_rpaths(macho_rpaths_t *rpaths);
macho_rpaths_t *macho_resolve_rpaths(macho_ctx_t *ctx);
void macho_release_deps(macho_deps_t *deps);
bool macho_uses_external_libswift(macho_deps_t *deps);
macho_deps_t *macho_resolve_deps(macho_ctx_t *ctx, macho_rpaths_t *rpaths);
macho_signature_t *macho_get_signature(macho_slice_t *slice);
void macho_release_signature(macho_signature_t *signature);
macho_slice_t *macho_get_best_slice(macho_ctx_t *ctx);
int macho_sign_binary(macho_slice_t *slice, char *ident, uint8_t **out_data, uint32_t *out_size, uint8_t *cd_hash);
bool macho_should_process(macho_ctx_t *ctx);

#endif /* basebins_macho_h */
