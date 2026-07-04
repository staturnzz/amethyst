#include "util.h"
#include "memory.h"
#include "ppl.h"
#include "trustcache.h"
#include "codesign.h"

static int create_cs_blob(int fd, char *path, uint32_t slice_offset, uint64_t vnode, uint64_t ubc_info) {
    macho_ctx_t *macho = macho_load(path);
    if (macho == NULL) return -1;

    macho_slice_t *slice = NULL;
    for (uint32_t i = 0; i < macho->slice_count; i++) {
        if (macho->slice_list[i].offset == slice_offset) {
            slice = &macho->slice_list[i];
            break;
        }
    }

    if (slice == NULL) {
        macho_release(macho);
        return -1;
    }

    uint8_t *cs_data = NULL;
    uint32_t cs_size = 0;
    uint8_t cd_hash[32] = {0};
    char *ident = (char *)resolve_binary_name(path);
    if (ident == NULL) ident = "amethyst-codesign";

    int status = macho_sign_binary(slice, ident, &cs_data, &cs_size, cd_hash);
    macho_release(macho);
    if (status != 0) return -1;

    uint64_t existing_cs_blob = kread64(ubc_info + koffsetof(ubc_info, cs_blob));
    while (KADDR_VALID(existing_cs_blob)) {
        uint32_t current_hash[20] = {0};
        kread_buf(existing_cs_blob + offsetof(cs_blob_t, csb_cdhash), current_hash, 20);
        if (memcmp(cd_hash, current_hash, 20) == 0) {
            free(cs_data);
            return 0;
        }
        existing_cs_blob = kread64(existing_cs_blob);
    }

    if (!trustcache_check(cd_hash)) {
        trustcache_lock_add_hash(cd_hash, CS_HASHTYPE_SHA256);
    }
    
    lseek(fd, 0, SEEK_SET);
    fsignatures_t signature = {0};
    signature.fs_file_start = slice->offset;
    signature.fs_blob_start = (void *)cs_data;
    signature.fs_blob_size = cs_size;

    status = fcntl(fd, F_ADDSIGS, &signature);
    free(cs_data);
    if (status != 0) return -1;
    
    usleep(1000);
    ubc_info = kread64(vnode + koffsetof(vnode, ubcinfo));
    if (ubc_info == 0) return -1;
    
    uint64_t current_cs_blob = kread64(ubc_info + koffsetof(ubc_info, cs_blob));
    uint64_t target_cs_blob = 0;
    
    while (KADDR_VALID(current_cs_blob)) {
        if (kread64(current_cs_blob + offsetof(cs_blob_t, csb_base_offset)) == (uint64_t)slice_offset) {
            uint32_t current_hash[20] = {0};
            kread_buf(current_cs_blob + offsetof(cs_blob_t, csb_cdhash), current_hash, 20);

            if (memcmp(cd_hash, current_hash, 20) == 0) {
                target_cs_blob = current_cs_blob;
                break;
            }
        }
        current_cs_blob = kread64(current_cs_blob);
    }

    if (target_cs_blob == 0) return -1;
    uint32_t csb_flags = kread32(target_cs_blob + offsetof(cs_blob_t, csb_flags));
    csb_flags &= ~(CS_HARD|CS_RESTRICT|CS_KILL|CS_REQUIRE_LV|CS_FORCED_LV|CS_ENFORCEMENT);
    csb_flags |= CS_VALID|CS_SIGNED|CS_GET_TASK_ALLOW|CS_DEBUGGED|CS_PLATFORM_PATH|CS_PLATFORM_BINARY|CS_EXECSEG_SKIP_LV;
    kwrite32(target_cs_blob + offsetof(cs_blob_t, csb_flags), csb_flags);

    kwrite32(target_cs_blob + offsetof(cs_blob_t, csb_signer_type), CS_SIGNER_TYPE_UNKNOWN);
   // kwrite32(target_cs_blob + offsetof(cs_blob_t, csb_reconstituted), 1);
    kwrite32(target_cs_blob + offsetof(cs_blob_t, csb_cpu_type), CPU_TYPE_ARM64);
    kwrite32(target_cs_blob + offsetof(cs_blob_t, csb_flags), csb_flags);

    if (kread32(target_cs_blob + offsetof(cs_blob_t, csb_platform.binary)) == 0) {
        kwrite32(target_cs_blob + offsetof(cs_blob_t, csb_platform.binary), 1);
    }

#ifdef __arm64e__
    uint64_t pmap_cs_entry = kread64(target_cs_blob + 0xb0);
    if (KADDR_VALID(pmap_cs_entry)) {
        uint32_t current_trustlevel = kread32(pmap_cs_entry + koffsetof(pmap_cs_code_directory, trust));
        if (current_trustlevel != 1) {
            uint64_t trustlevel_pa = kvtophys(pmap_cs_entry + koffsetof(pmap_cs_code_directory, trust));
            if (trustlevel_pa != 0) {
                ppl_write32(trustlevel_pa, 1);
                usleep(1000);

                current_trustlevel = kread32(pmap_cs_entry + koffsetof(pmap_cs_code_directory, trust));
                if (current_trustlevel != 1) ppl_write32(trustlevel_pa, 1);
            }
        }
    }
#endif

    fcntl(fd, F_FLUSH_DATA);
    usleep(1000);
    return 0;
}

int sign_binary(char *path, uint32_t le_offset, uint32_t le_size, uint32_t slice_offset, uint32_t file_type) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;

    uint64_t vnode = vnode_for_fd(fd);
    if (vnode == 0) goto err;

    uint64_t ubc_info = kread64(vnode + koffsetof(vnode, ubcinfo));
    if (ubc_info == 0) goto err;

#ifndef __arm64e__
    uint64_t cs_blob = kread64(ubc_info + koffsetof(ubc_info, cs_blob));
    if (cs_blob != 0) return 0;
#endif

    if (create_cs_blob(fd, path, slice_offset, vnode, ubc_info) != 0) goto err;
    if (kread64(vnode + koffsetof(ubc_info, cs_blob)) == 0) goto err;
    close(fd);
    return 0;

err:
    if (fd >= 0) close(fd);
    return -1;
}

int fixup_cs_flags(uint64_t proc) {
    if (proc == 0) return -1;
    uint32_t add_flags = CS_PLATFORM_BINARY | CS_VALID | CS_DEBUGGED | CS_INVALID_ALLOWED | CS_GET_TASK_ALLOW | CS_EXECSEG_SKIP_LV;
    uint32_t remove_flags = CS_RESTRICT | CS_HARD | CS_KILL | CS_REQUIRE_LV | CS_FORCED_LV | CS_ENFORCEMENT;

    uint32_t cs_flags = kread32(proc + koffsetof(proc, csflags));
    cs_flags &= ~remove_flags;
    cs_flags |= add_flags;

    kwrite32(proc + koffsetof(proc, csflags), cs_flags);
    return 0;
}
