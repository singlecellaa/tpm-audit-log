#include "tpm_nv.h"

#include <stdio.h>
#include <string.h>

/*
 * get_nv_handle
 *   Helper to map an NV index to an ESYS_TR handle.
 */
static int get_nv_handle(ESYS_CONTEXT *esys, uint32_t index, ESYS_TR *out) {
    if (!esys || !out) return -1;
    TSS2_RC rc = Esys_TR_FromTPMPublic(esys, index,
                                       ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                                       out);
    if (rc != TSS2_RC_SUCCESS) {
        fprintf(stderr, "NV handle 0x%x load failed: 0x%x\n", index, rc);
        return -1;
    }
    return 0;
}

/*
 * tpm_nv_write_head
 *   Writes the HASH_SIZE chain head into the specified NV index at offset 0.
 * Parameters:
 *   esys      - initialized ESYS context.
 *   nv_index  - NV index handle (e.g., 0x1500016) with owner auth.
 *   head      - chain head buffer to persist.
 * Returns:
 *   0 on success, -1 on failure.
 */
int tpm_nv_write_head(ESYS_CONTEXT *esys, uint32_t nv_index,
                      const unsigned char head[HASH_SIZE]) {
    if (!esys || !head) return -1;
    ESYS_TR nv_handle = ESYS_TR_NONE;
    if (get_nv_handle(esys, nv_index, &nv_handle) != 0) return -1;

    TPM2B_MAX_NV_BUFFER data = {.size = HASH_SIZE};
    memcpy(data.buffer, head, HASH_SIZE);

    TSS2_RC rc = Esys_NV_Write(esys, ESYS_TR_RH_OWNER, nv_handle,
                               ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                               &data, /*offset*/0);
    if (rc != TSS2_RC_SUCCESS) {
        fprintf(stderr, "NV write failed: 0x%x\n", rc);
        return -1;
    }
    return 0;
}

/*
 * tpm_nv_read_head
 *   Reads HASH_SIZE bytes from NV index offset 0 into head_out.
 * Parameters:
 *   esys      - initialized ESYS context.
 *   nv_index  - NV index handle (owner auth).
 *   head_out  - destination buffer for the chain head.
 * Returns:
 *   0 on success, -1 on failure.
 */
int tpm_nv_read_head(ESYS_CONTEXT *esys, uint32_t nv_index,
                     unsigned char head_out[HASH_SIZE]) {
    if (!esys || !head_out) return -1;
    ESYS_TR nv_handle = ESYS_TR_NONE;
    if (get_nv_handle(esys, nv_index, &nv_handle) != 0) return -1;

    TPM2B_MAX_NV_BUFFER *out = NULL;
    TSS2_RC rc = Esys_NV_Read(esys, ESYS_TR_RH_OWNER, nv_handle,
                              ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                              /*size*/HASH_SIZE, /*offset*/0, &out);
    if (rc != TSS2_RC_SUCCESS) {
        fprintf(stderr, "NV read failed: 0x%x\n", rc);
        return -1;
    }
    if (out->size < HASH_SIZE) {
        fprintf(stderr, "NV data too small: %u\n", out->size);
        Esys_Free(out);
        return -1;
    }
    memcpy(head_out, out->buffer, HASH_SIZE);
    Esys_Free(out);
    return 0;
}
