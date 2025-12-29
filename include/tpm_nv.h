#ifndef TPM_NV_H
#define TPM_NV_H

#include <tss2/tss2_esys.h>
#include <stdint.h>
#include "common.h"

int tpm_nv_write_head(ESYS_CONTEXT *esys, uint32_t nv_index,
                      const unsigned char head[HASH_SIZE]);
int tpm_nv_read_head(ESYS_CONTEXT *esys, uint32_t nv_index,
                     unsigned char head_out[HASH_SIZE]);

#endif
