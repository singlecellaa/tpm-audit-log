#ifndef TPM_SIGNER_H
#define TPM_SIGNER_H

#include "common.h"
#include <tss2/tss2_esys.h>
#include <tss2/tss2_tctildr.h>

struct TpmSigner {
    ESYS_CONTEXT *esys;
    ESYS_TR key_handle;
    TSS2_TCTI_CONTEXT *tcti;
};

int tpm_signer_init(struct TpmSigner *signer, ESYS_CONTEXT *external_esys,
                    uint32_t persistent_handle);
int tpm_signer_sign(struct TpmSigner *signer, const unsigned char hash[HASH_SIZE],
                   unsigned char **sig, size_t *sig_len);
void tpm_signer_cleanup(struct TpmSigner *signer);

#endif
