/* TPM signing helper: loads a persistent key and signs hash buffers via ESAPI. */
#include "tpm_signer.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * tpm_signer_init
 *   Prepares a TPM signer context by loading a persistent key handle.
 * Parameters:
 *   signer             - output structure receiving ESYS/TCTI state.
 *   external_esys      - optional caller-owned ESYS context (NULL to auto-init).
 *   persistent_handle  - TPM persistent handle containing signing key.
 * Returns:
 *   0 when handle is loaded, -1 otherwise.
 */
int tpm_signer_init(struct TpmSigner *signer, ESYS_CONTEXT *external_esys,
                    uint32_t persistent_handle) {
    if (!signer) return -1;
    memset(signer, 0, sizeof(*signer));

    signer->esys = external_esys;
    if (!signer->esys) {
        /* Caller did not supply ESYS; spin up our own TCTI/ESYS. */
        TSS2_RC rc = Tss2_TctiLdr_Initialize(NULL, &signer->tcti);
        if (rc != TSS2_RC_SUCCESS) {
            fprintf(stderr, "TCTI init failed: 0x%x\n", rc);
            return -1;
        }
        rc = Esys_Initialize(&signer->esys, signer->tcti, NULL);
        if (rc != TSS2_RC_SUCCESS) {
            fprintf(stderr, "ESAPI init failed: 0x%x\n", rc);
            return -1;
        }
    }

    TSS2_RC rc = Esys_TR_FromTPMPublic(signer->esys, persistent_handle,
                                       ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                                       &signer->key_handle);
    if (rc != TSS2_RC_SUCCESS) {
        fprintf(stderr, "Failed to load persistent handle 0x%x: 0x%x\n",
                persistent_handle, rc);
        return -1;
    }
    return 0;
}

/*
 * tpm_signer_sign
 *   Signs a pre-hashed digest using the TPM signing key associated with signer.
 * Parameters:
 *   signer  - initialized signer containing ESYS context + key handle.
 *   hash    - digest buffer (length HASH_SIZE) to sign.
 *   sig     - output pointer receiving malloc'ed signature blob.
 *   sig_len - receives signature length in bytes.
 * Returns:
 *   0 on success, -1 if signing fails or parameters are invalid.
 */
int tpm_signer_sign(struct TpmSigner *signer, const unsigned char hash[HASH_SIZE],
                    unsigned char **sig, size_t *sig_len) {
    if (!signer || !signer->esys || !sig || !sig_len) return -1;

    TPM2B_DIGEST digest = {.size = HASH_SIZE};              /* pre-hashed chain head */
    memcpy(digest.buffer, hash, HASH_SIZE);

    TPMT_SIG_SCHEME scheme = {.scheme = TPM2_ALG_RSASSA,
                              .details = {.rsassa = {.hashAlg = TPM2_ALG_SHA256}}};

    TPMT_TK_HASHCHECK validation = {.tag = TPM2_ST_HASHCHECK, .hierarchy = TPM2_RH_NULL,
                                    .digest = {.size = 0}};

    TPMT_SIGNATURE *signature = NULL;
    TSS2_RC rc = Esys_Sign(signer->esys, signer->key_handle, ESYS_TR_PASSWORD,
                           ESYS_TR_NONE, ESYS_TR_NONE, &digest, &scheme, &validation,
                           &signature);
    if (rc != TSS2_RC_SUCCESS) {
        fprintf(stderr, "Esys_Sign failed: 0x%x\n", rc);
        return -1;
    }

    if (signature->sigAlg != TPM2_ALG_RSASSA) {
        fprintf(stderr, "Unexpected signature alg: %u\n", signature->sigAlg);
        Esys_Free(signature);
        return -1;
    }

    *sig_len = signature->signature.rsassa.sig.size;
    *sig = malloc(*sig_len);                                /* caller frees */
    if (!*sig) {
        Esys_Free(signature);
        return -1;
    }
    memcpy(*sig, signature->signature.rsassa.sig.buffer, *sig_len);
    Esys_Free(signature);
    return 0;
}

/*
 * tpm_signer_cleanup
 *   Releases any ESYS/TCTI resources created by tpm_signer_init.
 * Parameters:
 *   signer - context to tear down (safe to call on partial init).
 */
void tpm_signer_cleanup(struct TpmSigner *signer) {
    if (!signer) return;
    if (signer->esys && !signer->tcti) {
        /* Caller owns ESYS; do nothing. */
    } else if (signer->esys) {
        Esys_Finalize(&signer->esys);
    }
    if (signer->tcti) {
        Tss2_TctiLdr_Finalize(&signer->tcti);
    }
    signer->esys = NULL;
    signer->tcti = NULL;
    signer->key_handle = ESYS_TR_NONE;
}
