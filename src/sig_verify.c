#include "sig_verify.h"

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <stdio.h>

/*
 * verify_rsa_sha256
 *   Verifies an RSASSA-PKCS1-v1_5 SHA-256 signature using a PEM public key.
 * Parameters:
 *   pubkey_pem_path - path to PEM-encoded RSA public key (from tpm2_readpublic).
 *   digest          - 32-byte SHA-256 digest that was signed.
 *   sig/sig_len     - signature blob and length.
 * Returns:
 *   0 on valid signature, -1 on failure or invalid signature.
 */
int verify_rsa_sha256(const char *pubkey_pem_path,
                      const unsigned char digest[HASH_SIZE],
                      const unsigned char *sig, size_t sig_len) {
    if (!pubkey_pem_path || !digest || !sig || sig_len == 0) return -1;

    int ret = -1;
    BIO *bio = BIO_new_file(pubkey_pem_path, "r");
    if (!bio) return -1;
    RSA *rsa = PEM_read_bio_RSA_PUBKEY(bio, NULL, NULL, NULL);
    BIO_free(bio);
    if (!rsa) return -1;

    /* TPM RSASSA over SHA-256 digest corresponds to PKCS#1 v1.5 with NID_sha256. */
    if (RSA_verify(NID_sha256, digest, HASH_SIZE, sig, (unsigned int)sig_len, rsa) == 1) {
        ret = 0;
    }
    RSA_free(rsa);
    return ret;
}
