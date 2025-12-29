#ifndef SIG_VERIFY_H
#define SIG_VERIFY_H

#include <stddef.h>
#include "common.h"

int verify_rsa_sha256(const char *pubkey_pem_path,
                      const unsigned char digest[HASH_SIZE],
                      const unsigned char *sig, size_t sig_len);

#endif
