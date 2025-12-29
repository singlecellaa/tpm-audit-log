#ifndef VERIFICATION_H
#define VERIFICATION_H

#include "common.h"

int verification_replay(const char *log_path, const char *chain_path,
                        const unsigned char expected_head[HASH_SIZE]);

#endif
