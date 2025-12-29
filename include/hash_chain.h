#ifndef HASH_CHAIN_H
#define HASH_CHAIN_H

#include "common.h"

void hash_chain_init(struct HashChainState *state);
int hash_chain_update(struct HashChainState *state, const struct LogEntry *entry,
                     unsigned char out_hash[HASH_SIZE]);
void hash_chain_hex(const unsigned char hash[HASH_SIZE], char *out, size_t out_len);

#endif
