#ifndef STORAGE_H
#define STORAGE_H

#include "common.h"

int storage_append_log(const char *path, const struct LogEntry *entry);
int storage_save_chain(const char *path, const struct HashChainState *state);
int storage_append_signature(const char *path, uint64_t seq, const unsigned char *sig,
                             size_t sig_len);
int storage_load_chain(const char *path, struct HashChainState *state);

int storage_read_last_signature(const char *path, uint64_t *seq,
                                unsigned char **sig, size_t *sig_len);

#endif
