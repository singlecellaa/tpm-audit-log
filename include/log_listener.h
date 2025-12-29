#ifndef LOG_LISTENER_H
#define LOG_LISTENER_H

#include "common.h"

int log_listener_append(struct HashChainState *state, const char *line,
                        struct LogEntry *entry, unsigned char out_hash[HASH_SIZE]);

#endif
