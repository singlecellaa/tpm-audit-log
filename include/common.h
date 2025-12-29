#ifndef COMMON_H
#define COMMON_H

#include <stdint.h>
#include <stddef.h>

#define HASH_SIZE 32
#define MAX_LOG_LINE 4096
#define DEFAULT_STORAGE_PATH "data/logs.txt"
#define DEFAULT_CHAIN_PATH "data/chain_head.bin"
#define DEFAULT_SIG_PATH "data/signatures.bin"
#define DEFAULT_NV_INDEX 0x1500016
#define DEFAULT_PERSISTENT_KEY 0x81000010

struct LogEntry {
    uint64_t seq;
    uint64_t ts;
    char *message;  /* allocated string */
    unsigned char hash[HASH_SIZE];
};

struct HashChainState {
    uint64_t seq;
    unsigned char head[HASH_SIZE];
};

#endif
