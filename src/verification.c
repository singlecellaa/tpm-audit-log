/* Replays stored logs to recompute the hash chain and optionally compare head. */
#include "verification.h"
#include "common.h"
#include "hash_chain.h"
#include "storage.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * verification_replay
 *   Recomputes the hash chain from stored plaintext logs and compares the
 *   resulting head to a provided reference (optional).
 * Parameters:
 *   log_path      - path to plaintext log file produced by storage_append_log.
 *   chain_path    - path where the recomputed chain snapshot should be stored.
 *   expected_head - optional 32-byte hash to compare against (can be NULL).
 * Returns:
 *   0 when replay succeeds and matches (if provided), -1 otherwise.
 */
int verification_replay(const char *log_path, const char *chain_path,
                        const unsigned char expected_head[HASH_SIZE]) {
    if (!log_path || !chain_path) return -1;

    struct HashChainState state;
    hash_chain_init(&state);

    FILE *f = fopen(log_path, "r");
    if (!f) {
        fprintf(stderr, "Could not open %s\n", log_path);
        return -1;
    }

    char line_buf[MAX_LOG_LINE];
    unsigned char out_hash[HASH_SIZE];
    uint64_t seq = 0;

    while (fgets(line_buf, sizeof(line_buf), f)) {
        /* Expect format: seq,timestamp,message */
        char *p1 = strchr(line_buf, ',');
        if (!p1) continue;
        char *p2 = strchr(p1 + 1, ',');
        if (!p2) continue;

        *p1 = '\0';
        *p2 = '\0';
        const char *seq_str = line_buf;
        const char *ts_str = p1 + 1;
        char *msg = p2 + 1;

        size_t len = strlen(msg);
        if (len > 0 && (msg[len - 1] == '\n' || msg[len - 1] == '\r')) {
            msg[len - 1] = '\0';
        }

        struct LogEntry entry;
        entry.seq = (uint64_t)strtoull(seq_str, NULL, 10);
        entry.ts = (uint64_t)strtoull(ts_str, NULL, 10);
        entry.message = msg;
        memset(entry.hash, 0, HASH_SIZE);

        if (hash_chain_update(&state, &entry, out_hash) != 0) {
            fclose(f);
            return -1;
        }
    }
    fclose(f);

    if (expected_head) {
        if (memcmp(state.head, expected_head, HASH_SIZE) != 0) {
            fprintf(stderr, "Head hash mismatch\n");
            return -1;
        }
    }

    storage_save_chain(chain_path, &state);
    return 0;
}
