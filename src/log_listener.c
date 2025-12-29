/* Ingests a single log line into the hash chain. */
#include "log_listener.h"
#include "hash_chain.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/*
 * log_listener_append
 *   Ingests a single log line, updates the running hash chain, fills out the
 *   LogEntry (seq/timestamp/hash), and surfaces the resulting head digest.
 * Parameters:
 *   state    - in/out hash chain cursor to update.
 *   line     - UTF-8/ASCII log message to record.
 *   entry    - output entry populated with seq/ts/hash (message pointer borrowed).
 *   out_hash - caller-provided buffer receiving the new chain head.
 * Returns:
 *   0 on success, -1 on validation or hashing failures.
 */
int log_listener_append(struct HashChainState *state, const char *line,
                        struct LogEntry *entry, unsigned char out_hash[HASH_SIZE]) {
    if (!state || !line || !entry || !out_hash) return -1;

    entry->seq = state->seq + 1;              /* monotonic sequence number */
    entry->ts = (uint64_t)time(NULL);         /* coarse timestamp; can swap to source ts */
    entry->message = (char *)line;            /* caller owns storage/lifetime */
    memset(entry->hash, 0, HASH_SIZE);

    if (hash_chain_update(state, entry, out_hash) != 0) {
        return -1;
    }

    memcpy(entry->hash, out_hash, HASH_SIZE);
    return 0;
}
