/* Hash chain implementation: H_i = SHA256(H_{i-1} || seq || ts || log_i). */
#include "hash_chain.h"

#include <openssl/sha.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

/*
 * hash_chain_init
 *   Resets the hash chain cursor to an origin state (seq=0, head=0).
 * Parameters:
 *   state - chain cursor to initialize (required).
 */
void hash_chain_init(struct HashChainState *state) {
    if (!state) return;
    state->seq = 0;               /* start with empty chain */
    memset(state->head, 0, HASH_SIZE);
}

/*
 * hash_chain_update
 *   Extends the chain by hashing the previous head with the supplied entry.
 * Parameters:
 *   state    - in/out chain cursor, provides previous head and receives new head.
 *   entry    - log entry metadata to bind into the hash.
 *   out_hash - output buffer for the new chain head digest.
 * Returns:
 *   0 on success, -1 when inputs are invalid.
 */
int hash_chain_update(struct HashChainState *state, const struct LogEntry *entry,
                      unsigned char out_hash[HASH_SIZE]) {
    if (!state || !entry || !out_hash) return -1;

    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, state->head, HASH_SIZE);              /* bind prior head */
    SHA256_Update(&ctx, &entry->seq, sizeof(entry->seq));     /* order + gap detect */
    SHA256_Update(&ctx, &entry->ts, sizeof(entry->ts));       /* coarse time binding */
    SHA256_Update(&ctx, entry->message, strlen(entry->message));
    SHA256_Final(out_hash, &ctx);

    memcpy(state->head, out_hash, HASH_SIZE);                 /* advance chain head */
    state->seq = entry->seq;
    return 0;
}

/*
 * hash_chain_hex
 *   Renders a binary digest into lowercase hex for display/logging.
 * Parameters:
 *   hash    - binary input digest.
 *   out     - destination buffer for ASCII string.
 *   out_len - length of destination (needs >= HASH_SIZE*2+1).
 */
void hash_chain_hex(const unsigned char hash[HASH_SIZE], char *out, size_t out_len) {
    static const char *hex = "0123456789abcdef";
    if (!hash || !out || out_len < HASH_SIZE * 2 + 1) return;
    for (size_t i = 0; i < HASH_SIZE; ++i) {
        out[i * 2] = hex[(hash[i] >> 4) & 0xF];
        out[i * 2 + 1] = hex[hash[i] & 0xF];
    }
    out[HASH_SIZE * 2] = '\0';
}
