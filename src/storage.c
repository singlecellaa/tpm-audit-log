/* Minimal persistence layer: append raw logs, store chain heads, append signatures. */
#include "storage.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * storage_append_log
 *   Appends one log entry to the plaintext log file (CSV-style: seq,timestamp,text).
 * Parameters:
 *   path  - destination file path.
 *   entry - entry metadata to serialize.
 * Returns:
 *   0 on success, -1 on IO or argument errors.
 */
int storage_append_log(const char *path, const struct LogEntry *entry) {
    if (!path || !entry) return -1;
    FILE *f = fopen(path, "a");
    if (!f) return -1;
    /* CSV-like: seq,timestamp,message */
    fprintf(f, "%llu,%llu,%s\n",
            (unsigned long long)entry->seq,
            (unsigned long long)entry->ts,
            entry->message);
    fclose(f);
    return 0;
}

/*
 * storage_save_chain
 *   Writes the current hash chain state struct to disk for later recovery.
 * Parameters:
 *   path  - file path to overwrite.
 *   state - chain snapshot to serialize.
 * Returns:
 *   0 on success, -1 otherwise.
 */
int storage_save_chain(const char *path, const struct HashChainState *state) {
    if (!path || !state) return -1;
    FILE *f = fopen(path, "wb");
    if (!f) return -1;
    fwrite(state, sizeof(*state), 1, f);
    fclose(f);
    return 0;
}

/*
 * storage_append_signature
 *   Appends a binary record {seq, sig_len, sig_bytes} to the signature log.
 * Parameters:
 *   path    - signature file path (opened in append/binary mode).
 *   seq     - log sequence number that the signature protects.
 *   sig     - signature bytes.
 *   sig_len - length of signature buffer.
 * Returns:
 *   0 on success, -1 on IO or argument errors.
 */
int storage_append_signature(const char *path, uint64_t seq, const unsigned char *sig,
                             size_t sig_len) {
    if (!path || !sig || sig_len == 0) return -1;
    FILE *f = fopen(path, "ab");
    if (!f) return -1;
    fwrite(&seq, sizeof(seq), 1, f);
    fwrite(&sig_len, sizeof(sig_len), 1, f);
    fwrite(sig, 1, sig_len, f);
    fclose(f);
    return 0;
}

/*
 * storage_load_chain
 *   Reads the persisted chain snapshot from disk into memory.
 * Parameters:
 *   path  - file to read.
 *   state - destination buffer.
 * Returns:
 *   0 when data is read, -1 if file missing or short read.
 */
int storage_load_chain(const char *path, struct HashChainState *state) {
    if (!path || !state) return -1;
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    size_t r = fread(state, sizeof(*state), 1, f);
    fclose(f);
    return (r == 1) ? 0 : -1;
}

/*
 * storage_read_last_signature
 *   Iterates the signature file and returns the last record.
 */
int storage_read_last_signature(const char *path, uint64_t *seq,
                                unsigned char **sig, size_t *sig_len) {
    if (!path || !seq || !sig || !sig_len) return -1;
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    uint64_t s;
    size_t len;
    unsigned char *buf = NULL;
    while (1) {
        size_t r1 = fread(&s, sizeof(s), 1, f);
        if (r1 != 1) break;
        size_t r2 = fread(&len, sizeof(len), 1, f);
        if (r2 != 1) { buf = NULL; break; }
        buf = (unsigned char *)malloc(len);
        if (!buf) { buf = NULL; break; }
        size_t r3 = fread(buf, 1, len, f);
        if (r3 != len) { free(buf); buf = NULL; break; }
        /* Keep last record */
        if (*sig) { free(*sig); *sig = NULL; }
        *seq = s;
        *sig_len = len;
        *sig = buf;
        buf = NULL;
    }
    fclose(f);
    return (*sig != NULL) ? 0 : -1;
}
