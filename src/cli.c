#include "cli.h"
#include "common.h"
#include "hash_chain.h"
#include "log_listener.h"
#include "storage.h"
#include "sig_verify.h"
#include "tpm_nv.h"
#include "tpm_signer.h"
#include "verification.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

/*
 * file_exists
 *   Checks whether a given path exists (any file type).
 * Parameters:
 *   path - path to test.
 * Returns:
 *   non-zero if path exists, 0 otherwise.
 */
static int file_exists(const char *path) {
    struct stat st;
    return stat(path, &st) == 0;
}

/*
 * print_help
 *   Emits CLI usage instructions to stdout.
 */
static void print_help(void) {
    printf("Usage:\n");
    printf("  auditlog --append <text>\n");
    printf("  auditlog --append-file <path>\n");
    printf("  auditlog --stdin\n");
    printf("  auditlog --verify\n");
    printf("  auditlog --verify-sig --pubkey <pem>\n");
    printf("  auditlog --head\n");
    printf("  auditlog --nv-read-head\n");
}

/*
 * do_append
 *   Handles `--append` requests: loads/initializes chain, ingests text, persists
 *   log and chain state, signs via TPM, and writes chain head to NV.
 * Parameters:
 *   text    - message to append.
 * Returns:
 *   0 on success, -1 on error.
 */
static int do_append(const char *text) {
    struct HashChainState state;
    if (file_exists(DEFAULT_CHAIN_PATH)) {
        if (storage_load_chain(DEFAULT_CHAIN_PATH, &state) != 0) {
            fprintf(stderr, "Failed to load chain state\n");
            return -1;
        }
    } else {
        hash_chain_init(&state);
    }

    struct LogEntry entry;
    unsigned char head[HASH_SIZE];
    if (log_listener_append(&state, text, &entry, head) != 0) {
        fprintf(stderr, "Failed to append log\n");
        return -1;
    }

    if (storage_append_log(DEFAULT_STORAGE_PATH, &entry) != 0) {
        fprintf(stderr, "Failed to persist log\n");
        return -1;
    }
    storage_save_chain(DEFAULT_CHAIN_PATH, &state);

    /* Mandatory: sign the new chain head with TPM persistent key and store signature. */
    struct TpmSigner signer;
    if (tpm_signer_init(&signer, NULL, DEFAULT_PERSISTENT_KEY) != 0) {
        fprintf(stderr, "TPM init failed\n");
        return -1;
    }
    unsigned char *sig = NULL;
    size_t sig_len = 0;
    if (tpm_signer_sign(&signer, head, &sig, &sig_len) != 0) {
        fprintf(stderr, "TPM sign failed\n");
        tpm_signer_cleanup(&signer);
        return -1;
    }
    if (storage_append_signature(DEFAULT_SIG_PATH, state.seq, sig, sig_len) != 0) {
        fprintf(stderr, "Persist signature failed\n");
        free(sig);
        tpm_signer_cleanup(&signer);
        return -1;
    }

    /* Mandatory: write the current head into TPM NV for persistence/rollback protection. */
    if (tpm_nv_write_head(signer.esys, DEFAULT_NV_INDEX, head) != 0) {
        fprintf(stderr, "NV write failed\n");
        free(sig);
        tpm_signer_cleanup(&signer);
        return -1;
    }

    free(sig);
    tpm_signer_cleanup(&signer);

    char hex[HASH_SIZE * 2 + 1];
    hash_chain_hex(head, hex, sizeof(hex));
    printf("Appended seq=%llu head=%s\n", (unsigned long long)state.seq, hex);
    return 0;
}

/*
 * do_verify
 *   Replays stored logs, recomputes hash chain, and reports integrity status.
 * Returns:
 *   0 when verification succeeds, non-zero otherwise.
 */
static int do_verify(void) {
    unsigned char expected[HASH_SIZE];
    struct HashChainState persisted;
    if (storage_load_chain(DEFAULT_CHAIN_PATH, &persisted) == 0) {
        memcpy(expected, persisted.head, HASH_SIZE);
    } else {
        memset(expected, 0, HASH_SIZE);
    }
    int rc = verification_replay(DEFAULT_STORAGE_PATH, DEFAULT_CHAIN_PATH, expected);
    if (rc == 0) {
        printf("Verification OK\n");
    } else {
        printf("Verification FAILED\n");
    }
    return rc;
}

/*
 * do_head
 *   Prints the current sequence number and hex head from persisted chain state.
 * Returns:
 *   0 on success, -1 when no state available.
 */
static int do_head(void) {
    struct HashChainState state;
    if (storage_load_chain(DEFAULT_CHAIN_PATH, &state) != 0) {
        fprintf(stderr, "No chain state found\n");
        return -1;
    }
    char hex[HASH_SIZE * 2 + 1];
    hash_chain_hex(state.head, hex, sizeof(hex));
    printf("seq=%llu head=%s\n", (unsigned long long)state.seq, hex);
    return 0;
}

/*
 * cli_run
 *   Entry point invoked by main(): parses argv and dispatches subcommands.
 * Parameters:
 *   argc/argv - standard process arguments.
 * Returns:
 *   subcommand status or 1 when usage is invalid.
 */
int cli_run(int argc, char **argv) {
    if (argc < 2) {
        print_help();
        return 0;
    }

    if (strcmp(argv[1], "--append") == 0 && argc >= 3) {
        return do_append(argv[2]);
    }
    if (strcmp(argv[1], "--verify") == 0) {
        return do_verify();
    }
    if (strcmp(argv[1], "--verify-sig") == 0) {
        const char *pub = NULL;
        for (int i = 2; i < argc - 1; ++i) {
            if (strcmp(argv[i], "--pubkey") == 0) pub = argv[i + 1];
        }
        if (!pub) {
            fprintf(stderr, "Missing --pubkey <pem>\n");
            return 1;
        }
        /* Load expected head, last signature and verify. */
        struct HashChainState st;
        if (storage_load_chain(DEFAULT_CHAIN_PATH, &st) != 0) {
            fprintf(stderr, "No chain state\n");
            return 1;
        }
        uint64_t seq;
        unsigned char *sig = NULL; size_t sig_len = 0;
        if (storage_read_last_signature(DEFAULT_SIG_PATH, &seq, &sig, &sig_len) != 0) {
            fprintf(stderr, "No signature entries\n");
            return 1;
        }
        int ok = verify_rsa_sha256(pub, st.head, sig, sig_len);
        free(sig);
        if (ok == 0) {
            printf("Signature OK for seq=%llu\n", (unsigned long long)seq);
            return 0;
        } else {
            printf("Signature FAILED\n");
            return 1;
        }
    }
    if (strcmp(argv[1], "--head") == 0) {
        return do_head();
    }

    if (strcmp(argv[1], "--append-file") == 0 && argc >= 3) {
        const char *path = argv[2];
        FILE *f = fopen(path, "r");
        if (!f) { fprintf(stderr, "Cannot open %s\n", path); return 1; }
        char buf[MAX_LOG_LINE];
        int rc_total = 0;
        while (fgets(buf, sizeof(buf), f)) {
            size_t len = strlen(buf);
            if (len && (buf[len-1] == '\n' || buf[len-1] == '\r')) buf[len-1] = '\0';
            if (do_append(buf) != 0) rc_total = 1;
        }
        fclose(f);
        return rc_total;
    }

    if (strcmp(argv[1], "--stdin") == 0) {
        char buf[MAX_LOG_LINE];
        int rc_total = 0;
        while (fgets(buf, sizeof(buf), stdin)) {
            size_t len = strlen(buf);
            if (len && (buf[len-1] == '\n' || buf[len-1] == '\r')) buf[len-1] = '\0';
            if (do_append(buf) != 0) rc_total = 1;
        }
        return rc_total;
    }

    if (strcmp(argv[1], "--nv-read-head") == 0) {
        struct TpmSigner signer;
        if (tpm_signer_init(&signer, NULL, DEFAULT_PERSISTENT_KEY) != 0) {
            fprintf(stderr, "TPM init failed\n");
            return 1;
        }
        unsigned char head[HASH_SIZE];
        int rc = tpm_nv_read_head(signer.esys, DEFAULT_NV_INDEX, head);
        tpm_signer_cleanup(&signer);
        if (rc == 0) {
            char hex[HASH_SIZE*2+1]; hash_chain_hex(head, hex, sizeof(hex));
            printf("NV head=%s\n", hex);
            return 0;
        } else {
            printf("NV read FAILED\n");
            return 1;
        }
    }

    print_help();
    return 1;
}
