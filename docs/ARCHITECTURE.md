# Architecture Sketch

- Ingest: `log_listener` receives lines (from files, stdin, or sockets) and hands to `hash_chain`.
- Integrity: `hash_chain` computes forward-secure links `H_i = SHA256(H_{i-1} || seq || ts || log_i)`.
- Sealing: `tpm_signer` signs chain heads with a TPM 2.0 persistent key (PCR policy optional). NV index can hold chain head and monotonic counter snapshots.
- Storage: `storage` persists raw logs, chain head, and signatures under `data/`.
- Verify: `verification` replays the chain and compares against stored head or provided head; TPM public key verifies signatures.
- CLI: lightweight demo tool for append/verify/head; replace with REST later.

## TPM Provisioning (sim)
- Start simulator (ibmtpm/tpm-server) and `tpm2-abrmd`.
- Create primary + RSA signing key; make it persistent (e.g., handle 0x81000010).
- Create NV index (e.g., 0x1500016) for chain snapshots; optional policy counter.
- Bind key usage to PCR policy if desired.

## Data Flow
1. Append: line -> hash_chain -> optional TPM sign -> storage writes log/chain/signature.
2. Verify: replay `data/logs.txt`, recompute head, compare to `data/chain_head.bin`, and verify TPM signature with public key.

## Hardening Ideas
- Add authenticated transport between modules (mTLS or Unix sockets with creds).
- Move logs to append-only FS or WORM storage.
- Add per-entry signatures or Merkle tree checkpoints.
- Export chain heads periodically to remote anchor or blockchain.
