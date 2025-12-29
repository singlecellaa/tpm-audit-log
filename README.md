# TPM-Backed Audit Log (C)

TPM-protected, hash-chained audit logging prototype for Ubuntu 20.04 using TPM2 stack (tpm-server/ibmtpm1661 + tpm2-abrmd 2.3.1 + tpm2-tools 4.3.2 + tpm2-tss 3.1.0 + tpm2-tss-engine 1.1.0).

## Components
- Log Listener: tails system/app logs (stdin/file) and feeds hash chain.
- Hash Chain Manager: computes H_i = H(H_{i-1} | log_i) using SHA-256.
- TPM Signer: signs chain heads via TPM-resident key (PCR policy optional).
- TPM NV: persists chain head in TPM NV (anti-rollback anchor).
- Storage: raw logs, chain state, signatures.
- Verification: replays chain; can verify signatures with TPM pubkey.
- CLI: append from text/file/stdin; verify chain/signature; read NV head.

## Build
```
mkdir -p build
cc -Wall -Wextra -Iinclude -o build/auditlog \
  src/main.c src/log_listener.c src/hash_chain.c src/tpm_signer.c \
  src/storage.c src/verification.c src/cli.c src/tpm_nv.c src/sig_verify.c \
  -ltss2-esys -ltss2-rc -ltss2-tctildr -ltss2-mu -lcrypto
```

## Quick Start (sim TPM)
1) Start simulator: `scripts/run_tpm.sh`
2) Provision key + NV index: `scripts/tpm_setup.sh`
3) Build: `make`
4) Append logs (sign + NV write are automatic):
  - `build/auditlog --append "hello"`
  - `build/auditlog --append-file /var/log/syslog`
  - `tail -F /var/log/syslog | build/auditlog --stdin`
5) Verify chain replay: `build/auditlog --verify`
6) Verify signature (export TPM pubkey first):
  - `tpm2_readpublic -c 0x81000010 -o pub.pem -f PEM`
  - `build/auditlog --verify-sig --pubkey pub.pem`
7) Read NV chain head: `build/auditlog --nv-read-head`

## Layout
- src/: C sources for each module
- include/: headers
- scripts/: TPM simulator + provisioning helpers
- docs/: design notes
- config/: sample configs
- data/: default local storage (git-ignored)
- tests/: placeholder

## Notes
- Default hash: SHA-256 via OpenSSL; replace with TSS hash if preferred.
- TPM handles: persistent key 0x81000010; NV index 0x1500016 stores chain head (written automatically on append).
- Signing is mandatory on append; signatures stored in data/signatures.bin; chain head also written to NV.
- This is a prototype: add auth/ACLs, auditd/rsyslog integration, PCR policies, NV counters, and hardened storage for production.
