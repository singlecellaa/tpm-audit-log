#!/usr/bin/env bash
set -euo pipefail

# Comprehensive demo/test script with verbose output.
# Assumes simulator + abrmd already running (scripts/run_tpm.sh) and TPM provisioned (scripts/tpm_setup.sh).
# Produces rich logs to stdout and writes artifacts under ./data/.

RED="\e[31m"; GREEN="\e[32m"; YELLOW="\e[33m"; RESET="\e[0m"
msg() { printf "%b[TEST]%b %s\n" "$YELLOW" "$RESET" "$*"; }
ok()  { printf "%b[ OK ]%b %s\n" "$GREEN" "$RESET" "$*"; }
fail(){ printf "%b[FAIL]%b %s\n" "$RED" "$RESET" "$*"; }

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$ROOT_DIR/build/auditlog"
LOG="$ROOT_DIR/data/logs.txt"
CHAIN="$ROOT_DIR/data/chain_head.bin"
SIGS="$ROOT_DIR/data/signatures.bin"
PUB="$ROOT_DIR/data/pub.pem"

msg "Cleaning old data"
rm -f "$LOG" "$CHAIN" "$SIGS" "$PUB"

msg "Building binary"
make -C "$ROOT_DIR" >/tmp/auditlog_make.log && ok "make completed" || { fail "make failed (see /tmp/auditlog_make.log)"; exit 1; }

msg "Export TPM public key (for sig verify)"
if tpm2_readpublic -c 0x81000010 -o "$PUB" -f PEM >/tmp/auditlog_pub.log 2>&1; then
  ok "TPM pubkey exported to $PUB"
else
  fail "tpm2_readpublic failed (see /tmp/auditlog_pub.log)"; exit 1;
fi

msg "Append sample entries (auto sign + NV write)"
if "$BIN" --append "alpha" && "$BIN" --append "beta"; then
  ok "Appends succeeded"
else
  fail "Append failed"; exit 1;
fi

msg "Show current head"
if HEAD_OUT=$("$BIN" --head); then
  ok "$HEAD_OUT"
else
  fail "head failed"; exit 1;
fi

msg "NV head readback"
if NV_OUT=$("$BIN" --nv-read-head); then
  ok "$NV_OUT"
else
  fail "NV read failed"; exit 1;
fi

msg "Verify chain replay"
if "$BIN" --verify; then
  ok "Verification OK"
else
  fail "Verification FAILED"; exit 1;
fi

msg "Verify signature with exported pubkey"
if "$BIN" --verify-sig --pubkey "$PUB"; then
  ok "Signature OK"
else
  fail "Signature FAILED"; exit 1;
fi

msg "Append via stdin (tail-like)"
printf "gamma\ndelta\n" | "$BIN" --stdin && ok "stdin append OK" || { fail "stdin append failed"; exit 1; }

msg "Re-verify after stdin appends"
if "$BIN" --verify; then
  ok "Verification OK (post-stdin)"
else
  fail "Verification FAILED (post-stdin)"; exit 1;
fi

msg "Inspect log file tail"
tail -n 10 "$LOG"

ok "Demo/test completed"
