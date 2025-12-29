#!/usr/bin/env bash
set -euo pipefail

# Start IBM TPM simulator (tpm-server/ibmtpm) and tpm2-abrmd on Ubuntu 20.04.
# Adjust paths as needed. Run this in one terminal, then use tpm_setup.sh.
# Default mode: abrmd connects to simulator; tools can use tabrmd TCTI (no mssim lib needed client-side).

TPM_PORT=${TPM_PORT:-2321}
TPM_PORT2=${TPM_PORT2:-2322}
TPM_SOCK=${TPM_SOCK:-/tmp/tpm-simulator.sock}

if pgrep -x tpm2-abrmd >/dev/null; then
  echo "tpm2-abrmd already running" >&2
else
  echo "Launching TPM simulator..." >&2
  (tpm_server -rm & echo $! > /tmp/tpm-sim.pid)
  sleep 1
  echo "Launching tpm2-abrmd..." >&2
  (tpm2-abrmd --tcti=mssim:host=127.0.0.1,port=$TPM_PORT,port2=$TPM_PORT2 --allow-root --session --flush-all & echo $! > /tmp/tpm2-abrmd.pid)
fi

# Default: talk to abrmd from tools (no mssim lib needed client side)
export TPM2TOOLS_TCTI="tabrmd:bus_name=com.intel.tss2.Tabrmd"
echo "TPM simulator listening on ports $TPM_PORT/$TPM_PORT2"
echo "TPM2TOOLS_TCTI=$TPM2TOOLS_TCTI"
