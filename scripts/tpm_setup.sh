#!/usr/bin/env bash
set -euo pipefail

# Provision a signing key and NV index for the demo. Requires tpm2-tools 4.3.2.
# Run after scripts/run_tpm.sh. Idempotent-ish: overwrites existing handles.

HANDLE=${HANDLE:-0x81000010}
NV_INDEX=${NV_INDEX:-0x1500016}
AUTH=${AUTH:-""}
TPM_PORT=${TPM_PORT:-2321}
TPM_PORT2=${TPM_PORT2:-2322}
# Default to tabrmd so the client side doesn’t need mssim; abrmd already talks to the simulator.
TPM2TOOLS_TCTI=${TPM2TOOLS_TCTI:-"tabrmd:bus_name=com.intel.tss2.Tabrmd"}
export TPM2TOOLS_TCTI

# Flush old transient objects
for H in $(tpm2_getcap handles-transient | awk '/0x/{print $1}'); do tpm2_flushcontext $H; done

# Create primary
PRIMARY_CTX=$(mktemp)
tpm2_createprimary -C o -g sha256 -G rsa -c "$PRIMARY_CTX"

# Create signing key
SIGN_CTX=$(mktemp)
PUB_PEM=signkey.pub
PRIV_PEM=signkey.priv
PUB="data/pub.pem"
tpm2_create -C "$PRIMARY_CTX" -G rsa -u $PUB_PEM -r $PRIV_PEM
tpm2_readpublic -c 0x81000010 -o "$PUB" -f PEM

# Load and make persistent (skip if already present)
CHILD_CTX=$(mktemp)
tpm2_load -C "$PRIMARY_CTX" -u $PUB_PEM -r $PRIV_PEM -c "$CHILD_CTX"
if ! tpm2_getcap handles-persistent | grep -q "$HANDLE"; then
  tpm2_evictcontrol -C o -c "$CHILD_CTX" $HANDLE || true
fi

# Create NV index for chain head snapshots
if ! tpm2_getcap handles-nv-index | grep -q "$NV_INDEX"; then
  tpm2_nvdefine $NV_INDEX -C o -s 64 -a "ownerread|ownerwrite|policywrite"
fi

echo "Provisioned signing key at $HANDLE and NV index $NV_INDEX"
