#!/bin/bash
set -e
export SGX_MODE="direct"
export CONTRACT_ADDRESS=""
export CONTRACT_RPC_URL=""
export CONTRACT_CHAIN_ID=""
export FREEZE_DURATION_SECONDS="5"
export SYNC_NODES=""
export MIN_QUORUM="1"
python3 /test-manifest-patch.py "0x558add1b741DC857fB8F0543C26057F39f4fc5f9"
if [ "$SGX_MODE" = "direct" ] || [ "$SGX_MODE" = "sim" ]; then
    # Direct mode: fix fallback cert CN
    sed -i 's/CN=direct-mode-fallback/CN=SGX-Wallet-Client/' /usr/local/bin/gramine-entrypoint.sh
fi
exec /usr/local/bin/gramine-entrypoint.sh
