#!/usr/bin/env python3
"""
Direct-mode manifest patcher.

In gramine-direct, encrypted mounts are not supported (no MRENCLAVE key).
This script:
  1. Removes the encrypted wallet mount (no MRENCLAVE key in direct mode)
  2. Adds wallet directory to allowed_files (SQLite needs read/write)

NOTE: RUNTIME_PARAMS is no longer injected here. The smart contract is now
the single source of truth for runtimeParams (including
`attestation.allowNonRaTls`). For direct/simulation mode, the operator must
set `runtimeParams.attestation.allowNonRaTls = true` on-chain via
`WalletTrustContract.setRuntimeParams(...)` before booting the enclave.

The compiled manifest uses multi-line TOML format:
  [[fs.mounts]]
  type = "encrypted"
  path = "/app/sgx-enclave/wallet"
  uri = "file:/app/sgx-enclave/wallet"
  key_name = "_sgx_mrenclave"

Usage: python3 patch-manifest-direct.py /app/sgx-enclave/node.manifest
"""
import re, sys

manifest = sys.argv[1]

with open(manifest) as f:
    content = f.read()

# 1. Remove the encrypted wallet mount block (compiled TOML multi-line format)
content = re.sub(
    r'\[\[fs\.mounts\]\]\s*\n'
    r'type\s*=\s*"encrypted"\s*\n'
    r'path\s*=\s*"/app/sgx-enclave/wallet"\s*\n'
    r'uri\s*=\s*"file:/app/sgx-enclave/wallet"\s*\n'
    r'key_name\s*=\s*"_sgx_mrenclave"\s*\n',
    '',
    content
)

# 2. Add wallet directory to allowed_files (if not already present)
if '"file:/app/sgx-enclave/wallet/"' not in content:
    content = content.replace(
        '"file:/app/sgx-enclave/ratls-cert.pem",',
        '"file:/app/sgx-enclave/ratls-cert.pem",\n    "file:/app/sgx-enclave/wallet/",'
    )

with open(manifest, "w") as f:
    f.write(content)

print("[patch-manifest-direct] Removed encrypted wallet mount, added wallet/ to allowed_files")
