# Decentralized,sgx based self-custody web3 wallet running in gramine and sync data by authorized peer through raft protocol
# xWallet

A non-custodial blockchain wallet system built on Intel SGX (Software Guard Extensions) trusted execution environment with WebAuthn/Passkey authentication. Private keys are generated and stored exclusively inside the SGX enclave — the platform never has access to user keys.

## Overview

All cryptographic operations (key generation, transaction signing, key import/export) run inside the SGX enclave. The platform never has access to plaintext private keys.

Every signing request (`/api/tx/sign`) goes through a **14-point authorization checklist** — platform whitelist verification, WebAuthn P256 Passkey signature, on-chain revocation lookup, authorization expiry, cron-window matching, target address allowlist, per-transaction amount limit, and cumulative spend limit. The endpoint supports two transaction formats: structured `txParams` (platform-supplied fields) and `rawTxHex` (raw bytes, where all auth-relevant fields are parsed from the bytes rather than trusted from the caller).

## Architecture

```
sgx-wallet/
├── contracts/          # Solidity smart contract (trust anchor, whitelist, revocation)
├── sgx-enclave/        # Node.js application running inside the SGX enclave
│   ├── src/
│   │   ├── api/        # 20 REST API endpoint handlers
│   │   ├── modules/    # Core business logic
│   │   │   ├── webauthn/          # Passkey registration & verification
│   │   │   ├── auth-engine/       # 14-point authorization verification
│   │   │   ├── signing/           # Transaction signing (secp256k1, EIP-7702)
│   │   │   ├── key-management/    # ECDH-secured key import/export
│   │   │   ├── wallet-management/ # BIP39/BIP44 wallet CRUD
│   │   │   ├── state-management/  # Authorization state & spend tracking
│   │   │   ├── contract-client/   # On-chain whitelist & revocation queries
│   │   │   ├── remote-attestation/# SGX attestation quote generation
│   │   │   └── sync/              # Multi-node 2PC synchronization
│   │   └── database/   # SQLite schema & connection pooling
├── test-integration/   # End-to-end integration tests
```

### Key Components

| Component | Description |
|-----------|-------------|
| `WalletTrustContract.sol` | On-chain trust anchor: platform/enclave whitelist, runtime params, revocation records |
| `sgx-enclave/src/server.js` | Express HTTP server with 20 API endpoints and 2PC sync support |
| `auth-engine/` | 14-point authorization checklist with cryptographic proof verification |
| `signing/` | Raw transaction signing; supports Ethereum, BSC, Polygon, and other EVM chains |
| `key-management/` | ECDH-secured two-step key import and export flows |
| `sync/` | P2P WebSocket synchronization using Raft-style leader election and Hybrid Logical Clocks |

## Prerequisites

- Node.js 18+
- npm 8+
- [Hardhat](https://hardhat.org/) (for smart contract compilation and local testing)
- Docker + [Gramine](https://gramine.readthedocs.io/) (for SGX enclave containerization; optional for local development)

## Quick Start

### 1. Install dependencies

```bash
# Smart contracts
cd contracts && npm install

# SGX enclave
cd ../sgx-enclave && npm install

# Integration tests
cd ../test-integration && npm install
```

### 2. Compile smart contracts

```bash
cd contracts
npx hardhat compile
```

### 3. Run integration tests (local)

The test suite starts a local Hardhat blockchain, deploys the contract, and runs the enclave:

```bash
cd test-integration
./setup-contract.sh    # Starts Hardhat node, deploys contract, writes .env.contract
./start-enclave.sh     # Starts the SGX enclave on port 3000
node run-general-tests.mjs
```

### 4. Run the enclave standalone

```bash
cd sgx-enclave

export CONTRACT_RPC_URL=http://127.0.0.1:8545
export CONTRACT_CHAIN_ID=31337
export CONTRACT_ADDRESS=<deployed_contract_address>
export SGX_HTTP_PORT=3000

node index.js
```

### 5. Build and run with Docker (SGX)

```bash
# Build the SGX enclave image
docker build -f sgx-enclave/Dockerfile -t sgx-enclave .

# Run in real SGX mode
docker run --device /dev/sgx_enclave --device /dev/sgx_provision \
  --security-opt seccomp=unconfined \
  sgx-enclave

# Run in simulation mode (no SGX hardware required)
docker run -e SGX_MODE=direct \
  --security-opt seccomp=unconfined \
  sgx-enclave
```

## Configuration

Configuration is loaded from two sources: **environment variables** (at startup) and the **`WalletTrustContract`** (on-chain, read at startup and refreshed periodically). When both sources provide a value, the **contract value takes precedence and fully replaces the environment variable value**.

```
Smart contract (on-chain)  →  Environment variable  →  Code default
         highest priority                                lowest priority
```

If `CONTRACT_RPC_URL`, `CONTRACT_CHAIN_ID`, or `CONTRACT_ADDRESS` are omitted, the enclave skips the contract read and starts in **env-only mode** — on-chain features such as authorization revocation checks will be unavailable.

### Environment variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `CONTRACT_RPC_URL` | Yes¹ | — | RPC endpoint of the target blockchain (e.g. `http://127.0.0.1:8545`) |
| `CONTRACT_CHAIN_ID` | Yes¹ | — | Chain ID (e.g. `31337` for local Hardhat, `1` for Ethereum mainnet) |
| `CONTRACT_ADDRESS` | Yes¹ | — | Deployed `WalletTrustContract` address |
| `CONTRACT_RPC_TLS_CA_CERT` | No | — | Base64-encoded TLS CA certificate for verifying the RPC server's TLS certificate chain. Required for HTTPS RPC URLs (non-localhost). Ignored for HTTP or 127.0.0.1/localhost URLs. Pinned after first successful contract read. |
| `SGX_HTTP_PORT` | No | `3000` | HTTP port for the API server |
| `SYNC_NODES` | No | — | Comma-separated WSS peer URLs for multi-node sync; omit for single-node mode |
| `SYNC_LISTEN_PORT` | No | `3307` | WebSocket listening port for P2P sync |
| `NODE_ID` | No | random UUID per start | Stable per-instance identifier. Injection-only (never from contract, since contract config is shared across nodes). A stable `NODE_ID` allows full-sync senders to resume across receiver restarts; when unset, a fresh UUID is generated every start and any in-flight full-sync restarts from scratch on the sender side (idempotent, but wastes bandwidth). |
| `NUM_SHARDS` | No | `16` | Number of shards for horizontal scaling (do not change after first deployment); ENV takes priority over `runtimeParams.sync.numShards` from contract |
| `MIN_QUORUM` | No | `2` (multi-node) / `1` (single) | Minimum peers required for quorum; overridden by `runtimeParams.sync.minQuorum` from contract |
| `PLATFORM_WHITELIST` | No | — | Fallback platform whitelist: comma-separated Ethereum addresses. **Replaced by contract value when contract list is non-empty.** |
| `ENCLAVE_WHITELIST` | No | — | Fallback enclave whitelist: JSON array (see format below). **Replaced by contract value when contract list is non-empty.** |
| `CODE_REPOSITORY` | No | — | Fallback source code repository URL. **Replaced by contract value when non-empty.** |
| `RUNTIME_PARAMS` | No | — | Fallback runtime parameters: JSON object (see structure below). **Replaced by contract value when non-empty.** |
| `FREEZE_DURATION_SECONDS` | No | `259200` (72 h) | Freeze window duration when a Passkey is registered for an existing account that already has wallets (anti-account-takeover); overridden by `runtimeParams.security.freezeDurationSeconds` from contract |
| `PROXY_API_KEY` | No | — | Intel PCCS API key for remote attestation. **Env-only — never stored in the contract.** |
| `RATLS_CERT_PATH` | No | `/app/sgx-enclave/ratls-cert.pem` | Path to the RA-TLS certificate file written by the Gramine launcher. **Env-only — never stored in the contract.** |

¹ All three contract variables must be provided together. If any one is missing the enclave starts in env-only mode.

### What the smart contract stores

The `WalletTrustContract` is the on-chain trust anchor. Its owner can update these fields at any time; the enclave reads them at startup and re-reads them on a configurable interval (`runtimeParams.cache.refreshInterval`, default 60 s).

| Contract field | Env variable fallback | Override rule |
|----------------|-----------------------|---------------|
| `runtimeParams` (JSON string) | `RUNTIME_PARAMS` | Contract value replaces env entirely when non-null |
| `platformWhitelist` (address[]) | `PLATFORM_WHITELIST` | Contract list replaces env list when contract list is non-empty |
| `enclaveWhitelist` (struct[]) | `ENCLAVE_WHITELIST` | Contract list replaces env list when contract list is non-empty |
| `codeRepository` (string) | `CODE_REPOSITORY` | Contract value replaces env value when non-empty |
| `passkeyRecovery` (mapping) | — | Owner-authorized passkey recovery entries; queried in real-time by the enclave during passkey registration (no env fallback) |

### `RUNTIME_PARAMS` / `runtimeParams` structure

Both the `RUNTIME_PARAMS` env variable and the on-chain `runtimeParams` field share the same JSON schema. All fields are optional; omitted fields fall back to the corresponding env variable or code default.

```json
{
  "session": {
    "importTtlSeconds": 300,
    "exportTtlSeconds": 86400,
    "cleanupIntervalSeconds": 3600
  },
  "cache": {
    "refreshInterval": 60000
  },
  "sync": {
    "numShards": 16,
    "minQuorum": 2
  },
  "reconnect": {
    "initialMs": 5000,
    "incrementMs": 30000,
    "maxMs": 300000
  },
  "attestation": {
    "pccsUrl": "https://pccs.example.com",
    "trustedRootCAs": ["-----BEGIN CERTIFICATE-----\n..."],
    "allowOutdatedTcb": false,
    "allowDebugEnclave": false,
    "allowHwConfigNeeded": false,
    "allowSwHardeningNeeded": false,
    "allowNonRaTls": false
  },
  "security": {
    "freezeDurationSeconds": 259200
  }
}
```

### `ENCLAVE_WHITELIST` format

```json
[
  {
    "mrenclave": "0x...",
    "mrsigner": "0x...",
    "isvprodid": 0,
    "isvsvn": 0,
    "description": "Production v1.0"
  }
]
```

## API Overview

All endpoints accept `POST` requests with a JSON body:

```json
{
  "payload": "<JSON string>",
  "platformSignature": "<hex-encoded signature>"
}
```

All responses include:

```json
{
  "attestationQuote": "<hex-encoded SGX quote>",
  "data": "<JSON string>"
}
```

| Endpoint | Description |
|----------|-------------|
| `POST /api/challenge` | Generate a WebAuthn challenge |
| `POST /api/passkey/register/complete` | Complete Passkey registration |
| `POST /api/passkey/delete` | Delete a registered Passkey |
| `POST /api/passkey/list` | List registered Passkeys for a user |
| `POST /api/wallet/create` | Create a new BIP39-based wallet |
| `POST /api/wallet/get` | Get a specific wallet |
| `POST /api/wallet/list` | List wallets for a user |
| `POST /api/wallet/delete` | Delete a wallet |
| `POST /api/wallet/entry/delete` | Delete a single wallet entry |
| `POST /api/auth/status` | Query authorization state and spend tracking |
| `POST /api/tx/sign` | Sign a transaction (txParams or rawTxHex mode); always requires full 14-point authorization |
| `POST /api/key/import/init` | Initialize an ECDH key import session |
| `POST /api/key/import/complete` | Complete the encrypted key import |
| `POST /api/key/export/init` | Initialize a key export session |
| `POST /api/key/export/complete` | Retrieve the encrypted exported key |
| `POST /api/evidence/get` | Get a single authorization evidence record |
| `POST /api/evidence/list` | List authorization evidence records |
| `POST /api/enclave/info` | Get enclave identity and attestation info |
| `POST /api/admin/userId/list` | List all user IDs (platform admin) |

For full request/response schemas, see docs.

## Security Model

1. **No key escrow**: Private keys are generated inside the SGX enclave and never leave it in plaintext.
2. **Passkey authentication**: All user operations require a WebAuthn P256 signature from a registered Passkey.
3. **On-chain revocation**: Authorization grants can be revoked on-chain at any time; the enclave checks the revocation list on every signing request.
4. **14-point authorization verification**: TEE-authorized signing verifies platform whitelist, user Passkey signature, on-chain revocation, expiry, cron windows, target addresses, amount limits, and cumulative spend limits before producing any signature.
5. **Remote attestation**: The enclave provides SGX attestation quotes so clients can cryptographically verify they are talking to genuine, unmodified enclave code.
6. **Account freeze**: Registering a new Passkey for an account that already holds wallets triggers a configurable freeze window (default 72 hours), preventing an attacker from immediately using a hijacked Passkey to access funds.

## Documentation

Detailed design documents are in the docs/ directory:

- docs/master-rules.md — Project governance, architecture, and data models
- docs/eoa-wallet-solution.md — Full wallet design for mobile clients
- docs/sgx-enclave-api.md — HTTP API reference
- docs/authorization-json-guide.md — Authorization JSON structure reference
- docs/security-risks.md — Security threat analysis
- docs/details/ — 30+ detailed design documents for individual modules

## License

xWallet Source Available License 1.0 — see [LICENSE](LICENSE) and [LICENSING.md](LICENSING.md).
