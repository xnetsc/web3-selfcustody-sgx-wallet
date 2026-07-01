# =================================================================
# Gramine SGX Dockerfile for SGX Enclave (Wallet Business Logic)
# =================================================================
# Builds a Gramine-based Docker image that runs inside an SGX enclave:
#   - SQLite in-process database (better-sqlite3)
#   - WSS RA-TLS peer-to-peer data synchronization
#   - SGX-enclave wallet business logic (Express HTTP API)
#
# No external database server — SQLite runs in-process.
# Nodes synchronize via WSS RA-TLS (HLC-based conflict resolution).
#
# Directory structure inside image:
#   /app/sgx-enclave/      - wallet business logic + node_modules
#                            (RA-TLS verifier comes from @xnetx/sgx-ra-tls-verify npm pkg)
#
# Build:   docker build -f sgx-enclave/Dockerfile -t sgx-enclave .
#          (from project root directory)
#
# Run SGX: docker run --device /dev/sgx_enclave --device /dev/sgx_provision \
#           --security-opt seccomp=unconfined \
#            sgx-enclave
#
# Run SIM: docker run -e SGX_MODE=direct \
#            --security-opt seccomp=unconfined \
#            sgx-enclave
#
# Configuration:
#   All runtime configuration must be supplied via `docker run -e ...` and
#   only the variables in the manifest passthrough whitelist take effect:
#     CONTRACT_RPC_URL / CONTRACT_CHAIN_ID / CONTRACT_ADDRESS / CONTRACT_RPC_TLS_CA_CERT  (bootstrap)
#     SGX_HTTP_PORT / SYNC_NODES / SYNC_LISTEN_PORT             (deployment)
#     RATLS_CERT_PATH / PROXY_API_KEY                           (local/sensitive)
#   Everything else (runtimeParams, whitelists, codeRepository, freeze
#   duration, num shards, min quorum) is read from the smart contract.
#   .env files inside the image are ignored (dotenv removed).
# =================================================================

FROM gramineproject/gramine:latest

ENV DEBIAN_FRONTEND=noninteractive

# =================================================================
# Install build-essential and compilation tools (PERMANENT)
# Final image must include build tools as runtime dependencies
# =================================================================
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential gcc g++ make cmake pkg-config \
    autoconf automake libtool \
    curl wget ca-certificates gnupg lsb-release \
    xz-utils tar gzip coreutils \
    && rm -rf /var/lib/apt/lists/*

# =================================================================
# Install Intel AESM service and PCCS configuration
# Based on official Intel SGX installation guide
# =================================================================
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl gnupg2 apt-transport-https ca-certificates \
    && curl -fsSL "https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key" | tee /tmp/intel-sgx-deb.key | gpg --dearmor -o /usr/share/keyrings/intel-sgx-deb.gpg \
    && echo "deb [arch=amd64 signed-by=/usr/share/keyrings/intel-sgx-deb.gpg] https://download.01.org/intel-sgx/sgx_repo/ubuntu jammy main" > /etc/apt/sources.list.d/intel-sgx.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
    libsgx-launch libsgx-urts libsgx-epid libsgx-quote-ex \
    sgx-aesm-service \
    libsgx-dcap-ql libsgx-dcap-default-qpl libsgx-ae-qe3 libsgx-ae-id-enclave libsgx-pce-logic libsgx-qe3-logic \
    || echo "Some DCAP packages may not be available, continuing..." \
    && rm -rf /var/lib/apt/lists/* /tmp/intel-sgx-deb.key

# Configure PCCS (Provisioning Certificate Caching Service)
RUN mkdir -p /etc/sgx_default_qcnl && \
    echo 'PCCS_URL=https://api.trustedservices.intel.com/sgx/certification/v4' > /etc/sgx_default_qcnl.conf && \
    echo 'USE_SECURE_CERT=FALSE' >> /etc/sgx_default_qcnl.conf && \
    echo 'PCK_CACHING_DISABLED=FALSE' >> /etc/sgx_default_qcnl.conf && \
    echo 'PCK_CERT_CACHING_DISABLED=FALSE' >> /etc/sgx_default_qcnl.conf

# Configure DCAP Quote Verification Library (QVL) path
RUN mkdir -p /etc/sgxlin && \
    echo '/usr/lib/x86_64-linux-gnu' > /etc/sgxlin/sgx_default_qvl_epid.conf && \
    echo '/usr/lib/x86_64-linux-gnu' > /etc/sgxlin/sgx_default_qvl_dcap.conf

# Configure AESM service with PCCS API key
RUN mkdir -p /var/cache/aesm /var/run/aesmd /etc/aesm/assets && \
    echo '{"pccs_api_key":"a8ece8747e7b4d8d98d23faec065b0b8"}' > /etc/aesm/assets/pccs_api_key.json

# Ensure DCAP libraries are in the correct location
RUN ldconfig

# Configure aesmd user and SGX groups
RUN getent group sgx_prv > /dev/null 2>&1 || groupadd -r sgx_prv && \
    getent passwd aesmd > /dev/null 2>&1 || useradd -r -s /usr/sbin/nologin -g aesmd aesmd && \
    usermod -aG sgx_prv aesmd 2>/dev/null || true

# Configure udev rules for SGX devices
RUN echo 'SUBSYSTEM=="sgx", KERNEL=="sgx_enclave", MODE="0666"' > /etc/udev/rules.d/91-sgx-aesm.rules && \
    echo 'SUBSYSTEM=="sgx", KERNEL=="sgx_provision", MODE="0660", GROUP="sgx_prv"' >> /etc/udev/rules.d/91-sgx-aesm.rules

# =================================================================
# Install Node.js v20.18.0 (LTS)
# =================================================================
RUN curl -fsSL "https://nodejs.org/dist/v20.18.0/node-v20.18.0-linux-x64.tar.xz" \
      | tar -xJ --strip-components=1 -C /usr/local \
    && node --version && npm --version

# =================================================================
# Create application directory
# =================================================================
RUN mkdir -p /app/sgx-enclave

# =================================================================
# Install sgx-enclave dependencies
# Copy package files first for Docker cache
# =================================================================
WORKDIR /app/sgx-enclave
COPY sgx-enclave/package.json sgx-enclave/package-lock.json* ./
RUN npm install --production && npm cache clean --force

# =================================================================
# Copy sgx-enclave source code
# =================================================================
COPY sgx-enclave/index.js ./
COPY sgx-enclave/src/ ./src/

# =================================================================
# Copy Gramine launcher and manifest template
# =================================================================
COPY sgx-enclave/gramine-launcher.js ./
COPY sgx-enclave/node.manifest.template ./

# =================================================================
# Create runtime directories
#   ./wallet - encrypted storage (encrypted mount in manifest)
# =================================================================
RUN mkdir -p ./wallet

# =================================================================
# NOTE: No .env file is generated inside the image.
# All runtime configuration must be supplied via `docker run -e ...`
# and is filtered by the manifest passthrough whitelist (see
# node.manifest.template). dotenv is not loaded by the enclave.
# =================================================================

# =================================================================
# Discover trusted shared libraries for enclave manifest
# Only Node.js binary (no external database server in this image)
# =================================================================
RUN set -e && \
    BINARIES="/usr/local/bin/node" && \
    : > /tmp/libs.txt && \
    for bin in $BINARIES; do \
        [ -f "$bin" ] || continue; \
        ldd "$bin" 2>/dev/null | grep "=> /" | awk '{print $3}' >> /tmp/libs.txt || true; \
        ldd "$bin" 2>/dev/null | grep "ld-linux" | awk '{print $1}' >> /tmp/libs.txt || true; \
    done && \
    for nss in /usr/lib/x86_64-linux-gnu/libnss_*.so*; do \
        [ -f "$nss" ] && echo "$nss" >> /tmp/libs.txt || true; \
    done && \
    : > /tmp/trusted-out.txt && \
    sort -u /tmp/libs.txt | while read -r lib; do \
        if [ -n "$lib" ] && [ -f "$lib" ]; then \
            echo "  \"file:$lib\"," >> /tmp/trusted-out.txt; \
            real=$(readlink -f "$lib" 2>/dev/null); \
            if [ -n "$real" ] && [ -f "$real" ] && [ "$real" != "$lib" ]; then \
                echo "  \"file:$real\"," >> /tmp/trusted-out.txt; \
            fi; \
            case "$lib" in \
                /lib/*) \
                    alt="/usr${lib}"; \
                    [ -f "$alt" ] && echo "  \"file:$alt\"," >> /tmp/trusted-out.txt || true; \
                    ;; \
                /usr/lib/*) \
                    alt="${lib#/usr}"; \
                    [ -f "$alt" ] && echo "  \"file:$alt\"," >> /tmp/trusted-out.txt || true; \
                    ;; \
            esac; \
        fi; \
    done && \
    sort -u /tmp/trusted-out.txt > /app/sgx-enclave/trusted-libs-toml.txt && \
    echo "Generated $(wc -l < /app/sgx-enclave/trusted-libs-toml.txt) trusted lib entries" && \
    rm -f /tmp/libs.txt /tmp/trusted-out.txt

# =================================================================
# Inject discovered libraries into manifest template
# =================================================================
RUN sed -i '/__TRUSTED_LIBS_PLACEHOLDER__/r /app/sgx-enclave/trusted-libs-toml.txt' \
        /app/sgx-enclave/node.manifest.template \
    && sed -i '/__TRUSTED_LIBS_PLACEHOLDER__/d' /app/sgx-enclave/node.manifest.template

# =================================================================
# Remove trusted_files entries pointing to non-existent paths
# =================================================================
RUN set -e && cd /app/sgx-enclave && \
    printf '%s\n' \
      'import re, os' \
      'with open("node.manifest.template") as f:' \
      '    lines = f.read().split(chr(10))' \
      'out = []' \
      'in_tf = False' \
      'for line in lines:' \
      '    if "sgx.trusted_files" in line and "=" in line:' \
      '        in_tf = True; out.append(line); continue' \
      '    if in_tf and line.strip() == "]":' \
      '        in_tf = False; out.append(line); continue' \
      '    if in_tf:' \
      '        m = re.search(r'"'"'"file:(/[^"]+)"'"'"', line)' \
      '        if m:' \
      '            p = m.group(1)' \
      '            if "{{" in line: out.append(line); continue' \
      '            if p.endswith("/"):' \
      '                if not os.path.isdir(p.rstrip("/")): print("  Skip dir:",p); continue' \
      '            else:' \
      '                if not os.path.isfile(p): print("  Skip file:",p); continue' \
      '    out.append(line)' \
      'with open("node.manifest.template","w") as f:' \
      '    f.write(chr(10).join(out))' \
      'print("Manifest validated: cleaned sgx.trusted_files only")' \
      > /tmp/clean_manifest.py && \
    python3 /tmp/clean_manifest.py && rm -f /tmp/clean_manifest.py

# =================================================================
# Generate SGX signing key and compile+sign manifest
# Then extract MRENCLAVE so the operator can register it on-chain
# (env-side ENCLAVE_WHITELIST fallback has been removed — the smart
#  contract is now the only source of truth for the whitelist).
# =================================================================
RUN openssl genrsa -3 -out /app/sgx-enclave/enclave-key.pem 3072

RUN cd /app/sgx-enclave && \
    gramine-manifest \
      -Dlog_level=debug \
      node.manifest.template > node.manifest && \
    gramine-sgx-sign \
      --manifest node.manifest \
      --key enclave-key.pem \
      --output node.manifest.sgx && \
    MRENCLAVE=$(gramine-sgx-sigstruct-view node.sig 2>&1 | grep -i 'mr_enclave' | awk '{print $NF}') && \
    echo "==============================================" && \
    echo "Extracted MRENCLAVE: $MRENCLAVE" && \
    echo "Operator MUST register this MRENCLAVE on-chain via" && \
    echo "  WalletTrustContract.addEnclaveIdentity(...)" && \
    echo "before starting any enclave node — env fallback is disabled." && \
    echo "=============================================="

# =================================================================
# Gramine entrypoint script (runs OUTSIDE enclave)
#
# SGX_MODE controls execution mode:
#   SGX_MODE=direct  -> gramine-direct (simulation, no SGX hardware)
#   SGX_MODE=sgx     -> gramine-sgx (real SGX, default)
#   (unset/default)  -> gramine-sgx
# =================================================================
COPY sgx-enclave/patch-manifest-direct.py /usr/local/bin/patch-manifest-direct.py

COPY <<-'ENTRY_EOF' /usr/local/bin/gramine-entrypoint.sh
#!/bin/bash
set -e
cd /app/sgx-enclave

# Start Intel AESM service in background (Docker doesn't use systemd)
echo "[Entrypoint] Starting Intel AESM service..."

# Ensure required directories exist with correct permissions
mkdir -p /var/run/aesmd /var/cache/aesm /var/log
chown -R aesmd:aesmd /var/run/aesmd /var/cache/aesm 2>/dev/null || true
chmod 755 /var/run/aesmd /var/cache/aesm 2>/dev/null || true

# Clear any stale socket files
rm -f /var/run/aesmd/aesm.socket 2>/dev/null || true

# Locate the AESM service binary
# Intel sgx-aesm-service installs to /opt/intel/sgx-aesm-service/aesm/aesm_service
AESM_BIN=""
for candidate in \
    /opt/intel/sgx-aesm-service/aesm/aesm_service \
    /usr/bin/aesm_service \
    /usr/sbin/aesm_service \
    /usr/local/bin/aesm_service \
    /usr/bin/aesmd \
    /usr/sbin/aesmd; do
    if [ -x "$candidate" ]; then
        AESM_BIN="$candidate"
        break
    fi
done

if [ -z "$AESM_BIN" ]; then
    # Last-resort: search common prefixes
    AESM_BIN=$(find /opt/intel /usr -name 'aesm_service' -type f 2>/dev/null | head -1)
fi

if [ -n "$AESM_BIN" ]; then
    AESM_DIR="$(dirname "$AESM_BIN")"
    echo "[Entrypoint] Found AESM binary: $AESM_BIN (dir: $AESM_DIR)"
    # aesm_service loads enclave .so files from its own directory at runtime.
    # Prepend that directory to LD_LIBRARY_PATH so the dynamic linker finds them.
    if [ -n "$LD_LIBRARY_PATH" ]; then
        export LD_LIBRARY_PATH="${AESM_DIR}:${LD_LIBRARY_PATH}"
    else
        export LD_LIBRARY_PATH="${AESM_DIR}"
    fi
    # Use --no-daemon so the process stays in the foreground (as a background job here).
    # Without --no-daemon, aesm_service forks a daemon and the parent exits immediately,
    # which makes kill -0 checks unreliable.
    nohup "$AESM_BIN" --no-daemon > /var/log/aesm.log 2>&1 &
    AESM_PID=$!
    echo "[Entrypoint] AESM service started with PID: $AESM_PID (--no-daemon)"

    # Wait up to 30 seconds for the AESM socket to appear
    echo "[Entrypoint] Waiting for AESM socket to be ready..."
    for i in $(seq 1 30); do
        if [ -S /var/run/aesmd/aesm.socket ]; then
            echo "[Entrypoint] AESM socket ready after ${i}s: /var/run/aesmd/aesm.socket"
            break
        fi
        # Check if the foreground process is still alive
        if ! kill -0 "$AESM_PID" 2>/dev/null; then
            echo "[Entrypoint] AESM process exited unexpectedly, checking log..."
            cat /var/log/aesm.log 2>/dev/null || true
            break
        fi
        sleep 1
    done

    # Final verification
    if [ -S /var/run/aesmd/aesm.socket ]; then
        echo "[Entrypoint] AESM service running normally ✓"
        ls -la /var/run/aesmd/aesm.socket
    else
        echo "[Entrypoint] WARNING: AESM socket not ready after timeout"
        echo "[Entrypoint] AESM log contents:"
        cat /var/log/aesm.log 2>/dev/null || echo "(no log file)"
        echo "[Entrypoint] /var/run/aesmd contents:"
        ls -la /var/run/aesmd/ 2>/dev/null || echo "(directory not found)"
    fi
else
    echo "[Entrypoint] WARNING: AESM service binary not found"
    echo "[Entrypoint] Searching for aesm binaries..."
    find /opt/intel /usr -name '*aesm*' 2>/dev/null | head -20
fi

echo "========================================="
echo " SGX Enclave (Wallet + SQLite + WSS Sync)"
echo " SGX_MODE: ${SGX_MODE:-sgx}"
echo "========================================="

# Ensure runtime directories exist (private key is in-memory only)
mkdir -p ./wallet

if [ "$SGX_MODE" = "direct" ] || [ "$SGX_MODE" = "sim" ]; then
    echo "[Entrypoint] Starting in SIMULATION mode (gramine-direct)..."

    # Direct mode: backup manifest, patch encrypted->chroot and bypass
    # gramine-ratls (no SGX hardware → RA-TLS cert generation fails).
    # Generate fallback self-signed certs for testing, then start gramine.
    MANIFEST="/app/sgx-enclave/node.manifest"
    if [ -f "$MANIFEST" ]; then
        cp "$MANIFEST" "${MANIFEST}.bak"
        # Direct mode: remove the encrypted wallet mount entirely (chroot is read-only,
        # SQLite needs write access). Instead, add wallet files to allowed_files.
        python3 /usr/local/bin/patch-manifest-direct.py "$MANIFEST"
        echo "[Entrypoint] Patched manifest for direct mode (wallet -> allowed_files)"
    fi

    # In direct mode, Node.js cert generator runs inside the enclave and
    # generates the certificate (no SGX quote). Private key stays in memory.

    gramine-direct ./node &
    GRAMINE_PID=$!

    # Restore original manifest immediately after gramine starts
    if [ -f "${MANIFEST}.bak" ]; then
        sleep 1
        cp "${MANIFEST}.bak" "$MANIFEST"
        rm -f "${MANIFEST}.bak"
        echo "[Entrypoint] Restored original manifest"
    fi

    # Wait for gramine process (foreground behavior)
    wait $GRAMINE_PID
    exit $?
else
    # SGX mode: everything runs inside the enclave
    echo "[Entrypoint] Starting in SGX mode (gramine-sgx)..."
    exec gramine-sgx ./node
fi
ENTRY_EOF
RUN chmod +x /usr/local/bin/gramine-entrypoint.sh

# =================================================================
# Expose HTTP port (sgx-enclave API, default 3000)
# =================================================================
EXPOSE 3000
EXPOSE 3307

WORKDIR /app/sgx-enclave

ENTRYPOINT ["/usr/local/bin/gramine-entrypoint.sh"]