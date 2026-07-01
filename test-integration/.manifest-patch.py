import re, sys, os
addr = sys.argv[1]
sgx_mode = os.environ.get("SGX_MODE", "sgx")
envfile = "/app/sgx-enclave/.env"

# Patch .env with test platform address
with open(envfile) as f:
    env = f.read()
env = re.sub(r"^PLATFORM_WHITELIST=.*", "PLATFORM_WHITELIST=" + addr, env, flags=re.MULTILINE)

def patch_env(env, key, value):
    if re.search(r"^" + key + r"=", env, flags=re.MULTILINE):
        return re.sub(r"^" + key + r"=.*", key + "=" + value, env, flags=re.MULTILINE)
    else:
        return env + f"\n{key}={value}"

# Patch contract config if provided via environment variables
for key in ("CONTRACT_ADDRESS", "CONTRACT_RPC_URL", "CONTRACT_CHAIN_ID", "CONTRACT_RPC_TLS_CA_CERT", "FREEZE_DURATION_SECONDS"):
    val = os.environ.get(key, "")
    if val:
        env = patch_env(env, key, val)
        print(f"[TestSetup] .env patched: {key}={val}")

# Always override SYNC_NODES and MIN_QUORUM to avoid inheriting Dockerfile production defaults
sync_nodes = os.environ.get("SYNC_NODES", "")
env = patch_env(env, "SYNC_NODES", sync_nodes)
print(f"[TestSetup] .env patched: SYNC_NODES={sync_nodes!r}")

min_quorum = os.environ.get("MIN_QUORUM", "")
if min_quorum:
    env = patch_env(env, "MIN_QUORUM", min_quorum)
    print(f"[TestSetup] .env patched: MIN_QUORUM={min_quorum}")

with open(envfile, "w") as f:
    f.write(env)
print(f"[TestSetup] .env patched: PLATFORM_WHITELIST={addr}")
print(f"[TestSetup] SGX_MODE={sgx_mode}")
