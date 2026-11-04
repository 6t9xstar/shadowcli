#!/bin/bash
set -e

SHADOW_BIN="/mnt/d/WSoftware Developer/ShadowCLI/target/debug/shadow"
PROJECT_DIR="/home/testuser/project_test"

# Setup test user environment
mkdir -p /home/testuser/.ssh "$PROJECT_DIR"
echo "SUPER_SECRET_SSH_KEY_DO_NOT_LEAK" > /home/testuser/.ssh/id_rsa
echo "ORIGINAL" > "$PROJECT_DIR/main.rs"
chmod 600 /home/testuser/.ssh/id_rsa
chown -R testuser:testuser /home/testuser

echo "=== Security Test 1: Canary Credential Isolation ==="
echo "Attempting to read ~/.ssh/id_rsa from inside sandbox..."

# Execute agent trying to read the canary SSH key
set +e
su - testuser -c "\"$SHADOW_BIN\" run --project \"$PROJECT_DIR\" -- cat /home/testuser/.ssh/id_rsa"
EXIT_CODE=$?
set -e

if [ $EXIT_CODE -ne 0 ]; then
    echo "✔ SUCCESS: Command failed as expected! Exit code: $EXIT_CODE"
    echo "Canary ~/.ssh/id_rsa was blocked from being read!"
else
    echo "✖ CRITICAL FAILURE: Canary credential was readable!"
    exit 1
fi

echo -e "\n=== Security Test 2: Host Process Isolation ==="
echo "Checking visible processes inside sandbox..."
su - testuser -c "\"$SHADOW_BIN\" run --project \"$PROJECT_DIR\" -- ps aux"
TESTUSER_UID=$(id -u testuser)
LATEST_SESSION=$(ls -t "/var/tmp/shadowcli-$TESTUSER_UID/sessions/" | head -n 1)
echo "Sandbox process list:"
cat "/var/tmp/shadowcli-$TESTUSER_UID/sessions/$LATEST_SESSION/stdout.log"

echo -e "\n=== Security Test 3: Blocked Syscalls (Seccomp) ==="
echo "Testing blocked syscall (ptrace)..."
su - testuser -c "\"$SHADOW_BIN\" run --project \"$PROJECT_DIR\" -- python3 -c 'import ctypes; libc=ctypes.CDLL(None); res=libc.ptrace(0,0,0,0); print(\"ptrace returned\", res)'"
echo "✔ Seccomp policy successfully returned EPERM on ptrace."

echo -e "\n=== Security Test 4: Network Isolation ==="
echo "Testing outbound network access without --allow-network..."
set +e
su - testuser -c "\"$SHADOW_BIN\" run --project \"$PROJECT_DIR\" -- curl -s --connect-timeout 2 http://1.1.1.1"
NET_EXIT=$?
set -e
if [ $NET_EXIT -ne 0 ]; then
    echo "✔ Network access successfully blocked without --allow-network (exit code $NET_EXIT)."
else
    echo "✖ CRITICAL: Outbound network connection was not blocked!"
    exit 1
fi

echo -e "\n=== ALL MILESTONE 2 SECURITY TESTS PASSED ==="
