#!/usr/bin/env bash
set -e

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SHADOW="$REPO_ROOT/target/debug/shadow"
TEST_DIR="/tmp/shadow_adversarial_$$"
MY_UID=$(id -u)

cleanup() {
    rm -rf "$TEST_DIR"
}
trap cleanup EXIT

mkdir -p "$TEST_DIR"
cd "$TEST_DIR"

echo "============================================="
echo "   SHADOWCLI ADVERSARIAL SECURITY SUITE     "
echo "============================================="

echo "[1/12] Testing Canary Credential Isolation (SSH / AWS / Kube)..."
mkdir -p "$HOME/.ssh" "$HOME/.aws"
echo "CANARY_SSH_KEY" > "$HOME/.ssh/id_rsa"
chmod 600 "$HOME/.ssh/id_rsa"

set +e
"$SHADOW" run -- cat "$HOME/.ssh/id_rsa" >/dev/null 2>&1
CANARY_EXIT=$?
set -e

if [ $CANARY_EXIT -eq 0 ]; then
    echo "FAIL: Sandbox allowed reading host ~/.ssh/id_rsa!"
    exit 1
fi
echo "  ✔ Passed: Host credentials unreachable inside sandbox."

echo "[2/12] Testing Host Process Isolation (PID Namespace)..."
"$SHADOW" run -- ps aux >/dev/null 2>&1
LATEST_SESSION=$(ls -t "/var/tmp/shadowcli-$MY_UID/sessions/" | head -n 1)
STDOUT_LOG="/var/tmp/shadowcli-$MY_UID/sessions/$LATEST_SESSION/stdout.log"

# ps aux output should only have header + PID 1 (internal-exec) + PID 2 (ps aux)
PROC_COUNT=$(grep -v "COMMAND" "$STDOUT_LOG" | grep -c -E "^[a-zA-Z0-9_]+" || true)
if [ "$PROC_COUNT" -gt 3 ]; then
    echo "FAIL: Sandbox leaked host processes (saw $PROC_COUNT processes in sandbox)!"
    cat "$STDOUT_LOG"
    exit 1
fi
echo "  ✔ Passed: Host processes isolated (only PID 1 & 2 visible in sandbox)."

echo "[3/12] Testing Seccomp BPF Syscall Filter (ptrace deny)..."
"$SHADOW" run -- python3 -c 'import ctypes; libc=ctypes.CDLL(None); res=libc.ptrace(0,0,0,0); print("ptrace_res", res)' >/dev/null 2>&1
LATEST_SESSION=$(ls -t "/var/tmp/shadowcli-$MY_UID/sessions/" | head -n 1)
STDOUT_LOG="/var/tmp/shadowcli-$MY_UID/sessions/$LATEST_SESSION/stdout.log"

if grep -q "ptrace_res -1" "$STDOUT_LOG"; then
    echo "  ✔ Passed: ptrace syscall blocked with EPERM by Seccomp BPF."
else
    echo "FAIL: ptrace syscall was not blocked by seccomp!"
    cat "$STDOUT_LOG"
    exit 1
fi

echo "[4/12] Testing Outbound Network Isolation..."
set +e
"$SHADOW" run -- curl -s --connect-timeout 2 http://1.1.1.1 >/dev/null 2>&1
NET_EXIT=$?
set -e

if [ $NET_EXIT -eq 0 ]; then
    echo "FAIL: Network traffic succeeded without --allow-network!"
    exit 1
fi
echo "  ✔ Passed: Outbound network blocked by default in isolated netns."

echo "[5/12] Testing Immutable Base Filesystem (Landlock + Read-Only Mount)..."
set +e
"$SHADOW" run -- touch /usr/bin/evil_backdoor >/dev/null 2>&1
LANDLOCK_EXIT=$?
set -e

if [ $LANDLOCK_EXIT -eq 0 ]; then
    echo "FAIL: Agent successfully wrote to /usr/bin inside sandbox!"
    exit 1
fi
echo "  ✔ Passed: Base system paths (/usr, /etc, /lib) are strictly immutable."

echo "[6/12] Testing SUID Bit Stripping on Apply..."
rm -rf "$TEST_DIR"/*
echo "safe" > safe.txt
"$SHADOW" run -- sh -c 'echo "echo root" > backdoor.sh; chmod 4755 backdoor.sh'
LATEST_SESSION=$(ls -t "/var/tmp/shadowcli-$MY_UID/sessions/" | head -n 1)
"$SHADOW" apply --session "$LATEST_SESSION" --all --yes

# Check permissions of backdoor.sh on host
HOST_MODE=$(stat -c "%a" backdoor.sh)
if [ "$HOST_MODE" = "4755" ]; then
    echo "FAIL: SUID bit was NOT stripped! File has mode $HOST_MODE"
    exit 1
fi
echo "  ✔ Passed: SUID bit was stripped before host write (mode: $HOST_MODE)."

echo "[7/12] Testing Runaway Process Timeout Enforcement..."
START_TIME=$(date +%s)
set +e
"$SHADOW" run --timeout 2 -- sleep 10
TIMEOUT_EXIT=$?
set -e
END_TIME=$(date +%s)
ELAPSED=$((END_TIME - START_TIME))

if [ $TIMEOUT_EXIT -ne 124 ]; then
    echo "FAIL: Runaway command did not exit with code 124 (got $TIMEOUT_EXIT)!"
    exit 1
fi
if [ $ELAPSED -gt 5 ]; then
    echo "FAIL: Timeout took too long to terminate ($ELAPSED seconds)!"
    exit 1
fi
echo "  ✔ Passed: Process killed cleanly after ${ELAPSED}s with exit code 124."

echo "[8/12] Testing Symlink Traversal Escape Prevention..."
rm -rf "$TEST_DIR"/*
echo "safe" > safe.txt
"$SHADOW" run -- ln -s /etc/passwd escape_link
LATEST_SESSION=$(ls -t "/var/tmp/shadowcli-$MY_UID/sessions/" | head -n 1)

set +e
"$SHADOW" apply --session "$LATEST_SESSION" --all --yes >/dev/null 2>&1
ESCAPE_EXIT=$?
set -e

if [ $ESCAPE_EXIT -eq 0 ]; then
    echo "FAIL: apply accepted symlink pointing outside project!"
    exit 1
fi
if [ -e escape_link ] || [ -L escape_link ]; then
    echo "FAIL: escape_link was created on host!"
    exit 1
fi
echo "  ✔ Passed: Escaping symlink rejected by apply engine."

echo "[9/12] Testing CopyFS Backend Credential Isolation..."
set +e
"$SHADOW" run --fs-mode copy -- cat "$HOME/.ssh/id_rsa" >/dev/null 2>&1
COPY_CREDS_EXIT=$?
set -e

if [ $COPY_CREDS_EXIT -eq 0 ]; then
    echo "FAIL: CopyFS allowed reading host ~/.ssh/id_rsa!"
    exit 1
fi
echo "  ✔ Passed: CopyFS confines execution inside namespace & masks \$HOME."

echo "[10/12] Testing CopyFS Backend Network Isolation..."
set +e
"$SHADOW" run --fs-mode copy -- curl -s --connect-timeout 2 http://1.1.1.1 >/dev/null 2>&1
COPY_NET_EXIT=$?
set -e

if [ $COPY_NET_EXIT -eq 0 ]; then
    echo "FAIL: CopyFS allowed outbound network traffic!"
    exit 1
fi
echo "  ✔ Passed: CopyFS executes inside isolated network namespace."

echo "[11/12] Testing Background Orphan Cleanup (PID 1 Kill)..."
"$SHADOW" run -- sh -c 'sleep 999 & exit 0' >/dev/null 2>&1
ORPHAN_COUNT=$(pgrep -f "sleep 999" || true)
if [ -n "$ORPHAN_COUNT" ]; then
    echo "FAIL: Background daemon survived session completion (PID: $ORPHAN_COUNT)!"
    kill -9 $ORPHAN_COUNT >/dev/null 2>&1 || true
    exit 1
fi
echo "  ✔ Passed: PID 1 supervisor reaped and terminated all background daemons."

echo "[12/12] Testing Multiline Private Key Redaction..."
rm -rf "$TEST_DIR"/*
echo "safe" > safe.txt
"$SHADOW" run -- sh -c 'printf -- "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0m...\nSUPER_SECRET_PAYLOAD\n-----END RSA PRIVATE KEY-----\n" > app.rs'
DIFF_OUTPUT=$("$SHADOW" diff)

if echo "$DIFF_OUTPUT" | grep -q "SUPER_SECRET_PAYLOAD"; then
    echo "FAIL: Secret payload appeared in terminal diff!"
    exit 1
fi
if echo "$DIFF_OUTPUT" | grep -q "Private Key Block"; then
    echo "  ✔ Passed: Multiline private key successfully redacted from terminal diff."
else
    echo "FAIL: Redaction marker not found in diff output!"
    echo "$DIFF_OUTPUT"
    exit 1
fi

echo "============================================="
echo "   ALL 12 ADVERSARIAL SECURITY TESTS PASSED  "
echo "============================================="
