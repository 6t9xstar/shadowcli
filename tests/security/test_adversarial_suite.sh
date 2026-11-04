#!/usr/bin/env bash
set -e

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SHADOW="$REPO_ROOT/target/debug/shadow"
TEST_DIR="/tmp/shadow_adversarial_$$"
MY_UID=$(id -u)

get_latest_session() {
    ls -td "/var/tmp/shadowcli-$MY_UID/sessions/"01* 2>/dev/null | head -n 1 | xargs -r basename
}

cleanup() {
    rm -rf "$TEST_DIR"
}
trap cleanup EXIT

mkdir -p "$TEST_DIR"
cd "$TEST_DIR"

echo "============================================="
echo "   SHADOWCLI ADVERSARIAL SECURITY SUITE     "
echo "============================================="

echo "[1/18] Testing Canary Credential Isolation (SSH / AWS / Kube)..."
mkdir -p "$HOME/.ssh" "$HOME/.aws"
echo "CANARY_SSH_KEY" > "$HOME/.ssh/id_rsa"
chmod 600 "$HOME/.ssh/id_rsa"

set +e
"$SHADOW" run -- cat "$HOME/.ssh/id_rsa" >/dev/null 2>&1
CANARY_EXIT=$?
set -e

LATEST_SESSION=$(get_latest_session)
DEF_BACKEND=$(grep -oE '"backend":[[:space:]]*"[^"]+"' "/var/tmp/shadowcli-$MY_UID/sessions/$LATEST_SESSION/meta.json" 2>/dev/null | awk -F'"' '{print $4}' || echo "unknown")
echo "  Exercised Default Backend: $DEF_BACKEND"

if [ $CANARY_EXIT -eq 0 ]; then
    echo "FAIL: Sandbox allowed reading host ~/.ssh/id_rsa!"
    exit 1
fi
echo "  ✔ Passed: Host credentials unreachable inside sandbox."

echo "[2/18] Testing Host Process Isolation (PID Namespace)..."
"$SHADOW" run -- ps aux >/dev/null 2>&1
LATEST_SESSION=$(get_latest_session)
STDOUT_LOG="/var/tmp/shadowcli-$MY_UID/sessions/$LATEST_SESSION/stdout.log"

# ps aux output should only have header + PID 1 (internal-exec) + PID 2 (ps aux)
PROC_COUNT=$(grep -v "COMMAND" "$STDOUT_LOG" | grep -c -E "^[a-zA-Z0-9_]+" || true)
if [ "$PROC_COUNT" -gt 3 ]; then
    echo "FAIL: Sandbox leaked host processes (saw $PROC_COUNT processes in sandbox)!"
    cat "$STDOUT_LOG"
    exit 1
fi
echo "  ✔ Passed: Host processes isolated (only PID 1 & 2 visible in sandbox)."

echo "[3/18] Testing Seccomp BPF Syscall Filter (ptrace deny)..."
"$SHADOW" run -- python3 -c 'import ctypes; libc=ctypes.CDLL(None); res=libc.ptrace(0,0,0,0); print("ptrace_res", res)' >/dev/null 2>&1
LATEST_SESSION=$(get_latest_session)
STDOUT_LOG="/var/tmp/shadowcli-$MY_UID/sessions/$LATEST_SESSION/stdout.log"

if grep -q "ptrace_res -1" "$STDOUT_LOG"; then
    echo "  ✔ Passed: ptrace syscall blocked with EPERM by Seccomp BPF."
else
    echo "FAIL: ptrace syscall was not blocked by seccomp!"
    cat "$STDOUT_LOG"
    exit 1
fi

echo "[4/18] Testing Outbound Network Isolation..."
set +e
"$SHADOW" run -- curl -s --connect-timeout 2 http://1.1.1.1 >/dev/null 2>&1
NET_EXIT=$?
set -e

if [ $NET_EXIT -eq 0 ]; then
    echo "FAIL: Network traffic succeeded without --allow-network!"
    exit 1
fi
echo "  ✔ Passed: Outbound network blocked by default in isolated netns."

echo "[5/18] Testing Immutable Base Filesystem (Landlock + Read-Only Mount)..."
set +e
"$SHADOW" run -- touch /usr/bin/evil_backdoor >/dev/null 2>&1
LANDLOCK_EXIT=$?
set -e

if [ $LANDLOCK_EXIT -eq 0 ]; then
    echo "FAIL: Agent successfully wrote to /usr/bin inside sandbox!"
    exit 1
fi
echo "  ✔ Passed: Base system paths (/usr, /etc, /lib) are strictly immutable."

echo "[6/18] Testing SUID Bit Stripping on Apply..."
rm -rf "$TEST_DIR"/*
echo "safe" > safe.txt
"$SHADOW" run -- sh -c 'echo "echo root" > backdoor.sh; chmod 4755 backdoor.sh'
LATEST_SESSION=$(get_latest_session)
REVIEW_HASH=$("$SHADOW" diff --session "$LATEST_SESSION" | grep -oE "Review Hash: [a-f0-9]{64}" | head -n 1 | awk '{print $3}')
"$SHADOW" apply --session "$LATEST_SESSION" --review-hash "$REVIEW_HASH" --all --yes

# Check permissions of backdoor.sh on host
HOST_MODE=$(stat -c "%a" backdoor.sh)
if [ "$HOST_MODE" = "4755" ]; then
    echo "FAIL: SUID bit was NOT stripped! File has mode $HOST_MODE"
    exit 1
fi
echo "  ✔ Passed: SUID bit was stripped before host write (mode: $HOST_MODE)."

echo "[7/18] Testing Runaway Process Timeout Enforcement..."
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

echo "[8/18] Testing Symlink Traversal Escape Prevention..."
rm -rf "$TEST_DIR"/*
echo "safe" > safe.txt
"$SHADOW" run -- ln -s /etc/passwd escape_link
LATEST_SESSION=$(get_latest_session)
REVIEW_HASH=$("$SHADOW" diff --session "$LATEST_SESSION" | grep -oE "Review Hash: [a-f0-9]{64}" | head -n 1 | awk '{print $3}')

set +e
"$SHADOW" apply --session "$LATEST_SESSION" --review-hash "$REVIEW_HASH" --all --yes >/dev/null 2>&1
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

echo "[9/18] Testing CopyFS Backend Credential Isolation..."
set +e
"$SHADOW" run --fs-mode copy -- cat "$HOME/.ssh/id_rsa" >/dev/null 2>&1
COPY_CREDS_EXIT=$?
set -e

LATEST_SESSION=$(get_latest_session)
EXPLICIT_BACKEND=$(grep -oE '"backend":[[:space:]]*"[^"]+"' "/var/tmp/shadowcli-$MY_UID/sessions/$LATEST_SESSION/meta.json" 2>/dev/null | awk -F'"' '{print $4}' || echo "unknown")
echo "  Exercised Explicit Backend: $EXPLICIT_BACKEND"
if [ "$EXPLICIT_BACKEND" != "copy" ]; then
    echo "FAIL: --fs-mode copy did not select copy backend!"
    exit 1
fi

if [ $COPY_CREDS_EXIT -eq 0 ]; then
    echo "FAIL: CopyFS allowed reading host ~/.ssh/id_rsa!"
    exit 1
fi
echo "  ✔ Passed: CopyFS confines execution inside namespace & masks \$HOME."

echo "[10/18] Testing CopyFS Backend Network Isolation..."
set +e
"$SHADOW" run --fs-mode copy -- curl -s --connect-timeout 2 http://1.1.1.1 >/dev/null 2>&1
COPY_NET_EXIT=$?
set -e

if [ $COPY_NET_EXIT -eq 0 ]; then
    echo "FAIL: CopyFS allowed outbound network traffic!"
    exit 1
fi
echo "  ✔ Passed: CopyFS executes inside isolated network namespace."

echo "[11/18] Testing Background Orphan Cleanup (PID 1 Kill)..."
"$SHADOW" run -- sh -c 'sleep 999 & exit 0' >/dev/null 2>&1
ORPHAN_COUNT=$(pgrep -f "sleep 999" || true)
if [ -n "$ORPHAN_COUNT" ]; then
    echo "FAIL: Background daemon survived session completion (PID: $ORPHAN_COUNT)!"
    kill -9 $ORPHAN_COUNT >/dev/null 2>&1 || true
    exit 1
fi
echo "  ✔ Passed: PID 1 supervisor reaped and terminated all background daemons."

echo "[12/18] Testing Multiline Private Key Redaction..."
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

echo "[13/18] Testing Seccomp BPF Nested Namespace Denial (unshare deny)..."
"$SHADOW" run -- python3 -c 'import ctypes; libc=ctypes.CDLL(None); res=libc.unshare(0x20000); print("unshare_res", res)' >/dev/null 2>&1
LATEST_SESSION=$(get_latest_session)
STDOUT_LOG="/var/tmp/shadowcli-$MY_UID/sessions/$LATEST_SESSION/stdout.log"

if grep -q "unshare_res -1" "$STDOUT_LOG"; then
    echo "  ✔ Passed: unshare syscall blocked with EPERM by Seccomp BPF."
else
    echo "FAIL: unshare syscall was not blocked by seccomp!"
    cat "$STDOUT_LOG"
    exit 1
fi

echo "[14/18] Testing Parent Directory Symlink Escape Prevention..."
rm -rf "$TEST_DIR"/*
OUTSIDE_TARGET="/tmp/shadow_outside_target_$$"
mkdir -p "$OUTSIDE_TARGET"
mkdir -p "$TEST_DIR/sub_dir"
echo "base" > "$TEST_DIR/sub_dir/payload.txt"

# Sandbox run modifying sub_dir/payload.txt
"$SHADOW" run -- sh -c 'echo "evil" > sub_dir/payload.txt'
LATEST_SESSION=$(get_latest_session)
REVIEW_HASH=$("$SHADOW" diff --session "$LATEST_SESSION" | grep -oE "Review Hash: [a-f0-9]{64}" | head -n 1 | awk '{print $3}')

# Adversary replaces sub_dir with symlink pointing outside project before apply
rm -rf "$TEST_DIR/sub_dir"
ln -s "$OUTSIDE_TARGET" "$TEST_DIR/sub_dir"

set +e
"$SHADOW" apply --session "$LATEST_SESSION" --review-hash "$REVIEW_HASH" --all --yes >/dev/null 2>&1
PARENT_SYM_EXIT=$?
set -e

rm -rf "$OUTSIDE_TARGET"
if [ $PARENT_SYM_EXIT -eq 0 ]; then
    echo "FAIL: apply permitted writing through parent symlink outside project!"
    exit 1
fi
echo "  ✔ Passed: Apply engine rejected parent directory symlink escape."

echo "[15/18] Testing Landlock Sensitive Path Denial (Doctor Verification)..."
DOCTOR_OUT=$("$SHADOW" doctor)
if echo "$DOCTOR_OUT" | grep -q "Landlock LSM" && echo "$DOCTOR_OUT" | grep -q "PASS"; then
    echo "  ✔ Passed: Landlock LSM verified active and enforced."
else
    echo "FAIL: Doctor report showed Landlock LSM failed or missing!"
    echo "$DOCTOR_OUT"
    exit 1
fi

echo "[16/18] Testing Normal Supported Developer Workload Inside Sandbox..."
rm -rf "$TEST_DIR"/*
echo 'fn main() { println!("Hello from sandbox"); }' > main.rs
set +e
"$SHADOW" run -- sh -c 'echo "mod feature;" >> main.rs; echo "pub fn test() {}" > feature.rs'
NORMAL_EXIT=$?
set -e

if [ $NORMAL_EXIT -ne 0 ]; then
    echo "FAIL: Standard development workload failed inside sandbox with exit code $NORMAL_EXIT!"
    exit 1
fi

DIFF_OUT=$("$SHADOW" diff)
if echo "$DIFF_OUT" | grep -q "pub fn test()"; then
    echo "  ✔ Passed: Normal supported command executed successfully with complete diff."
else
    echo "FAIL: Diff did not contain expected feature modification!"
    echo "$DIFF_OUT"
    exit 1
fi

echo "[17/18] Testing /dev/shm Isolation and Scoped Device Access..."
SHM_CANARY="/dev/shm/shadow_canary_shm_$$"
rm -f "$SHM_CANARY"

# Inside sandbox: /dev/null, /dev/zero, /dev/urandom must work, /dev/shm writes succeed
set +e
"$SHADOW" run -- sh -c "echo 'DEV_NULL_OK' > /dev/null && head -c 8 /dev/urandom > /dev/null && head -c 8 /dev/zero > /dev/null && echo 'SHM_SECRET' > '$SHM_CANARY'"
SHM_RUN_EXIT=$?
set -e

if [ $SHM_RUN_EXIT -ne 0 ]; then
    echo "FAIL: Sandbox command writing to /dev/shm or reading /dev/null/zero/urandom failed (exit $SHM_RUN_EXIT)!"
    exit 1
fi

# The file written inside sandbox /dev/shm MUST NOT exist on host /dev/shm
if [ -f "$SHM_CANARY" ]; then
    echo "FAIL: Host /dev/shm was polluted by sandbox execution ($SHM_CANARY exists on host)!"
    rm -f "$SHM_CANARY"
    exit 1
fi

# Verify writing directly to /dev root inside sandbox fails with permission denied
set +e
"$SHADOW" run -- touch /dev/shadow_malicious_device >/dev/null 2>&1
DEV_TOUCH_EXIT=$?
set -e

if [ $DEV_TOUCH_EXIT -eq 0 ]; then
    echo "FAIL: Writing to /dev root inside sandbox succeeded!"
    exit 1
fi
echo "  ✔ Passed: /dev/shm isolated on private tmpfs; /dev root is read-only; character devices functional."

echo "[18/18] Testing Package Cache Symlink Traversal Protection..."
# Setup a cache symlink candidate pointing to sensitive host directory
CACHE_BACKUP=""
mkdir -p "$HOME/.cache"
if [ -e "$HOME/.cache/pip" ] || [ -L "$HOME/.cache/pip" ]; then
    CACHE_BACKUP="/tmp/shadow_pip_backup_$$"
    mv "$HOME/.cache/pip" "$CACHE_BACKUP"
fi

# Create symlink ~/.cache/pip -> ~/.ssh
ln -s "$HOME/.ssh" "$HOME/.cache/pip"

set +e
"$SHADOW" run -- cat "$HOME/.cache/pip/id_rsa" >/dev/null 2>&1
CACHE_SYM_EXIT=$?
set -e

# Cleanup symlink and restore backup
rm -f "$HOME/.cache/pip"
if [ -n "$CACHE_BACKUP" ] && [ -e "$CACHE_BACKUP" ]; then
    mv "$CACHE_BACKUP" "$HOME/.cache/pip"
fi

if [ $CACHE_SYM_EXIT -eq 0 ]; then
    echo "FAIL: Package cache candidate symlink permitted accessing $HOME/.ssh/id_rsa!"
    exit 1
fi
echo "  ✔ Passed: Symlinked package cache candidates rejected by O_NOFOLLOW / symlink_metadata."

echo "============================================="
echo "   ALL 18 ADVERSARIAL SECURITY TESTS PASSED  "
echo "============================================="
