#!/usr/bin/env bash
set -e

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SHADOW="$REPO_ROOT/target/debug/shadow"
TEST_DIR="/tmp/shadow_apply_test_$$"

cleanup() {
    rm -rf "$TEST_DIR"
}
trap cleanup EXIT

echo "=== Test 1: Transactional Apply and Rollback ==="
rm -rf "$TEST_DIR"
mkdir -p "$TEST_DIR"
cd "$TEST_DIR"

echo "v1_original" > keep.txt
echo "to_delete" > delete_me.txt

# Run agent modifications in sandbox
"$SHADOW" run -- sh -c 'echo "v2_modified" > keep.txt; echo "new_file" > added.txt; rm delete_me.txt'

# Verify host is still clean
if [ "$(cat keep.txt)" != "v1_original" ]; then
    echo "FAIL: host keep.txt changed before apply!"
    exit 1
fi
if [ ! -f delete_me.txt ]; then
    echo "FAIL: delete_me.txt deleted before apply!"
    exit 1
fi
if [ -f added.txt ]; then
    echo "FAIL: added.txt created before apply!"
    exit 1
fi
echo "✔ Host remained unchanged after sandbox run."

# Review diff and extract cryptographic review hash
REVIEW_HASH=$("$SHADOW" diff | grep -oE "Review Hash: [a-f0-9]{64}" | head -n 1 | awk '{print $3}')
if [ -z "$REVIEW_HASH" ]; then
    echo "FAIL: Could not extract review hash from diff!"
    exit 1
fi

# Apply changes with review hash
"$SHADOW" apply --all --yes --review-hash "$REVIEW_HASH"
if [ "$(cat keep.txt)" != "v2_modified" ]; then
    echo "FAIL: keep.txt not updated after apply!"
    exit 1
fi
if [ "$(cat added.txt)" != "new_file" ]; then
    echo "FAIL: added.txt not created after apply!"
    exit 1
fi
if [ -f delete_me.txt ]; then
    echo "FAIL: delete_me.txt not deleted after apply!"
    exit 1
fi
echo "✔ Changes successfully applied transactionally."

# Test rollback (rollback does not require review hash)
"$SHADOW" apply --rollback
if [ "$(cat keep.txt)" != "v1_original" ]; then
    echo "FAIL: keep.txt was not restored on rollback!"
    exit 1
fi
if [ ! -f delete_me.txt ]; then
    echo "FAIL: delete_me.txt was not restored on rollback!"
    exit 1
fi
if [ -f added.txt ]; then
    echo "FAIL: added.txt was not removed on rollback!"
    exit 1
fi
echo "✔ Rollback successfully reverted all modifications."

echo "=== Test 2: Symlink Traversal Protection ==="
rm -rf "$TEST_DIR"
mkdir -p "$TEST_DIR"
cd "$TEST_DIR"

echo "safe" > safe.txt
# Agent creates symlinks targeting /etc/shadow or escaping root via ../../
"$SHADOW" run -- ln -s /etc/shadow evil_escape
"$SHADOW" run -- ln -s ../../../../../etc/passwd rel_escape

REVIEW_HASH=$("$SHADOW" diff | grep -oE "Review Hash: [a-f0-9]{64}" | head -n 1 | awk '{print $3}')

# Attempting apply should refuse to create the escaping symlinks
set +e
"$SHADOW" apply --all --yes --review-hash "$REVIEW_HASH"
APPLY_EXIT=$?
set -e

if [ $APPLY_EXIT -eq 0 ]; then
    echo "FAIL: apply should have rejected symlink pointing outside project!"
    exit 1
fi

if [ -e "$TEST_DIR/evil_escape" ] || [ -L "$TEST_DIR/evil_escape" ]; then
    echo "FAIL: evil_escape symlink was created on host!"
    exit 1
fi

if [ -e "$TEST_DIR/rel_escape" ] || [ -L "$TEST_DIR/rel_escape" ]; then
    echo "FAIL: rel_escape symlink was created on host!"
    exit 1
fi
"$SHADOW" discard || true
echo "✔ Symlink path traversal blocked cleanly."

echo "=== Test 3: Protected Path Enforcement ==="
rm -rf "$TEST_DIR"
mkdir -p "$TEST_DIR"
cd "$TEST_DIR"

echo "safe" > safe.txt
echo "SECRET_KEY=123" > .env

# Agent modifies .env
"$SHADOW" run -- sh -c 'echo "SECRET_KEY=HACKED" > .env'
REVIEW_HASH=$("$SHADOW" diff | grep -oE "Review Hash: [a-f0-9]{64}" | head -n 1 | awk '{print $3}')

# Apply without --force-protected must fail
set +e
"$SHADOW" apply --all --yes --review-hash "$REVIEW_HASH"
PROTECTED_EXIT=$?
set -e

if [ $PROTECTED_EXIT -eq 0 ]; then
    echo "FAIL: apply should have required --force-protected for .env!"
    exit 1
fi

if [ "$(cat .env)" != "SECRET_KEY=123" ]; then
    echo "FAIL: .env was modified on host without --force-protected!"
    exit 1
fi
echo "✔ Protected path prevented unconfirmed modification."

# Apply with --force-protected should succeed
"$SHADOW" apply --all --yes --force-protected --review-hash "$REVIEW_HASH"
if [ "$(cat .env)" != "SECRET_KEY=HACKED" ]; then
    echo "FAIL: .env was not modified with --force-protected!"
    exit 1
fi
echo "✔ Protected path override with --force-protected succeeded."

echo "=== Test 4: Automatic Transactional Rollback on Mid-Apply Failure ==="
rm -rf "$TEST_DIR"
mkdir -p "$TEST_DIR"
cd "$TEST_DIR"

echo "initial_a" > 01_file.txt
"$SHADOW" run -- sh -c 'echo "modified_a" > 01_file.txt; ln -s /etc/shadow 99_evil_escape'
REVIEW_HASH=$("$SHADOW" diff | grep -oE "Review Hash: [a-f0-9]{64}" | head -n 1 | awk '{print $3}')

# Apply should encounter evil_escape and fail, and automatically revert 01_file.txt
set +e
"$SHADOW" apply --all --yes --review-hash "$REVIEW_HASH"
FAIL_EXIT=$?
set -e

if [ $FAIL_EXIT -eq 0 ]; then
    echo "FAIL: apply should have failed due to 99_evil_escape!"
    exit 1
fi

if [ "$(cat 01_file.txt)" != "initial_a" ]; then
    echo "FAIL: Automatic rollback failed! 01_file.txt was left dirty as '$(cat 01_file.txt)'"
    exit 1
fi
echo "✔ Automatic rollback restored pre-apply baseline after validation error."

echo "=== Test 5: Concurrent Apply Exclusion (ApplyLock) ==="
rm -rf "$TEST_DIR"
mkdir -p "$TEST_DIR"
cd "$TEST_DIR"
echo "init" > doc.txt
"$SHADOW" run -- sh -c 'echo "concurrent_mod" > doc.txt'
MY_UID=$(id -u)
LATEST_SESSION=$(ls "/var/tmp/shadowcli-$MY_UID/sessions/" | sort | tail -n 1)
SESSION_DIR="/var/tmp/shadowcli-$MY_UID/sessions/$LATEST_SESSION"

REVIEW_HASH=$("$SHADOW" diff --session "$LATEST_SESSION" | grep -oE "Review Hash: [a-f0-9]{64}" | head -n 1 | awk '{print $3}')

# Simulate concurrent process acquiring session flock
exec 200>"$SESSION_DIR/apply.lock"
flock -n 200

# Test concurrent apply while lock is held
set +e
"$SHADOW" apply --session "$LATEST_SESSION" --review-hash "$REVIEW_HASH" --all --yes 2>&1 | grep -q "Apply lock violation"
LOCK_REJECTED=$?
set -e

# Test concurrent discard while lock is held
set +e
"$SHADOW" discard --session "$LATEST_SESSION" 2>&1 | grep -q "locked by an active apply"
DISCARD_LOCKED=$?
set -e

# Release lock
exec 200>&-

if [ $LOCK_REJECTED -ne 0 ]; then
    echo "FAIL: Concurrent apply was not rejected while session lock was held!"
    exit 1
fi
echo "✔ Concurrent apply safely rejected while session lock was held."

if [ $DISCARD_LOCKED -ne 0 ]; then
    echo "FAIL: Concurrent discard was permitted while session apply lock was held!"
    exit 1
fi
echo "✔ Concurrent discard safely rejected while session lock was held."

# Now applying after lock release should succeed
"$SHADOW" apply --session "$LATEST_SESSION" --review-hash "$REVIEW_HASH" --all --yes >/dev/null 2>&1
if [ "$(cat doc.txt)" != "concurrent_mod" ]; then
    echo "FAIL: Apply failed after lock release!"
    exit 1
fi
echo "✔ Apply succeeded after session lock released."

echo "=== Test 6: Automatic Rollback After Mid-Apply Validation Failure ==="
rm -rf "$TEST_DIR"
mkdir -p "$TEST_DIR"
cd "$TEST_DIR"
echo "baseline_data" > existing_doc.txt
"$SHADOW" run -- sh -c 'echo "modified_data" > existing_doc.txt; ln -s /etc/passwd bad_symlink'
LATEST_SESSION=$(ls "/var/tmp/shadowcli-$MY_UID/sessions/" | sort | tail -n 1)
REVIEW_HASH=$("$SHADOW" diff --session "$LATEST_SESSION" | grep -oE "Review Hash: [a-f0-9]{64}" | head -n 1 | awk '{print $3}')

set +e
"$SHADOW" apply --session "$LATEST_SESSION" --review-hash "$REVIEW_HASH" --all --yes >/dev/null 2>&1
FAILED_APPLY_EXIT=$?
set -e

if [ $FAILED_APPLY_EXIT -eq 0 ]; then
    echo "FAIL: Apply should have failed due to invalid symlink!"
    exit 1
fi

# Verify existing_doc.txt was restored to baseline_data by automatic rollback
if [ "$(cat existing_doc.txt)" != "baseline_data" ]; then
    echo "FAIL: Automatic rollback did not restore existing_doc.txt! Left as '$(cat existing_doc.txt)'"
    exit 1
fi
echo "✔ Automatic rollback restored pre-apply baseline after failed apply."

echo "=== ALL APPLY & ROLLBACK TESTS PASSED ==="
