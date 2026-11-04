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

# Apply changes
"$SHADOW" apply --all --yes
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

# Test rollback
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

# Attempting apply should refuse to create the escaping symlinks
set +e
"$SHADOW" apply --all --yes
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

# Apply without --force-protected must fail
set +e
"$SHADOW" apply --all --yes
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
"$SHADOW" apply --all --yes --force-protected
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

# Apply should encounter evil_escape and fail, and automatically revert 01_file.txt
set +e
"$SHADOW" apply --all --yes
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

echo "=== ALL APPLY & ROLLBACK TESTS PASSED ==="
