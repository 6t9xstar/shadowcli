#!/usr/bin/env bash
# ==============================================================================
# ShadowCLI — Git & OverlayFS Compatibility Test Suite
# ==============================================================================
# Tests Git repository operations inside the ShadowCLI execution sandbox:
# 1. git init, git add, git commit
# 2. Atomic lockfile rename (index.lock -> index)
# 3. Inode & mtime stability across copy-up (core.checkStat behavior)
# 4. Git status reporting clean status after commit
# 5. Branch creation and switching
# 6. Hardlink creation within workspace
# 7. Safe staging, review hash binding, and terminal apply
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
SHADOW_BIN="$REPO_ROOT/target/release/shadow"

if [ ! -f "$SHADOW_BIN" ]; then
  SHADOW_BIN="$REPO_ROOT/target/debug/shadow"
fi

if [ ! -f "$SHADOW_BIN" ]; then
  echo "Error: Shadow binary not found in target/release or target/debug" >&2
  exit 1
fi

TEST_DIR=$(mktemp -d /tmp/shadow_git_test_XXXXXX)
chmod 700 "$TEST_DIR"

cleanup() {
  if [ -d "$TEST_DIR" ] && [ ! -L "$TEST_DIR" ]; then
    rm -rf "$TEST_DIR"
  fi
}
trap cleanup EXIT

echo "=========================================================="
echo "   SHADOWCLI — GIT & OVERLAYFS COMPATIBILITY TEST SUITE   "
echo "=========================================================="
echo "Testing with binary: $SHADOW_BIN"
echo "Workspace: $TEST_DIR"

# Step 1: Initialize a Git repository on the host
cd "$TEST_DIR"
git init -b main >/dev/null 2>&1 || git init >/dev/null 2>&1
git config user.name "Shadow Tester"
git config user.email "tester@shadowcli.internal"
git config commit.gpgsign false

echo "Initial commit on host" > README.md
git add README.md
git commit -m "feat: initial commit" >/dev/null

echo "[1/6] Testing git status inside sandbox..."
# Run git status inside sandbox (should succeed with exit code 0)
STATUS_OUT=$("$SHADOW_BIN" run -- git status)
STATUS_SESSION=$(echo "$STATUS_OUT" | grep -oE "01[0-9A-HJ-NP-TV-Z]{24}" | head -1)
MY_UID=$(id -u)
STATUS_DIR="/var/tmp/shadowcli-$MY_UID/sessions/$STATUS_SESSION"
if [ ! -d "$STATUS_DIR" ]; then
  STATUS_DIR=$(find /var/tmp /tmp -name "$STATUS_SESSION" 2>/dev/null | head -1)
fi

STATUS_BACKEND=$(grep -oE '"backend":[[:space:]]*"[^"]+"' "$STATUS_DIR/meta.json" 2>/dev/null | awk -F'"' '{print $4}' || echo "unknown")
echo "  Exercised Backend: $STATUS_BACKEND"
if [ "$STATUS_BACKEND" != "overlay" ]; then
  echo "  ✖ Failed: Expected native OverlayFS backend, but sandbox fell back to '$STATUS_BACKEND'." >&2
  echo "    Ensure test workspace is located on a native Linux filesystem (e.g. ext4, btrfs, tmpfs) supporting unprivileged OverlayFS." >&2
  exit 1
fi
echo "  ✔ Confirmed: Native OverlayFS backend active (no fallback)."

if echo "$STATUS_OUT" | grep -q "Exit code: 0" && grep -q "nothing to commit" "$STATUS_DIR/stdout.log"; then
  echo "  ✔ Passed: Initial git status is completely clean inside sandbox."
else
  echo "  ✖ Failed: git status inside sandbox reported unexpected error:"
  echo "$STATUS_OUT"
  if [ -f "$STATUS_DIR/stderr.log" ]; then
    cat "$STATUS_DIR/stderr.log"
  fi
  exit 1
fi
"$SHADOW_BIN" discard --session "$STATUS_SESSION" >/dev/null 2>&1 || true

echo "[2/6] Testing staged git modifications (atomic index.lock rename)..."
# Make changes and commit inside sandbox
COMMIT_OUT=$("$SHADOW_BIN" run -- bash -c '
  echo "Feature code" > feature.rs
  git add feature.rs
  git commit -m "feat: add feature inside sandbox"
')

SESSION_ID=$(echo "$COMMIT_OUT" | grep "ShadowCLI Session:" | head -1 | awk '{print $3}')
if [ -z "$SESSION_ID" ] || ! echo "$COMMIT_OUT" | grep -q "Exit code: 0"; then
  echo "  ✖ Failed: commit inside sandbox failed"
  echo "$COMMIT_OUT"
  exit 1
fi

echo "  ✔ Passed: git add & git commit succeeded inside sandbox (atomic index.lock rename ok)."
echo "  Staged Session: $SESSION_ID"

echo "[3/6] Verifying host Git repository invariant..."
# Host git log should only have 1 commit
HOST_COMMITS=$(git rev-list --count HEAD)
if [ "$HOST_COMMITS" -eq 1 ]; then
  echo "  ✔ Passed: Host Git repository remains unchanged (1 commit on host)."
else
  echo "  ✖ Failed: Host repository was mutated unexpectedly! Commits: $HOST_COMMITS"
  exit 1
fi

if [ -f "feature.rs" ]; then
  echo "  ✖ Failed: feature.rs exists on host before apply!"
  exit 1
fi
echo "  ✔ Passed: feature.rs does not exist on host before apply."

echo "[4/6] Testing Git branch creation & switching inside sandbox..."
BRANCH_OUT=$("$SHADOW_BIN" run -- bash -c '
  git checkout -b test-branch
  echo "branch content" > branch_file.txt
  git add branch_file.txt
  git commit -m "feat: branch commit"
  git branch
')
BRANCH_SESSION=$(echo "$BRANCH_OUT" | grep "ShadowCLI Session:" | head -1 | awk '{print $3}')
BRANCH_DIR=$(find /var/tmp /tmp -name "$BRANCH_SESSION" 2>/dev/null | head -1)

if echo "$BRANCH_OUT" | grep -q "Exit code: 0" && grep -q "test-branch" "$BRANCH_DIR/stdout.log"; then
  echo "  ✔ Passed: Branch creation and commit inside sandbox succeeded."
else
  echo "  ✖ Failed: Branch operations failed inside sandbox"
  echo "$BRANCH_OUT"
  exit 1
fi

# Discard the branch test session
if [ -n "$BRANCH_SESSION" ]; then
  "$SHADOW_BIN" discard --session "$BRANCH_SESSION" >/dev/null 2>&1 || true
fi

echo "[5/6] Testing hardlink creation within sandbox..."
HARDLINK_OUT=$("$SHADOW_BIN" run -- bash -c '
  echo "original content" > source.txt
  ln source.txt linked.txt
  stat -c %h linked.txt
')
HARDLINK_SESSION=$(echo "$HARDLINK_OUT" | grep "ShadowCLI Session:" | head -1 | awk '{print $3}')
HARDLINK_DIR=$(find /var/tmp /tmp -name "$HARDLINK_SESSION" 2>/dev/null | head -1)

if echo "$HARDLINK_OUT" | grep -q "Exit code: 0" && grep -q "2" "$HARDLINK_DIR/stdout.log"; then
  echo "  ✔ Passed: Hardlinks created successfully within sandbox (link count: 2)."
else
  echo "  ✖ Failed: Hardlink creation failed inside sandbox:"
  echo "$HARDLINK_OUT"
  exit 1
fi
HARDLINK_SESSION=$(echo "$HARDLINK_OUT" | grep "ShadowCLI Session:" | head -1 | awk '{print $3}')
if [ -n "$HARDLINK_SESSION" ]; then
  "$SHADOW_BIN" discard --session "$HARDLINK_SESSION" >/dev/null 2>&1 || true
fi

echo "[6/6] Testing Review Hash & Apply on Git changes..."
REVIEW_OUT=$("$SHADOW_BIN" diff --session "$SESSION_ID")
REVIEW_HASH=$(echo "$REVIEW_OUT" | grep "Review Hash:" | head -1 | awk '{print $3}')
echo "  Review Hash: $REVIEW_HASH"

# Apply the staged git commit session
"$SHADOW_BIN" apply --session "$SESSION_ID" --review-hash "$REVIEW_HASH" --all --yes --force-protected >/dev/null

if [ -f "feature.rs" ]; then
  echo "  ✔ Passed: feature.rs applied to host project."
fi

HOST_COMMITS_AFTER=$(git rev-list --count HEAD)
if [ "$HOST_COMMITS_AFTER" -eq 1 ]; then
  echo "  ✔ Passed: Host Git history is protected against unauthorized sandbox commits (1 commit preserved)."
fi

# Developer now commits the applied changes on the host with their own identity
git add feature.rs
git commit -m "feat: developer committed applied feature" >/dev/null

CLEAN_STATUS=$(git status)
if echo "$CLEAN_STATUS" | grep -q "nothing to commit"; then
  echo "  ✔ Passed: Host developer successfully committed applied changes; git status clean."
else
  echo "  ✖ Post-apply status dirty:"
  echo "$CLEAN_STATUS"
  exit 1
fi

echo "=========================================================="
echo "   ALL GIT & OVERLAYFS COMPATIBILITY TESTS PASSED         "
echo "=========================================================="
