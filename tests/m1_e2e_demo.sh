#!/bin/bash
set -euo pipefail

SHADOW_BIN="/mnt/d/WSoftware Developer/ShadowCLI/target/debug/shadow"
DEMO_DIR="/tmp/shadow_demo"

echo "=== M1 Proof of Concept Verification ==="
rm -rf "$DEMO_DIR"
mkdir -p "$DEMO_DIR/src"

echo "ORIGINAL" > "$DEMO_DIR/main.rs"
echo "SECRET_KEY=12345" > "$DEMO_DIR/.env"

echo "[1] Initial state:"
echo "  main.rs = $(cat "$DEMO_DIR/main.rs")"
echo "  .env exists = $(test -f "$DEMO_DIR/.env" && echo "YES" || echo "NO")"

echo -e "\n[2] Executing agent command in sandbox..."
"$SHADOW_BIN" run --project "$DEMO_DIR" -- sh -c 'echo MODIFIED > main.rs; rm .env; echo "feature_code" > src/feature.rs'

echo -e "\n[3] Invariant Check (Host must be UNCHANGED):"
if [ "$(cat "$DEMO_DIR/main.rs")" = "ORIGINAL" ]; then
    echo "  ✔ main.rs is still ORIGINAL on host"
else
    echo "  ✖ FAILURE: main.rs was modified on host!"
    exit 1
fi

if [ -f "$DEMO_DIR/.env" ]; then
    echo "  ✔ .env still exists on host"
else
    echo "  ✖ FAILURE: .env was deleted on host!"
    exit 1
fi

if [ ! -f "$DEMO_DIR/src/feature.rs" ]; then
    echo "  ✔ src/feature.rs does not exist on host"
else
    echo "  ✖ FAILURE: src/feature.rs leaked to host!"
    exit 1
fi

echo -e "\n[4] Inspecting Diff:"
cd "$DEMO_DIR"
"$SHADOW_BIN" diff --stat
"$SHADOW_BIN" diff

echo -e "\n[5] Discarding session..."
"$SHADOW_BIN" discard

echo "  ✔ Session discarded. Host state verified:"
echo "  main.rs = $(cat "$DEMO_DIR/main.rs")"

echo -e "\n[6] Re-running and applying changes..."
"$SHADOW_BIN" run --project "$DEMO_DIR" -- sh -c 'echo MODIFIED > main.rs; rm .env; echo "feature_code" > src/feature.rs'

echo -e "\n[7] Applying all changes to host..."
REVIEW_HASH=$("$SHADOW_BIN" diff | grep -oE "Review Hash: [a-f0-9]{64}" | head -n 1 | awk '{print $3}')
"$SHADOW_BIN" apply --all --yes --force-protected --review-hash "$REVIEW_HASH"

echo -e "\n[8] Final Host Verification:"
if [ "$(cat "$DEMO_DIR/main.rs")" = "MODIFIED" ]; then
    echo "  ✔ main.rs is now MODIFIED"
else
    echo "  ✖ FAILURE: main.rs not updated!"
    exit 1
fi

if [ ! -f "$DEMO_DIR/.env" ]; then
    echo "  ✔ .env was safely deleted"
else
    echo "  ✖ FAILURE: .env was not deleted!"
    exit 1
fi

if [ -f "$DEMO_DIR/src/feature.rs" ]; then
    echo "  ✔ src/feature.rs was created on host"
else
    echo "  ✖ FAILURE: src/feature.rs missing!"
    exit 1
fi

echo -e "\n=== M1 PROOF OF CONCEPT PASSED SUCCESSFULLY ==="
