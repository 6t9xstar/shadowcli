#!/usr/bin/env bash
# ==============================================================================
# ShadowCLI — Claude Code End-to-End Walkthrough Demo
#
# Reproducible demonstration of:
# 1. Automated configuration via `shadow claude-setup`
# 2. Agent command execution trapped in kernel sandbox via MCP (`shadow_run`)
# 3. Invariant verification (host project remains completely unchanged)
# 4. Diff review, secret redaction, and review hash computation via `shadow_diff`
# 5. Agent self-approval prevention (rejecting `shadow_apply` via MCP)
# 6. Native tool bypass boundary demonstration (Node.js/direct writes vs sandbox)
# 7. Cryptographic review-hash bound developer terminal apply (`shadow apply`)
# 8. Transactional rollback verification (`shadow apply --rollback`)
# ==============================================================================

set -euo pipefail

# Formatting
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Prefer release binary if available, fallback to debug
if [ -f "$REPO_ROOT/target/release/shadow" ]; then
    SHADOW_BIN="$REPO_ROOT/target/release/shadow"
else
    SHADOW_BIN="$REPO_ROOT/target/debug/shadow"
fi

# Create an unpredictable, unshared temporary directory with restrictive permissions
DEMO_DIR=$(mktemp -d /tmp/shadow_claude_demo_XXXXXX)
chmod 700 "$DEMO_DIR"

# Strict safety validation: verify isolated temporary directory properties
if [ -L "$DEMO_DIR" ]; then
    echo "ERROR: Refusing to execute: workspace is a symlink ($DEMO_DIR)" >&2
    exit 1
fi

case "$DEMO_DIR" in
    /tmp/shadow_claude_demo_*) ;;
    *)
        echo "ERROR: Refusing to execute: workspace is outside /tmp/shadow_claude_demo_*" >&2
        exit 1
        ;;
esac

cleanup() {
    if [[ -n "${DEMO_DIR:-}" && "$DEMO_DIR" == /tmp/shadow_claude_demo_* && -d "$DEMO_DIR" && ! -L "$DEMO_DIR" ]]; then
        rm -rf "$DEMO_DIR"
    fi
}
trap cleanup EXIT

echo -e "${BOLD}${BLUE}======================================================================${NC}"
echo -e "${BOLD}${BLUE}       SHADOWCLI — CLAUDE CODE INTEGRATION E2E DEMO WALKTHROUGH       ${NC}"
echo -e "${BOLD}${BLUE}======================================================================${NC}"
echo -e "Binary under test: ${CYAN}$SHADOW_BIN${NC}"
echo -e "Demo workspace:    ${CYAN}$DEMO_DIR${NC}"
echo ""

# Helper to send JSON-RPC message to `shadow mcp` and capture clean response
call_mcp() {
    local request="$1"
    echo "$request" | "$SHADOW_BIN" mcp 2>/dev/null | grep '"jsonrpc"' | head -n 1
}

# ------------------------------------------------------------------------------
# STEP 1: Initialize Sample Project & Configure Claude Code
# ------------------------------------------------------------------------------
echo -e "${BOLD}[STEP 1] Setting up project & configuring Claude Code...${NC}"
mkdir -p "$DEMO_DIR/src"
cd "$DEMO_DIR"

# Baseline files
cat <<'EOF' > Cargo.toml
[package]
name = "demo-app"
version = "0.1.0"
edition = "2021"
EOF

cat <<'EOF' > src/main.rs
fn main() {
    println!("Hello from original production codebase!");
}
EOF

cat <<'EOF' > .env
DATABASE_URL=postgres://demo_user:demo_password@db.internal:5432/app
API_KEY=demo_placeholder_token_abcdef123456
EOF

echo -e "  Baseline files created: Cargo.toml, src/main.rs, .env"

# Run automated setup wizard
"$SHADOW_BIN" claude-setup --write >/dev/null

echo -e "  ${GREEN}✔${NC} Ran 'shadow claude-setup --write'"
echo -e "  Generated ${CYAN}.mcp.json${NC}:"
sed 's/^/    /' .mcp.json
echo -e "  Generated ${CYAN}.claude/settings.json${NC} (Application Gating Rule):"
sed 's/^/    /' .claude/settings.json
echo ""

# ------------------------------------------------------------------------------
# STEP 2: Agent Executes Command in Sandbox via MCP (shadow_run)
# ------------------------------------------------------------------------------
echo -e "${BOLD}[STEP 2] Simulating Claude Code executing refactoring command via MCP...${NC}"

# Claude Code sends JSON-RPC tools/call for shadow_run:
# 1. Modifies src/main.rs
# 2. Creates new module src/security.rs
# 3. Deletes .env
RUN_REQ=$(cat <<'EOF'
{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"shadow_run","arguments":{"command":"echo 'pub fn verify() -> bool { true }' > src/security.rs && echo 'mod security; fn main() { println!(\"Security verified: {}\", security::verify()); }' > src/main.rs && rm .env"}}}
EOF
)

RUN_RESP=$(call_mcp "$RUN_REQ")
SESSION_ID=$(python3 -c "import sys, json; msg = json.loads(sys.argv[1]); text = msg['result']['content'][0]['text']; print([line.split(': ')[1].strip() for line in text.splitlines() if line.startswith('Session ID:')][0])" "$RUN_RESP")

echo -e "  ${GREEN}✔${NC} MCP tool 'shadow_run' completed successfully."
echo -e "  Session ID created: ${CYAN}$SESSION_ID${NC}"
echo ""

# ------------------------------------------------------------------------------
# STEP 3: Invariant Check — Host Disk Remains Byte-for-Byte Unchanged
# ------------------------------------------------------------------------------
echo -e "${BOLD}[STEP 3] Verifying zero-mutation invariant on host filesystem...${NC}"

if grep -q "production codebase" src/main.rs; then
    echo -e "  ${GREEN}✔ [INVARIANT OK]${NC} src/main.rs on host is still ORIGINAL"
else
    echo -e "  ${RED}✖ [FAIL]${NC} src/main.rs on host was unexpectedly modified!"
    exit 1
fi

if [ -f .env ]; then
    echo -e "  ${GREEN}✔ [INVARIANT OK]${NC} .env still exists on host (deletion was staged in sandbox)"
else
    echo -e "  ${RED}✖ [FAIL]${NC} .env on host was deleted!"
    exit 1
fi

if [ ! -f src/security.rs ]; then
    echo -e "  ${GREEN}✔ [INVARIANT OK]${NC} src/security.rs does not exist on host (creation was staged in sandbox)"
else
    echo -e "  ${RED}✖ [FAIL]${NC} src/security.rs was created on host prematurely!"
    exit 1
fi
echo ""

# ------------------------------------------------------------------------------
# STEP 4: Inspect Staged Diff, Redaction, and Review Hash via shadow_diff
# ------------------------------------------------------------------------------
echo -e "${BOLD}[STEP 4] Inspecting staged diff and cryptographic review hash via MCP...${NC}"

DIFF_REQ=$(cat <<EOF
{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"shadow_diff","arguments":{"session_id":"$SESSION_ID"}}}
EOF
)

DIFF_RESP=$(call_mcp "$DIFF_REQ")
DIFF_TEXT=$(python3 -c "import sys, json; msg = json.loads(sys.argv[1]); print(msg['result']['content'][0]['text'])" "$DIFF_RESP")

REVIEW_HASH=$(echo "$DIFF_TEXT" | grep -oE "Review Hash: [a-f0-9]{64}" | head -n 1 | awk '{print $3}')

echo -e "  ${GREEN}✔${NC} Cryptographic Review Hash extracted: ${CYAN}$REVIEW_HASH${NC}"
echo -e "  Diff output (with secret redaction active):"
echo "----------------------------------------------------------------------"
echo "$DIFF_TEXT" | sed 's/^/  /'
echo "----------------------------------------------------------------------"
echo ""

# ------------------------------------------------------------------------------
# STEP 5: Agent Self-Approval Prevention
# ------------------------------------------------------------------------------
echo -e "${BOLD}[STEP 5] Testing agent self-approval prevention via MCP...${NC}"

APPLY_REQ=$(cat <<EOF
{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"shadow_apply","arguments":{"session_id":"$SESSION_ID","confirm":true}}}
EOF
)

APPLY_RESP=$(call_mcp "$APPLY_REQ")
IS_ERR=$(python3 -c "import sys, json; msg = json.loads(sys.argv[1]); print(msg['result']['isError'])" "$APPLY_RESP")
ERR_MSG=$(python3 -c "import sys, json; msg = json.loads(sys.argv[1]); print(msg['result']['content'][0]['text'])" "$APPLY_RESP")

if [ "$IS_ERR" = "True" ]; then
    echo -e "  ${GREEN}✔${NC} shadow_apply call via MCP was cleanly REJECTED by server."
    echo -e "  Server explanation:"
    echo "$ERR_MSG" | sed 's/^/    /'
else
    echo -e "  ${RED}✖ [FAIL]${NC} shadow_apply was accepted by MCP server! Violation of zero-trust!"
    exit 1
fi
echo ""

# ------------------------------------------------------------------------------
# STEP 6: Native Tool Bypass Boundary Comparison (The Critical Boundary)
# ------------------------------------------------------------------------------
echo -e "${BOLD}[STEP 6] Demonstrating Native Tool Bypass Boundary (Node.js/Direct Edits)...${NC}"
echo -e "  ${YELLOW}Notice:${NC} Claude Code's native 'Edit' and 'Write' tools use Node.js runtime calls."
echo -e "  Direct runtime filesystem writes bypass ShadowCLI completely:"

# Simulate direct unconfined runtime write
python3 -c "open('unconfined_bypass.txt', 'w').write('Direct write by unconfined process');"

if [ -f "unconfined_bypass.txt" ]; then
    echo -e "  ${YELLOW}⚠ [BOUNDARY VERIFIED]${NC} 'unconfined_bypass.txt' was written directly to host disk."
    echo -e "    - No ShadowCLI session was created"
    echo -e "    - No review hash was computed"
    echo -e "    - No human approval was required"
    echo -e "    ${BOLD}Conclusion:${NC} 'deny: [\"Bash(*)\"]' in settings.json directs Claude to use MCP,"
    echo -e "    but is an application gating rule. Full containment requires routing all work via 'shadow_run'."
    rm -f unconfined_bypass.txt
fi
echo ""

# ------------------------------------------------------------------------------
# STEP 7: Developer Applies Changes in Terminal with Review Hash Binding
# ------------------------------------------------------------------------------
echo -e "${BOLD}[STEP 7] Developer Terminal Apply with Review Hash Verification...${NC}"

# Test 7a: Apply without review hash fails
set +e
"$SHADOW_BIN" apply --session "$SESSION_ID" --all --yes >/dev/null 2>&1
NO_HASH_EXIT=$?
set -e
if [ $NO_HASH_EXIT -ne 0 ]; then
    echo -e "  ${GREEN}✔${NC} Apply without --review-hash failed closed as required."
fi

# Test 7b: Apply with altered review hash fails
set +e
"$SHADOW_BIN" apply --session "$SESSION_ID" --review-hash "0000000000000000000000000000000000000000000000000000000000000000" --all --yes >/dev/null 2>&1
BAD_HASH_EXIT=$?
set -e
if [ $BAD_HASH_EXIT -ne 0 ]; then
    echo -e "  ${GREEN}✔${NC} Apply with mismatched review hash failed closed."
fi

# Test 7c: Apply without --force-protected fails for sensitive path (.env)
set +e
"$SHADOW_BIN" apply --session "$SESSION_ID" --review-hash "$REVIEW_HASH" --all --yes >/dev/null 2>&1
PROTECTED_EXIT=$?
set -e
if [ $PROTECTED_EXIT -ne 0 ]; then
    echo -e "  ${GREEN}✔${NC} Protected path enforcement: prevented unconfirmed deletion of '.env'."
fi

# Test 7d: Apply with exact verified review hash and --force-protected succeeds
echo -e "  Executing terminal apply with valid review hash and --force-protected:"
echo -e "  ${CYAN}shadow apply --session $SESSION_ID --review-hash $REVIEW_HASH --all --yes --force-protected${NC}"
"$SHADOW_BIN" apply --session "$SESSION_ID" --review-hash "$REVIEW_HASH" --all --yes --force-protected

# Verify host state now reflects changes
if [ -f src/security.rs ] && grep -q "Security verified" src/main.rs && [ ! -f .env ]; then
    echo -e "  ${GREEN}✔${NC} Host project updated transactionally:"
    echo -e "    - src/security.rs created: $(cat src/security.rs)"
    echo -e "    - src/main.rs updated:     $(cat src/main.rs)"
    echo -e "    - .env removed"
else
    echo -e "  ${RED}✖ [FAIL]${NC} Host project state inconsistent after apply!"
    exit 1
fi
echo ""

# ------------------------------------------------------------------------------
# STEP 8: Transactional Rollback Verification
# ------------------------------------------------------------------------------
echo -e "${BOLD}[STEP 8] Transactional Rollback Verification...${NC}"
echo -e "  Executing rollback: ${CYAN}shadow apply --rollback${NC}"
"$SHADOW_BIN" apply --rollback

# Verify pre-apply baseline restored
if [ -f .env ] && grep -q "production codebase" src/main.rs && [ ! -f src/security.rs ]; then
    echo -e "  ${GREEN}✔${NC} Rollback successfully restored exact pre-apply baseline:"
    echo -e "    - src/main.rs restored to original"
    echo -e "    - src/security.rs removed"
    echo -e "    - .env restored: $(head -n 1 .env)"
else
    echo -e "  ${RED}✖ [FAIL]${NC} Rollback failed to restore original files!"
    exit 1
fi
echo ""

echo -e "${BOLD}${GREEN}======================================================================${NC}"
echo -e "${BOLD}${GREEN}       SHADOWCLI DEMO COMPLETED SUCCESSFULLY — ALL STEPS VERIFIED     ${NC}"
echo -e "${BOLD}${GREEN}======================================================================${NC}"
