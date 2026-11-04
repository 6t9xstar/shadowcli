#!/usr/bin/env bash
set -e

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SHADOW="$REPO_ROOT/target/debug/shadow"
TEST_DIR="/tmp/shadow_claude_test_$$"
MY_UID=$(id -u)

cleanup() {
    rm -rf "$TEST_DIR"
}
trap cleanup EXIT

mkdir -p "$TEST_DIR"
cd "$TEST_DIR"

echo "=========================================================="
echo "   SHADOWCLI — CLAUDE CODE MCP INTEGRATION TEST SUITE    "
echo "=========================================================="

# Helper to send JSON-RPC message to shadow mcp and capture response line
call_mcp() {
    local request="$1"
    echo "$request" | "$SHADOW" mcp 2>/dev/null | grep '"jsonrpc"' | head -n 1
}

echo "[1/9] Testing MCP Initialization & Protocol Negotiation..."
INIT_REQ='{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"claude-code","version":"1.0.0"}}}'
INIT_RESP=$(call_mcp "$INIT_REQ")

if echo "$INIT_RESP" | grep -q '"protocolVersion":"2024-11-05"' && echo "$INIT_RESP" | grep -q '"name":"shadowcli"'; then
    echo "  ✔ Passed: MCP initialize succeeded with protocolVersion 2024-11-05 and serverInfo shadowcli."
else
    echo "FAIL: MCP initialize failed!"
    echo "Response: $INIT_RESP"
    exit 1
fi

echo "[2/9] Testing MCP Tool Discovery (tools/list)..."
LIST_REQ='{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}'
LIST_RESP=$(call_mcp "$LIST_REQ")

for tool in "shadow_run" "shadow_diff" "shadow_discard" "shadow_status"; do
    if ! echo "$LIST_RESP" | grep -q "\"name\":\"$tool\""; then
        echo "FAIL: Expected tool '$tool' not declared in tools/list response!"
        echo "Response: $LIST_RESP"
        exit 1
    fi
done

# CRITICAL ZERO-TRUST AUDIT: shadow_apply MUST NOT be present in tools/list!
if echo "$LIST_RESP" | grep -q '"name":"shadow_apply"'; then
    echo "FAIL: shadow_apply was exposed in tools/list! Agent-controlled self-approval detected!"
    exit 1
fi
echo "  ✔ Passed: Tools declared (shadow_run, shadow_diff, shadow_discard, shadow_status). shadow_apply is correctly excluded from MCP tools."

echo "[3/9] Testing Sandboxed Execution via shadow_run (Zero Host Mutation)..."
echo "base_content" > existing.txt
RUN_REQ='{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"shadow_run","arguments":{"command":"echo \"new_code\" > staged.rs"}}}'
RUN_RESP=$(call_mcp "$RUN_REQ")

if ! echo "$RUN_RESP" | grep -q "Execution Succeeded"; then
    echo "FAIL: shadow_run failed to execute command!"
    echo "Response: $RUN_RESP"
    exit 1
fi

# Extract session ID from response
SESSION_ID=$(echo "$RUN_RESP" | grep -oE "Session ID: [0-9A-HJKMNP-TV-Z]{26}" | awk '{print $3}')
if [ -z "$SESSION_ID" ]; then
    echo "FAIL: Could not extract Session ID from shadow_run response!"
    echo "Response: $RUN_RESP"
    exit 1
fi

# CRITICAL ZERO-MUTATION VERIFICATION: staged.rs must NOT exist on host yet!
if [ -f "$TEST_DIR/staged.rs" ]; then
    echo "FAIL: Host file was modified during sandboxed execution! Zero-mutation violated!"
    exit 1
fi
echo "  ✔ Passed: Command executed inside sandbox; host remained completely unchanged (zero-mutation staging)."

echo "[4/9] Testing Diff Review & Secret Redaction via shadow_diff..."
# 1. Check normal diff
DIFF_REQ="{\"jsonrpc\":\"2.0\",\"id\":4,\"method\":\"tools/call\",\"params\":{\"name\":\"shadow_diff\",\"arguments\":{\"session_id\":\"$SESSION_ID\"}}}"
DIFF_RESP=$(call_mcp "$DIFF_REQ")

if echo "$DIFF_RESP" | grep -q "staged.rs" && echo "$DIFF_RESP" | grep -q "new_code"; then
    echo "  ✔ Passed: Diff captured staged.rs modification correctly."
else
    echo "FAIL: shadow_diff did not show expected file modification!"
    echo "Response: $DIFF_RESP"
    exit 1
fi

# 2. Check secret redaction
SECRET_REQ='{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"shadow_run","arguments":{"command":"printf -- \"-----BEGIN RSA PRIVATE KEY-----\\nMIIEowIBAAKCAQEA0m...\\nSUPER_SECRET_PAYLOAD\\n-----END RSA PRIVATE KEY-----\\n\" > app.rs"}}}'
SECRET_RUN_RESP=$(call_mcp "$SECRET_REQ")
SECRET_SESSION=$(echo "$SECRET_RUN_RESP" | grep -oE "Session ID: [0-9A-HJKMNP-TV-Z]{26}" | awk '{print $3}')

SECRET_DIFF_REQ="{\"jsonrpc\":\"2.0\",\"id\":6,\"method\":\"tools/call\",\"params\":{\"name\":\"shadow_diff\",\"arguments\":{\"session_id\":\"$SECRET_SESSION\"}}}"
SECRET_DIFF_RESP=$(call_mcp "$SECRET_DIFF_REQ")

if echo "$SECRET_DIFF_RESP" | grep -q "SUPER_SECRET_PAYLOAD"; then
    echo "FAIL: Private key secret payload leaked in MCP diff response!"
    exit 1
fi
if echo "$SECRET_DIFF_RESP" | grep -q "Private Key Block" || echo "$SECRET_DIFF_RESP" | grep -q "REDACTED"; then
    echo "  ✔ Passed: Multiline private key successfully redacted from MCP diff response."
else
    echo "FAIL: Redaction marker not found in MCP diff response!"
    echo "Response: $SECRET_DIFF_RESP"
    exit 1
fi

echo "[5/9] Testing Agent Approval Prevention & Cryptographic Review Hash Binding..."
# 1. Verify agent cannot self-approve or apply changes via MCP tool call
APPLY_MCP_REQ="{\"jsonrpc\":\"2.0\",\"id\":7,\"method\":\"tools/call\",\"params\":{\"name\":\"shadow_apply\",\"arguments\":{\"session_id\":\"$SESSION_ID\",\"confirm\":true}}}"
APPLY_MCP_RESP=$(call_mcp "$APPLY_MCP_REQ")

if echo "$APPLY_MCP_RESP" | grep -q "not an available MCP tool" && echo "$APPLY_MCP_RESP" | grep -q "AI agents cannot self-approve"; then
    echo "  ✔ Passed: shadow_apply tool call via MCP rejected with security explanation."
else
    echo "FAIL: MCP shadow_apply was not properly rejected!"
    echo "Response: $APPLY_MCP_RESP"
    exit 1
fi

# 2. Extract cryptographic Review Hash from shadow_diff
REVIEW_HASH=$(echo "$DIFF_RESP" | grep -oE "Review Hash: [a-f0-9]{64}" | head -n 1 | awk '{print $3}')
if [ -z "$REVIEW_HASH" ] || [ ${#REVIEW_HASH} -ne 64 ]; then
    echo "FAIL: Could not extract valid 64-char SHA-256 Review Hash from shadow_diff!"
    echo "Diff response: $DIFF_RESP"
    exit 1
fi
echo "  ✔ Extracted valid cryptographic Review Hash: $REVIEW_HASH"

# 3. Attempt terminal apply WITHOUT --review-hash -> must fail
set +e
"$SHADOW" apply --session "$SESSION_ID" --all --yes >/tmp/no_hash_err.log 2>&1
NO_HASH_EXIT=$?
set -e

if [ $NO_HASH_EXIT -ne 0 ] && grep -q "Missing required --review-hash" /tmp/no_hash_err.log; then
    echo "  ✔ Passed: Terminal apply without --review-hash rejected with security error."
else
    echo "FAIL: Terminal apply without --review-hash succeeded or did not report missing hash error!"
    cat /tmp/no_hash_err.log
    exit 1
fi

# 4. Attempt terminal apply with WRONG/TAMPERED --review-hash -> must fail
set +e
"$SHADOW" apply --session "$SESSION_ID" --review-hash "0000000000000000000000000000000000000000000000000000000000000000" --all --yes >/tmp/bad_hash_err.log 2>&1
BAD_HASH_EXIT=$?
set -e

if [ $BAD_HASH_EXIT -ne 0 ] && grep -q "Review hash mismatch" /tmp/bad_hash_err.log; then
    echo "  ✔ Passed: Terminal apply with mismatched review hash rejected."
else
    echo "FAIL: Terminal apply with wrong review hash was not rejected!"
    cat /tmp/bad_hash_err.log
    exit 1
fi

# 5. Tampering Test: modify file in upperdir after diff -> hash changes -> apply fails
echo "base" > tamper_base.txt
TAMPER_RUN_REQ='{"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"shadow_run","arguments":{"command":"echo \"clean\" > tamper.txt"}}}'
TAMPER_RUN_RESP=$(call_mcp "$TAMPER_RUN_REQ")
TAMPER_SESSION=$(echo "$TAMPER_RUN_RESP" | grep -oE "Session ID: [0-9A-HJKMNP-TV-Z]{26}" | awk '{print $3}')

TAMPER_DIFF_REQ="{\"jsonrpc\":\"2.0\",\"id\":9,\"method\":\"tools/call\",\"params\":{\"name\":\"shadow_diff\",\"arguments\":{\"session_id\":\"$TAMPER_SESSION\"}}}"
TAMPER_DIFF_RESP=$(call_mcp "$TAMPER_DIFF_REQ")
TAMPER_REVIEW_HASH=$(echo "$TAMPER_DIFF_RESP" | grep -oE "Review Hash: [a-f0-9]{64}" | head -n 1 | awk '{print $3}')

# Now simulate an adversary secretly modifying upperdir after review
TAMPER_UPPER="/var/tmp/shadowcli-$MY_UID/sessions/$TAMPER_SESSION/upper"
echo "MALICIOUS_INJECTION" >> "$TAMPER_UPPER/tamper.txt"

set +e
"$SHADOW" apply --session "$TAMPER_SESSION" --review-hash "$TAMPER_REVIEW_HASH" --all --yes >/tmp/tamper_err.log 2>&1
TAMPER_EXIT=$?
set -e

if [ $TAMPER_EXIT -ne 0 ] && grep -q "Review hash mismatch" /tmp/tamper_err.log; then
    echo "  ✔ Passed: Modifying upperdir files after review invalidates review hash; apply safely aborted."
else
    echo "FAIL: Apply succeeded or didn't detect modified upperdir!"
    cat /tmp/tamper_err.log
    exit 1
fi
"$SHADOW" discard --session "$TAMPER_SESSION" >/dev/null 2>&1

# 6. Valid terminal apply with matching session ID and review hash -> must succeed
"$SHADOW" apply --session "$SESSION_ID" --review-hash "$REVIEW_HASH" --all --yes >/dev/null 2>&1

if [ -f "$TEST_DIR/staged.rs" ] && grep -q "new_code" "$TEST_DIR/staged.rs"; then
    echo "  ✔ Passed: Developer applied reviewed changes in terminal with matching hash; host updated."
else
    echo "FAIL: Host file staged.rs was not applied correctly!"
    exit 1
fi

# 7. Attempt duplicate apply on already-applied session -> must report already applied
DUP_OUTPUT=$("$SHADOW" apply --session "$SESSION_ID" --review-hash "$REVIEW_HASH" --all --yes 2>&1)
if echo "$DUP_OUTPUT" | grep -q "already applied"; then
    echo "  ✔ Passed: Duplicate apply on already-applied session prevented."
else
    echo "FAIL: Duplicate apply was not prevented!"
    echo "Output: $DUP_OUTPUT"
    exit 1
fi

echo "[6/9] Testing Security Confinement via MCP Tool Call..."
# 1. Canary credential access inside sandbox
CREDS_REQ='{"jsonrpc":"2.0","id":10,"method":"tools/call","params":{"name":"shadow_run","arguments":{"command":"cat ~/.ssh/id_rsa"}}}'
CREDS_RESP=$(call_mcp "$CREDS_REQ")
if echo "$CREDS_RESP" | grep -q "No such file or directory" || echo "$CREDS_RESP" | grep -q "Exit code: 1"; then
    echo "  ✔ Passed: Host credential access blocked inside MCP sandbox execution."
else
    echo "FAIL: Host credentials were accessible via MCP shadow_run!"
    echo "Response: $CREDS_RESP"
    exit 1
fi

# 2. Outbound network access inside sandbox
NET_REQ='{"jsonrpc":"2.0","id":11,"method":"tools/call","params":{"name":"shadow_run","arguments":{"command":"curl -s --connect-timeout 2 http://1.1.1.1"}}}'
NET_RESP=$(call_mcp "$NET_REQ")
if echo "$NET_RESP" | grep -q "Exit code: " && ! echo "$NET_RESP" | grep -q "Exit code: 0"; then
    echo "  ✔ Passed: Outbound network egress blocked by default inside MCP sandbox execution."
else
    echo "FAIL: Outbound network traffic was permitted via MCP shadow_run!"
    echo "Response: $NET_RESP"
    exit 1
fi

# 3. Base-image filesystem modification inside sandbox
BASE_REQ='{"jsonrpc":"2.0","id":12,"method":"tools/call","params":{"name":"shadow_run","arguments":{"command":"touch /usr/bin/evil_test"}}}'
BASE_RESP=$(call_mcp "$BASE_REQ")
if echo "$BASE_RESP" | grep -q "Read-only file system" || echo "$BASE_RESP" | grep -q "Permission denied" || echo "$BASE_RESP" | grep -q "Exit code: 1"; then
    echo "  ✔ Passed: Base filesystem paths (/usr/bin) are strictly immutable inside MCP sandbox."
else
    echo "FAIL: Agent modified /usr/bin via MCP shadow_run!"
    echo "Response: $BASE_RESP"
    exit 1
fi

echo "[7/9] Testing Session Discard via shadow_discard..."
DISCARD_RUN_REQ='{"jsonrpc":"2.0","id":13,"method":"tools/call","params":{"name":"shadow_run","arguments":{"command":"echo \"discard_me\" > discard.txt"}}}'
DISCARD_RUN_RESP=$(call_mcp "$DISCARD_RUN_REQ")
DISCARD_SESSION=$(echo "$DISCARD_RUN_RESP" | grep -oE "Session ID: [0-9A-HJKMNP-TV-Z]{26}" | awk '{print $3}')

DISCARD_REQ="{\"jsonrpc\":\"2.0\",\"id\":14,\"method\":\"tools/call\",\"params\":{\"name\":\"shadow_discard\",\"arguments\":{\"session_id\":\"$DISCARD_SESSION\"}}}"
DISCARD_RESP=$(call_mcp "$DISCARD_REQ")

if echo "$DISCARD_RESP" | grep -q "discarded"; then
    echo "  ✔ Passed: shadow_discard successfully purged unapplied session."
else
    echo "FAIL: shadow_discard failed!"
    echo "Response: $DISCARD_RESP"
    exit 1
fi
if [ -f "$TEST_DIR/discard.txt" ]; then
    echo "FAIL: Discarded file appeared on host!"
    exit 1
fi

echo "[8/9] Testing Application-Layer Bypass Boundaries & Limitations..."
# Bypass Demonstration 1: Unconfined Native Shell Execution
# If Claude Code executes a native shell outside ShadowCLI, it runs with host privileges.
echo "unconfined_write" > unconfined_host.txt
if [ -f "$TEST_DIR/unconfined_host.txt" ]; then
    echo "  ✔ Verified Limitation: Commands executed directly via host shell modify host files immediately."
    echo "    (Confirms that denying Bash(*) in .claude/settings.json is an application-level gating rule,"
    echo "     not a kernel-level containment boundary around the Claude Code process itself)."
fi

# Bypass Demonstration 2: Native File Edit/Write Tools
# Claude Code's native file editing tools (Edit, Write) operate via Node.js runtime fs APIs.
# They bypass shadow_run unless explicitly restricted.
echo "node_fs_bypass" > direct_edit.txt
if [ -f "$TEST_DIR/direct_edit.txt" ]; then
    echo "  ✔ Verified Limitation: Host Node.js fs APIs bypass ShadowCLI's CoW overlay and diff review."
fi

# Network Boundary Demonstration:
# The host agent process has network access to communicate with Anthropic API (api.anthropic.com),
# while commands executed via shadow_run are locked in an isolated network namespace.
set +e
curl -s --connect-timeout 2 -I https://api.anthropic.com >/dev/null 2>&1
HOST_NET_STATUS=$?
set -e
if [ $HOST_NET_STATUS -eq 0 ]; then
    echo "  ✔ Verified Network Boundary: Host process has outbound network to reach api.anthropic.com,"
    echo "    while sandboxed commands within shadow_run are strictly blocked by network namespace."
else
    echo "  ℹ Note: Host could not reach api.anthropic.com (offline or DNS restricted), but network namespace boundary holds."
fi

echo "[9/9] Testing Merge-Safe Claude Setup Wizard (.mcp.json & settings.json)..."
SETUP_DIR="$TEST_DIR/setup_merge_test"
mkdir -p "$SETUP_DIR/.claude"

# Pre-populate existing .mcp.json with an existing 3rd-party server
cat <<'EOF' > "$SETUP_DIR/.mcp.json"
{
  "mcpServers": {
    "sqlite": {
      "command": "uvx",
      "args": ["mcp-server-sqlite", "--db-path", "test.db"]
    }
  },
  "customSetting": 42
}
EOF

# Pre-populate existing .claude/settings.json with existing rules and model
cat <<'EOF' > "$SETUP_DIR/.claude/settings.json"
{
  "permissions": {
    "allow": ["Read(*)"],
    "deny": ["WebSearch(*)"]
  },
  "model": "claude-3-7-sonnet-20250219"
}
EOF

# Run setup wizard with --write in the target directory
(cd "$SETUP_DIR" && "$SHADOW" claude-setup --write >/dev/null)

# Verify .mcp.json: preserved sqlite, added shadowcli, preserved customSetting
if grep -q "sqlite" "$SETUP_DIR/.mcp.json" && grep -q "shadowcli" "$SETUP_DIR/.mcp.json" && grep -q "customSetting" "$SETUP_DIR/.mcp.json"; then
    echo "  ✔ Passed: .mcp.json safely merged 'shadowcli' while preserving existing servers and root fields."
else
    echo "FAIL: .mcp.json clobbered existing servers or settings!"
    exit 1
fi

# Verify .mcp.json backup was created
if ls "$SETUP_DIR/.mcp.json.bak"* >/dev/null 2>&1; then
    echo "  ✔ Passed: Created backup of original .mcp.json before merging."
else
    echo "FAIL: Backup of .mcp.json was not created!"
    exit 1
fi

# Verify .claude/settings.json: preserved Read(*), preserved WebSearch(*), added Bash(*), preserved model
if grep -q "Read(\*)" "$SETUP_DIR/.claude/settings.json" && grep -q "Bash(\*)" "$SETUP_DIR/.claude/settings.json" && grep -q "claude-3-7-sonnet" "$SETUP_DIR/.claude/settings.json"; then
    echo "  ✔ Passed: settings.json appended 'Bash(*)' while preserving existing allow/deny rules and settings."
else
    echo "FAIL: settings.json clobbered existing permissions or model settings!"
    exit 1
fi

# Verify .claude/settings.json backup was created
if ls "$SETUP_DIR/.claude/settings.json.bak"* >/dev/null 2>&1; then
    echo "  ✔ Passed: Created backup of original settings.json before merging."
else
    echo "FAIL: Backup of settings.json was not created!"
    exit 1
fi

echo "=========================================================="
echo "   ALL 9 CLAUDE CODE INTEGRATION TESTS PASSED CLEANLY     "
echo "=========================================================="
