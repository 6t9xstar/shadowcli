#!/usr/bin/env bash
# ==============================================================================
# ShadowCLI — Host AppArmor Setup Script for Ubuntu 24.04+ (Noble Numbat)
# ==============================================================================
# Ubuntu 24.04 restricts unprivileged user namespaces by default via:
#   sysctl kernel.apparmor_restrict_unprivileged_userns=1
#
# This script installs an AppArmor profile that grants unprivileged userns
# capabilities specifically to ShadowCLI binaries (/usr/local/bin/shadow,
# ~/.cargo/bin/shadow, and local target builds) WITHOUT disabling AppArmor globally.
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
PROFILE_SRC="$REPO_ROOT/packaging/apparmor/shadow"
APPARMOR_DEST="/etc/apparmor.d/shadow"

if [ "$EUID" -ne 0 ]; then
  echo "Error: This script must be run as root (or via sudo)." >&2
  echo "Usage: sudo bash scripts/setup_host_apparmor.sh" >&2
  exit 1
fi

if [ ! -f "$PROFILE_SRC" ]; then
  echo "Error: Source profile not found at $PROFILE_SRC" >&2
  exit 1
fi

if [ ! -d "/etc/apparmor.d" ]; then
  echo "Warning: /etc/apparmor.d does not exist. AppArmor does not appear to be installed on this host."
  exit 0
fi

echo "==> Installing ShadowCLI AppArmor profile to $APPARMOR_DEST..."
cp "$PROFILE_SRC" "$APPARMOR_DEST"
chmod 644 "$APPARMOR_DEST"

if command -v apparmor_parser >/dev/null 2>&1; then
  echo "==> Loading profile into kernel via apparmor_parser..."
  apparmor_parser -r "$APPARMOR_DEST"
  echo "✔ Successfully loaded ShadowCLI AppArmor profile."
else
  echo "⚠ apparmor_parser not found; profile installed but not loaded."
fi

# Check status of kernel.apparmor_restrict_unprivileged_userns
if [ -f "/proc/sys/kernel/apparmor_restrict_unprivileged_userns" ]; then
  STATUS=$(cat /proc/sys/kernel/apparmor_restrict_unprivileged_userns)
  if [ "$STATUS" = "1" ]; then
    echo "✔ Ubuntu 24.04 userns restriction is active (kernel.apparmor_restrict_unprivileged_userns=1)."
    echo "  ShadowCLI is now permitted to create unprivileged user namespaces via its dedicated profile."
  fi
fi

echo "==> Setup complete! Run 'shadow doctor' to verify host readiness."
