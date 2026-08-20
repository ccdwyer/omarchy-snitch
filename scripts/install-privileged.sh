#!/usr/bin/env bash
# Install the snitch-block helper and polkit policy to root-owned paths,
# then authorize the *path-scoped helper action* so the first block is
# covered by auth_admin_keep — not a leftover `pkexec bash` grant.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
HELPER_SRC=""
for c in "$ROOT/bin/snitch-block" "$ROOT/target/release/snitch-block"; do
  if [[ -x "$c" ]]; then
    HELPER_SRC=$c
    break
  fi
done
if [[ -z "$HELPER_SRC" ]]; then
  echo "snitch-block is not built. Run ./build.sh first." >&2
  exit 1
fi

POLICY_SRC="$ROOT/polkit/io.github.chris.snitch.policy"
if [[ ! -f "$POLICY_SRC" ]]; then
  echo "missing $POLICY_SRC" >&2
  exit 1
fi

HELPER_DST=/usr/lib/snitch/snitch-block
POLICY_DST=/usr/share/polkit-1/actions/io.github.chris.snitch.policy

if [[ $(id -u) -eq 0 ]]; then
  install -d -m 0755 /usr/lib/snitch
  install -m 0755 "$HELPER_SRC" "$HELPER_DST"
  install -d -m 0755 /usr/share/polkit-1/actions
  install -m 0644 "$POLICY_SRC" "$POLICY_DST"
  echo "installed $HELPER_DST and polkit action io.github.chris.snitch.block"
  echo "next: as your user, run: pkexec $HELPER_DST status"
  echo "that caches the helper action (auth_admin_keep) so later blocks do not prompt."
  exit 0
fi

# Not root. Copy via pkexec /usr/bin/install (not bash). Then authorize the
# canonical helper itself — that is the action the policy annotates.
echo "installing helper and policy (may prompt once for /usr/bin/install)…"
pkexec /usr/bin/install -d -m 0755 /usr/lib/snitch
pkexec /usr/bin/install -m 0755 "$HELPER_SRC" "$HELPER_DST"
pkexec /usr/bin/install -d -m 0755 /usr/share/polkit-1/actions
pkexec /usr/bin/install -m 0644 "$POLICY_SRC" "$POLICY_DST"

echo "authorizing $HELPER_DST (this is the keep-grant for later blocks)…"
pkexec "$HELPER_DST" status
echo "setup complete. further snitch-block calls should not prompt (auth_admin_keep)."
