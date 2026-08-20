#!/usr/bin/env bash
# Install the snitch-block helper and polkit policy to root-owned paths.
# Run once after `omarchy plugin add` so the demo has a single auth_admin_keep
# prompt instead of one on every block.
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

install_as_root() {
  install -d -m 0755 /usr/lib/snitch
  install -m 0755 "$HELPER_SRC" /usr/lib/snitch/snitch-block
  install -d -m 0755 /usr/share/polkit-1/actions
  install -m 0644 "$POLICY_SRC" /usr/share/polkit-1/actions/io.github.chris.snitch.policy
  echo "installed /usr/lib/snitch/snitch-block and polkit action io.github.chris.snitch.block"
}

if [[ $(id -u) -eq 0 ]]; then
  install_as_root
else
  exec pkexec bash "$0"
fi
