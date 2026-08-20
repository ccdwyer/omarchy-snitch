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

run_root() {
  if [[ $(id -u) -eq 0 ]]; then
    "$@"
  else
    # TTY sudo: pkexec goes through Omarchy's in-process polkit agent, which
    # restarts when the plugin directory changes (cargo writes bin/) and
    # dismisses the prompt. A visible terminal can take the password itself.
    sudo "$@"
  fi
}

echo "installing helper and policy (sudo will ask for your password)…"
run_root /usr/bin/install -d -m 0755 /usr/lib/snitch
run_root /usr/bin/install -m 0755 "$HELPER_SRC" "$HELPER_DST"
run_root /usr/bin/install -d -m 0755 /usr/share/polkit-1/actions
run_root /usr/bin/install -m 0644 "$POLICY_SRC" "$POLICY_DST"

if [[ ! -x "$HELPER_DST" ]]; then
  echo "failed to install $HELPER_DST" >&2
  exit 1
fi

echo "authorizing $HELPER_DST (this is the keep-grant for later blocks)…"
if [[ $(id -u) -eq 0 ]]; then
  "$HELPER_DST" status || true
else
  # Best-effort. If the polkit agent is bouncing, blocking still works; the
  # first block will prompt instead of this status call.
  pkexec "$HELPER_DST" status || sudo "$HELPER_DST" status || true
fi
echo "setup complete. further snitch-block calls should not prompt (auth_admin_keep)."
