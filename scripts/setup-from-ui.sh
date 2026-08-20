#!/usr/bin/env bash
# One-shot setup from the Snitch panel: packages, build, privileged helper.
set -euo pipefail
cd "$(dirname "$0")/.."

export PATH="/usr/bin:${HOME}/.cargo/bin:${PATH}"
hash -r 2>/dev/null || true

need_pkgs=()
command -v cargo >/dev/null 2>&1 || need_pkgs+=(rust)
command -v nft >/dev/null 2>&1 || need_pkgs+=(nftables)
command -v conntrack >/dev/null 2>&1 || need_pkgs+=(conntrack-tools)

if ((${#need_pkgs[@]})); then
  echo "Installing ${need_pkgs[*]}…"
  omarchy pkg add "${need_pkgs[@]}"
  hash -r 2>/dev/null || true
fi

if ! command -v cargo >/dev/null 2>&1; then
  echo "cargo is still missing after package install." >&2
  exit 1
fi

if [[ ! -x ./bin/snitchd || ! -x ./bin/snitch-block ]]; then
  ./build.sh
  # Writing bin/ reloads the plugin and restarts the polkit agent. Wait so
  # the following sudo/pkexec prompt is not dismissed.
  echo "Waiting for the shell to settle after compile…"
  sleep 3
fi

./scripts/install-privileged.sh
echo "Snitch setup finished."
