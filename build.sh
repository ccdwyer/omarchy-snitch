#!/usr/bin/env bash
# Build snitchd (unprivileged) and snitch-block (privileged helper).
# On the Omarchy/Linux box this produces native binaries in ./bin.
set -euo pipefail
cd "$(dirname "$0")"

if ! command -v cargo >/dev/null 2>&1; then
  echo "cargo is missing — installing the rust package…"
  omarchy pkg add rust
  hash -r 2>/dev/null || true
  export PATH="/usr/bin:${HOME}/.cargo/bin:${PATH}"
fi
if ! command -v cargo >/dev/null 2>&1; then
  echo "cargo is still missing after installing rust." >&2
  exit 1
fi

echo "building snitchd + snitch-block (release)"
cargo build --release --workspace

mkdir -p bin
cp -f target/release/snitchd bin/snitchd
cp -f target/release/snitch-block bin/snitch-block
chmod +x bin/snitchd bin/snitch-block

SUM=bin/SHA256SUMS
if command -v sha256sum >/dev/null 2>&1; then
  (cd bin && sha256sum snitchd snitch-block > SHA256SUMS)
elif command -v shasum >/dev/null 2>&1; then
  (cd bin && shasum -a 256 snitchd snitch-block > SHA256SUMS)
else
  echo "no sha256 tool; skipping checksums" >&2
  SUM=""
fi

echo "built:"
ls -l bin/snitchd bin/snitch-block
if [[ -n "$SUM" && -f "$SUM" ]]; then
  cat "$SUM"
fi

echo
echo "optional: ./scripts/install-privileged.sh"
echo "  pkexec installs snitch-block + polkit policy (one auth_admin_keep prompt)"
