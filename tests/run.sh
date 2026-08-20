#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

echo "== cargo test =="
cargo test --workspace

echo "== node model tests =="
node tests/test_connection_model.js
node tests/test_geo.js

echo "== snitchd --self-test =="
if [[ -x target/debug/snitchd ]]; then
  target/debug/snitchd --self-test
elif [[ -x target/release/snitchd ]]; then
  target/release/snitchd --self-test
else
  cargo build -p snitchd
  target/debug/snitchd --self-test
fi

echo "== replay fixture parses =="
node -e '
const fs = require("fs");
const CM = require("./ConnectionModel.js");
const lines = fs.readFileSync("tests/fixtures/replay.ndjson","utf8").trim().split("\n");
let s = CM.emptyState();
for (const line of lines) s = CM.applyLine(s, line, 1);
if (s.count < 1) { console.error("replay produced empty model"); process.exit(1); }
console.log("replay connections", s.count, "apps", Object.keys(s.apps).length);
'

echo "all off-device tests passed"
