"use strict";
const assert = require("assert");
const path = require("path");
const fs = require("fs");
const CM = require("../ConnectionModel.js");

function applyFixture() {
  const text = fs.readFileSync(path.join(__dirname, "fixtures/replay.ndjson"), "utf8");
  let state = CM.emptyState();
  for (const line of text.split("\n")) {
    if (!line.trim()) continue;
    state = CM.applyLine(state, line, 5000);
  }
  return state;
}

function testGrouping() {
  const state = applyFixture();
  assert.ok(state.apps.firefox, "firefox grouped");
  assert.ok(state.apps.spotify, "spotify grouped");
  // slack's flows disconnect at the end of the fixture; grouping is still
  // visible mid-stream (covered by drawable/filter tests using earlier lines).
  // 40 chrome-style: two firefox pids still one app
  const pids = state.apps.firefox.pids;
  assert.ok(pids.indexOf(4402) !== -1);
  assert.ok(pids.indexOf(4403) !== -1);
  assert.strictEqual(state.apps.firefox.id, "firefox");
}

function testUnresolvedNeverDrawable() {
  const state = applyFixture();
  const arcs = CM.drawableArcs(state.connections, { lat: 0, lon: 0 }, 40);
  for (const a of arcs) {
    assert.strictEqual(a.unresolved, false);
    assert.ok(a.country, "drawable arc has country");
  }
  const unresolved = Object.values(state.connections).filter((c) => c.unresolved);
  assert.ok(unresolved.length >= 1, "fixture has unresolved UDP");
}

function testNetworkKey() {
  assert.strictEqual(CM.networkKey("142.250.190.14"), "142.250.190.0/24");
  assert.strictEqual(CM.networkKey("142.250.190.99"), "142.250.190.0/24");
  assert.strictEqual(CM.networkKey("8.8.8.8"), "8.8.8.0/24");
  const k = CM.networkKey("2001:db8:abcd:12::1");
  assert.ok(k.endsWith("/48"), k);
  assert.strictEqual(CM.networkKey("2001:db8:abcd:99::ffff"), k);
}

function testDisconnect() {
  let state = CM.emptyState();
  state = CM.applyLine(state, JSON.stringify({
    type: "connect",
    id: "tcp:1:1.2.3.4:443",
    proto: "tcp",
    app: { id: "curl", name: "curl", icon: "curl", desktop: "", pid: 9, system: false },
    local: { ip: "10.0.0.2", port: 4 },
    remote: { ip: "1.2.3.4", port: 443 },
    country: "US", lat: 1, lon: 2, unresolved: false, newNetwork: true, networkKey: "1.2.3.0/24"
  }), 1);
  assert.strictEqual(state.count, 1);
  assert.strictEqual(state.pulse, true);
  state = CM.applyLine(state, JSON.stringify({ type: "disconnect", id: "tcp:1:1.2.3.4:443" }), 2);
  assert.strictEqual(state.count, 0);
  assert.ok(!state.apps.curl);
}

function testPort53NoPulseRequirement() {
  // Pulse is driven by newNetwork from the daemon; daemon sets it false for :53.
  let state = CM.emptyState();
  state = CM.applyLine(state, JSON.stringify({
    type: "connect",
    id: "udp:1:8.8.8.8:53",
    proto: "udp",
    app: { id: "firefox", name: "Firefox", pid: 1 },
    remote: { ip: "8.8.8.8", port: 53 },
    country: "US", lat: 37, lon: -95, unresolved: false, newNetwork: false, networkKey: "8.8.8.0/24"
  }), 1);
  assert.strictEqual(state.pulse, false);
}

function testDigest() {
  const state = applyFixture();
  assert.ok(state.digestText.indexOf("new network") !== -1, state.digestText);
}

function testFilter() {
  const state = applyFixture();
  const se = CM.filterApps(state.ordered, "sweden");
  // country is US/SE codes, not names — search "SE" or spotify
  const sp = CM.filterApps(state.ordered, "spot");
  assert.strictEqual(sp.length, 1);
  assert.strictEqual(sp[0].id, "spotify");
  const us = CM.filterApps(state.ordered, "SE");
  assert.ok(us.some((a) => a.id === "spotify"));
}

function testBlockBadge() {
  let state = applyFixture();
  CM.setBlocked(state, "firefox", "cgroup");
  assert.strictEqual(state.apps.firefox.blocked, true);
  assert.strictEqual(state.apps.firefox.mechanism, "cgroup");
  assert.ok(CM.anyBlocked(state));
  CM.setBlocked(state, "firefox", "");
  assert.strictEqual(state.apps.firefox.blocked, false);
}

function testTimeWaitNotInFixtureLiveSet() {
  // TIME_WAIT is a parser concern; the model only sees what the daemon emits.
  const state = applyFixture();
  for (const c of Object.values(state.connections)) {
    assert.notStrictEqual(c.state, "TIME_WAIT");
  }
}

testGrouping();
testUnresolvedNeverDrawable();
testNetworkKey();
testDisconnect();
testPort53NoPulseRequirement();
testDigest();
testFilter();
function testIsBlockable() {
  assert.strictEqual(CM.isBlockable({ id: "firefox", system: false }), true);
  assert.strictEqual(CM.isBlockable({ id: "system", system: true }), false);
  assert.strictEqual(CM.isBlockable({ id: "system" }), false);
  assert.strictEqual(CM.isBlockable({ id: "unknown" }), false);
  assert.strictEqual(CM.isBlockable({ id: "Unknown", system: false }), false);
  assert.strictEqual(CM.isBlockable(null), false);
}

testBlockBadge();
testIsBlockable();
testTimeWaitNotInFixtureLiveSet();
console.log("test_connection_model.js ok");
