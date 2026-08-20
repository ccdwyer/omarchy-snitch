"use strict";
const assert = require("assert");
const Geo = require("../Geo.js");

function testProject() {
  const p = Geo.project(0, 0, 360, 180);
  assert.strictEqual(p.x, 180);
  assert.strictEqual(p.y, 90);
  const us = Geo.project(-95.7, 37.1, 360, 180);
  assert.ok(us.x < 180 && us.x > 0);
  assert.ok(us.y < 90 && us.y > 0);
}

function testTimezone() {
  const ny = Geo.timezoneOrigin("America/New_York");
  assert.ok(ny.lat > 40 && ny.lat < 42);
  const st = Geo.timezoneOrigin("Europe/Stockholm");
  assert.ok(st.lon > 17 && st.lon < 19);
}

function testHit() {
  const mid = Geo.pointOnQuad(0, 0, 50, 20, 100, 0, 0.5);
  const hit = Geo.hitArc(mid.x, mid.y, 0, 0, 50, 20, 100, 0, 8);
  assert.ok(hit);
  const miss = Geo.hitArc(50, 80, 0, 0, 50, 20, 100, 0, 4);
  assert.ok(!miss);
}

testProject();
testTimezone();
testHit();
console.log("test_geo.js ok");
