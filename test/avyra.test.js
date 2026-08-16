"use strict";

const assert = require("node:assert/strict");
const test = require("node:test");

const { AvyraHandoff, stableJson } = require("../src/avyra");

test("stableJson is deterministic for object key order", () => {
  assert.equal(stableJson({ b: 2, a: 1 }), stableJson({ a: 1, b: 2 }));
});

test("issued token verifies for allowed origin and capability", () => {
  let now = 1_000_000;
  const handoff = new AvyraHandoff({
    secret: "1234567890abcdef",
    allowedOrigins: ["https://example.test"],
    clock: () => now,
  });
  const token = handoff.issue({
    subject: "user-1",
    origin: "https://example.test",
    capabilities: ["profile:read"],
  });
  const payload = handoff.verify(token, {
    origin: "https://example.test",
    requiredCapability: "profile:read",
  });
  assert.equal(payload.sub, "user-1");
});

test("replay is rejected after consumption", () => {
  const handoff = new AvyraHandoff({
    secret: "1234567890abcdef",
    allowedOrigins: ["https://example.test"],
    clock: () => 1_000_000,
  });
  const token = handoff.issue({ subject: "u", origin: "https://example.test" });
  handoff.verify(token);
  assert.throws(() => handoff.verify(token), /replay/);
});

test("origin mismatch is rejected", () => {
  const handoff = new AvyraHandoff({
    secret: "1234567890abcdef",
    allowedOrigins: ["https://a.test", "https://b.test"],
    clock: () => 1_000_000,
  });
  const token = handoff.issue({ subject: "u", origin: "https://a.test" });
  assert.throws(() => handoff.verify(token, { origin: "https://b.test" }), /origin mismatch/);
});

test("missing capability is rejected", () => {
  const handoff = new AvyraHandoff({
    secret: "1234567890abcdef",
    allowedOrigins: ["https://a.test"],
    clock: () => 1_000_000,
  });
  const token = handoff.issue({ subject: "u", origin: "https://a.test", capabilities: ["read"] });
  assert.throws(() => handoff.verify(token, { requiredCapability: "write" }), /not granted/);
});

test("expired token is rejected", () => {
  let now = 1_000_000;
  const handoff = new AvyraHandoff({
    secret: "1234567890abcdef",
    allowedOrigins: ["https://a.test"],
    clock: () => now,
  });
  const token = handoff.issue({ subject: "u", origin: "https://a.test", ttlSeconds: 1 });
  now += 2_000;
  assert.throws(() => handoff.verify(token), /expired/);
});

test("tampered token is rejected", () => {
  const handoff = new AvyraHandoff({
    secret: "1234567890abcdef",
    allowedOrigins: ["https://a.test"],
    clock: () => 1_000_000,
  });
  const token = handoff.issue({ subject: "u", origin: "https://a.test" });
  const [body, signature] = token.split(".");
  const tampered = `${body.slice(0, -1)}A.${signature}`;
  assert.throws(() => handoff.verify(tampered), /invalid signature|Unexpected token|JSON/);
});
