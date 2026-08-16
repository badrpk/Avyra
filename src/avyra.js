"use strict";

const crypto = require("node:crypto");

function b64url(value) {
  return Buffer.from(value).toString("base64url");
}

function fromB64url(value) {
  return Buffer.from(value, "base64url").toString("utf8");
}

function stableJson(value) {
  if (Array.isArray(value)) return `[${value.map(stableJson).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.keys(value).sort().map((k) => `${JSON.stringify(k)}:${stableJson(value[k])}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

class AvyraHandoff {
  constructor({ secret, allowedOrigins = [], clock = () => Date.now() } = {}) {
    if (!secret || String(secret).length < 16) throw new TypeError("secret must be at least 16 characters");
    this.secret = String(secret);
    this.allowedOrigins = new Set(allowedOrigins.map(String));
    this.clock = clock;
    this.usedNonces = new Set();
  }

  issue({ subject, origin, capabilities = [], ttlSeconds = 300, metadata = {} }) {
    if (!subject) throw new TypeError("subject is required");
    this.#assertOrigin(origin);
    if (!Number.isInteger(ttlSeconds) || ttlSeconds <= 0 || ttlSeconds > 3600) {
      throw new RangeError("ttlSeconds must be an integer between 1 and 3600");
    }
    const now = Math.floor(this.clock() / 1000);
    const nonce = crypto.randomBytes(16).toString("hex");
    const payload = {
      v: 1,
      sub: String(subject),
      origin: String(origin),
      capabilities: [...new Set(capabilities.map(String))].sort(),
      metadata,
      iat: now,
      exp: now + ttlSeconds,
      nonce,
    };
    const body = b64url(stableJson(payload));
    const sig = this.#sign(body);
    return `${body}.${sig}`;
  }

  verify(token, { origin, requiredCapability, consume = true } = {}) {
    if (typeof token !== "string" || !token.includes(".")) throw new Error("invalid token format");
    const [body, signature, ...rest] = token.split(".");
    if (rest.length || !body || !signature) throw new Error("invalid token format");
    const expected = this.#sign(body);
    const a = Buffer.from(signature);
    const b = Buffer.from(expected);
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) throw new Error("invalid signature");

    const payload = JSON.parse(fromB64url(body));
    const now = Math.floor(this.clock() / 1000);
    if (payload.v !== 1) throw new Error("unsupported token version");
    if (now >= payload.exp) throw new Error("token expired");
    if (origin && payload.origin !== origin) throw new Error("origin mismatch");
    this.#assertOrigin(payload.origin);
    if (requiredCapability && !payload.capabilities.includes(requiredCapability)) {
      throw new Error("required capability not granted");
    }
    if (this.usedNonces.has(payload.nonce)) throw new Error("token replay detected");
    if (consume) this.usedNonces.add(payload.nonce);
    return payload;
  }

  #assertOrigin(origin) {
    if (!origin || !this.allowedOrigins.has(String(origin))) throw new Error(`origin not allowed: ${origin}`);
  }

  #sign(body) {
    return crypto.createHmac("sha256", this.secret).update(body).digest("base64url");
  }
}

module.exports = { AvyraHandoff, stableJson };
