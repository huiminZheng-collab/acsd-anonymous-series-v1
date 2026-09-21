#!/usr/bin/env node
"use strict";

// Independent, zero-dependency verifier for the ACSD approval COSE subset.
// It intentionally shares no Python parser or signature code with cose.py.
const crypto = require("crypto");
const fs = require("fs");

class Reader {
  constructor(bytes) { this.bytes = bytes; this.offset = 0; }
  take(n) {
    if (!Number.isSafeInteger(n) || n < 0 || this.offset + n > this.bytes.length) throw new Error("CBOR_TRUNCATED");
    const out = this.bytes.subarray(this.offset, this.offset + n); this.offset += n; return out;
  }
  uint(ai) {
    if (ai < 24) return ai;
    let n;
    if (ai === 24) { n = this.take(1).readUInt8(); if (n < 24) throw new Error("CBOR_NONMINIMAL"); return n; }
    if (ai === 25) { n = this.take(2).readUInt16BE(); if (n < 256) throw new Error("CBOR_NONMINIMAL"); return n; }
    if (ai === 26) { n = this.take(4).readUInt32BE(); if (n < 65536) throw new Error("CBOR_NONMINIMAL"); return n; }
    if (ai === 27) {
      const b = this.take(8); n = Number(b.readBigUInt64BE());
      if (!Number.isSafeInteger(n) || n < 2 ** 32) throw new Error("CBOR_NONMINIMAL_OR_UNSAFE");
      return n;
    }
    throw new Error(ai === 31 ? "CBOR_INDEFINITE" : "CBOR_RESERVED_AI");
  }
  item() {
    const initial = this.take(1)[0], major = initial >> 5, ai = initial & 31;
    if (major === 0) return this.uint(ai);
    if (major === 1) return -1 - this.uint(ai);
    if (major === 2) return this.take(this.uint(ai));
    if (major === 3) {
      const raw = this.take(this.uint(ai)), text = raw.toString("utf8");
      if (!Buffer.from(text, "utf8").equals(raw)) throw new Error("CBOR_INVALID_UTF8");
      return text;
    }
    if (major === 4) return Array.from({length: this.uint(ai)}, () => this.item());
    if (major === 5) {
      const count = this.uint(ai), map = new Map();
      for (let i = 0; i < count; i++) {
        const key = this.item();
        if (!["number", "string"].includes(typeof key)) throw new Error("CBOR_MAP_KEY_UNSUPPORTED");
        const marker = `${typeof key}:${key}`;
        if (map.has(marker)) throw new Error("CBOR_DUPLICATE_MAP_KEY");
        map.set(marker, this.item());
      }
      return map;
    }
    if (major === 6) return {tag: this.uint(ai), value: this.item()};
    throw new Error("CBOR_UNSUPPORTED_MAJOR");
  }
  all() { const value = this.item(); if (this.offset !== this.bytes.length) throw new Error("CBOR_TRAILING_BYTES"); return value; }
}

function head(major, n) {
  if (n < 24) return Buffer.from([(major << 5) | n]);
  if (n < 256) return Buffer.from([(major << 5) | 24, n]);
  if (n < 65536) { const b = Buffer.alloc(3); b[0] = (major << 5) | 25; b.writeUInt16BE(n, 1); return b; }
  const b = Buffer.alloc(5); b[0] = (major << 5) | 26; b.writeUInt32BE(n, 1); return b;
}
function bstr(b) { return Buffer.concat([head(2, b.length), b]); }
function tstr(s) { const b = Buffer.from(s, "utf8"); return Buffer.concat([head(3, b.length), b]); }
function array(items) { return Buffer.concat([head(4, items.length), ...items]); }
function sigStructure(protectedBytes, payload) {
  return array([tstr("Signature1"), bstr(protectedBytes), bstr(Buffer.alloc(0)), bstr(payload)]);
}

function verify(targetPath, approvalPath, publicKeyPath, expectedKid) {
  const targetFile = fs.readFileSync(targetPath);
  const expectedPayload = targetFile.at(-1) === 10 ? targetFile.subarray(0, -1) : targetFile;
  const approval = fs.readFileSync(approvalPath);
  if (approval.length > 1024 * 1024) throw new Error("COSE_TOO_LARGE");
  const outer = new Reader(approval).all();
  if (!outer || outer.tag !== 18 || !Array.isArray(outer.value) || outer.value.length !== 4) throw new Error("COSE_SIGN1_STRUCTURE");
  const [protectedBytes, unprotected, payload, signature] = outer.value;
  if (!Buffer.isBuffer(protectedBytes) || !(unprotected instanceof Map) || !Buffer.isBuffer(payload) || !Buffer.isBuffer(signature)) throw new Error("COSE_SIGN1_STRUCTURE");
  if (!protectedBytes.equals(Buffer.from([0xa1, 0x01, 0x27]))) throw new Error("COSE_ALG_NOT_EDDSA");
  const protectedMap = new Reader(protectedBytes).all();
  if (!(protectedMap instanceof Map) || protectedMap.get("number:1") !== -8 || protectedMap.size !== 1) throw new Error("COSE_ALG_NOT_EDDSA");
  if (unprotected.size !== 0) throw new Error("COSE_UNPROTECTED_HEADER_FORBIDDEN");
  if (!payload.equals(expectedPayload)) throw new Error("COSE_PAYLOAD_MISMATCH");
  if (signature.length !== 64) throw new Error("COSE_SIGNATURE_LENGTH");
  const publicKey = crypto.createPublicKey(fs.readFileSync(publicKeyPath));
  const kid = crypto.createHash("sha256").update(publicKey.export({format: "der", type: "spki"})).digest("hex");
  if (kid !== expectedKid) throw new Error("PUBLIC_KEY_ID_MISMATCH");
  if (!crypto.verify(null, sigStructure(protectedBytes, payload), publicKey, signature)) throw new Error("APPROVAL_SIGNATURE_INVALID");
  return {valid: true, key_id: kid, payload_sha256: crypto.createHash("sha256").update(payload).digest("hex")};
}

if (require.main === module) {
  try {
    if (process.argv.length !== 6) throw new Error("usage: node verify_approval.cjs TARGET APPROVAL PUBLIC_KEY EXPECTED_KID");
    console.log(JSON.stringify(verify(...process.argv.slice(2))));
  } catch (error) {
    console.error(String(error && error.message ? error.message : error));
    process.exit(1);
  }
}

module.exports = {Reader, sigStructure, verify};
