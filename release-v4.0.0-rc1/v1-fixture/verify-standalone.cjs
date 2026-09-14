#!/usr/bin/env node
'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const project = __dirname;
const evidence = path.join(project, 'evidence');
const reads = [];
function projectFile(relativePath) {
  if (typeof relativePath !== 'string' || path.isAbsolute(relativePath)) throw new Error('artifact path must be a relative string');
  const absolute = path.resolve(project, relativePath); const relative = path.relative(project, absolute);
  if (!relative || relative === '..' || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative)) {
    throw new Error('artifact path escapes project');
  }
  return absolute;
}
function read(file, encoding) {
  const absolute = path.resolve(file); reads.push(path.relative(project, absolute).replace(/\\/g, '/'));
  return fs.readFileSync(absolute, encoding);
}
function readJson(file) { return JSON.parse(read(file, 'utf8')); }
function sha256Hex(bytes) { return crypto.createHash('sha256').update(bytes).digest('hex'); }
function equal(a, b) { return Buffer.isBuffer(a) && Buffer.isBuffer(b) && a.equals(b); }
function canonicalFile(file) { const bytes = read(file); return bytes.at(-1) === 10 ? bytes.subarray(0, bytes.length - 1) : bytes; }
function canonicalJson(value) {
  if (value === null) return 'null';
  if (typeof value === 'boolean') return value ? 'true' : 'false';
  if (typeof value === 'string') return JSON.stringify(value);
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value)) throw new Error('signed JSON permits integer numbers only');
    return String(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (value && typeof value === 'object' && Object.getPrototypeOf(value) === Object.prototype) {
    const keys = Object.keys(value);
    if (keys.some((key) => !/^[\x00-\x7f]*$/.test(key))) throw new Error('signed JSON object keys must be ASCII');
    return `{${keys.sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
  }
  throw new Error('unsupported signed JSON value');
}
function parseCanonicalJson(bytes) {
  const text = bytes.toString('utf8'); if (!Buffer.from(text, 'utf8').equals(bytes)) return null;
  try {
    const value = JSON.parse(text);
    return Buffer.from(canonicalJson(value), 'utf8').equals(bytes) ? value : null;
  } catch { return null; }
}
const WORK_ID_TOKEN = /urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/g;
function explicitWorkIdWitnesses(content) {
  const text = content.toString('utf8'); if (!Buffer.from(text, 'utf8').equals(content)) return null;
  return [...text.matchAll(WORK_ID_TOKEN)].map((match) => ({
    work_id: match[0], byte_offset: Buffer.byteLength(text.slice(0, match.index), 'utf8'), byte_length: Buffer.byteLength(match[0], 'utf8'),
  }));
}
function citationWitnessesMatch(payloadWitnesses, expectedWitnesses) {
  return Array.isArray(payloadWitnesses) && payloadWitnesses.length === expectedWitnesses.length
    && payloadWitnesses.every((witness, index) => witness && typeof witness === 'object' && !Array.isArray(witness)
      && Object.keys(witness).length === 3 && typeof witness.work_id === 'string'
      && Number.isSafeInteger(witness.byte_offset) && Number.isSafeInteger(witness.byte_length)
      && witness.work_id === expectedWitnesses[index].work_id
      && witness.byte_offset === expectedWitnesses[index].byte_offset
      && witness.byte_length === expectedWitnesses[index].byte_length);
}
function referencesMatchContent(payload, content) {
  const witnesses = explicitWorkIdWitnesses(content); if (witnesses === null) return false;
  const extracted = [...new Set(witnesses.map((item) => item.work_id))].sort();
  return Array.isArray(payload.reference_work_ids) && payload.reference_work_ids.every((item) => typeof item === 'string')
    && JSON.stringify(payload.reference_work_ids) === JSON.stringify(extracted)
    && citationWitnessesMatch(payload.citation_witnesses, witnesses);
}

class CborError extends Error {}
class Decoder {
  constructor(bytes) { this.bytes = Buffer.from(bytes); this.offset = 0; }
  take(length) {
    if (!Number.isSafeInteger(length) || length < 0 || this.offset + length > this.bytes.length) throw new CborError('truncated CBOR');
    const value = this.bytes.subarray(this.offset, this.offset + length); this.offset += length; return value;
  }
  uint(ai) {
    if (ai < 24) return ai;
    if (ai === 24) { const v = this.take(1)[0]; if (v < 24) throw new CborError('non-minimal uint8'); return v; }
    if (ai === 25) { const v = this.take(2).readUInt16BE(); if (v <= 0xff) throw new CborError('non-minimal uint16'); return v; }
    if (ai === 26) { const v = this.take(4).readUInt32BE(); if (v <= 0xffff) throw new CborError('non-minimal uint32'); return v; }
    if (ai === 27) { const v = this.take(8).readBigUInt64BE(); if (v <= 0xffffffffn || v > BigInt(Number.MAX_SAFE_INTEGER)) throw new CborError('non-minimal or unsafe uint64'); return Number(v); }
    throw new CborError(ai === 31 ? 'indefinite CBOR rejected' : 'reserved CBOR additional information');
  }
  item() {
    const initial = this.take(1)[0]; const major = initial >> 5; const ai = initial & 31;
    if (major === 0) return this.uint(ai);
    if (major === 1) return -1 - this.uint(ai);
    if (major === 2) return Buffer.from(this.take(this.uint(ai)));
    if (major === 3) { const bytes = this.take(this.uint(ai)); const text = bytes.toString('utf8'); if (!Buffer.from(text).equals(bytes)) throw new CborError('invalid UTF-8'); return text; }
    if (major === 4) return Array.from({ length: this.uint(ai) }, () => this.item());
    if (major === 5) {
      const map = new Map(); const seen = new Set(); const count = this.uint(ai);
      for (let i = 0; i < count; i += 1) {
        const key = this.item(); const id = Buffer.isBuffer(key) ? `b:${key.toString('hex')}` : `${typeof key}:${String(key)}`;
        if (seen.has(id)) throw new CborError('duplicate map key'); seen.add(id); map.set(key, this.item());
      }
      return map;
    }
    if (major === 6) return { tag: this.uint(ai), value: this.item() };
    if (major === 7 && ai === 20) return false;
    if (major === 7 && ai === 21) return true;
    if (major === 7 && ai === 22) return null;
    throw new CborError('unsupported CBOR simple/float');
  }
  all() { const value = this.item(); if (this.offset !== this.bytes.length) throw new CborError('trailing CBOR'); return value; }
}
function decode(bytes) { return new Decoder(bytes).all(); }
function encodeHead(major, length) {
  const value = BigInt(length);
  if (value < 24n) return Buffer.from([(major << 5) | Number(value)]);
  if (value <= 0xffn) return Buffer.from([(major << 5) | 24, Number(value)]);
  if (value <= 0xffffn) { const out = Buffer.alloc(3); out[0] = (major << 5) | 25; out.writeUInt16BE(Number(value), 1); return out; }
  if (value <= 0xffffffffn) { const out = Buffer.alloc(5); out[0] = (major << 5) | 26; out.writeUInt32BE(Number(value), 1); return out; }
  const out = Buffer.alloc(9); out[0] = (major << 5) | 27; out.writeBigUInt64BE(value, 1); return out;
}
function encode(value) {
  if (value === null) return Buffer.from([0xf6]);
  if (value === false) return Buffer.from([0xf4]);
  if (value === true) return Buffer.from([0xf5]);
  if (Number.isSafeInteger(value)) return value >= 0 ? encodeHead(0, value) : encodeHead(1, -1 - value);
  if (Buffer.isBuffer(value)) return Buffer.concat([encodeHead(2, value.length), value]);
  if (typeof value === 'string') { const bytes = Buffer.from(value); return Buffer.concat([encodeHead(3, bytes.length), bytes]); }
  if (Array.isArray(value)) return Buffer.concat([encodeHead(4, value.length), ...value.map(encode)]);
  throw new CborError(`cannot encode ${typeof value}`);
}
function get(map, key) { return map instanceof Map ? map.get(key) : undefined; }
function verifyCose(message, publicKey) {
  try {
    const outer = decode(message);
    if (!outer || outer.tag !== 18 || !Array.isArray(outer.value) || outer.value.length !== 4) throw new CborError('not tagged COSE_Sign1');
    const [protectedBytes, unprotected, payload, signature] = outer.value;
    if (!Buffer.isBuffer(protectedBytes) || !(unprotected instanceof Map) || unprotected.size !== 0
      || !Buffer.isBuffer(payload) || !Buffer.isBuffer(signature)) throw new CborError('invalid COSE fields');
    const protectedHeaders = protectedBytes.length ? decode(protectedBytes) : new Map();
    if (!(protectedHeaders instanceof Map) || get(protectedHeaders, 1) !== -8) throw new CborError('invalid protected headers');
    const tbs = encode(['Signature1', protectedBytes, Buffer.alloc(0), payload]);
    return { ok: crypto.verify(null, tbs, publicKey, signature), payload, protectedHeaders };
  } catch (error) { return { ok: false, error: error.message }; }
}

const requested = process.argv[2] || 'artifacts/standalone-packages/p-v1.json';
const packagePath = projectFile(requested);
const packageValue = readJson(packagePath);
const body = canonicalFile(projectFile(packageValue.release_path)); const parsedPayload = parseCanonicalJson(body); const payload = parsedPayload || {};
const content = read(projectFile(packageValue.content_path)); const authorIds = Array.isArray(payload.authors) ? payload.authors.map((item) => item.key_id) : [];
const keys = new Map((Array.isArray(payload.authors) ? payload.authors : []).map((author) => [author.key_id, { ...author, bytes: read(projectFile(author.public_key_path)) }]));
const endorsers = new Set(); let valid = true;
valid = valid && Boolean(parsedPayload) && packageValue.schema === 'acsd-v1.6.0-standalone-paper-package/v1'
  && packageValue.release_id === `urn:sha256:${sha256Hex(body)}` && packageValue.series_required_for_verification === false
  && payload.content && payload.content.path === packageValue.content_path && payload.content.sha256 === sha256Hex(content)
  && referencesMatchContent(payload, content)
  && new Set(authorIds).size === authorIds.length && packageValue.endorsements.length === authorIds.length
  && JSON.stringify(packageValue.endorsement_ids) === JSON.stringify(packageValue.endorsements.map((item) => item.id))
  && Array.isArray(payload.authors) && payload.authors.every((author, position) => author.slot === position + 1 && keys.has(author.key_id))
  && payload.ai_use && Array.isArray(payload.ai_use.human_review_key_ids)
  && new Set(payload.ai_use.human_review_key_ids).size === payload.ai_use.human_review_key_ids.length
  && payload.ai_use.human_review_key_ids.every((id) => authorIds.includes(id));
for (const endorsement of packageValue.endorsements) {
  const key = keys.get(endorsement.author_key_id); if (!key) { valid = false; continue; }
  const message = read(projectFile(endorsement.path)); const result = verifyCose(message, key.bytes);
  const claims = result.protectedHeaders ? get(result.protectedHeaders, 15) : null; const kid = result.protectedHeaders ? get(result.protectedHeaders, 4) : null;
  valid = valid && result.ok && equal(result.payload, body) && sha256Hex(message) === endorsement.sha256
    && get(result.protectedHeaders, 3) === packageValue.content_type && Buffer.isBuffer(kid) && kid.toString('hex') === key.kid_hex
    && get(claims, 1) === key.issuer && get(claims, 2) === packageValue.release_id && get(claims, 6) === payload?.issued_at
    && endorsement.release_key === packageValue.release_key;
  endorsers.add(endorsement.author_key_id);
}
valid = valid && endorsers.size === authorIds.length && authorIds.every((id) => endorsers.has(id));
let pathEscapeRejected = false; try { projectFile('../escape'); } catch { pathEscapeRejected = true; }
valid = valid && pathEscapeRejected;
const allowedReads = new Set([path.relative(project, packagePath).replace(/\\/g, '/'), packageValue.release_path, packageValue.content_path,
  ...payload.authors.map((item) => item.public_key_path), ...packageValue.endorsements.map((item) => item.path)]);
const forbiddenReads = [...new Set(reads.filter((item) => !allowedReads.has(item)))];
const output = {
  schema: 'acsd-v1.6.0-standalone-verification-results/v1', checked_at: '2026-09-09',
  verifier: 'zero-dependency Node.js strict CBOR/COSE single-package verifier',
  package: path.relative(project, packagePath).replace(/\\/g, '/'), release_key: packageValue.release_key,
  release_id: packageValue.release_id, release_valid: valid, endorsements_expected: authorIds.length,
  parent_path_escape_rejected: pathEscapeRejected,
  forbidden_or_undeclared_reads: forbiddenReads,
  standalone_without_other_papers_or_series: valid && forbiddenReads.length === 0,
  read_footprint: [...new Set(reads)].sort(),
};
fs.mkdirSync(evidence, { recursive: true });
fs.writeFileSync(path.join(evidence, 'standalone-verification-results.json'), `${JSON.stringify(output, null, 2)}\n`, 'utf8');
console.log(JSON.stringify({ release_key: output.release_key, release_valid: output.release_valid,
  endorsements_expected: output.endorsements_expected, forbidden_or_undeclared_reads: forbiddenReads.length,
  standalone_without_other_papers_or_series: output.standalone_without_other_papers_or_series }, null, 2));
if (!output.standalone_without_other_papers_or_series) process.exitCode = 1;
