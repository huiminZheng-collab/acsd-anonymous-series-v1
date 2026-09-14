#!/usr/bin/env node
'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const project = __dirname;
function projectFile(relativePath) {
  if (typeof relativePath !== 'string' || path.isAbsolute(relativePath)) throw new Error('artifact path must be a relative string');
  const absolute = path.resolve(project, relativePath); const relative = path.relative(project, absolute);
  if (!relative || relative === '..' || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative)) {
    throw new Error('artifact path escapes project');
  }
  return absolute;
}
const artifacts = projectFile('artifacts');
const evidence = projectFile('evidence');
const index = readJson(path.join(artifacts, 'profile-index.json'));

function readJson(file) { return JSON.parse(fs.readFileSync(file, 'utf8')); }
function writeJson(file, value) { fs.writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`, 'utf8'); }
function sha256(bytes) { return crypto.createHash('sha256').update(bytes).digest(); }
function sha256Hex(bytes) { return sha256(bytes).toString('hex'); }
function equal(a, b) { return Buffer.isBuffer(a) && Buffer.isBuffer(b) && a.equals(b); }
function canonicalFile(file) { const bytes = fs.readFileSync(file); return bytes.at(-1) === 10 ? bytes.subarray(0, bytes.length - 1) : bytes; }
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
function explicitWorkIds(content) {
  const witnesses = explicitWorkIdWitnesses(content);
  return witnesses === null ? null : [...new Set(witnesses.map((item) => item.work_id))].sort();
}
function citationWitnessesMatch(payloadWitnesses, expectedWitnesses) {
  return Array.isArray(payloadWitnesses) && Array.isArray(expectedWitnesses)
    && payloadWitnesses.length === expectedWitnesses.length
    && payloadWitnesses.every((witness, index) => witness && typeof witness === 'object' && !Array.isArray(witness)
      && Object.keys(witness).length === 3 && typeof witness.work_id === 'string'
      && Number.isSafeInteger(witness.byte_offset) && Number.isSafeInteger(witness.byte_length)
      && witness.work_id === expectedWitnesses[index].work_id
      && witness.byte_offset === expectedWitnesses[index].byte_offset
      && witness.byte_length === expectedWitnesses[index].byte_length);
}
function referencesMatchContent(payload, content) {
  const witnesses = explicitWorkIdWitnesses(content);
  return Array.isArray(payload.reference_work_ids) && payload.reference_work_ids.every((item) => typeof item === 'string')
    && JSON.stringify(payload.reference_work_ids) === JSON.stringify(explicitWorkIds(content))
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
    if (ai === 31) throw new CborError('indefinite CBOR rejected');
    throw new CborError('reserved CBOR additional information');
  }
  item() {
    const initial = this.take(1)[0]; const major = initial >> 5; const ai = initial & 31;
    if (major === 0) return this.uint(ai);
    if (major === 1) return -1 - this.uint(ai);
    if (major === 2) return Buffer.from(this.take(this.uint(ai)));
    if (major === 3) { const bytes = this.take(this.uint(ai)); const text = bytes.toString('utf8'); if (!Buffer.from(text).equals(bytes)) throw new CborError('invalid UTF-8'); return text; }
    if (major === 4) return Array.from({ length: this.uint(ai) }, () => this.item());
    if (major === 5) {
      const count = this.uint(ai); const map = new Map(); const seen = new Set();
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
function parseCose(message) {
  const outer = decode(message);
  if (!outer || outer.tag !== 18 || !Array.isArray(outer.value) || outer.value.length !== 4) throw new CborError('not tagged COSE_Sign1');
  const [protectedBytes, unprotected, payload, signature] = outer.value;
  if (!Buffer.isBuffer(protectedBytes) || !(unprotected instanceof Map) || !Buffer.isBuffer(payload) || !Buffer.isBuffer(signature)) throw new CborError('invalid COSE fields');
  const protectedHeaders = protectedBytes.length ? decode(protectedBytes) : new Map();
  if (!(protectedHeaders instanceof Map)) throw new CborError('protected header is not map');
  for (const key of protectedHeaders.keys()) if (unprotected.has(key)) throw new CborError('duplicate protected/unprotected label');
  if (unprotected.has(1)) throw new CborError('alg must be protected');
  return { protectedBytes, protectedHeaders, unprotected, payload, signature };
}
function verifyCose(message, publicKey) {
  try {
    const cose = parseCose(message);
    if (get(cose.protectedHeaders, 1) !== -8) return { ok: false, error: 'unsupported algorithm', cose };
    const tbs = encode(['Signature1', cose.protectedBytes, Buffer.alloc(0), cose.payload]);
    const ok = crypto.verify(null, tbs, publicKey, cose.signature);
    return { ok, error: ok ? null : 'signature invalid', cose, payload: cose.payload };
  } catch (error) { return { ok: false, error: error.message }; }
}
function fields(cose) {
  const claims = get(cose.protectedHeaders, 15);
  return {
    alg: get(cose.protectedHeaders, 1), contentType: get(cose.protectedHeaders, 3), kid: get(cose.protectedHeaders, 4),
    issuer: claims instanceof Map ? get(claims, 1) : null, subject: claims instanceof Map ? get(claims, 2) : null,
    issuedAt: claims instanceof Map ? get(claims, 6) : null,
  };
}
function hasCycle(nodes, edges) {
  const outgoing = new Map([...nodes].map((node) => [node, []]));
  const indegree = new Map([...nodes].map((node) => [node, 0]));
  for (const [source, target] of edges) { outgoing.get(source).push(target); indegree.set(target, indegree.get(target) + 1); }
  const queue = [...nodes].filter((node) => indegree.get(node) === 0); let visited = 0;
  while (queue.length) {
    const node = queue.pop(); visited += 1;
    for (const target of outgoing.get(node)) { indegree.set(target, indegree.get(target) - 1); if (indegree.get(target) === 0) queue.push(target); }
  }
  return visited !== nodes.size;
}

const checks = [];
function check(name, passed, interpretation, observed) { checks.push({ name, passed: Boolean(passed), interpretation, ...(observed === undefined ? {} : { observed }) }); }

const publicKeys = new Map(Object.entries(index.public_keys).map(([keyId, meta]) => [keyId, { ...meta, bytes: fs.readFileSync(projectFile(meta.public_key_path)) }]));
const endorsementMeta = new Map(index.endorsements.map((item) => [item.id, item]));
const releases = new Map();
for (const [releaseKey, meta] of Object.entries(index.releases)) {
  const body = canonicalFile(projectFile(meta.release_path));
  const payload = parseCanonicalJson(body);
  const packageValue = readJson(projectFile(meta.package_path));
  const content = fs.readFileSync(projectFile(meta.content_path));
  const authorKeyIds = Array.isArray(payload?.authors) ? payload.authors.map((author) => author.key_id) : [];
  let valid = Boolean(payload) && meta.release_id === `urn:sha256:${sha256Hex(body)}`
    && packageValue.release_id === meta.release_id && packageValue.series_required_for_verification === false
    && payload.content && payload.content.sha256 === sha256Hex(content) && payload.content.path === meta.content_path
    && referencesMatchContent(payload, content)
    && new Set(authorKeyIds).size === authorKeyIds.length
    && Array.isArray(payload.authors) && payload.authors.every((author, position) => author.slot === position + 1 && publicKeys.has(author.key_id)
      && author.issuer === publicKeys.get(author.key_id).issuer && author.kid_hex === publicKeys.get(author.key_id).kid_hex
      && author.public_key_path === publicKeys.get(author.key_id).public_key_path)
    && payload.ai_use && Array.isArray(payload.ai_use.human_review_key_ids)
    && new Set(payload.ai_use.human_review_key_ids).size === payload.ai_use.human_review_key_ids.length
    && payload.ai_use.human_review_key_ids.every((keyId) => authorKeyIds.includes(keyId));
  const seenEndorsers = new Set();
  for (const endorsementId of meta.endorsement_ids) {
    const endorsement = endorsementMeta.get(endorsementId); const author = endorsement && publicKeys.get(endorsement.author_key_id);
    if (!endorsement || !author) { valid = false; continue; }
    const message = fs.readFileSync(projectFile(endorsement.path)); const result = verifyCose(message, author.bytes);
    const header = result.cose ? fields(result.cose) : {};
    valid = valid && result.ok && sha256Hex(message) === endorsement.sha256 && equal(result.payload, body)
      && result.cose.unprotected.size === 0 && header.issuer === author.issuer && header.subject === meta.release_id
      && header.contentType === index.content_types.paper && Buffer.isBuffer(header.kid) && header.kid.toString('hex') === author.kid_hex
      && header.issuedAt === payload?.issued_at && endorsement.release_key === releaseKey;
    seenEndorsers.add(endorsement.author_key_id);
  }
  valid = valid && seenEndorsers.size === authorKeyIds.length && authorKeyIds.every((keyId) => seenEndorsers.has(keyId));
  releases.set(releaseKey, { releaseKey, meta, body, payload, packageValue, content, valid });
}
check('all eight paper releases are independently verifiable without any series bundle', [...releases.values()].every((item) => item.valid),
'Each standalone package binds exact content, ordered anonymous author keys, roles, contribution/AI declarations, and every listed endorsement.');
check('every release reference manifest and signed byte witnesses equal explicit WorkID tokens in exact content', [...releases.values()].every((item) => referencesMatchContent(item.payload, item.content)),
'The fixture recognizes only explicit urn:uuid WorkID tokens and their UTF-8 byte ranges; it does not claim to parse natural-language citation semantics.');
check('all eighteen endorsement objects are used exactly by their declared release', index.endorsements.length === 18
  && index.endorsements.every((item) => releases.get(item.release_key).meta.endorsement_ids.includes(item.id)),
'No author signature is silently reused as approval of a different release payload.');

function verifySignedNegativeFixture(meta) {
  if (!meta) return { signed: false, textBound: true };
  const body = canonicalFile(projectFile(meta.payload_path));
  let payload = null; try { payload = JSON.parse(body.toString('utf8')); } catch {}
  const canonical = parseCanonicalJson(body) !== null; const content = fs.readFileSync(projectFile(meta.content_path));
  if (!payload || !Array.isArray(payload.authors)) return { signed: false, canonical, textBound: false };
  const expectedAuthors = new Set(payload.authors.map((author) => author.key_id)); const seenAuthors = new Set(); let signed = true;
  for (const endorsement of meta.endorsements) {
    const author = publicKeys.get(endorsement.author_key_id); const message = fs.readFileSync(projectFile(endorsement.path)); const result = author ? verifyCose(message, author.bytes) : { ok: false };
    const header = result.cose ? fields(result.cose) : {};
    signed = signed && Boolean(author) && result.ok && sha256Hex(message) === endorsement.sha256
      && equal(result.payload, body) && Boolean(result.cose) && result.cose.unprotected.size === 0 && header.issuer === author.issuer
      && header.subject === meta.release_id && header.contentType === index.content_types.paper
      && Buffer.isBuffer(header.kid) && header.kid.toString('hex') === author.kid_hex && header.issuedAt === payload.issued_at;
    seenAuthors.add(endorsement.author_key_id);
  }
  signed = signed && seenAuthors.size === expectedAuthors.size && [...expectedAuthors].every((keyId) => seenAuthors.has(keyId));
  return { signed, canonical, textBound: referencesMatchContent(payload, content) };
}
const referenceMismatch = verifySignedNegativeFixture(index.negative_fixtures?.reference_work_id_mismatch);
const witnessMismatch = verifySignedNegativeFixture(index.negative_fixtures?.citation_witness_offset_mismatch);
check('a correctly signed release whose reference manifest disagrees with exact content is rejected', referenceMismatch.signed && !referenceMismatch.textBound,
'Author and release signatures alone do not make a reference declaration a text witness; the explicit WorkID token binding is also required.');
check('a correctly signed release whose citation-witness byte offset disagrees with exact content is rejected', witnessMismatch.signed && !witnessMismatch.textBound,
'A signed citation witness is checked against the content bytes fixed by the release hash; a shifted offset cannot be accepted as textual support.');
const noncanonicalJson = verifySignedNegativeFixture(index.negative_fixtures?.noncanonical_json);
check('a correctly signed but noncanonical JSON release is rejected', noncanonicalJson.signed && !noncanonicalJson.canonical,
'The signed release body must have one profile-defined JSON byte representation, so duplicate fields, whitespace variants, and non-integer number spellings cannot create parser-dependent meanings.');

function parseSignedObject(meta, contentType, expectedSubject) {
  const key = publicKeys.get(meta.key_id); const message = fs.readFileSync(projectFile(meta.path));
  const body = canonicalFile(projectFile(meta.payload_path)); const signature = key ? verifyCose(message, key.bytes) : { ok: false };
  const header = signature.cose ? fields(signature.cose) : {}; const payload = parseCanonicalJson(body);
  const valid = key && signature.ok && sha256Hex(message) === meta.sha256 && equal(signature.payload, body)
    && signature.cose.unprotected.size === 0 && header.issuer === key.issuer && header.subject === expectedSubject
    && header.contentType === contentType && Buffer.isBuffer(header.kid) && header.kid.toString('hex') === key.kid_hex
    && payload && header.issuedAt === payload.issued_at;
  return { meta, key, message, body, signature, header, payload, valid };
}

const bundles = new Map();
for (const [bundleId, meta] of Object.entries(index.bundles)) {
  const expectedSubject = bundleId === 'copy-bundle' ? index.series_ids.copy : index.series_ids.original;
  bundles.set(bundleId, parseSignedObject(meta, index.content_types.series, expectedSubject));
}
const rotationMeta = { ...index.rotation, key_id: index.rotation.from_key_id };
const rotation = parseSignedObject(rotationMeta, index.content_types.rotation, index.series_ids.original);
rotation.valid = rotation.valid && rotation.payload.from_kid_hex === publicKeys.get(index.rotation.from_key_id).kid_hex
  && rotation.payload.to_kid_hex === publicKeys.get(index.rotation.to_key_id).kid_hex
  && rotation.payload.to_public_key_sha256 === sha256Hex(publicKeys.get(index.rotation.to_key_id).bytes)
  && rotation.payload.previous_bundle_sha256 === bundles.get('bundle1').meta.sha256 && rotation.payload.effective_sequence === 2;

function validateBundle(bundleId, allowRotation = true) {
  const bundle = bundles.get(bundleId); if (!bundle || !bundle.valid) return false;
  const payload = bundle.payload; const original = payload.series_id === index.series_ids.original;
  if (!Number.isSafeInteger(payload.commitment_anchor_rank) || payload.commitment_anchor_rank < 0 || !Array.isArray(payload.releases)) return false;
  if (payload.epoch === 0) {
    if (payload.sequence !== 1 || payload.previous_bundle_sha256 !== null || payload.rotation_sha256 !== null) return false;
  } else {
    if (!allowRotation || !rotation.valid || payload.epoch !== 1 || payload.sequence !== 2
      || payload.previous_bundle_sha256 !== bundles.get('bundle1').meta.sha256 || payload.rotation_sha256 !== index.rotation.sha256
      || bundle.meta.key_id !== index.rotation.to_key_id) return false;
  }
  const listed = new Set();
  const declaredWorkIds = new Set();
  for (const entry of payload.releases) {
    const release = releases.get(entry.release_key);
    if (!release || !release.valid || release.meta.release_id !== entry.release_id || JSON.stringify(release.payload.slot) !== JSON.stringify(entry.slot)) return false;
    if (!Number.isSafeInteger(entry.slot.version) || entry.slot.version < 0 || entry.slot.version >= payload.commitment_anchor_rank) return false;
    listed.add(entry.release_id);
    declaredWorkIds.add(entry.slot.work_id);
  }
  if (!Array.isArray(payload.semantic_edges)) return false;
  for (const edge of payload.semantic_edges) {
    if (!edge || edge.relation !== 'cites' || typeof edge.from_work_id !== 'string' || typeof edge.to_work_id !== 'string'
      || !declaredWorkIds.has(edge.from_work_id) || !declaredWorkIds.has(edge.to_work_id)) return false;
    const supported = payload.releases.some((entry) => {
      const source = releases.get(entry.release_key);
      return entry.slot.work_id === edge.from_work_id && source?.valid && source.payload.reference_work_ids.includes(edge.to_work_id);
    });
    if (!supported) return false;
  }
  for (const [workId, heads] of Object.entries(payload.heads)) {
    for (const releaseId of heads) {
      const release = [...releases.values()].find((item) => item.meta.release_id === releaseId);
      if (!listed.has(releaseId) || !release || release.payload.work_id !== workId) return false;
    }
  }
  return original || payload.series_id === index.series_ids.copy;
}
check('series epoch 0, authorized key rotation, epoch 1, and copy lineage signatures verify', validateBundle('bundle1')
  && rotation.valid && validateBundle('bundle-epoch1-seq2') && validateBundle('bundle-epoch1-seq2-conflict') && validateBundle('copy-bundle'),
'Series bundles contain exact standalone release IDs; the epoch-1 key is accepted only through the old-key rotation statement.');

const observations = new Map();
for (const [observationId, meta] of Object.entries(index.observations)) {
  const key = publicKeys.get('local-observer'); const message = fs.readFileSync(projectFile(meta.path)); const body = canonicalFile(projectFile(meta.payload_path));
  const signature = verifyCose(message, key.bytes); const header = signature.cose ? fields(signature.cose) : {}; const payload = parseCanonicalJson(body);
  const bundle = payload && bundles.get(payload.bundle_id);
  const valid = Boolean(payload) && signature.ok && equal(signature.payload, body) && sha256Hex(message) === meta.sha256 && bundle && bundle.meta.sha256 === payload.bundle_sha256
    && header.issuer === key.issuer && header.subject === `urn:sha256:${payload?.bundle_sha256}` && header.contentType === index.content_types.observation
    && header.issuedAt === payload?.observed_at && payload.independent_time === false;
  observations.set(observationId, { meta, message, body, signature, header, payload, valid });
}
check('both local observation statements verify while explicitly disclaiming independent time', [...observations.values()].every((item) => item.valid),
'The fixture can order two local observations but does not upgrade them to RFC3161 or external-time evidence.');

const releaseById = new Map([...releases.values()].map((item) => [item.meta.release_id, item]));
const acceptedBundleEntries = [...bundles.entries()].filter(([bundleId]) => validateBundle(bundleId));
const bundleByHash = new Map(acceptedBundleEntries.map(([id, item]) => [item.meta.sha256, id]));
const cryptoNodes = new Set([...releases.keys()].map((id) => `release:${id}`));
for (const [id] of acceptedBundleEntries) cryptoNodes.add(`bundle:${id}`);
cryptoNodes.add('rotation');
const cryptoEdges = [];
for (const release of releases.values()) if (release.payload.parent_release_id) cryptoEdges.push([`release:${release.releaseKey}`, `release:${releaseById.get(release.payload.parent_release_id).releaseKey}`]);
for (const [bundleId, bundle] of acceptedBundleEntries) {
  for (const entry of bundle.payload.releases) cryptoEdges.push([`bundle:${bundleId}`, `release:${entry.release_key}`]);
  if (bundle.payload.previous_bundle_sha256) cryptoEdges.push([`bundle:${bundleId}`, `bundle:${bundleByHash.get(bundle.payload.previous_bundle_sha256)}`]);
  if (bundle.payload.rotation_sha256) cryptoEdges.push([`bundle:${bundleId}`, 'rotation']);
}
cryptoEdges.push(['rotation', 'bundle:bundle1']);
const bundle1Edges = bundles.get('bundle1').payload.semantic_edges;
const semanticNodes = new Set(bundle1Edges.flatMap((edge) => [edge.from_work_id, edge.to_work_id]));
const semanticEdges = bundle1Edges.map((edge) => [edge.from_work_id, edge.to_work_id]);
const computedCryptoCycle = hasCycle(cryptoNodes, cryptoEdges); const computedSemanticCycle = hasCycle(semanticNodes, semanticEdges);
const model = readJson(projectFile(index.model_results_path));
check('mutual citations form a semantic cycle while cryptographic dependencies remain acyclic', computedSemanticCycle && !computedCryptoCycle
  && model.semantic_reference_graph.has_cycle && !model.cryptographic_dependency_graph.has_cycle && model.single_paper_requires_series === false,
'Stable WorkIDs break the content-hash cycle; a later bundle maps both logical works to exact independently signed releases.');
check('P-v1 and Q-v1 mutually cite WorkIDs rather than each other\'s unresolved release hash', releases.get('p-v1').payload.reference_work_ids.includes(index.work_ids.q)
  && releases.get('q-v1').payload.reference_work_ids.includes(index.work_ids.p)
  && releases.get('p-v1').payload.parent_release_id === null && releases.get('q-v1').payload.parent_release_id === null
  && releases.get('p-v1').content.includes(Buffer.from(index.work_ids.q)) && releases.get('q-v1').content.includes(Buffer.from(index.work_ids.p)),
'Both paper payloads can be finalized before the series bundle without a circular hash equation.');

function slotKey(release) { const slot = release.payload.slot; return `${slot.work_id}|${slot.version}|${slot.line}`; }
function hasInvalidCommitmentRank(bundle) {
  const payload = bundle?.payload;
  return !Number.isSafeInteger(payload?.commitment_anchor_rank) || payload.commitment_anchor_rank < 0
    || !Array.isArray(payload.releases) || payload.releases.some((entry) => !entry?.slot
      || !Number.isSafeInteger(entry.slot.version) || entry.slot.version < 0
      || entry.slot.version >= payload.commitment_anchor_rank);
}
function hasUnsupportedSemanticEdge(bundle) {
  const payload = bundle?.payload;
  if (!Array.isArray(payload?.releases) || !Array.isArray(payload.semantic_edges)) return true;
  const declaredWorkIds = new Set(payload.releases.map((entry) => entry?.slot?.work_id));
  return payload.semantic_edges.some((edge) => !edge || edge.relation !== 'cites'
    || typeof edge.from_work_id !== 'string' || typeof edge.to_work_id !== 'string'
    || !declaredWorkIds.has(edge.from_work_id) || !declaredWorkIds.has(edge.to_work_id)
    || !payload.releases.some((entry) => {
      const source = releases.get(entry.release_key);
      return entry.slot.work_id === edge.from_work_id && source?.valid && source.payload.reference_work_ids.includes(edge.to_work_id);
    }));
}
function evaluateScenario(scenario) {
  if (scenario.type === 'standalone') return releases.get(scenario.release_keys[0]).valid
    ? { verdict: 'ACCEPTED', code: 'STANDALONE_VALID' } : { verdict: 'INVALID', code: 'STANDALONE_INVALID' };
  if (scenario.type === 'bundle') return validateBundle(scenario.bundle_ids[0])
    ? { verdict: 'ACCEPTED', code: 'SERIES_VALID' } : { verdict: 'INVALID', code: 'SERIES_INVALID' };
  if (scenario.type === 'graph') return computedSemanticCycle && !computedCryptoCycle
    ? { verdict: 'ACCEPTED', code: 'SEMANTIC_CYCLE_DAG_VALID' } : { verdict: 'INVALID', code: 'GRAPH_MODEL_INVALID' };
  if (scenario.type === 'commitment_rank') {
    const bundle = bundles.get(scenario.bundle_ids[0]);
    return bundle?.valid && hasInvalidCommitmentRank(bundle) && !validateBundle(scenario.bundle_ids[0])
      ? { verdict: 'INVALID', code: 'COMMITMENT_RANK_INVALID' } : { verdict: 'INVALID', code: 'COMMITMENT_RANK_FIXTURE_INVALID' };
  }
  if (scenario.type === 'semantic_edge') {
    const bundle = bundles.get(scenario.bundle_ids[0]);
    return bundle?.valid && hasUnsupportedSemanticEdge(bundle) && !validateBundle(scenario.bundle_ids[0])
      ? { verdict: 'INVALID', code: 'SEMANTIC_EDGE_UNSUPPORTED' } : { verdict: 'INVALID', code: 'SEMANTIC_EDGE_FIXTURE_INVALID' };
  }
  if (scenario.type === 'late_amendment') {
    const oldRelease = releases.get(scenario.release_keys[0]); const amended = releases.get(scenario.release_keys[1]); const bundle = bundles.get(scenario.bundle_ids[0]);
    const oldListed = bundle.payload.releases.some((entry) => entry.release_id === oldRelease.meta.release_id);
    const newListed = bundle.payload.releases.some((entry) => entry.release_id === amended.meta.release_id);
    return oldRelease.valid && amended.valid && amended.payload.parent_release_id === oldRelease.meta.release_id
      && amended.payload.slot.version > oldRelease.payload.slot.version && amended.payload.issued_at > bundle.payload.issued_at && oldListed && !newListed
      ? { verdict: 'ACCEPTED', code: 'LATE_AMENDMENT' } : { verdict: 'INVALID', code: 'AMENDMENT_CHAIN_INVALID' };
  }
  if (scenario.type === 'substitution') {
    const release = releases.get(scenario.release_keys[0]); const bundle = bundles.get(scenario.bundle_ids[0]);
    return bundle.payload.releases.some((entry) => entry.release_id === release.meta.release_id)
      ? { verdict: 'ACCEPTED', code: 'BUNDLE_RELEASE_MATCH' } : { verdict: 'INVALID', code: 'BUNDLE_RELEASE_MISMATCH' };
  }
  if (scenario.type === 'copy') {
    const original = bundles.get(scenario.bundle_ids[0]); const copied = bundles.get(scenario.bundle_ids[1]);
    const contentMatch = releases.get('p-v1').payload.content.sha256 === releases.get('copy-p-v1').payload.content.sha256
      && releases.get('q-v1').payload.content.sha256 === releases.get('copy-q-v1').payload.content.sha256;
    const later = observations.get('copy').payload.observed_at > observations.get('original').payload.observed_at;
    return validateBundle(scenario.bundle_ids[0]) && validateBundle(scenario.bundle_ids[1]) && contentMatch && later
      && original.payload.series_id !== copied.payload.series_id && original.meta.key_id !== copied.meta.key_id
      ? { verdict: 'INDETERMINATE', code: 'CONTENT_REUSE_DIFFERENT_LINEAGE' } : { verdict: 'INVALID', code: 'COPY_COMPARISON_INVALID' };
  }
  if (scenario.type === 'paper_pair') {
    const left = releases.get(scenario.release_keys[0]); const right = releases.get(scenario.release_keys[1]);
    if (!left.valid || !right.valid) return { verdict: 'INVALID', code: 'PAPER_INVALID' };
    if (slotKey(left) === slotKey(right) && left.meta.release_id !== right.meta.release_id) return { verdict: 'EQUIVOCATION', code: 'PAPER_SLOT_CONFLICT' };
    if (left.payload.work_id === right.payload.work_id && left.payload.slot.version === right.payload.slot.version
      && left.payload.parent_release_id === right.payload.parent_release_id && left.payload.slot.line !== right.payload.slot.line) return { verdict: 'ACCEPTED', code: 'LEGITIMATE_BRANCH' };
    return { verdict: 'INDETERMINATE', code: 'UNRELATED_RELEASES' };
  }
  if (scenario.type === 'bundle_pair') {
    const left = bundles.get(scenario.bundle_ids[0]); const right = bundles.get(scenario.bundle_ids[1]);
    const sameSlot = left.payload.series_id === right.payload.series_id && left.payload.epoch === right.payload.epoch
      && left.payload.sequence === right.payload.sequence && left.payload.previous_bundle_sha256 === right.payload.previous_bundle_sha256
      && left.payload.exclusive_sequence && right.payload.exclusive_sequence;
    return validateBundle(scenario.bundle_ids[0]) && validateBundle(scenario.bundle_ids[1]) && sameSlot && left.meta.sha256 !== right.meta.sha256
      ? { verdict: 'EQUIVOCATION', code: 'SERIES_SEQUENCE_CONFLICT' } : { verdict: 'INDETERMINATE', code: 'NO_SERIES_CONFLICT' };
  }
  if (scenario.type === 'missing_rotation') return validateBundle(scenario.bundle_ids[0], false)
    ? { verdict: 'ACCEPTED', code: 'SERIES_VALID' } : { verdict: 'INVALID', code: 'UNAUTHORIZED_SERIES_KEY' };
  if (scenario.type === 'author_link') {
    const left = releases.get(scenario.release_keys[0]); const right = releases.get(scenario.release_keys[1]);
    const leftKids = new Set(left.payload.authors.map((item) => item.kid_hex)); const overlap = right.payload.authors.some((item) => leftKids.has(item.kid_hex));
    return overlap ? { verdict: 'ACCEPTED', code: 'AUTHOR_LINK_DIRECT' } : { verdict: 'INDETERMINATE', code: 'AUTHOR_LINK_UNPROVEN' };
  }
  return { verdict: 'INVALID', code: 'UNKNOWN_SCENARIO' };
}

const scenarios = readJson(projectFile(index.scenarios_path)).scenarios;
const scenarioResults = [];
for (const scenario of scenarios) {
  const result = evaluateScenario(scenario); const passed = result.verdict === scenario.expected && result.code === scenario.expected_code;
  scenarioResults.push({ id: scenario.id, expected: scenario.expected, actual: result.verdict, expected_code: scenario.expected_code, actual_code: result.code, passed });
  check(`${scenario.id} returns ${scenario.expected}/${scenario.expected_code}`, passed,
  'The verifier distinguishes standalone validity, series continuity, later amendments, content reuse, legitimate branches, exact-slot conflicts, and missing identity links.');
}

const canonicalCorpus = readJson(projectFile('canonical-json-corpus.json'));
const nodeCanonicalCorpusResults = Array.isArray(canonicalCorpus.cases) ? canonicalCorpus.cases.map((testCase) => ({
  id: testCase.id, expected_canonical: testCase.expected_canonical,
  accepted: typeof testCase.body === 'string' && parseCanonicalJson(Buffer.from(testCase.body, 'utf8')) !== null,
})).map((result) => ({ ...result, passed: result.accepted === result.expected_canonical })) : [];
check('canonical JSON corpus has the expected Node acceptance decisions',
  canonicalCorpus.schema === 'acsd-v1.6.0-canonical-json-corpus/v1' && nodeCanonicalCorpusResults.length > 0
  && nodeCanonicalCorpusResults.every((result) => result.passed),
'The corpus exercises key order, duplicate fields, whitespace, decimal and unsafe integers, UTF-8 values, and non-ASCII keys against the signed-object profile.');
const pythonReference = readJson(path.join(evidence, 'python-reference-results.json'));
let pathEscapeRejected = false; try { projectFile('../escape'); } catch { pathEscapeRejected = true; }
check('artifact path resolver rejects parent-directory escapes', pathEscapeRejected,
'All profile-referenced paths must be relative descendants of the artifact project; a signed declaration cannot make the verifier read a parent path.');
check('Python and Node agree on every canonical JSON corpus decision',
  JSON.stringify(pythonReference.canonical_json_corpus) === JSON.stringify(nodeCanonicalCorpusResults),
'Independent runtimes must make the same accept/reject decision before a signed body is interpreted as a release, series, rotation, or observation object.');
check('independent Node verification agrees with the Python generation/reference path', pythonReference.all_standalone_releases_valid
  && pythonReference.all_series_objects_valid && pythonReference.all_observations_valid
  && pythonReference.all_valid_bundle_commitment_ranks_valid && pythonReference.signed_rank_too_low_bundle_rejected
  && pythonReference.all_release_reference_manifests_match_content && pythonReference.signed_reference_work_id_mismatch_rejected
  && pythonReference.signed_citation_witness_offset_mismatch_rejected
  && pythonReference.signed_noncanonical_json_rejected
  && pythonReference.canonical_json_corpus_all_match_expected
  && pythonReference.all_valid_bundle_semantic_edges_supported && pythonReference.signed_unsupported_semantic_edge_rejected
  && pythonReference.semantic_graph_cyclic && pythonReference.cryptographic_graph_acyclic,
'Separate implementations agree on all signatures and on the semantic-cycle/cryptographic-DAG separation.');
const provenance = readJson(projectFile('source-provenance.json'));
check('pinned third-party archives match the audited source-provenance hashes', provenance.software.length === 2
  && provenance.software.every((item) => fs.existsSync(projectFile(item.archive))
    && sha256Hex(fs.readFileSync(projectFile(item.archive))) === item.sha256),
'The offline build consumes only the two named, hash-pinned archives recorded in the source ledger.');
const sourceStatuses = new Map(provenance.standards_and_prior_work.map((item) => [item.name, item.status]));
check('prior work is classified by source status instead of being presented as one undifferentiated novelty claim',
  sourceStatuses.get('PROV-DM: The PROV Data Model') === 'W3C Recommendation'
  && sourceStatuses.get('SWHID Specification v1.2 Core Identifiers') === 'public specification'
  && sourceStatuses.get('Trusty URIs: Verifiable, Immutable, and Permanent Digital Artifacts for Linked Data') === 'primary research paper'
  && sourceStatuses.get('RFC 9052 — CBOR Object Signing and Encryption') === 'IETF Internet Standard'
  && sourceStatuses.get('RFC 9943 — SCITT Architecture') === 'IETF Proposed Standard'
  && provenance.scope_limit.includes('substantial prior work') && provenance.scope_limit.includes('application-specific executable profile'),
'The novelty boundary is the anonymous-scholarly-series profile and its executable counterexamples, not provenance, intrinsic identifiers, or signed statements themselves.');
check('scope boundaries remain explicit', index.external_time_used === false && index.external_transparency_service_used === false
  && index.author_natural_identity_established === false && index.cross_paper_author_identity_link_established === false
  && index.originality_truth_established === false && index.legal_non_repudiation_established === false,
'The series layer adds lineage evidence but does not create independent time, natural-person identity, cross-paper identity links, originality truth, or legal non-repudiation.');

const failures = checks.filter((item) => !item.passed);
const output = {
  schema: 'acsd-v1.6.0-independent-series-results/v1', checked_at: '2026-09-09',
  verifier: 'zero-dependency Node.js strict CBOR/COSE, standalone-paper, series-DAG, rotation, observation, and closed-verdict verifier',
  checks: { expected: checks.length, passed: checks.length - failures.length, failed: failures.length, failures: failures.map((item) => item.name) },
  profile_result: failures.length ? 'INVALID' : 'VALID', cases: checks, scenario_results: scenarioResults,
  claims: {
    standalone_paper_requires_series: false,
    mutual_semantic_citation_requires_cyclic_hash_dependencies: false,
    stable_work_ids_plus_later_bundle_preserve_crypto_dag: failures.length === 0,
    signed_bundle_with_low_commitment_rank_accepted: false,
    signed_bundle_with_unsupported_semantic_edge_accepted: false,
    signed_reference_work_id_mismatch_accepted: false,
    signed_citation_witness_offset_mismatch_accepted: false,
    signed_noncanonical_json_accepted: false,
    legitimate_parallel_branch_is_equivocation: false,
    same_exclusive_slot_double_release_is_equivocation: true,
    copy_and_resign_proves_originality: false,
    local_observation_establishes_independent_time: false,
    cross_paper_author_identity_established: false,
  },
};
fs.mkdirSync(evidence, { recursive: true }); writeJson(path.join(evidence, 'independent-verification-results.json'), output);
console.log(JSON.stringify({ checks: output.checks, profile_result: output.profile_result, scenario_results: scenarioResults, claims: output.claims }, null, 2));
if (failures.length) process.exitCode = 1;
