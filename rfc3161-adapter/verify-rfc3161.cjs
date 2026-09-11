#!/usr/bin/env node
'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');

function usage() {
  return [
    'Usage:',
    '  node verify-rfc3161.cjs --subject-digest <64 hex> --query <request.tsq>',
    '    --response <response.tsr> --ca <pinned-root.pem> --out <evidence.json>',
    '    [--subject-type <label>] [--provider-label <label>] [--tsa-cert <cert.pem>]',
  ].join('\n');
}

function parseArgs(argv) {
  const out = {};
  for (let i = 0; i < argv.length; i += 2) {
    const key = argv[i];
    const value = argv[i + 1];
    if (!key?.startsWith('--') || value === undefined) throw new Error(usage());
    out[key.slice(2)] = value;
  }
  return out;
}

function run(openssl, args, requireSuccess = true) {
  const result = spawnSync(openssl, args, {
    encoding: 'utf8',
    windowsHide: true,
    maxBuffer: 8 * 1024 * 1024,
  });
  if (result.error) throw result.error;
  if (requireSuccess && result.status !== 0) {
    throw new Error(`OpenSSL verification failed (${result.status}).\n${result.stdout || ''}${result.stderr || ''}`);
  }
  return { exit_code: result.status, stdout: result.stdout || '', stderr: result.stderr || '' };
}

function sha256Bytes(bytes) {
  return crypto.createHash('sha256').update(bytes).digest('hex');
}

function sha256File(file) {
  return sha256Bytes(fs.readFileSync(file));
}

function stable(value) {
  if (Array.isArray(value)) return `[${value.map(stable).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stable(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

function firstMatch(text, regex) {
  const match = text.match(regex);
  return match ? match[1].trim() : null;
}

function parseImprint(text) {
  const block = firstMatch(text, /Message data:\s*\n([\s\S]*?)(?=\n\S[^\n]*:|$)/u);
  if (!block) return null;
  return block
    .split(/\r?\n/u)
    .map((line) => line.trim().split(/\s{3,}/u)[0].replace(/^[0-9a-f]{4}\s*-\s*/iu, ''))
    .flatMap((hexColumn) => hexColumn.match(/[0-9a-f]{2}/giu) || [])
    .join('')
    .toLowerCase();
}

function parseQuery(text) {
  return {
    hash_algorithm: firstMatch(text, /Hash Algorithm:\s*([^\r\n]+)/u),
    message_imprint_hex: parseImprint(text),
    policy_oid: firstMatch(text, /Policy OID:\s*([^\r\n]+)/u),
    nonce: firstMatch(text, /Nonce:\s*([^\r\n]+)/u),
    certificate_required: firstMatch(text, /Certificate required:\s*([^\r\n]+)/u),
  };
}

function parseReply(text) {
  return {
    status: firstMatch(text, /Status:\s*([^\r\n]+)/u),
    policy_oid: firstMatch(text, /Policy OID:\s*([^\r\n]+)/u),
    hash_algorithm: firstMatch(text, /Hash Algorithm:\s*([^\r\n]+)/u),
    message_imprint_hex: parseImprint(text),
    serial_number: firstMatch(text, /Serial number:\s*([^\r\n]+)/u),
    gen_time_display: firstMatch(text, /Time stamp:\s*([^\r\n]+)/u),
    accuracy_display: firstMatch(text, /Accuracy:\s*([^\r\n]+)/u),
    ordering: firstMatch(text, /Ordering:\s*([^\r\n]+)/u),
    nonce: firstMatch(text, /Nonce:\s*([^\r\n]+)/u),
    tsa_name: firstMatch(text, /TSA:\s*([^\r\n]+)/u),
  };
}

function descriptor(file, mediaType, baseDir) {
  return {
    path: path.relative(baseDir, file).replace(/\\/g, '/'),
    media_type: mediaType,
    sha256: sha256File(file),
    size_bytes: fs.statSync(file).size,
  };
}

const args = parseArgs(process.argv.slice(2));
for (const required of ['subject-digest', 'query', 'response', 'ca', 'out']) {
  if (!args[required]) throw new Error(`Missing --${required}.\n${usage()}`);
}
const subjectDigest = args['subject-digest'].toLowerCase();
if (!/^[0-9a-f]{64}$/u.test(subjectDigest)) throw new Error('--subject-digest must be a SHA-256 hex digest.');

const openssl = process.env.ACSD_OPENSSL || 'C:\\Program Files\\Git\\usr\\bin\\openssl.exe';
const queryFile = path.resolve(args.query);
const responseFile = path.resolve(args.response);
const caFile = path.resolve(args.ca);
const outputFile = path.resolve(args.out);
const tsaCertFile = args['tsa-cert'] ? path.resolve(args['tsa-cert']) : null;
for (const file of [queryFile, responseFile, caFile, ...(tsaCertFile ? [tsaCertFile] : [])]) {
  if (!fs.existsSync(file)) throw new Error(`Input file not found: ${file}`);
}
fs.mkdirSync(path.dirname(outputFile), { recursive: true });
const baseDir = path.dirname(outputFile);

const queryText = run(openssl, ['ts', '-query', '-in', queryFile, '-text']).stdout;
const replyText = run(openssl, ['ts', '-reply', '-in', responseFile, '-text']).stdout;
const query = parseQuery(queryText);
const reply = parseReply(replyText);
const verification = run(openssl, ['ts', '-verify', '-queryfile', queryFile, '-in', responseFile, '-CAfile', caFile]);

const checks = {
  openssl_full_query_verification: verification.exit_code === 0,
  query_uses_sha256: query.hash_algorithm?.toLowerCase() === 'sha256',
  reply_uses_sha256: reply.hash_algorithm?.toLowerCase() === 'sha256',
  query_imprint_matches_claimed_subject: query.message_imprint_hex === subjectDigest,
  reply_imprint_matches_claimed_subject: reply.message_imprint_hex === subjectDigest,
  nonce_is_present: Boolean(query.nonce && reply.nonce),
  nonce_matches: query.nonce === reply.nonce,
  response_is_granted: reply.status === 'Granted.',
};
const accepted = Object.values(checks).every(Boolean);
if (!accepted) throw new Error(`RFC 3161 evidence rejected: ${JSON.stringify(checks)}`);

const core = {
  schema: 'acsd-external-receipt-evidence/v1',
  profile: 'acsd-v1.3.3-rfc3161-external',
  subject: {
    type: args['subject-type'] || 'opaque-sha256-subject',
    hash_algorithm: 'sha256',
    digest: subjectDigest,
  },
  provider: {
    label_unverified: args['provider-label'] || null,
    operator_independence: 'not_established_by_cryptographic_verification',
  },
  adapter: {
    protocol: 'RFC3161',
    implementation: run(openssl, ['version']).stdout.trim(),
    raw_artifacts_are_authoritative: true,
  },
  request: descriptor(queryFile, 'application/timestamp-query', baseDir),
  response: descriptor(responseFile, 'application/timestamp-reply', baseDir),
  pinned_trust_anchor: descriptor(caFile, 'application/x-pem-file', baseDir),
  tsa_certificate: tsaCertFile ? descriptor(tsaCertFile, 'application/x-pem-file', baseDir) : null,
  parsed_untrusted_display: { query, response: reply },
  validation: {
    status: 'verified_under_supplied_pinned_anchor',
    checks,
    openssl_stdout: verification.stdout.trim(),
  },
  semantics: {
    established: 'The retained RFC 3161 response verifies for this nonce-bearing request and subject digest under the supplied trust anchor.',
    conditional: 'Independent time evidence exists only if the trust anchor was pinned independently and the TSA operator and clock were actually independent of the claimant.',
    not_established: 'Civil identity, contribution truth, consent, authorship, TSA governance, and public availability are outside this cryptographic check.',
  },
};
const canonical = stable(core);
const evidence = { ...core, canonical_utf8: canonical, digest: sha256Bytes(Buffer.from(canonical, 'utf8')) };
fs.writeFileSync(outputFile, `${JSON.stringify(evidence, null, 2)}\n`, 'utf8');
console.log(JSON.stringify({ accepted, evidence_digest: evidence.digest, output: outputFile }, null, 2));

