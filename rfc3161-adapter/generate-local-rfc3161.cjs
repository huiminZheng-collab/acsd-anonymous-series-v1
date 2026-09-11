#!/usr/bin/env node
'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');

const root = __dirname;
const openssl = process.env.ACSD_OPENSSL || 'C:\\Program Files\\Git\\usr\\bin\\openssl.exe';
const enrollmentPath = path.resolve(root, '..', 'acsd-key-enrollment-generator-js', 'artifacts', 'predeposit-enrollment.json');
const artifacts = path.join(root, 'artifacts');
const adversarial = path.join(root, 'adversarial');
const privateDir = path.join(root, 'private-test-keys');

for (const dir of [artifacts, adversarial, privateDir]) fs.mkdirSync(dir, { recursive: true });

function rel(p) {
  return path.relative(root, p).replace(/\\/g, '/');
}

function q(arg) {
  return /[\s"]/u.test(arg) ? JSON.stringify(arg) : arg;
}

function run(args, options = {}) {
  const result = spawnSync(openssl, args, {
    cwd: root,
    encoding: 'utf8',
    windowsHide: true,
    maxBuffer: 8 * 1024 * 1024,
  });
  if (result.error) throw result.error;
  if (options.requireSuccess !== false && result.status !== 0) {
    throw new Error(`OpenSSL failed (${result.status}): openssl ${args.map(q).join(' ')}\n${result.stdout || ''}${result.stderr || ''}`);
  }
  return {
    exit_code: result.status,
    stdout: result.stdout || '',
    stderr: result.stderr || '',
  };
}

function writeText(p, value) {
  fs.writeFileSync(p, value, 'utf8');
}

function sha256Bytes(bytes) {
  return crypto.createHash('sha256').update(bytes).digest('hex');
}

function sha256File(p) {
  return sha256Bytes(fs.readFileSync(p));
}

function sha256Text(value) {
  return sha256Bytes(Buffer.from(value, 'utf8'));
}

function stable(value) {
  if (Array.isArray(value)) return `[${value.map(stable).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map((k) => `${JSON.stringify(k)}:${stable(value[k])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

function artifactDescriptor(p, mediaType) {
  return {
    path: rel(p),
    media_type: mediaType,
    sha256: sha256File(p),
    size_bytes: fs.statSync(p).size,
  };
}

function firstMatch(text, regex) {
  const match = text.match(regex);
  return match ? match[1].trim() : null;
}

function parseTimestampReply(text) {
  const messageBlock = firstMatch(text, /Message data:\s*\n([\s\S]*?)(?=\n\S[^\n]*:|$)/u);
  const messageImprint = messageBlock
    ? messageBlock
      .split(/\r?\n/u)
      .map((line) => line.trim().split(/\s{3,}/u)[0].replace(/^[0-9a-f]{4}\s*-\s*/iu, ''))
      .flatMap((hexColumn) => hexColumn.match(/[0-9a-f]{2}/giu) || [])
      .join('')
      .toLowerCase()
    : null;
  return {
    status: firstMatch(text, /Status:\s*([^\r\n]+)/u),
    policy_oid: firstMatch(text, /Policy OID:\s*([^\r\n]+)/u),
    hash_algorithm: firstMatch(text, /Hash Algorithm:\s*([^\r\n]+)/u),
    message_imprint_hex: messageImprint,
    serial_number: firstMatch(text, /Serial number:\s*([^\r\n]+)/u),
    gen_time_display: firstMatch(text, /Time stamp:\s*([^\r\n]+)/u),
    accuracy_display: firstMatch(text, /Accuracy:\s*([^\r\n]+)/u),
    ordering: firstMatch(text, /Ordering:\s*([^\r\n]+)/u),
    nonce: firstMatch(text, /Nonce:\s*([^\r\n]+)/u),
    tsa_name: firstMatch(text, /TSA:\s*([^\r\n]+)/u),
  };
}

function probe(name, args, expectedExitCode, interpretation) {
  const result = run(args, { requireSuccess: false });
  return {
    name,
    expected_exit_code: expectedExitCode,
    observed_exit_code: result.exit_code,
    passed: result.exit_code === expectedExitCode,
    interpretation,
    stdout_tail: result.stdout.trim().split(/\r?\n/u).slice(-4),
    stderr_tail: result.stderr.trim().split(/\r?\n/u).slice(-6),
  };
}

function ensureRootAndTsa(prefix, rootCert, tsaCert, rootKey, tsaKey, tsaCsr) {
  if (!fs.existsSync(rootKey) || !fs.existsSync(rootCert)) {
    run([
      'req', '-x509', '-newkey', 'rsa:2048', '-sha256', '-nodes',
      '-keyout', rel(rootKey), '-out', rel(rootCert), '-days', '30',
      '-subj', `/CN=ACSD v1.3.3 ${prefix} TEST ROOT/OU=NOT FOR PRODUCTION`,
      '-addext', 'basicConstraints=critical,CA:TRUE',
      '-addext', 'keyUsage=critical,keyCertSign,cRLSign',
    ]);
  }
  if (!fs.existsSync(tsaKey) || !fs.existsSync(tsaCert)) {
    run([
      'req', '-new', '-newkey', 'rsa:2048', '-sha256', '-nodes',
      '-keyout', rel(tsaKey), '-out', rel(tsaCsr),
      '-subj', `/CN=ACSD v1.3.3 ${prefix} TEST TSA/OU=NOT FOR PRODUCTION`,
    ]);
    run([
      'x509', '-req', '-in', rel(tsaCsr), '-CA', rel(rootCert), '-CAkey', rel(rootKey),
      '-CAcreateserial', '-out', rel(tsaCert), '-days', '30', '-sha256',
      '-extfile', 'config/tsa-cert-ext.cnf', '-extensions', 'tsa_cert',
    ]);
  }
}

if (!fs.existsSync(openssl)) throw new Error(`OpenSSL not found: ${openssl}`);
if (!fs.existsSync(enrollmentPath)) throw new Error(`Enrollment artifact not found: ${enrollmentPath}`);

const enrollment = JSON.parse(fs.readFileSync(enrollmentPath, 'utf8'));
const subjectDigest = enrollment?.enrollment_core?.digest;
const canonical = enrollment?.enrollment_core?.canonical_utf8;
if (!/^[0-9a-f]{64}$/u.test(subjectDigest || '')) throw new Error('Enrollment core SHA-256 digest is missing or malformed.');
if (sha256Text(canonical) !== subjectDigest) throw new Error('Enrollment core canonical_utf8 does not match its declared digest.');

const rootKey = path.join(privateDir, 'tsa-root-key.pem');
const tsaKey = path.join(privateDir, 'tsa-key.pem');
const tsaCsr = path.join(privateDir, 'tsa.csr');
const rootCert = path.join(artifacts, 'tsa-root.pem');
const tsaCert = path.join(artifacts, 'tsa-cert.pem');
ensureRootAndTsa('HONEST', rootCert, tsaCert, rootKey, tsaKey, tsaCsr);

const serialFile = path.join(privateDir, 'tsa-serial');
if (!fs.existsSync(serialFile)) writeText(serialFile, '01\n');

const digestFile = path.join(artifacts, 'enrollment-core.sha256.txt');
const queryFile = path.join(artifacts, 'enrollment.tsq');
const responseFile = path.join(artifacts, 'enrollment.tsr');
const tokenFile = path.join(artifacts, 'enrollment-token.der');
const tstInfoFile = path.join(artifacts, 'enrollment-tstinfo.der');
const replyTextFile = path.join(artifacts, 'enrollment-timestamp.txt');
writeText(digestFile, `${subjectDigest}\n`);

run(['ts', '-query', '-digest', subjectDigest, '-sha256', '-cert', '-out', rel(queryFile)]);
run(['ts', '-reply', '-queryfile', rel(queryFile), '-config', 'config/openssl-tsa.cnf', '-section', 'tsa_config1', '-out', rel(responseFile)]);
run(['ts', '-reply', '-in', rel(responseFile), '-token_out', '-out', rel(tokenFile)]);
const replyText = run(['ts', '-reply', '-in', rel(responseFile), '-text']).stdout;
writeText(replyTextFile, replyText);
const parsed = parseTimestampReply(replyText);

const version = run(['version', '-a']).stdout.trim();
const tsaFingerprint = run(['x509', '-in', rel(tsaCert), '-noout', '-fingerprint', '-sha256']).stdout.trim();
const rootFingerprint = run(['x509', '-in', rel(rootCert), '-noout', '-fingerprint', '-sha256']).stdout.trim();
const tsaPurpose = probe(
  'tsa_certificate_has_timestamp_signing_purpose',
  ['verify', '-purpose', 'timestampsign', '-CAfile', rel(rootCert), rel(tsaCert)],
  0,
  'The signer certificate chains to the pinned root and has the RFC 3161 timestamp-signing purpose.',
);

const wrongDigest = `${subjectDigest[0] === '0' ? '1' : '0'}${subjectDigest.slice(1)}`;
const secondQuery = path.join(adversarial, 'same-digest-different-nonce.tsq');
run(['ts', '-query', '-digest', subjectDigest, '-sha256', '-cert', '-out', rel(secondQuery)]);

const tamperedResponse = path.join(adversarial, 'tampered-response.tsr');
const tampered = Buffer.from(fs.readFileSync(responseFile));
tampered[Math.max(0, tampered.length - 17)] ^= 0x01;
fs.writeFileSync(tamperedResponse, tampered);

const altRootKey = path.join(privateDir, 'attacker-root-key.pem');
const altTsaKey = path.join(privateDir, 'attacker-tsa-key.pem');
const altTsaCsr = path.join(privateDir, 'attacker-tsa.csr');
const altRootCert = path.join(adversarial, 'attacker-root.pem');
const altTsaCert = path.join(adversarial, 'attacker-tsa-cert.pem');
ensureRootAndTsa('ATTACKER', altRootCert, altTsaCert, altRootKey, altTsaKey, altTsaCsr);
const altResponse = path.join(adversarial, 'attacker-issued.tsr');
run([
  'ts', '-reply', '-queryfile', rel(queryFile), '-config', 'config/openssl-tsa.cnf', '-section', 'tsa_config1',
  '-signer', rel(altTsaCert), '-inkey', rel(altTsaKey), '-chain', rel(altRootCert), '-out', rel(altResponse),
]);

const badTsaKey = path.join(privateDir, 'bad-eku-tsa-key.pem');
const badTsaCsr = path.join(privateDir, 'bad-eku-tsa.csr');
const badTsaCert = path.join(adversarial, 'bad-eku-tsa-cert.pem');
if (!fs.existsSync(badTsaKey) || !fs.existsSync(badTsaCert) || fs.statSync(badTsaCert).size === 0) {
  run([
    'req', '-new', '-newkey', 'rsa:2048', '-sha256', '-nodes',
    '-keyout', rel(badTsaKey), '-out', rel(badTsaCsr),
    '-subj', '/CN=ACSD v1.3.3 WRONG EKU TEST CERT/OU=NOT FOR PRODUCTION',
  ]);
  run([
    'x509', '-req', '-in', rel(badTsaCsr), '-CA', rel(rootCert), '-CAkey', rel(rootKey),
    '-CAserial', rel(path.join(artifacts, 'tsa-root.srl')), '-out', rel(badTsaCert), '-days', '30', '-sha256',
    '-extfile', 'config/bad-tsa-cert-ext.cnf', '-extensions', 'bad_tsa_cert',
  ]);
}

const probes = [
  probe(
    'full_query_response_binding',
    ['ts', '-verify', '-queryfile', rel(queryFile), '-in', rel(responseFile), '-CAfile', rel(rootCert)],
    0,
    'Checks CMS signature, timestamp certificate path, subject message imprint, and the request nonce.',
  ),
  probe(
    'correct_digest_without_query',
    ['ts', '-verify', '-digest', subjectDigest, '-in', rel(responseFile), '-CAfile', rel(rootCert)],
    0,
    'Digest-only verification succeeds but does not prove that this response answers the retained nonce-bearing request.',
  ),
  probe(
    'cms_signature_and_chain_verification',
    ['cms', '-verify', '-inform', 'DER', '-in', rel(tokenFile), '-CAfile', rel(rootCert), '-purpose', 'timestampsign', '-out', rel(tstInfoFile)],
    0,
    'The extracted CMS token signature and signer chain verify independently of the higher-level timestamp query check.',
  ),
  probe(
    'wrong_subject_digest_rejected',
    ['ts', '-verify', '-digest', wrongDigest, '-in', rel(responseFile), '-CAfile', rel(rootCert)],
    1,
    'The signed message imprint cannot be rebound to a different enrollment digest.',
  ),
  probe(
    'different_nonce_query_rejected',
    ['ts', '-verify', '-queryfile', rel(secondQuery), '-in', rel(responseFile), '-CAfile', rel(rootCert)],
    1,
    'A query for the same digest but a different nonce is not the request answered by this response.',
  ),
  probe(
    'tampered_der_rejected',
    ['ts', '-verify', '-queryfile', rel(queryFile), '-in', rel(tamperedResponse), '-CAfile', rel(rootCert)],
    1,
    'A one-bit mutation of the DER response is rejected.',
  ),
  probe(
    'attacker_tsa_rejected_by_pinned_root',
    ['ts', '-verify', '-queryfile', rel(queryFile), '-in', rel(altResponse), '-CAfile', rel(rootCert)],
    1,
    'A syntactically and cryptographically valid timestamp from an untrusted private TSA is rejected by the pinned honest root.',
  ),
  probe(
    'attacker_tsa_accepted_if_attacker_root_is_trusted',
    ['ts', '-verify', '-queryfile', rel(queryFile), '-in', rel(altResponse), '-CAfile', rel(altRootCert)],
    0,
    'Cryptographic validity is relative to the configured trust anchor; accepting a self-appointed root destroys independent-witness semantics.',
  ),
  probe(
    'wrong_eku_certificate_rejected_for_timestamp_purpose',
    ['verify', '-purpose', 'timestampsign', '-CAfile', rel(rootCert), rel(badTsaCert)],
    2,
    'A certificate that chains correctly but is authorized only for code signing is not a valid TSA certificate.',
  ),
  tsaPurpose,
];

const expectedImprintMatches = parsed.message_imprint_hex === subjectDigest;
const allPassed = probes.every((item) => item.passed) && expectedImprintMatches;
const testResults = {
  schema: 'acsd-rfc3161-adapter-test-results/v1',
  profile: 'acsd-v1.3.3-local-rfc3161',
  subject_digest: subjectDigest,
  parsed_message_imprint: parsed.message_imprint_hex,
  parsed_message_imprint_matches_subject: expectedImprintMatches,
  all_expected_outcomes_observed: allPassed,
  probes,
};
writeText(path.join(artifacts, 'verification-results.json'), `${JSON.stringify(testResults, null, 2)}\n`);

const evidenceCore = {
  schema: 'acsd-external-receipt-evidence/v1',
  profile: 'acsd-v1.3.3-rfc3161-local-test',
  subject: {
    type: 'predeposit-enrollment-core',
    hash_algorithm: 'sha256',
    digest: subjectDigest,
    source_artifact_sha256: sha256File(enrollmentPath),
  },
  adapter: {
    protocol: 'RFC3161',
    implementation: 'OpenSSL ts',
    implementation_version: version.split(/\r?\n/u)[0],
    raw_artifacts_are_authoritative: true,
  },
  request: artifactDescriptor(queryFile, 'application/timestamp-query'),
  response: artifactDescriptor(responseFile, 'application/timestamp-reply'),
  token: artifactDescriptor(tokenFile, 'application/timestamp-token'),
  tst_info: artifactDescriptor(tstInfoFile, 'application/timestamp-info'),
  parsed_untrusted_display: parsed,
  trust: {
    root: artifactDescriptor(rootCert, 'application/x-pem-file'),
    tsa_certificate: artifactDescriptor(tsaCert, 'application/x-pem-file'),
    root_fingerprint_display: rootFingerprint,
    tsa_fingerprint_display: tsaFingerprint,
    anchor_selection: 'locally pinned test root',
    operator_independence: 'not_established',
  },
  validation: {
    status: allPassed ? 'verified_under_local_test_anchor' : 'failed',
    full_query_response_binding: probes.find((p) => p.name === 'full_query_response_binding').passed,
    message_imprint_matches_subject: expectedImprintMatches,
    timestamp_certificate_purpose_valid: tsaPurpose.passed,
    test_results: artifactDescriptor(path.join(artifacts, 'verification-results.json'), 'application/json'),
  },
  semantics: {
    established: [
      'A holder of the pinned local TSA key issued this RFC 3161 token over the enrollment-core digest.',
      'The token is bound to the retained nonce-bearing request under the tested verification profile.',
    ],
    not_established: [
      'The TSA was operated by a party independent of the claimant.',
      'The TSA clock was externally disciplined or audited.',
      'Any civil identity, actual contribution, consent, or authorship fact.',
      'A public observer could retrieve this receipt at the stated time.',
    ],
  },
};
const evidenceCanonical = stable(evidenceCore);
const evidence = {
  ...evidenceCore,
  canonical_utf8: evidenceCanonical,
  digest: sha256Text(evidenceCanonical),
};
writeText(path.join(artifacts, 'external-receipt-evidence.json'), `${JSON.stringify(evidence, null, 2)}\n`);

const publicSubmissionEnvelope = {
  schema: 'acsd-rfc3161-public-submission-envelope/v1',
  profile: 'acsd-v1.3.3-rfc3161',
  state: 'prepared_not_submitted',
  network_action_performed: false,
  authorization: 'not_granted_for_external_write',
  target: {
    tsa_operator: null,
    endpoint: null,
    trust_anchor_source: null,
  },
  http_request: {
    method: 'POST',
    content_type: 'application/timestamp-query',
    accept: 'application/timestamp-reply',
    body: artifactDescriptor(queryFile, 'application/timestamp-query'),
  },
  response_acceptance: [
    'retain the raw DER response and the exact nonce-bearing request',
    'verify the response against a trust anchor obtained independently of the claimant and TSA response',
    'require the response message imprint to equal the enrollment-core SHA-256 digest',
    'require the timestamp signer certificate to be valid for timestamp signing',
    'record operator policy, retention promise, and clock/audit claims separately from cryptographic validity',
  ],
  prohibited_shortcuts: [
    'do not trust a root certificate supplied only by the claimant',
    'do not accept a parsed time string without the raw signed response',
    'do not discard the request and fall back to digest-only verification when nonce binding is required',
  ],
};
writeText(path.join(artifacts, 'public-submission-envelope.json'), `${JSON.stringify(publicSubmissionEnvelope, null, 2)}\n`);

const summary = {
  subject_digest: subjectDigest,
  timestamp_time_display: parsed.gen_time_display,
  evidence_digest: evidence.digest,
  tests_passed: probes.filter((p) => p.passed).length,
  tests_total: probes.length,
  parsed_imprint_matches: expectedImprintMatches,
  overall: allPassed ? 'PASS' : 'FAIL',
};
writeText(path.join(artifacts, 'run-summary.json'), `${JSON.stringify(summary, null, 2)}\n`);
console.log(JSON.stringify(summary, null, 2));
if (!allPassed) process.exitCode = 1;
