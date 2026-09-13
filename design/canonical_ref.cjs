#!/usr/bin/env node
'use strict';
// Canonical JSON reference: semantics extracted verbatim from the v1 Node
// verifier (release-staging/acsd-anonymous-series-v1.0.0/public/artifact/verify-standalone.cjs).
// Used by canonical_diff_runner.py for Python-vs-Node differential tests.
//
// Interface: reads a UTF-8 JSON array of strings from the file named by
// argv[2], emits a JSON array of results to stdout. For each input text:
//   { ok: true,  hex: "<canonical bytes hex>", is_canonical: bool }
//   { ok: false, err: "<code>",              is_canonical: false }

const fs = require('fs');

function canonicalJson(value) {
  if (value === null) return 'null';
  if (typeof value === 'boolean') return value ? 'true' : 'false';
  if (typeof value === 'string') {
    if (!value.isWellFormed()) throw new Error('LONE_SURROGATE');
    return JSON.stringify(value);
  }
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value)) throw new Error('UNSAFE_INTEGER');
    return String(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (value && typeof value === 'object' && Object.getPrototypeOf(value) === Object.prototype) {
    const keys = Object.keys(value);
    if (keys.some((key) => !/^[\x00-\x7f]*$/.test(key))) throw new Error('NONASCII_KEY');
    return `{${keys.sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
  }
  throw new Error('UNSUPPORTED_VALUE');
}

function evaluate(text) {
  const raw = Buffer.from(text, 'utf8');
  let parsed;
  try { parsed = JSON.parse(text); }
  catch (e) { return { ok: false, err: 'PARSE_ERROR', is_canonical: false }; }
  try {
    const b = Buffer.from(canonicalJson(parsed), 'utf8');
    return { ok: true, hex: b.toString('hex'), is_canonical: b.equals(raw) };
  } catch (e) {
    return { ok: false, err: e.message, is_canonical: false };
  }
}

if (require.main === module) {
  const inputs = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
  process.stdout.write(JSON.stringify(inputs.map(evaluate)));
}

module.exports = {canonicalJson, evaluate};
