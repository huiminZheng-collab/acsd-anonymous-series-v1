#!/usr/bin/env node
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const root = __dirname;
const manifestName = 'RELEASE-MANIFEST.sha256';
const forbiddenDirectory = new RegExp('(^|/)(private-test-keys|[.]deps|node_modules|__pycache__|[.]npm-cache|[.]git)(/|$)');
const linePattern = /^([0-9a-f]{64})  (.+)$/;

function fail(message) { throw new Error(message); }
function allFiles(directory) {
  const result = [];
  for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
    const full = path.join(directory, entry.name);
    const rel = path.relative(root, full).split(path.sep).join('/');
    if (forbiddenDirectory.test(rel)) continue;
    if (entry.isDirectory()) result.push(...allFiles(full));
    else if (entry.isFile() && rel !== manifestName) result.push(rel);
  }
  return result.sort();
}

const manifestPath = path.join(root, manifestName);
if (!fs.existsSync(manifestPath)) fail(`missing ${manifestName}`);
const expected = new Map();
const body = fs.readFileSync(manifestPath, 'utf8');
for (const line of body.trimEnd().split(/\r?\n/)) {
  const match = linePattern.exec(line);
  if (!match) fail(`invalid manifest line: ${line}`);
  const [, digest, rel] = match;
  if (rel.includes('\\') || rel === manifestName || forbiddenDirectory.test(rel) || expected.has(rel)) fail(`disallowed manifest path: ${rel}`);
  expected.set(rel, digest);
}
const actual = allFiles(root);
const failures = [];
for (const rel of actual) {
  const want = expected.get(rel);
  if (!want) { failures.push(`unlisted: ${rel}`); continue; }
  const got = crypto.createHash('sha256').update(fs.readFileSync(path.join(root, rel))).digest('hex');
  if (got !== want) failures.push(`hash mismatch: ${rel}`);
}
for (const rel of expected.keys()) if (!actual.includes(rel)) failures.push(`missing: ${rel}`);
if (failures.length) fail(failures.join('\n'));
console.log(JSON.stringify({ schema: 'acsd-release-manifest-verification/v1', entries: actual.length, result: 'VALID' }));
