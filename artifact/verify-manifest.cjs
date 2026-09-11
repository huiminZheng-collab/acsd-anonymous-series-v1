#!/usr/bin/env node
'use strict';
const crypto = require('crypto'); const fs = require('fs'); const path = require('path');
const root = __dirname; const manifest = JSON.parse(fs.readFileSync(path.join(root, 'public-manifest.json'), 'utf8')); const failures = [];
for (const entry of manifest.files) {
  const file = path.resolve(root, entry.path); const inside = file.startsWith(`${root}${path.sep}`);
  const exists = inside && fs.existsSync(file) && fs.statSync(file).isFile(); const sizeMatches = exists && fs.statSync(file).size === entry.size_bytes;
  const digestMatches = sizeMatches && crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex') === entry.sha256;
  if (!inside || !exists || !sizeMatches || !digestMatches) failures.push(entry.path);
}
console.log(JSON.stringify({ schema: 'acsd-v1.6.0-manifest-verification/v1', expected: manifest.files.length,
  passed: manifest.files.length - failures.length, failed: failures.length, failures }, null, 2));
if (failures.length) process.exitCode = 1;
