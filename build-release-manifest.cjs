#!/usr/bin/env node
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const root = __dirname;
const manifestName = 'RELEASE-MANIFEST.sha256';
const forbiddenDirectory = new RegExp('(^|/)(private-test-keys|[.]deps|[.]lake|node_modules|__pycache__|[.]npm-cache|[.]git)(/|$)');

function allFiles(directory) {
  const result = [];
  for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
    const full = path.join(directory, entry.name);
    const rel = path.relative(root, full).split(path.sep).join('/');
    if (forbiddenDirectory.test(rel)) continue;
    if (entry.isDirectory()) result.push(...allFiles(full));
    else if (entry.isFile() && rel !== manifestName) result.push(rel);
  }
  return result;
}

const lines = allFiles(root).sort().map((rel) => {
  const digest = crypto.createHash('sha256').update(fs.readFileSync(path.join(root, rel))).digest('hex');
  return `${digest}  ${rel}`;
});
fs.writeFileSync(path.join(root, manifestName), `${lines.join('\n')}\n`, 'utf8');
console.log(JSON.stringify({ manifest: manifestName, entries: lines.length }));
