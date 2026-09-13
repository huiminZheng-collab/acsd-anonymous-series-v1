#!/usr/bin/env node
'use strict';
const crypto = require('crypto'); const fs = require('fs'); const path = require('path');
const root = __dirname; const output = path.join(root, 'public-manifest.json');
const excludedSegments = ['private-test-keys', '.deps', '__pycache__', '.npm-cache', 'node_modules'];
function walk(directory) {
  return fs.readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    if (entry.isDirectory() && excludedSegments.includes(entry.name)) return [];
    const child = path.join(directory, entry.name); return entry.isDirectory() ? walk(child) : [child];
  });
}
const files = walk(root).filter((file) => file !== output).sort();
const entries = files.map((file) => ({ path: path.relative(root, file).replace(/\\/g, '/'), size_bytes: fs.statSync(file).size,
  sha256: crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex') }));
fs.writeFileSync(output, `${JSON.stringify({ schema: 'acsd-v1.6.0-public-manifest/v1', excluded_paths: excludedSegments.map((name) => `${name}/`), files: entries }, null, 2)}\n`, 'utf8');
console.log(JSON.stringify({ entries: entries.length }));
