#!/usr/bin/env node
"use strict";

// Independent Node adapter for acsd-verification-certificate/v1. It emits
// verified byte-level facts and deliberately emits no verdict or claim.

const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const {canonicalJson} = require("./canonical_ref.cjs");
const {verify} = require("./verify_approval.cjs");

const SCHEMA = "acsd-verification-certificate/v1";
const sha256 = (bytes) => crypto.createHash("sha256").update(bytes).digest("hex");

function fail(condition, code) {
  if (!condition) throw new Error(code);
}

function readCanonical(root, relative) {
  const raw = fs.readFileSync(path.join(root, relative));
  const payload = raw.at(-1) === 10 ? raw.subarray(0, -1) : raw;
  let value;
  try { value = JSON.parse(payload.toString("utf8")); }
  catch (_) { throw new Error(`TRANSCRIPT_JSON_INVALID:${relative}`); }
  fail(Buffer.from(canonicalJson(value), "utf8").equals(payload),
    `TRANSCRIPT_JSON_NONCANONICAL:${relative}`);
  return {value, raw, payload};
}

function dialogueLeaf(index, text, saltHex) {
  fail(Number.isSafeInteger(index) && index >= 0, "TRANSCRIPT_OPENING");
  const salt = Buffer.from(saltHex, "hex");
  fail(salt.length === 32 && saltHex.length === 64, "TRANSCRIPT_OPENING");
  const position = Buffer.alloc(8);
  position.writeBigUInt64BE(BigInt(index));
  return crypto.createHash("sha256").update(Buffer.concat([
    Buffer.from("ACSD-PEC-DIALOGUE-LEAF-v1\0", "utf8"),
    position,
    salt,
    Buffer.from(text, "utf8"),
  ])).digest();
}

function verifyWindow(rootHex, opened) {
  fail(/^[0-9a-f]{64}$/.test(rootHex), "DIALOGUE_ROOT");
  fail(Array.isArray(opened) && opened.length > 0, "TRANSCRIPT_OPENING");
  for (let i = 0; i + 1 < opened.length; i++) {
    fail(opened[i].index + 1 === opened[i + 1].index, "DISCLOSURE_WINDOW_INVALID");
  }
  for (const item of opened) {
    fail(item && typeof item === "object" && typeof item.bytes === "string" &&
      Array.isArray(item.path), "TRANSCRIPT_OPENING");
    let node = dialogueLeaf(item.index, item.bytes, item.salt);
    for (const step of item.path) {
      fail(Array.isArray(step) && step.length === 2 &&
        /^[0-9a-f]{64}$/.test(step[0]) && ["L", "R"].includes(step[1]),
        "TRANSCRIPT_OPENING");
      const sibling = Buffer.from(step[0], "hex");
      node = crypto.createHash("sha256").update(Buffer.concat([
        Buffer.from("ACSD-PEC-DIALOGUE-NODE-v1\0", "utf8"),
        ...(step[1] === "R" ? [node, sibling] : [sibling, node]),
      ])).digest();
    }
    fail(node.toString("hex") === rootHex, "DISCLOSURE_BINDING_MISMATCH");
  }
}

function build(root) {
  const targetFile = readCanonical(root, "approval-target.json");
  const pecFile = readCanonical(root, "pec.json");
  const disclosureFile = readCanonical(root, "dialogue-disclosure.json");
  const target = targetFile.value;
  const pec = pecFile.value;
  const disclosure = disclosureFile.value;
  const pecDigest = sha256(pecFile.payload);
  const targetDigest = sha256(targetFile.payload);
  const disclosureDigest = sha256(disclosureFile.payload);

  const required = pec.governance && pec.governance.required_pec_approval_key_ids;
  fail(Array.isArray(required) && JSON.stringify(required) ===
    JSON.stringify([...new Set(required)].sort()), "TRANSCRIPT_REQUIRED_KEYS");
  fail(JSON.stringify(target.required_key_ids) === JSON.stringify(required),
    "TRANSCRIPT_KEY_SET_MISMATCH");
  fail(target.pec_digest === pecDigest, "TRANSCRIPT_PEC_BINDING");
  fail(disclosure.pec_digest === pecDigest, "TRANSCRIPT_DISCLOSURE_PEC");
  fail(pec.claim_policy && Array.isArray(pec.claim_policy.permitted_outcomes) &&
    pec.claim_policy.permitted_outcomes.includes("COMMITTED_EVIDENCE_MATCH"),
    "TRANSCRIPT_EVENT_POLICY");

  const events = pec.events.filter((item) => item.event_id === disclosure.event_id);
  fail(events.length === 1, "TRANSCRIPT_EVENT_LOOKUP");
  const event = events[0];
  fail(event.sequence === disclosure.event_sequence, "TRANSCRIPT_EVENT_SEQUENCE");
  fail(event.kind === disclosure.kind, "TRANSCRIPT_EVENT_KIND");
  const commitment = event.commitment || {};
  fail(commitment.scheme === "merkle-dialogue-v1", "TRANSCRIPT_COMMITMENT_SCHEME");
  fail(disclosure.disclosure_mode === "dialogue_window", "TRANSCRIPT_DISCLOSURE_MODE");
  verifyWindow(commitment.digest, disclosure.opened_material);

  let inputs = [
    {role: "approval-target", path: "approval-target.json", sha256: sha256(targetFile.raw)},
    {role: "pec", path: "pec.json", sha256: sha256(pecFile.raw)},
    {role: "event-disclosure", path: "dialogue-disclosure.json", sha256: sha256(disclosureFile.raw)},
  ];
  const signatureFacts = [];
  for (const [purpose, relative, directory] of [
    ["author-approval", "approval-target.json", "release-approvals"],
    ["event-disclosure", "dialogue-disclosure.json", "disclosure-approvals"],
  ]) {
    const payloadDigest = purpose === "author-approval" ? targetDigest : disclosureDigest;
    for (const keyId of required) {
      const publicRelative = `public-keys/${keyId}.pub`;
      const coseRelative = `${directory}/${keyId}.cose`;
      const publicRaw = fs.readFileSync(path.join(root, publicRelative));
      const coseRaw = fs.readFileSync(path.join(root, coseRelative));
      const result = verify(
        path.join(root, relative), path.join(root, coseRelative),
        path.join(root, publicRelative), keyId,
      );
      fail(result.payload_sha256 === payloadDigest, "TRANSCRIPT_PAYLOAD_DIGEST");
      inputs.push(
        {role: "public-key", path: publicRelative, sha256: sha256(publicRaw)},
        {role: `${purpose}-cose`, path: coseRelative, sha256: sha256(coseRaw)},
      );
      signatureFacts.push({
        purpose,
        key_id: keyId,
        payload_digest: payloadDigest,
        cose_digest: sha256(coseRaw),
      });
    }
  }
  inputs = [...new Map(inputs.map((item) => [item.path, item])).values()]
    .sort((a, b) => a.path.localeCompare(b.path) || a.role.localeCompare(b.role));
  signatureFacts.sort((a, b) =>
    a.purpose.localeCompare(b.purpose) || a.key_id.localeCompare(b.key_id));
  const opened = disclosure.opened_material;
  return {
    schema: SCHEMA,
    inputs,
    approval_target: {
      target_digest: targetDigest,
      pec_digest: pecDigest,
      required_key_ids: required,
    },
    policy: {
      pec_digest: pecDigest,
      permitted_outcomes: pec.claim_policy.permitted_outcomes,
    },
    event_disclosure: {
      body_digest: disclosureDigest,
      pec_digest: pecDigest,
      event_id: event.event_id,
      event_sequence: event.sequence,
      commitment_digest: commitment.digest,
      first_index: opened[0].index,
      last_index: opened.at(-1).index,
      required_key_ids: required,
    },
    signature_facts: signatureFacts,
    merkle_facts: [{
      body_digest: disclosureDigest,
      commitment_digest: commitment.digest,
      first_index: opened[0].index,
      last_index: opened.at(-1).index,
      opened_leaf_count: opened.length,
    }],
    identity_assertions: [],
    timestamp_facts: [],
    trusted_inputs: [],
  };
}

if (require.main === module) {
  try {
    if (process.argv.length !== 3) throw new Error("usage: node verification_certificate.cjs BUNDLE");
    process.stdout.write(canonicalJson(build(process.argv[2])) + "\n");
  } catch (error) {
    console.error(String(error && error.message ? error.message : error));
    process.exit(1);
  }
}

module.exports = {build, verifyWindow};
