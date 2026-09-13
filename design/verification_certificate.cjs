#!/usr/bin/env node
"use strict";

// Independent Node adapter for ACSD verification certificates v1/v2. It emits
// verified byte-level facts and deliberately emits no verdict or claim.

const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const {canonicalJson} = require("./canonical_ref.cjs");
const {verify} = require("./verify_approval.cjs");

const SCHEMA_V1 = "acsd-verification-certificate/v1";
const SCHEMA_V2 = "acsd-verification-certificate/v2";
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

function build(root, options = {}) {
  const includeIdentity = options.includeIdentity === true;
  const targetFile = readCanonical(root, "approval-target.json");
  const pecFile = readCanonical(root, "pec.json");
  const disclosureFile = readCanonical(root, "dialogue-disclosure.json");
  const target = targetFile.value;
  const pec = pecFile.value;
  const disclosure = disclosureFile.value;
  const pecDigest = sha256(pecFile.payload);
  const targetDigest = sha256(targetFile.payload);
  const disclosureDigest = sha256(disclosureFile.payload);
  let releaseFile = null;
  let identityFile = null;
  if (includeIdentity) {
    releaseFile = readCanonical(root, "release.json");
    identityFile = readCanonical(root, "identity/slot-1.json");
  }

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
  const identityAssertions = [];
  if (includeIdentity) {
    const release = releaseFile.value;
    const identity = identityFile.value;
    const releaseDigest = sha256(releaseFile.payload);
    fail(target.release_digest === releaseDigest, "TRANSCRIPT_IDENTITY_RELEASE_BINDING");
    fail(identity && Object.keys(identity).sort().join(",") === [
      "author_key_id", "author_slot", "identity_assertion", "publication_ref",
      "purpose", "release_id", "schema", "work_id",
    ].sort().join(","), "TRANSCRIPT_IDENTITY_FIELDS");
    fail(identity.schema === "acsd-identity-disclosure/v1" &&
      identity.release_id === `urn:sha256:${releaseDigest}` &&
      identity.work_id === release.work_id &&
      identity.purpose === "publication-unblinding",
    "TRANSCRIPT_IDENTITY_SCOPE");
    const author = release.authors.filter((item) => item.slot === identity.author_slot);
    fail(author.length === 1 && author[0].key_id === identity.author_key_id,
      "TRANSCRIPT_IDENTITY_SLOT");
    const assertion = identity.identity_assertion;
    fail(assertion && Object.keys(assertion).sort().join(",") ===
      ["display_name", "persistent_identifier"].sort().join(",") &&
      typeof assertion.display_name === "string" && assertion.display_name.trim() !== "" &&
      (assertion.persistent_identifier === null ||
        typeof assertion.persistent_identifier === "string"),
    "TRANSCRIPT_IDENTITY_ASSERTION");
    fail(identity.publication_ref === null || typeof identity.publication_ref === "string",
      "TRANSCRIPT_IDENTITY_PUBLICATION_REF");
    const keyId = identity.author_key_id;
    const publicRelative = `public-keys/${keyId}.pub`;
    const coseRelative = "identity/slot-1.cose";
    const publicRaw = fs.readFileSync(path.join(root, publicRelative));
    const coseRaw = fs.readFileSync(path.join(root, coseRelative));
    const verified = verify(
      path.join(root, "identity/slot-1.json"), path.join(root, coseRelative),
      path.join(root, publicRelative), keyId,
    );
    fail(verified.payload_sha256 === sha256(identityFile.payload),
      "TRANSCRIPT_IDENTITY_PAYLOAD");
    inputs.push(
      {role: "release", path: "release.json", sha256: sha256(releaseFile.raw)},
      {role: "identity-disclosure", path: "identity/slot-1.json",
        sha256: sha256(identityFile.raw)},
      {role: "identity-disclosure-cose", path: coseRelative, sha256: sha256(coseRaw)},
      {role: "public-key", path: publicRelative, sha256: sha256(publicRaw)},
    );
    signatureFacts.push({
      purpose: "identity-disclosure",
      key_id: keyId,
      payload_digest: sha256(identityFile.payload),
      cose_digest: sha256(coseRaw),
    });
    identityAssertions.push({
      body_digest: sha256(identityFile.payload),
      release_digest: releaseDigest,
      author_slot: identity.author_slot,
      author_key_id: keyId,
      assertion_digest: sha256(Buffer.from(canonicalJson(assertion), "utf8")),
      cose_digest: sha256(coseRaw),
    });
  }
  inputs = [...new Map(inputs.map((item) => [item.path, item])).values()]
    .sort((a, b) => a.path.localeCompare(b.path) || a.role.localeCompare(b.role));
  signatureFacts.sort((a, b) =>
    a.purpose.localeCompare(b.purpose) || a.key_id.localeCompare(b.key_id));
  const opened = disclosure.opened_material;
  const result = {
    schema: includeIdentity ? SCHEMA_V2 : SCHEMA_V1,
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
    identity_assertions: identityAssertions,
    timestamp_facts: [],
    trusted_inputs: [],
  };
  if (includeIdentity) {
    result.release_context = {
      release_digest: sha256(releaseFile.payload),
      author_slots: releaseFile.value.authors.map((author) => ({
        slot: author.slot,
        key_id: author.key_id,
      })),
    };
  }
  return result;
}

if (require.main === module) {
  try {
    if (![3, 4].includes(process.argv.length) ||
        (process.argv.length === 4 && process.argv[3] !== "--include-identity")) {
      throw new Error("usage: node verification_certificate.cjs BUNDLE [--include-identity]");
    }
    process.stdout.write(canonicalJson(build(process.argv[2], {
      includeIdentity: process.argv[3] === "--include-identity",
    })) + "\n");
  } catch (error) {
    console.error(String(error && error.message ? error.message : error));
    process.exit(1);
  }
}

module.exports = {build, verifyWindow};
