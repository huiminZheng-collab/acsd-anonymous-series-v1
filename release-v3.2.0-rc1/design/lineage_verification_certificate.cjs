#!/usr/bin/env node
"use strict";

// Independent Node adapter for one exact authorized ACSD lineage edge.
// It emits checked facts, never a verdict or application claim.

const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const {canonicalJson} = require("./canonical_ref.cjs");
const {verify} = require("./verify_approval.cjs");

const SCHEMA = "acsd-lineage-verification-certificate/v1";
const sha256 = (bytes) => crypto.createHash("sha256").update(bytes).digest("hex");
const objectDigest = (value) => sha256(Buffer.from(canonicalJson(value), "utf8"));

function fail(condition, code) {
  if (!condition) throw new Error(code);
}

function exactFields(value, fields, code) {
  fail(value && typeof value === "object" && !Array.isArray(value) &&
    Object.keys(value).sort().join(",") === [...fields].sort().join(","), code);
}

function readCanonical(root, relative) {
  const raw = fs.readFileSync(path.join(root, relative));
  const payload = raw.at(-1) === 10 ? raw.subarray(0, -1) : raw;
  let value;
  try { value = JSON.parse(payload.toString("utf8")); }
  catch (_) { throw new Error(`LINEAGE_CERT_JSON_INVALID:${relative}`); }
  fail(Buffer.from(canonicalJson(value), "utf8").equals(payload),
    `LINEAGE_CERT_JSON_NONCANONICAL:${relative}`);
  return {value, raw, payload};
}

function authorityOf(release) {
  const authorKeys = release.authors.map((item) => item.key_id).sort();
  fail(authorKeys.length > 0 && new Set(authorKeys).size === authorKeys.length,
    "LINEAGE_AUTHORITY_INVALID");
  const authority = release.lineage_authority || {
    schema: "acsd-lineage-authority/v1",
    key_ids: authorKeys,
    threshold: authorKeys.length,
  };
  exactFields(authority, ["schema", "key_ids", "threshold"],
    "LINEAGE_AUTHORITY_INVALID");
  fail(authority.schema === "acsd-lineage-authority/v1" &&
    canonicalJson(authority.key_ids) === canonicalJson(authorKeys) &&
    Number.isSafeInteger(authority.threshold) && authority.threshold >= 1 &&
    authority.threshold <= authorKeys.length, "LINEAGE_AUTHORITY_INVALID");
  return authority;
}

function compactAuthority(value) {
  return {key_ids: value.key_ids, threshold: value.threshold};
}

function build(root) {
  const childReleaseFile = readCanonical(root, "release/release.json");
  const childGovernanceFile = readCanonical(root, "governance/statement.json");
  const childPecFile = readCanonical(root, "pec/pec.json");
  const targetFile = readCanonical(root, "approval/target.json");
  const approvalSetFile = readCanonical(root, "approval/approval-set.json");
  const parentReleaseFile = readCanonical(root, "lineage/parent-release.json");
  const parentPecFile = readCanonical(root, "lineage/parent-pec.json");
  const transitionFile = readCanonical(root, "lineage/transition.json");
  const release = childReleaseFile.value;
  const governance = childGovernanceFile.value;
  const pec = childPecFile.value;
  const target = targetFile.value;
  const approvalSet = approvalSetFile.value;
  const parentRelease = parentReleaseFile.value;
  const parentPec = parentPecFile.value;
  const transition = transitionFile.value;

  const childReleaseDigest = objectDigest(release);
  const childGovernanceDigest = objectDigest(governance);
  const childPecDigest = objectDigest(pec);
  const parentReleaseDigest = objectDigest(parentRelease);
  const parentPecDigest = objectDigest(parentPec);
  const transitionDigest = objectDigest(transition);
  const targetDigest = objectDigest(target);
  const parentAuthority = authorityOf(parentRelease);
  const childAuthority = authorityOf(release);
  const childKeys = release.authors.map((item) => item.key_id).sort();
  const sameAuthority = canonicalJson(parentAuthority) === canonicalJson(childAuthority);

  fail(release.work_id === parentRelease.work_id &&
    release.parent_release_id === `urn:sha256:${parentReleaseDigest}`,
  "LINEAGE_WORK_OR_PARENT_MISMATCH");
  const sameLine = release.slot.line === parentRelease.slot.line;
  fail((sameLine && release.slot.version === parentRelease.slot.version + 1) ||
    (!sameLine && release.slot.version === 1), "LINEAGE_VERSION_NOT_CONSECUTIVE");
  fail(pec.subject.work_id === release.work_id &&
    pec.subject.release_digest === childReleaseDigest &&
    pec.subject.predecessor_pec_digest === parentPecDigest &&
    pec.subject.line === release.slot.line &&
    pec.subject.version === `v${release.slot.version}`,
  "LINEAGE_PEC_BINDING");
  fail(pec.governance.statement_digest === childGovernanceDigest &&
    canonicalJson(pec.governance.required_pec_approval_key_ids) ===
      canonicalJson(childKeys), "LINEAGE_GOVERNANCE_BINDING");
  fail(pec.claim_policy.permitted_outcomes.includes("AUTHORIZED_SUCCESSOR") &&
    canonicalJson(pec.claim_policy.required_capabilities.AUTHORIZED_SUCCESSOR) ===
      canonicalJson(["predecessor-authority-exact-transition"]),
  "LINEAGE_CERT_POLICY");

  exactFields(transition, ["schema", "kind", "work_id", "parent", "child"],
    "LINEAGE_TRANSITION_FIELDS");
  fail(transition.schema === "acsd-lineage-transition/v1" &&
    transition.work_id === release.work_id, "LINEAGE_TRANSITION_BINDING");
  const expectedParent = {
    release_digest: parentReleaseDigest,
    pec_digest: parentPecDigest,
    line: parentRelease.slot.line,
    version: parentRelease.slot.version,
    authority: parentAuthority,
  };
  const expectedChild = {
    release_digest: childReleaseDigest,
    governance_digest: childGovernanceDigest,
    pec_digest: childPecDigest,
    line: release.slot.line,
    version: release.slot.version,
    authority: childAuthority,
  };
  const expectedKind = !sameLine ? "branch" :
    canonicalJson(parentAuthority.key_ids) !== canonicalJson(childAuthority.key_ids) ?
      "team-change" : parentAuthority.threshold !== childAuthority.threshold ?
        "threshold-change" : "continuation";
  fail(canonicalJson(transition.parent) === canonicalJson(expectedParent) &&
    canonicalJson(transition.child) === canonicalJson(expectedChild) &&
    transition.kind === expectedKind, "LINEAGE_TRANSITION_MISMATCH");

  const expectedTarget = {
    schema: "acsd-approval-target/v2",
    work_id: release.work_id,
    release_digest: childReleaseDigest,
    governance_digest: childGovernanceDigest,
    pec_digest: childPecDigest,
    required_key_ids: childKeys,
    lineage_transition_digest: transitionDigest,
  };
  fail(canonicalJson(target) === canonicalJson(expectedTarget),
    "APPROVAL_TARGET_BINDING_MISMATCH");

  let inputs = [
    {role: "parent-release", path: "lineage/parent-release.json",
      sha256: sha256(parentReleaseFile.raw)},
    {role: "parent-pec", path: "lineage/parent-pec.json",
      sha256: sha256(parentPecFile.raw)},
    {role: "child-release", path: "release/release.json",
      sha256: sha256(childReleaseFile.raw)},
    {role: "child-governance", path: "governance/statement.json",
      sha256: sha256(childGovernanceFile.raw)},
    {role: "child-pec", path: "pec/pec.json", sha256: sha256(childPecFile.raw)},
    {role: "child-approval-target", path: "approval/target.json",
      sha256: sha256(targetFile.raw)},
    {role: "lineage-transition", path: "lineage/transition.json",
      sha256: sha256(transitionFile.raw)},
    {role: "approval-set", path: "approval/approval-set.json",
      sha256: sha256(approvalSetFile.raw)},
  ];
  const signatureFacts = [];
  for (const keyId of childKeys) {
    const publicRelative = `public-keys/${keyId}.pub`;
    const coseRelative = `approvals/${keyId}.cose`;
    const publicRaw = fs.readFileSync(path.join(root, publicRelative));
    const coseRaw = fs.readFileSync(path.join(root, coseRelative));
    const checked = verify(path.join(root, "approval/target.json"),
      path.join(root, coseRelative), path.join(root, publicRelative), keyId);
    fail(checked.payload_sha256 === targetDigest, "LINEAGE_CHILD_APPROVAL");
    inputs.push(
      {role: "child-public-key", path: publicRelative, sha256: sha256(publicRaw)},
      {role: "child-approval-cose", path: coseRelative, sha256: sha256(coseRaw)},
    );
    signatureFacts.push({
      purpose: "child-approval", key_id: keyId, payload_digest: targetDigest,
      cose_digest: sha256(coseRaw), public_key_digest: sha256(publicRaw),
    });
  }

  const predecessorFacts = [];
  if (!sameAuthority) {
    const directory = path.join(root, "lineage", "authorizations");
    const names = fs.readdirSync(directory).filter((name) => name.endsWith(".cose")).sort();
    fail(names.length >= parentAuthority.threshold, "UNAUTHORIZED_SUCCESSOR");
    for (const name of names) {
      const keyId = name.slice(0, -5);
      fail(parentAuthority.key_ids.includes(keyId), "LINEAGE_AUTHORIZATION_UNKNOWN_KEY");
      const publicRelative = `lineage/parent-public-keys/${keyId}.pub`;
      const coseRelative = `lineage/authorizations/${keyId}.cose`;
      const publicRaw = fs.readFileSync(path.join(root, publicRelative));
      const coseRaw = fs.readFileSync(path.join(root, coseRelative));
      const checked = verify(path.join(root, "lineage/transition.json"),
        path.join(root, coseRelative), path.join(root, publicRelative), keyId);
      fail(checked.payload_sha256 === transitionDigest,
        "LINEAGE_PREDECESSOR_AUTHORIZATION");
      inputs.push(
        {role: "parent-public-key", path: publicRelative, sha256: sha256(publicRaw)},
        {role: "predecessor-authorization-cose", path: coseRelative,
          sha256: sha256(coseRaw)},
      );
      predecessorFacts.push({
        purpose: "predecessor-authorization", key_id: keyId,
        payload_digest: transitionDigest, cose_digest: sha256(coseRaw),
        public_key_digest: sha256(publicRaw),
      });
    }
  } else {
    fail(childKeys.filter((key) => parentAuthority.key_ids.includes(key)).length >=
      parentAuthority.threshold, "UNAUTHORIZED_SUCCESSOR");
  }
  signatureFacts.push(...predecessorFacts);

  exactFields(approvalSet, ["schema", "approval_target_digest", "author_approvals",
    "lineage_authorizations"], "APPROVAL_SET_FIELDS");
  const expectedAuthors = signatureFacts.filter((item) => item.purpose === "child-approval")
    .map((item) => ({key_id: item.key_id, cose_sha256: item.cose_digest}));
  const expectedLineage = predecessorFacts
    .map((item) => ({key_id: item.key_id, cose_sha256: item.cose_digest}));
  fail(approvalSet.schema === "acsd-approval-set/v1" &&
    approvalSet.approval_target_digest === targetDigest &&
    canonicalJson(approvalSet.author_approvals) === canonicalJson(expectedAuthors) &&
    canonicalJson(approvalSet.lineage_authorizations) === canonicalJson(expectedLineage),
  "APPROVAL_SET_SIGNATURE_MISMATCH");

  inputs.sort((a, b) => a.path.localeCompare(b.path) || a.role.localeCompare(b.role));
  signatureFacts.sort((a, b) =>
    a.purpose.localeCompare(b.purpose) || a.key_id.localeCompare(b.key_id));
  return {
    schema: SCHEMA,
    inputs,
    policy: {pec_digest: childPecDigest,
      permitted_outcomes: pec.claim_policy.permitted_outcomes},
    lineage_edge: {
      work_id_digest: sha256(Buffer.from(transition.work_id, "utf8")),
      transition_digest: transitionDigest,
      transition_input_digest: sha256(transitionFile.raw),
      transition_kind: transition.kind,
      authorization_mode: sameAuthority ? "continuity" : "transition",
      parent: {
        release_digest: transition.parent.release_digest,
        pec_digest: transition.parent.pec_digest,
        line_digest: sha256(Buffer.from(transition.parent.line, "utf8")),
        version: transition.parent.version,
        authority: compactAuthority(transition.parent.authority),
        release_input_digest: sha256(parentReleaseFile.raw),
        pec_input_digest: sha256(parentPecFile.raw),
      },
      child: {
        release_digest: transition.child.release_digest,
        pec_digest: transition.child.pec_digest,
        line_digest: sha256(Buffer.from(transition.child.line, "utf8")),
        version: transition.child.version,
        authority: compactAuthority(transition.child.authority),
        approval_target_digest: targetDigest,
        bound_transition_digest: target.lineage_transition_digest,
        release_input_digest: sha256(childReleaseFile.raw),
        governance_input_digest: sha256(childGovernanceFile.raw),
        pec_input_digest: sha256(childPecFile.raw),
        approval_target_input_digest: sha256(targetFile.raw),
      },
    },
    approval_set: {
      approval_target_digest: approvalSet.approval_target_digest,
      author_approvals: approvalSet.author_approvals,
      lineage_authorizations: approvalSet.lineage_authorizations,
      input_digest: sha256(approvalSetFile.raw),
    },
    signature_facts: signatureFacts,
  };
}

if (require.main === module) {
  try {
    if (process.argv.length !== 3) {
      throw new Error("usage: node lineage_verification_certificate.cjs BUNDLE");
    }
    process.stdout.write(canonicalJson(build(process.argv[2])) + "\n");
  } catch (error) {
    console.error(String(error && error.message ? error.message : error));
    process.exit(1);
  }
}

module.exports = {build};
