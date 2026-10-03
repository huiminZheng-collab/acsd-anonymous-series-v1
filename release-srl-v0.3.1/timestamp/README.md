# RFC 3161 evidence for SRL v0.3.1

This directory contains an externally issued RFC 3161 timestamp for the exact
bytes of `../RELEASE-MANIFEST.sha256`.

- Subject SHA-256: `3ffa5c6161ac71d4c2445b1df53cc848c1734f557c59a4ad87a3547f526f5fcc`
- Authority endpoint: `https://freetsa.org/tsr`
- Generation time: `2026-10-03T02:45:13+00:00`
- Policy OID: `1.2.3.4.1`
- Serial: `8d07a6b`
- Request SHA-256: `846a950b10c23ccc436294b100962e190a82dc2ba9c125f7382474dd553504a6`
- Response SHA-256: `d27a9a4392ca05cf05cce10723662191b61e81f34da2b237916f4c3540499bdc`
- TSA certificate SHA-256 fingerprint: `32e841a95cc1164101ffde41298ef2fc75c1c4372ef095e88a6bbd47dfb191fc`
- Local verification: `OK`

The response was verified against the exact manifest imprint, request nonce,
embedded CMS signature, timestamping EKU, signer identity, certificate validity
at generation time, and the explicitly pinned signer certificate.

This evidence establishes only that the TSA observed the manifest digest no
later than the recorded time. It does not prove authorship, novelty,
correctness, peer review, acceptance, or academic priority.
