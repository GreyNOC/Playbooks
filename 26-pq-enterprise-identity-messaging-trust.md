# 26 — Post-Quantum Enterprise Identity, Messaging & Trust Infrastructure

## Overview

Enterprise trust extends beyond TLS and application tokens. PIV/CAC and smart cards, device/user
certificates, FIDO/WebAuthn attestation, S/MIME, OpenPGP, document signing, timestamping, DNSSEC,
RPKI, service identities, and directory enrollment workflows all carry long-lived classical
signature or key-establishment dependencies. This playbook inventories and migrates those trust
surfaces without breaking identity proofing, recovery, revocation, or interoperability.

PQC support across these ecosystems is uneven. A selected algorithm, working prototype, or draft
profile is not equivalent to a final standard or supported enterprise product. Record maturity and
do not fabricate a migration target.

## Trust-surface map

| Surface | Inventory and migration concern |
| --- | --- |
| PIV/CAC/smart card | Card/app/reader/middleware algorithms, object sizes, issuance, recovery, dual-stack profile |
| User/device/workload identity | Enrollment, certificate profile, key storage, auth protocol, revocation, trust path |
| FIDO/WebAuthn/passkeys | Attestation chain, authenticator firmware, server metadata, account recovery |
| S/MIME/OpenPGP | Sign/encrypt capability, recipient negotiation, key discovery, archive decryptability |
| Document/timestamp signing | Signature format, long-term validation, timestamp and archival evidence |
| DNSSEC | Algorithm support across signer, registrar, registry, validator; rollover and packet size |
| RPKI | CA/repository/validator profile, router support, manifest/ROA signature and rollover |
| Service mesh/API identity | Workload cert profile, sidecar/proxy support, rotation, mixed-chain behavior |

## Readiness inventory

For each relying-party ecosystem, record issuer, verifier, client/device population, algorithms,
profiles/OIDs, key location, enrollment, revocation, recovery, chain building, timestamp/archive,
maximum artifact size, software/firmware versions, owner, supplier roadmap, and rollback.

Test **all** verifiers, not only the issuer. Migration readiness is the intersection of issuance,
distribution, storage, presentation, validation, revocation, recovery, audit, and support tooling.

## Migration patterns

- **Dual credentials:** separate classical and PQ credentials with explicit selection policy.
- **Composite/hybrid credential:** both components bound and verified under a defined profile.
- **Dual-stack trust:** classical and PQ hierarchies coexist with non-overlapping policy and a
  dated retirement plan.
- **Gateway translation:** a controlled boundary terminates one trust profile and reissues another;
  document the trust transfer and prevent it from silently weakening end-to-end assurance.

Never treat "either signature validates" as hybrid assurance unless the policy explicitly intends
OR semantics. PB-05 and PB-08 `C2/C3/C11/C15` apply.

## Identity migration workflow

1. Map identity proofing, enrollment, issuance, binding, authentication, authorization, revocation,
   recovery, replacement, and retirement.
2. Identify device/card/authenticator constraints and populations that cannot be upgraded.
3. Build a private test hierarchy/profile; validate every client, proxy, directory, verifier,
   help-desk, recovery, logging, and forensic workflow.
4. Pilot dual credentials with explicit UI/telemetry showing which credential/path succeeded.
5. Gate rollout on success, latency, artifact size, revocation, recovery, and support outcomes.
6. Detect classical-only fallback where policy required PQ/hybrid and expire exceptions.

## Secure messaging and document workflow

- Discover encryption and signature use separately; a message may be PQ-encrypted but
  classically authenticated.
- Preserve access to required archives without retaining uncontrolled universal decryption keys.
- Bind sender, recipient, content, algorithm, context, and timestamp to the signature/envelope.
- Verify large signatures/certificates across clients, gateways, malware scanning, DLP, journaling,
  mobile, and archive systems.
- Define behavior when a recipient lacks PQ support: fail, approved classical exception, or
  alternate protected channel—never silent fallback.
- For long-term document validation, preserve algorithm/profile, certificate/revocation evidence,
  trusted timestamp, and migration/renewal evidence without claiming future validity beyond the
  standards and archive policy.

## DNSSEC and RPKI workflow

Treat both as ecosystem migrations with external dependencies:

- Inventory signer/HSM, control plane, parent/registry/registrar, publication, validator/resolver,
  router, monitoring, and emergency rollover support.
- Model packet/object growth, fragmentation, transport fallback, cache, and validation behavior.
- Use published standards/profiles supported by the ecosystem; do not deploy private PQ algorithm
  identifiers onto shared infrastructure.
- Exercise pre-publication validation, staged rollover, failure monitoring, withdrawal, and
  recovery. A broken trust publication can cause an availability incident at Internet scale.

## Detection logic

```json
{
  "rule": "enterprise_trust_pq_policy_violation",
  "trigger_any": [
    "credential_or_message required_pq_hybrid AND accepted_path == classical_only",
    "hybrid_signature accepted_components < policy.required_components",
    "verifier_path.anchor_or_policy != expected",
    "algorithm_oid_or_parameter != encoded_material",
    "revoked_component accepted",
    "fallback_reason missing_or_unapproved",
    "issued_profile unsupported_by_recovery_or_archive"
  ],
  "action": "deny_or_exception + alert + record_full_validation_path"
}
```

## Indicators

- Issuer advertises PQ but relying party validates only the classical component.
- Enrollment or recovery exports private key/seed outside approved hardware protection.
- Help-desk recovery silently replaces a high-assurance credential with weaker authentication.
- S/MIME/document gateway strips or resigns PQ/hybrid material without an explicit trust record.
- Client, proxy, and origin build different certificate paths or enforce different constraints.
- DNSSEC/RPKI object/packet size causes timeout, truncation, or validation fallback.
- FIDO/WebAuthn server trusts attestation metadata/chain inconsistent with policy.
- Exception population grows or has no owner/expiry.

## Investigation and response

1. Capture the full presented material and the validation path/decision at each relying party.
2. Confirm profile/OID/parameter, component semantics, trust anchor, constraints, EKU, revocation,
   time, and fallback policy.
3. Determine whether the failure is issuance, distribution, parser, path building, policy,
   revocation, recovery, gateway, or ecosystem support.
4. Contain by disabling the affected profile/path, requiring dual validation, or returning the
   population to a known-good credential—not by globally trusting a test anchor.
5. For Internet trust infrastructure, coordinate with the relevant operator before changes and
   use staged withdrawal/rollback.

## Escalation criteria

- Authentication or signing accepted under a policy-invalid component/path.
- Private identity/signing key or recovery seed exposed.
- Revoked or destroyed credential remains accepted.
- PQ migration breaks identity recovery, archive access, DNSSEC, RPKI, or critical service identity.
- External ecosystem lacks a standardized/supported target but a deployment is represented as compliant.

## Analyst notes

```text
TRUST-ID:           TRUST-____
Surface / owner:    PIV | workload | FIDO | S/MIME | document | DNSSEC | RPKI / ____
Issuer / verifier:  ____ / ____
Profile/OID/params: ____
Key location:       ____   extractable? Y/N
Policy semantics:   classical | PQ | AND-hybrid | OR-transition
Presented path:     ____   accepted path: ____
Revocation/time:    ____ / ____
Fallback/exception: ____ / ____ expires ____
Recovery/archive:   tested Y/N / tested Y/N
Disposition:        pass | hold | rollback | revoke | ecosystem-blocked | incident
```

## Summary

Enterprise PQ identity is a relying-party migration, not just a new certificate. Inventory every
issuer and verifier, make hybrid semantics explicit, test revocation/recovery/archive, control
fallback, stage ecosystem changes, and refuse to label draft or unsupported profiles as compliance.
