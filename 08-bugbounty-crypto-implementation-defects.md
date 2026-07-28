# 08 — Bug Bounty: Cryptographic Implementation & Migration-Defect Hunting (Authorized)

> **Authorization required.** Authorized testing only, GreyNOC as submitting firm, scope on
> file. See [CONVENTIONS §6 Rules of Engagement](CONVENTIONS.md). Least-impact, no fabrication,
> coordinated disclosure. This playbook is a **defect-class catalog with validation guidance**,
> not exploit tooling.

## Overview

PB-07 gives the methodology; this is the **catalog of defect classes** that PQ migration and
E2EE deployments tend to introduce, each with how to recognize it, how to confirm it without
overstepping, and how it maps to the defensive detectors. Hunt these by class, form a
falsifiable hypothesis per PB-07 Phase 3, and validate on your own scope.

## Defect-class catalog

### C1 — Hybrid downgrade / PQ-share stripping
- **What:** A path that should negotiate hybrid (e.g., `X25519MLKEM768`) ends up classical-only —
  via misconfig, a TLS-terminating middlebox, or active manipulation. Re-opens HNDL exposure.
- **Recognize:** server negotiates hybrid on a direct probe but the production path doesn't;
  key-share size shows the PQ component absent.
- **Confirm (read-only):** compare direct vs. through-path negotiation; document both. Do not
  attempt to *force* a downgrade on other users' traffic.
- **Maps to:** PB-03. **Typical severity:** medium–high by data shelf-life (PB-02).

### C2 — "PQ theater" — hybrid present but not enforced/verified
- **What:** PQ material is exchanged but contributes no security: a hybrid signature where only
  the classical half is verified, or a KEM combiner that doesn't actually bind both secrets.
- **Recognize:** verification succeeds when the PQ component is malformed/absent (test on your own
  tokens/sessions); spec/impl mismatch in how the shared secret is derived.
- **Confirm:** present your-own artifact with the PQ half removed/garbled to a test/your-own
  tenant verifier and observe acceptance. Self-scoped only.
- **Maps to:** PB-05 (single-half hybrid), PB-03. **Severity:** high (PQ is decorative).

### C3 — Signature algorithm confusion / downgrade
- **What:** verifier accepts `alg:none`, a symmetric alg where asymmetric is expected, a
  classical alg where policy mandates PQ/hybrid, or an attacker-influenced `kid`/JWKS.
- **Recognize:** verifier policy isn't bound to key type/algorithm allowlist.
- **Confirm:** with your-own token against your-own/test tenant, present a header-manipulated
  token and observe the trust decision. Never against third-party production identities.
- **Maps to:** PB-05. **Severity:** high if it yields a valid trust decision on your-controlled material.

### C4 — Non-validated / experimental provider in a regulated path
- **What:** `oqs-provider`/liboqs (reference, not FIPS-validated) or a draft FN-DSA build in a
  path that carries a FIPS-140-3 obligation.
- **Recognize:** provider/library fingerprint in headers, error strings, or documented stack.
- **Confirm:** passive identification; report as a compliance/assurance gap, not an exploit.
- **Maps to:** PB-01. **Severity:** context-dependent (compliance, not always technical break).

### C5 — Key-transparency / directory weaknesses (E2EE)
- **What:** identity-key insertions accepted without consistent inclusion proofs; split-view
  possible; verification UI bypassable.
- **Recognize:** key change on your own account accepted without a verifiable transparency proof;
  inconsistent directory state from two of your own vantage points.
- **Confirm:** observe with your own accounts/devices only. Do **not** attempt MITM of real users.
- **Maps to:** PB-04. **Severity:** high (trust-root integrity).

### C6 — Weak randomness / nonce or sampling defects in PQ implementations
- **What:** FN-DSA/Falcon is notoriously sampling-sensitive; lattice schemes need correct
  rejection sampling and fresh randomness. Implementation slips can leak key material.
- **Recognize:** This class generally requires deep crypto analysis and is **easy to mis-report**.
  Treat any "I think the RNG is weak" hunch with extreme skepticism.
- **Confirm:** only with rigorous, reproducible evidence (e.g., demonstrable repeated values you
  are authorized to observe). If you cannot prove it cleanly, it is **not a finding** — do not
  speculate. Consider responsible escalation to the vendor's crypto team over a bounty submission.
- **Maps to:** PB-01/05. **Severity:** critical *if proven*, but proof bar is very high.

### C7 — Oversized-artifact handling defects
- **What:** ML-DSA/SLH-DSA signatures and PQ certs are large; code paths that assumed small
  classical sizes may truncate, mishandle, or silently fall back to classical "to fit."
- **Recognize:** large PQ cert chains or tokens triggering fallback, truncation, or errors that
  degrade security.
- **Confirm:** observe handling of legitimately large PQ artifacts on your own scope.
- **Maps to:** PB-03/05. **Severity:** medium–high if it forces a security downgrade.

### C8 — Downgrade via interop/fallback logic
- **What:** "be compatible" fallback that silently drops PQ when the peer claims non-support,
  exploitable by spoofing non-support.
- **Recognize:** capability advertisement honored without integrity, enabling forced fallback.
- **Confirm:** on your own client/session, observe whether advertised non-support triggers an
  insecure fallback. Self-scoped.
- **Maps to:** PB-03/04. **Severity:** medium–high.

### C9 — KEM decapsulation failure and oracle behavior
- **What:** A decapsulation path exposes whether a ciphertext was valid through error, timing,
  output shape, retry, or downstream behavior instead of applying the algorithm's required failure
  handling and implicit rejection behavior.
- **Recognize:** malformed ciphertext classes produce stable, attributable response differences;
  the application distinguishes decapsulation failure from later authentication failure.
- **Confirm (least-impact):** only on your own endpoint/key material, compare a small,
  pre-registered set of valid and intentionally malformed ciphertexts. Record raw per-trial timing
  and categorical results. Do not fuzz a shared production endpoint or infer an oracle from two
  noisy requests.
- **Maps to:** PB-05/PB-25; NIST SP 800-227. **Severity:** high–critical only when a reliable
  oracle with a concrete cryptographic consequence is demonstrated.

### C10 — Side-channel, fault and secret-residue exposure
- **What:** Timing, cache, power, electromagnetic, fault, crash-dump, swap, accelerator-memory, or
  post-use residue exposes secret-dependent state from key generation, decapsulation, or signing.
- **Recognize:** secret-dependent timing in a controlled implementation; private seed/key material
  in an authorized crash dump or freed buffer; one tenant's key material visible in another
  authorized test partition.
- **Confirm:** hosted APIs permit only remote, rate-capped timing observation under explicit scope.
  Local power/fault/cache or memory-residue work requires host/device authorization and isolated
  lab equipment. Stop at the first secret-bearing minimal proof; never recover a production key.
- **Maps to:** PB-25; PB-20 `I4`. **Severity:** consequence and attacker position determine score.

### C11 — Encoding, parameter, OID and mode confusion
- **What:** Verifiers or decapsulators accept non-canonical encodings, wrong parameter sets,
  mismatched algorithm identifiers/OIDs, incorrect public-key/ciphertext/signature lengths, or
  confused pure/prehash/context modes.
- **Recognize:** parser normalizes two encodings to one trust decision; declared and actual
  parameter sets differ; a key or signature is accepted under the wrong OID or context.
- **Confirm:** mutate one field at a time in your own signed/encrypted artifact, keeping the
  expected rejection rule explicit. Acceptance without the required binding is the evidence.
- **Maps to:** PB-05/PB-10/PB-25. **Severity:** high when it creates acceptance or key-establishment
  under policy-invalid parameters; low when the effect is only a strictness issue.

### C12 — Hybrid combiner, transcript and domain-separation defects
- **What:** Classical and PQ secrets are combined without binding algorithm identifiers, roles,
  transcript, peer identities, context, or protocol domain; order is ambiguous; one component can
  be replayed or substituted across sessions/protocols.
- **Recognize:** implementation/spec mismatch; the same component secret or signature verifies in
  a different role/context; altered negotiation metadata does not change the derived binding.
- **Confirm:** prefer code/spec review and test vectors. Dynamic proof uses only your own peers and
  changes one bound input while holding the rest constant. Never transplant another user's traffic.
- **Maps to:** PB-03/PB-05/PB-09. **Severity:** high–critical if a component can be removed,
  substituted, or replayed without detection.

### C13 — PQ key and seed lifecycle failures
- **What:** Seeds/private keys are generated, stored, exported, backed up, rotated, escrowed,
  destroyed, or restored without the protections their algorithm and use require; public and
  private material or tenants share unintended seeds.
- **Recognize:** exportable production signing seeds, identical public keys across independent
  tenants/installations, no rotation path, plaintext seed in backup/config/log, or destroyed key
  still usable from a replica.
- **Confirm:** configuration and your own test keys are the default proof. Compare public
  fingerprints across your own installations; test revocation/rotation with your own artifact.
  Never use or export a discovered live production private key.
- **Maps to:** PB-25/PB-11/PB-13. **Severity:** critical for exposed fleet signing/decapsulation
  material; medium–high for missing lifecycle controls with a reachable misuse path.

### C14 — Stateful signature state reuse, rollback or exhaustion
- **What:** LMS/XMSS signing state is cloned, restored, raced, reused, or exhausted, causing a
  one-time signing index to repeat or the signer to continue after its safe state boundary.
- **Recognize:** HA nodes or restored backups share a state range; transactional state update is
  absent; rollback produces a previously used leaf/index; monitoring does not project exhaustion.
- **Confirm:** only in a vendor-provided test signer or your isolated lab key. Demonstrate repeated
  state/index metadata without signing harmful or production artifacts. Production evidence should
  be configuration/state-management proof, not an induced reuse.
- **Maps to:** PB-11/PB-25. **Severity:** critical if production signing state reuse is proven.

### C15 — Mixed-chain and trust-store migration failures
- **What:** Classical/PQ/composite certificate or signing chains validate under inconsistent path,
  trust-anchor, revocation, name-constraint, EKU, or policy rules across clients and gateways.
- **Recognize:** a PQ/hybrid leaf is accepted through an unintended classical anchor; one path
  skips revocation or constraints; a proxy and origin reach different trust decisions.
- **Confirm:** use a private test hierarchy and your own clients/services. Present controlled
  alternate paths and record the exact path each verifier built. Never introduce a test CA into a
  shared production trust store.
- **Maps to:** PB-10/PB-05/PB-26. **Severity:** high when the alternate path bypasses a required
  trust or identity control.

## Hunting workflow

1. Pick a class above; write the falsifiable hypothesis (expected-secure behavior + falsifier).
2. Fingerprint the target's relevant surface read-only (PB-07 Phase 2).
3. Validate on your own scope with the minimum proof; reproduce twice from clean state.
4. If unproven, record the falsifier result and move on — a clean negative is a real outcome.
5. If proven, write one finding per defect with reproducible, redacted evidence.

## Anti-patterns (do not do these)

- Reporting C6-style "weak randomness" or "quantum-broken!" on a hunch with no reproducible proof.
  This is the most common low-quality PQ bug-bounty submission; it burns program trust.
- Inflating severity by asserting future-quantum impact without demonstrating present
  exploitability. State HNDL exposure factually (PB-02), don't dramatize it.
- Crossing into third-party dependencies or other users' data "just to confirm."
- Copying CVE/advisory text and presenting it as original analysis.

## Validation discipline (the GreyNOC bar)

- **Reproducible or it didn't happen.** Two clean reproductions, minimal steps, redacted evidence.
- **Self-scoped proof.** Demonstrate on your own accounts/tokens/sessions; never on real users.
- **Honest impact.** Map to a concrete, demonstrated consequence and the relevant defensive
  playbook the org would use to detect/fix it.

## Report template

Use the PB-07 report template. Add a `DEFECT-CLASS:` line (C1–C15) and a `PROOF-BAR-MET:` line
(`reproduced-twice: Y/N`, `self-scoped: Y/N`) so triage can immediately see the evidence quality.

## Stop conditions

The standing [CONVENTIONS §6](CONVENTIONS.md) stop conditions apply. Additionally stop on any
production private key/seed, real-user plaintext, stateful-signature reuse, shared-service
degradation, or result that would require continued oracle/side-channel sampling beyond the
program's written budget. Preserve the minimum evidence and notify the program.

## Summary

Migration-defect hunting is high-yield right now because organizations are swapping primitives
fast. Work the C1–C15 catalog by class, hold randomness and crypto-internals classes to an exacting
proof bar (refuse to speculate), keep every test self-scoped and least-impact, and report only
reproducible findings with honest, demonstrated impact. That discipline is what separates a
credible GreyNOC submission from the flood of low-quality "quantum" noise programs are learning
to ignore.
