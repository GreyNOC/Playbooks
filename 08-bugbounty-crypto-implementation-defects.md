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

Use the PB-07 report template. Add a `DEFECT-CLASS:` line (C1–C8) and a `PROOF-BAR-MET:` line
(`reproduced-twice: Y/N`, `self-scoped: Y/N`) so triage can immediately see the evidence quality.

## Summary

Migration-defect hunting is high-yield right now because organizations are swapping primitives
fast. Work the catalog by class, hold the C6 randomness/crypto-internals class to an exacting
proof bar (refuse to speculate), keep every test self-scoped and least-impact, and report only
reproducible findings with honest, demonstrated impact. That discipline is what separates a
credible GreyNOC submission from the flood of low-quality "quantum" noise programs are learning
to ignore.
