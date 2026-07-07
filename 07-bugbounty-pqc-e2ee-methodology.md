# 07 — Bug Bounty: PQC / E2EE Attack-Surface Methodology (Authorized)

> **Authorization required.** This playbook is for authorized testing only — a signed
> engagement or an in-scope, in-policy bug-bounty program, with GreyNOC as the submitting firm.
> Read [CONVENTIONS §6 Rules of Engagement](CONVENTIONS.md) before any activity. No scope on
> file = no testing. Least-impact, no fabrication, coordinated disclosure.

## Overview

A repeatable methodology for hunting real, reportable issues in an organization's post-quantum
and E2EE attack surface. The migration to PQ is being done under deadline across millions of
endpoints, which is exactly when implementation and configuration defects appear. This playbook
takes you from recon to a reproducible, well-scored report — emphasizing **read-only
inspection** and **validation discipline** over anything intrusive.

This is the offensive complement to the defensive playbooks: the classes you hunt here are the
same ones PB-03, PB-04, and PB-05 detect.

## Surface map

| Surface | What to look at | Defensive twin |
| --- | --- | --- |
| TLS / key exchange | offered vs. negotiated groups, hybrid support, downgrade/strip behavior | PB-03 |
| Certificates / chains | signature algorithms, PQ/hybrid handling, large-cert behavior | PB-05 |
| Tokens / federation | JWT/JWS/SAML alg handling, `kid`/JWKS trust, hybrid-sig verification | PB-05 |
| E2EE messaging | key-bundle handling, key-transparency/verification, negotiation fallback | PB-04 |
| Code / firmware signing | algorithm policy, pipeline trust | PB-05 |
| Crypto provider | FIPS-validated vs. experimental (e.g. `oqs-provider`) in a regulated path | PB-01 |

## Methodology (phased)

### Phase 0 — Scope & ROE confirmation
- Confirm in-scope assets, allowed test types, rate limits, and disclosure terms in writing.
- Identify out-of-scope dependencies (shared CDNs, third-party IdPs) — do not cross into them.
- Stand up an evidence-logging workflow so every action is timestamped and reproducible.

### Phase 1 — Passive recon (no traffic to target where possible)
- Enumerate in-scope hostnames/endpoints from program scope and your own OSINT (no intrusive scans).
- Note which platforms/CDNs front the targets (informs expected PQ capability, e.g., a Cloudflare/
  Akamai-fronted host should support hybrid).
- Build a target-specific surface list mapped to the table above.

### Phase 2 — Capability fingerprinting (read-only)
- Observe TLS negotiation behavior with benign, read-only handshakes you are authorized to make:
  ```
  openssl s_client -connect HOST:443 -groups X25519MLKEM768 -tls1_3 </dev/null
  openssl s_client -connect HOST:443 -tls1_3 </dev/null   # default negotiation
  ```
  Record offered vs. negotiated groups, cert signature algorithms, chain composition.
- For token/federation surfaces you are authorized to exercise, capture sample tokens *issued to
  you* (your own session) and record header `alg`, `kid`, `jwks_uri`.
- For E2EE products, document the published protocol (PQXDH/PQ3/MLS), key-bundle flow, and the
  key-verification/transparency mechanism — from your own account/devices only.

### Phase 3 — Hypothesis & defect-class targeting
Form falsifiable hypotheses tied to a class (full class catalog in PB-08), e.g.:
- "Server supports hybrid directly but live path negotiates classical (strip/misconfig)." → PB-03 class
- "Verifier accepts a classical `alg` where policy mandates PQ/hybrid (downgrade)." → PB-05 class
- "Hybrid signature verifies with only the classical component present." → PB-05 class
- "Identity-key change in the messaging app is accepted without transparency-proof consistency." → PB-04 class

Each hypothesis must state the expected-secure behavior and what observation would **falsify** it,
so a non-finding is recorded as cleanly as a finding (GreyNOC falsifier-required discipline).

### Phase 4 — Controlled validation (least-impact)
- Test against **your own** sessions/tokens/accounts wherever possible. Use the minimum proof to
  demonstrate the issue; never pivot, never touch other users' data.
- Prefer observation and single-request demonstrations over fuzzing campaigns; if a program allows
  active testing, stay within rate limits and stop at proof-of-concept.
- Reproduce twice from a clean state before believing a result.

### Phase 5 — Report
- One finding per defect, each independently reproducible from the evidence (see report template).
- Score impact honestly against real exploitability; do not inflate severity (no fabrication).

## Validation aids (read-only / self-scoped)

- TLS group/cert inspection: `openssl s_client` as above; browser devtools key-exchange view;
  Cloudflare's PQ test endpoint to confirm *your client's* hybrid behavior.
- Token inspection: decode JWT headers (your own tokens) to read `alg`/`kid`/`jwks_uri`; verify
  the verifier's algorithm policy by presenting your-own re-signed token *only against test/your
  own tenant where authorized*.
- E2EE: use the product's own safety-number / contact-key verification UI on your own devices to
  observe key-change and proof behavior.

## What "good" vs. "not a finding" looks like

- **Finding:** a verifier accepts policy-invalid material; a hybrid path strips PQ; a hybrid sig
  validates on the classical half alone; a key directory accepts an unprovable insertion.
- **Not a finding:** a legacy client negotiating classical (client-side, not a server defect); a
  documented migration window intentionally accepting both algorithms; large-cert cosmetic warnings.

## Report template

```
TITLE:        ____ (defect class — surface)
PROGRAM/SCOPE: ____   (auth ref: ____)
SEVERITY:     ____  (CVSS/program scale + honest exploitability rationale)
SURFACE:      TLS-KEM | cert | token/federation | E2EE | code-signing | provider
HYPOTHESIS:   expected-secure behavior: ____
OBSERVATION:  what actually happened: ____
REPRODUCTION: exact, minimal, self-scoped steps (commands/requests): ____
EVIDENCE:     logs/captures/screens (redacted of third-party data): ____
IMPACT:       concrete, demonstrated (no speculation): ____
REMEDIATION:  recommended fix (ties to PB-03/04/05): ____
FALSIFIER:    what observation would have disproven this: ____
```

## Stop conditions

Stop, preserve, and escalate to the program owner on: evidence of a prior real compromise,
exposure of third-party PII/secrets/plaintext, or anything that would require leaving authorized
scope to prove. Do not "just confirm" by overstepping.

## Summary

Hunt the PQ/E2EE surface the way the defensive playbooks watch it: fingerprint capability
read-only, form falsifiable hypotheses against known defect classes, validate with least impact
on your own scope, and report only what you can reproduce. The migration deadline is generating
real, high-value findings — discipline and honesty are what make them count and keep GreyNOC's
submitting-firm standing clean.
