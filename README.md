# GreyNOC Security Playbooks — AI · Post-Quantum · E2EE

Production-grade detection, response, and authorized-testing playbooks authored by the
GreyNOC detection-engineering team. This collection is re-centered on the cryptographic
transition that now defines the threat surface: **post-quantum (PQ) migration**,
**end-to-end-encrypted (E2EE) protocol security**, and **AI-augmented detection** —
with two playbooks dedicated to **authorized bug-bounty methodology** against PQ/E2EE
attack surface.

Each playbook follows the standard GreyNOC structure: overview, MITRE ATT&CK / ATLAS
mapping, detection strategy, indicators, sample logic, example data, investigation steps,
false positives, tuning, response actions, escalation criteria, an analyst-notes template,
and a closing summary. Written for SOC analysts, IR, detection engineers, and authorized
offensive operators. Behavior-based over signature-based; operational clarity over theory.

> **Why this rewrite.** NIST finalized the first PQ standards in August 2024 (FIPS 203
> ML-KEM, FIPS 204 ML-DSA, FIPS 205 SLH-DSA), with FN-DSA (FIPS 206) and the HQC backup
> KEM following. Hybrid TLS (`X25519MLKEM768`, NamedGroup `0x11EC`) is now default or
> near-default across Chrome, Firefox, Cloudflare, Akamai, and AWS, and E2EE messengers
> (Signal PQXDH, iMessage PQ3) ship PQ key establishment in production. The window where
> "crypto detection" meant "expired certs and weak ciphers" is closed. The dominant risk is
> now **harvest-now-decrypt-later (HNDL)**, **downgrade of hybrid handshakes**, and
> **migration-defect classes** introduced while organizations swap primitives under deadline.

---

## Index

| #  | Playbook | Focus |
| --- | --- | --- |
| 01 | [Cryptographic Inventory & PQC Readiness](01-cryptographic-inventory-pqc-readiness.md) | CBOM discovery, AI/LLM-assisted code auditing, crypto-agility scoring |
| 02 | [Harvest-Now-Decrypt-Later Exposure](02-harvest-now-decrypt-later.md) | Bulk-capture detection, long-shelf-life data prioritization |
| 03 | [Hybrid TLS / KEM Downgrade](03-hybrid-tls-kem-downgrade.md) | PQ key-exchange stripping, negotiation downgrade, middlebox tampering |
| 04 | [E2EE Messaging Protocol Security](04-e2ee-messaging-protocol-security.md) | Double Ratchet / PQXDH / PQ3 / MLS, key-transparency & MITM detection |
| 05 | [PQ Signature & Token Integrity](05-pq-signature-token-integrity.md) | ML-DSA / SLH-DSA / FN-DSA, JWT/SAML/X.509, algorithm-confusion |
| 06 | [AI-Augmented Detection & Guardrails](06-ai-augmented-detection-guardrails.md) | LLM-assisted triage, pipeline poisoning & prompt-injection defense (ATLAS) |
| 07 | [Bug Bounty: PQC/E2EE Methodology](07-bugbounty-pqc-e2ee-methodology.md) | Authorized recon → crypto-surface mapping → validation → reporting |
| 08 | [Bug Bounty: Crypto Implementation Defects](08-bugbounty-crypto-implementation-defects.md) | Authorized hunting of migration/downgrade/oracle defect classes |

See [CONVENTIONS.md](CONVENTIONS.md) for shared algorithm reference, named groups,
documentation address space, and **rules of engagement** that bind playbooks 07–08.

---

## How to Use

1. Read the playbook end-to-end before deploying any rule.
2. Map data sources to your environment; verify telemetry sufficiency before relying on a
   detection. PQ/E2EE detection depends on handshake- and key-level visibility that many
   estates do not yet log — confirm you have it before trusting the absence of alerts.
3. Translate the JSON-shaped sample logic to your platform (KQL, SPL, EQL, Sigma, etc.);
   validate on historical data where possible.
4. Adopt the analyst-notes template into your case-management workflow.
5. For playbooks 07–08, do not begin any activity without a signed authorization / program
   scope on file. GreyNOC operates as the submitting firm; ROE in CONVENTIONS is mandatory.
6. Revisit tuning after every confirmed true positive and false positive.

---

*GreyNOC — detection-engineering-first security operations. No fabrication: every finding,
indicator, and report artifact must be reproducible from evidence.*
