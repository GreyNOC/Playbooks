# GreyNOC Security Playbooks

Production-grade detection, response, and authorized-testing playbooks authored by the GreyNOC detection-engineering team. The library spans three complementary collections:

- **Detection & Response** — behavior-based SOC playbooks across the intrusion lifecycle, from initial access to impact, including AI incident response and inference-serving isolation.
- **AI · Post-Quantum · E2EE** — 28 playbooks covering the cryptographic transition, E2EE protocol security, enterprise AI governance/development/data/resilience, eight authorized bug-bounty playbooks — two against PQ/E2EE attack surface and six against AI systems — and an operator prompt library for AI-assisted security work.
- **Transmission & Physical Layer** — 3 playbooks covering the media everything else runs on and the silicon underneath them: radio-frequency spectrum, nanometer-scale optical, and post-quantum cryptography as it actually executes in fabricated logic. Where the adversary never touches a network port, where harvest-now-decrypt-later capture actually happens, and where a compiler can undo a constant-time implementation.

Every detection playbook follows the same GreyNOC structure: overview, MITRE ATT&CK / ATLAS mapping, detection strategy, indicators, sample logic, example data, investigation steps, false positives, tuning, response actions, escalation criteria, an analyst-notes template, and a closing summary. The authorized-testing playbooks (07–08, 15–20) follow the bug-bounty structure instead: overview, MITRE mapping, surface map or defect-class catalog, phased methodology or hunting workflow, anti-patterns, validation discipline, report template, stop conditions, and summary. Two sets of files deliberately carry neither structure, and this is noted so the difference does not read as an omission: the governance playbooks (21–24) are control-and-evidence documents organized around ownership, gates, and audit artifacts rather than detections; and the prompt library (28) is organized as prompt families, each entry carrying a use case, required inputs, the prompt, an output contract, and the verification step that must pass before the output is used. Written for SOC analysts, IR, detection engineers, and authorized offensive operators. Behavior-based over signature-based; operational clarity over theory.

> **MITRE mapping baseline.** Every ATT&CK mapping in the library is pinned to **ATT&CK Enterprise
> v19.2** (and ICS v19.2 for the TX collection), verified technique-by-technique against
> `attack.mitre.org` on **2026-08-09**; ATLAS citations are pinned to **collection 2026.06**. Each
> mapping table carries a *Mapping discipline* note naming the version it was checked against,
> because **names, IDs, and tactic assignments all move between releases**. ATT&CK v19 in
> particular retired the **Defense Evasion** tactic — `TA0005` became **Stealth** and `TA0112`
> **Defense Impairment** was split out — and renumbered techniques along the way: `T1562 Impair
> Defenses` and `T1070.001 Indicator Removal: Clear Windows Event Logs` no longer exist, and they
> do **not** resolve to the same replacement. `T1562` maps to the parent `T1685 Disable or Modify
> Tools`; `T1070.001` maps to the sub-technique **`T1685.005`**, so log-clearing detections keep
> their specificity instead of collapsing into the generic parent. Re-map to
> the collections your platform carries before deploying anything here. The rules are
> [CONVENTIONS §4](CONVENTIONS.md).

> **Why the crypto collection.** NIST finalized the first PQ standards in August 2024 (FIPS 203 ML-KEM, FIPS 204 ML-DSA, FIPS 205 SLH-DSA). Falcon / expected FN-DSA (FIPS 206) remains in development, and HQC has been selected as a backup KEM but is not yet standardized. Hybrid TLS (`X25519MLKEM768`, NamedGroup `0x11EC`) is deployed across major browsers and edge providers while its IETF specification progresses; verify current protocol status before making a standards claim. E2EE messengers (Signal PQXDH, iMessage PQ3) ship PQ key establishment in production. The dominant risks are now **harvest-now-decrypt-later (HNDL)**, **downgrade of hybrid handshakes**, and **migration-defect classes** introduced while organizations swap primitives under deadline.

A visual index of the full library is available in [index.html](index.html). Two compiled field
references are published:

| Publication | Key | Version | Contents |
| --- | --- | --- | --- |
| [GreyNOC_AI_PQC_Playbooks.pdf](output/pdf/GreyNOC_AI_PQC_Playbooks.pdf) | `ai-pqc` | v2.2.0 | The AI · Post-Quantum · E2EE collection, three AI D&R playbooks, and `CONVENTIONS.md` |
| [GreyNOC_Transmission_Physical_Layer_Playbooks.pdf](output/pdf/GreyNOC_Transmission_Physical_Layer_Playbooks.pdf) | `transmission` | v1.2.0 (2026-08-09) | The Transmission & Physical Layer collection, its coverage audit, and `CONVENTIONS.md` |

Rebuild both with `node scripts/build_playbook_pdfs.mjs`, one with
`node scripts/build_playbook_pdfs.mjs <key>`, or list the available publications with
`node scripts/build_playbook_pdfs.mjs --list`. Adding a collection means adding an entry to the
`PUBLICATIONS` array in that script — the Markdown-to-PDF pipeline itself is shared.

---

## Detection & Response Playbooks

| # | Playbook | Focus |
|---|----------|-------|
| 01 | [Password Spraying](01-password-spraying.md) | Distributed credential access against IdPs |
| 02 | [Brute Force Attack](02-brute-force.md) | Single-target authentication abuse |
| 03 | [Distributed Port Scan](03-distributed-port-scan.md) | Multi-source coordinated reconnaissance |
| 04 | [Credential Stuffing](04-credential-stuffing.md) | Leaked-credential replay against web/SaaS |
| 05 | [Impossible Travel](05-impossible-travel.md) | Geographic velocity + risk-feature composite |
| 06 | [Privilege Escalation](06-privilege-escalation.md) | Identity, endpoint, and cloud elevation |
| 07 | [Suspicious PowerShell Execution](07-suspicious-powershell.md) | Encoded, in-memory, and parented PowerShell abuse |
| 08 | [Malware Beaconing](08-malware-beaconing.md) | Periodic C2 traffic detection |
| 09 | [AI / Automated Agent Abuse](09-ai-automated-agent-abuse.md) | Adversary automation and owned-AI-feature abuse |
| 10 | [Coordinated Multi-Stage Attack](10-coordinated-multi-stage-attack.md) | Kill-chain correlation across entities |
| 11 | [Phishing](11-phishing.md) | Malicious email delivery, AiTM/MFA-bypass, retro-hunting |
| 12 | [Business Email Compromise](12-business-email-compromise.md) | Post-compromise mailbox rules, forwarding, OAuth abuse |
| 13 | [Lateral Movement](13-lateral-movement.md) | Host-to-host propagation and authentication-edge anomalies |
| 14 | [Active Directory Credential Theft](14-ad-credential-theft.md) | Kerberoasting, DCSync, LSASS dumping, ticket forgery |
| 15 | [Persistence Mechanisms](15-persistence-mechanisms.md) | Tasks, services, run keys, WMI subscriptions, rogue accounts |
| 16 | [Web Shell](16-web-shell.md) | Post-exploitation implants in the webroot |
| 17 | [Data Exfiltration](17-data-exfiltration.md) | Staging and egress anomalies to cloud, C2, and alt protocols |
| 18 | [Ransomware](18-ransomware.md) | Recovery-inhibition precursors and mass-encryption impact |
| 19 | [AI Security Incident Response & Evidence](19-ai-security-incident-response.md) | AI-specific triage, evidence, containment, provider coordination, and recovery |
| 20 | [AI Serving Plane & Multi-Tenant Isolation](20-ai-serving-plane-isolation.md) | Gateway authz, cache/batch isolation, model routing, quotas, and inference telemetry |

---

## AI · Post-Quantum · E2EE Playbooks

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
| 09 | [Post-Quantum VPN, IPsec & SSH Migration](09-pq-vpn-ipsec-ssh.md) | Hybrid KEX for IKEv2/IPsec, OpenSSH, WireGuard; tunnel downgrade detection |
| 10 | [Post-Quantum PKI & Certificate Lifecycle](10-pq-pki-certificate-lifecycle.md) | ML-DSA CA hierarchies, composite certs, CT mis-issuance, PQ-scale revocation |
| 11 | [Post-Quantum Code Signing & Firmware Integrity](11-pq-code-signing-firmware.md) | LMS/XMSS firmware & ML-DSA supply-chain signing; stateful-key hazards |
| 12 | [Post-Quantum E2EE for Real-Time Media](12-pq-e2ee-realtime-media.md) | WebRTC/DTLS-SRTP, SFrame, MLS calls; downgrade & ghost-participant detection |
| 13 | [Crypto-Agility & PQ Migration Operations](13-crypto-agility-migration-ops.md) | Agility architecture, wave rollout, rollback gates, algorithm-break runbook |
| 14 | [Quantum Risk Governance & Compliance](14-quantum-risk-governance.md) | Mosca's inequality, CNSA 2.0 / NSM-10 mandates, evidence-backed reporting |
| 15 | [Bug Bounty: AI & LLM Attack-Surface Methodology](15-bugbounty-ai-attack-surface-methodology.md) | Trust-boundary mapping, test harness, trial ledgers, security-vs-safety routing |
| 16 | [Bug Bounty: LLM Application-Layer Defects](16-bugbounty-llm-application-defects.md) | `L1–L19` — prompt injection, RAG scope, output handling, sessions, app authz, template and role-delimiter injection, schema coercion, streaming races, multimodal carriers, compaction provenance loss |
| 17 | [Bug Bounty: AI Supply Chain & Model Artifacts](17-bugbounty-ai-supply-chain-model-artifacts.md) | `S1–S12` — artifact provenance, registries, pipelines, PQ signing gaps, runtime and serving-image provenance, unsigned transforms |
| 18 | [Bug Bounty: Agentic Systems, Tools & the MCP Boundary](18-bugbounty-agentic-systems-mcp.md) | `G1–G14` — tool poisoning, confused deputy, connector scope, autonomy limits, run-initiation boundary, action attribution |
| 19 | [Bug Bounty: Model Behavior & Safety-Boundary Testing](19-bugbounty-model-behavior-safety-boundaries.md) | Routing, measurement standard, proof without harm — model-safety channel |
| 20 | [Bug Bounty: Inference Infrastructure & Multi-Tenant Isolation](20-bugbounty-inference-infrastructure-isolation.md) | `I1–I12` — control plane, tenant routing, caches, quotas, inference transport, vector-store tenancy, platform telemetry tenancy |
| 21 | [AI Governance, Asset Inventory & Third-Party Risk](21-ai-governance-asset-third-party-risk.md) | AI-BOM, risk tiers, shadow AI, approval, supplier assurance, and lifecycle ownership |
| 22 | [AI Secure Development, TEVV & Change Management](22-ai-secure-development-tev-v-change-management.md) | Threat modeling, evaluation gates, immutable release identity, regression and drift |
| 23 | [AI Data Governance, Privacy, Retention & DLP](23-ai-data-governance-privacy-retention.md) | End-to-end AI data flows, provider use, RAG/memory governance, deletion and DLP |
| 24 | [AI Resilience, Business Continuity & Decommissioning](24-ai-resilience-continuity-decommissioning.md) | Safe degraded modes, scoped kill controls, failover, recovery and complete retirement |
| 25 | [PQ Key Management & Data-at-Rest Migration](25-pq-key-management-data-at-rest.md) | PQ key/seed lifecycle, KMS/HSM, rewrap/re-encryption, backup and recovery |
| 26 | [PQ Enterprise Identity, Messaging & Trust Infrastructure](26-pq-enterprise-identity-messaging-trust.md) | PIV/FIDO, S/MIME, document signing, DNSSEC, RPKI and relying-party migration |
| 27 | [PQ Capacity, Interoperability & Vendor Assurance](27-pq-capacity-interoperability-vendor-assurance.md) | Artifact growth, HSM/network capacity, interop matrix, procurement and vendor evidence |
| 28 | [AI Prompt Library for Cyber Operations](28-ai-prompt-library-cyber-operations.md) | `P-DEF`/`P-OFF`/`P-BTY`/`P-BUG`/`P-REP` — 37 operator prompts with output contracts and verification steps, across defense, offensive security, bounty, bug analysis and reporting |

---

## Transmission & Physical Layer Playbooks

The media every other playbook assumes and none of them examined, plus the silicon beneath them.
All three are detection-and-response playbooks; none is a bug-bounty playbook, and none owns a
defect-class prefix.

| #  | Playbook | Focus |
| --- | --- | --- |
| TX-01 | [RF & Radio-Spectrum Intrusion](TX-01-rf-spectrum-intrusion.md) | Wi-Fi, BLE, cellular, GNSS spoofing, LPWAN implants, jamming, backhaul; RF-BOM and sensing tiers |
| TX-02 | [Nanometer-Scale Optical Data Transmission, Reception & Intrusion Handling](TX-02-optical-nm-data-transmission-intrusion.md) | Optical create/receive chain, fiber tapping, ROADM abuse, rogue wavelengths, FSO/laser links, optical air-gap channels |
| TX-03 | [PQC at the Nanometer Scale: Silicon, Physical Attack & the Physics Floor](TX-03-pq-nanometer-silicon-physical-attack.md) | ML-KEM/ML-DSA in silicon — compiler-induced timing defects, Rowhammer, laser FI, optical probing, hardware trojans, the FIPS side-channel assurance gap, and the Planck-scale scope floor |

Two structural limits are stated in both playbooks and should be carried into any report built on
them: **passive interception is undetectable in principle** (the answer is cryptographic, not
telemetric), and **detection is bounded by the bands and spans you actually instrument** — an empty
alert queue for an uninstrumented medium is a coverage gap, not a clean result.

The physical-layer coverage audit that produced this collection, including the reproducible term
sweep and the residual gaps it does **not** close, is in
[QAQC-physical-layer-coverage.md](QAQC-physical-layer-coverage.md).

---

See [CONVENTIONS.md](CONVENTIONS.md) for shared algorithm reference, named groups, documentation address space, the **MITRE mapping conventions** (§4) that pin and version every ATT&CK and ATLAS citation, **rules of engagement** (§6) that bind every bug-bounty playbook, the **AI-system testing addendum** (§7) that binds 15–20, the **defect-class registry and AI evidence notation** (§8), and the **versioned reference baseline** (§9).

---

## How to Use

1. Read the playbook end-to-end before deploying any rule.
2. Map data sources to your environment; verify telemetry sufficiency before relying on a detection. PQ/E2EE detection in particular depends on handshake- and key-level visibility that many estates do not yet log — confirm you have it before trusting the absence of alerts.
3. Translate the JSON-shaped sample logic to your platform (KQL, SPL, EQL, Sigma, etc.); validate on historical data where possible.
4. Re-map every MITRE citation to the collection your platform actually carries before you tag a detection with it. The baseline here is ATT&CK v19.2 / ATLAS 2026.06, stated in each table's *Mapping discipline* note; a SIEM still on a pre-v19 ATT&CK will not recognize `T1685`, and one on v19+ will not recognize `T1562`. Never sweep a tactic rename across a table — v19 renamed some assignments, renumbered others, and removed a few outright.
5. Adopt the analyst-notes template into your case-management workflow.
6. For the bug-bounty playbooks (crypto collection 07–08 and 15–20), do not begin any activity without a signed authorization / program scope on file. GreyNOC operates as the submitting firm; ROE in CONVENTIONS §6 is mandatory, and §7 adds non-negotiable rules for AI targets — self-scoped tenancy, inert canaries, capped request budgets, trial ledgers, and never generating genuinely harmful content as proof.
7. Revisit tuning after every confirmed true positive and false positive.

---

*GreyNOC — detection-engineering-first security operations. No fabrication: every finding, indicator, and report artifact must be reproducible from evidence.*
