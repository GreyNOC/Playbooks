# CONVENTIONS

Shared reference for the GreyNOC AI · PQ · E2EE playbook collection. Cited values reflect
the standards landscape as of mid-2026; verify against current NIST / IETF publications
before operational use, because this space is still moving.

---

## 1. Algorithm reference

**Key encapsulation (KEM) — replaces RSA / ECDH key exchange**

| Standard | Name | Basis | Parameter sets | Notes |
| --- | --- | --- | --- | --- |
| FIPS 203 | ML-KEM (Kyber) | Module-LWE lattice | 512 / 768 / 1024 | Primary KEM. ML-KEM-768 ciphertext ~1088 B |
| In development (final expected 2027) | HQC | Code-based (quasi-cyclic) | TBD | Backup KEM selected Mar 2025; **not yet a standard**; diversity hedge vs. lattice break |

**Signatures — replaces RSA / ECDSA / EdDSA**

| Standard | Name | Basis | Parameter sets | Notes |
| --- | --- | --- | --- | --- |
| FIPS 204 | ML-DSA (Dilithium) | Module-LWE/SIS lattice | 44 / 65 / 87 | **ML-DSA-65 is the recommended default.** Sig ~3309 B, pubkey ~1952 B |
| FIPS 205 | SLH-DSA (SPHINCS+) | Hash-based | many | Conservative backup; large sigs (~7.8–49.9 KB) |
| FIPS 206 (in development) | FN-DSA (Falcon) | NTRU lattice + FFT | — | Selected algorithm and expected standard name; **do not claim FIPS 206 compliance until final publication** |
| SP 800-208 | LMS / XMSS | Hash-based, stateful | — | Use **now** for firmware/code-signing per NSA guidance |

**Security levels:** L1 ≈ AES-128, L3 ≈ AES-192, L5 ≈ AES-256. Grover halves symmetric
strength, so for long-retention data prefer **AES-256** and **SHA-384** over AES-128/SHA-256.

**Naming discipline.** Use standardized names (ML-KEM, ML-DSA, SLH-DSA) in all reports,
tickets, and findings. Submission names (Kyber, Dilithium, SPHINCS+) are acceptable only as
parenthetical aliases. For Falcon, write **Falcon / expected FN-DSA (FIPS 206 in development)**
until FIPS 206 is final. Never represent a selected algorithm, draft, or reserved standard name
as a completed compliance target.

---

## 2. Hybrid TLS named groups

Hybrid = classical + PQ KEM run together; an attacker must break **both** to recover the
session key. Watch for these in `ClientHello` / `ServerHello` `supported_groups` / `key_share`:

| NamedGroup | Value | Composition | Client key share |
| --- | --- | --- | --- |
| X25519MLKEM768 | `0x11EC` | X25519 + ML-KEM-768 | ~1216 B |
| SecP256r1MLKEM768 | (impl-specific) | P-256 + ML-KEM-768 | — |
| SecP384r1MLKEM1024 | (impl-specific) | P-384 + ML-KEM-1024 | — |

Production support: Chrome/BoringSSL, Firefox, Cloudflare, Akamai (default Feb 2026), AWS,
OpenSSL 3.5+ (native), wolfSSL, rustls, Botan. `oqs-provider` (liboqs) is the reference
experimentation provider and is **not** FIPS-validated — flag it if seen in a production path.

Quick manual check (read-only inspection of a host you are authorized to test):
```
openssl s_client -connect HOST:443 -groups X25519MLKEM768 -tls1_3 </dev/null 2>/dev/null \
  | grep -i "Negotiated\|group"
```

---

## 3. E2EE protocol reference

| System | PQ status | Construction | Notes |
| --- | --- | --- | --- |
| Signal PQXDH | PQ initial key establishment (Level 2) | X25519 + ML-KEM, Double Ratchet | Sept 2023; PQ at handshake only |
| iMessage PQ3 | PQ initial + ongoing rekey (Level 3) | hybrid ECDH + ML-KEM, periodic PQ rekey (~every 50 epochs) | Uses signatures over MAC; Secure Enclave signing |
| MLS (RFC 9420) | classical baseline; PQ ciphersuites emerging | TreeKEM group key agreement | Group E2EE; watch ciphersuite negotiation |

**Open problem to keep in scope:** PQ *authentication* ("Level 4") is not solved at scale by
PQXDH or PQ3 — both still authenticate with classical primitives. Key-transparency systems
(iMessage Contact Key Verification, WhatsApp Auditable Key Directory) are the current
mitigations against key-substitution MITM; monitoring them is a detection opportunity (PB-04).

---

## 4. MITRE mapping conventions

- **ATT&CK** technique IDs are referenced where an enterprise technique applies
  (e.g., T1040 Network Sniffing, T1557 Adversary-in-the-Middle, T1600 Weaken Encryption,
  T1556 Modify Authentication Process, T1110 Brute Force, T1552 Unsecured Credentials).
- **ATLAS** is referenced as **name + ID + collection version** — e.g. *LLM Prompt Injection*
  (`AML.T0051`, ATLAS 2026.06). **Both the ID and the name are versioned and both do change**, so
  neither is cited bare: the collection version is what makes a citation checkable. Any playbook
  citing ATLAS states the collection version it was written against, and a reader re-maps to
  whatever their platform carries at deployment time.
  - The AI playbooks in this library (PB-15–PB-20) are written against the official
    `mitre-atlas/atlas-data` collection **version 2026.06** (format-version 6.0.0, collection
    `modified-date` 2026-05-27, published 2026-06-30). Verified from `dist/v6/ATLAS-2026.06.yaml`:
    **16 tactics** and **173 techniques** (103 parent techniques + 70 sub-techniques), of which
    **114 list `Agentic AI`** and **92 list `Generative AI`** among their `platforms` — every
    `Generative AI` technique also carries `Agentic AI`, so 114 is the union, not the sum.
  - **2026.06 renamed most `ML` techniques to `AI`, and renamed some outright.** Cite the 2026.06
    name: `AML.T0010` is *AI Supply Chain Compromise*, `AML.T0018` is *Manipulate AI Model*
    (formerly *Backdoor ML Model*), `AML.T0053` is *AI Agent Tool Invocation* (formerly *LLM Plugin
    Compromise*), and `AML.T0014` is *Discover AI Model Family* — **not** the older *Discover ML
    Artifacts*, which is a different concept. Pre-2026.06 artifacts in this library (D&R-09) still
    carry the older names; re-map them before reuse rather than assuming they match.
  - **2026.06 added purpose-built RAG and agentic techniques — map to them instead of forcing an
    older tag** (§4's "say so rather than forcing a tag" cuts both ways). The ones this collection
    leans on: *RAG Poisoning* (`AML.T0070`), *False RAG Entry Injection* (`AML.T0071`), *Data from
    AI Services: RAG Databases* (`AML.T0085.000`), *AI Agent Context Poisoning* (`AML.T0080`, with
    `.000 Memory`), *AI Agent Tool Poisoning* (`AML.T0110`), *Poisoned AI Agent Tool*
    (`AML.T0011.002`), *Publish Poisoned Models* (`AML.T0058`), *AI Supply Chain Rug Pull*
    (`AML.T0109`), *LLM Prompt Obfuscation* (`AML.T0068`), *LLM Prompt Self-Replication*
    (`AML.T0061`), and *Cost Harvesting: Agentic Resource Consumption* (`AML.T0034.002`).
    In particular, `AML.T0031` *Erode AI Model Integrity* is **not** the tag for corpus or memory
    poisoning — it describes degrading the model itself, and does not apply where the model is
    untouched.
  - ATLAS carries a `maturity` field per technique (`Realized`, `Demonstrated`, `Feasible`; in
    2026.06 the split is 64 / 90 / 19). Quote it when severity or plausibility is in question: a
    technique marked *Feasible* has not been observed in the wild, and a report that implies
    otherwise is fabricating impact.
- Where no clean mapping exists (much PQ-migration-defect work is pre-ATT&CK), the playbook
  says so rather than forcing a tag.

---

## 5. Example-data conventions

- Network examples use **RFC 5737** (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`)
  and **RFC 3849** (`2001:db8::/32`) documentation address space.
- Identities, domains, and tokens in examples are illustrative and non-attributable.
- Detection logic is **JSON-shaped pseudocode**, not a SIEM query. Translate per platform.
- **Cross-reference notation.** The library holds **three independently numbered collections**, so a
  bare number is never a valid citation. `PB-NN` always means *this* collection
  (AI · Post-Quantum · E2EE). A playbook in the Detection & Response collection is written `D&R-NN`
  — e.g. `D&R-09` is AI / Automated Agent Abuse, while `PB-09` is PQ VPN, IPsec & SSH. A playbook in
  the Transmission & Physical Layer collection is written `TX-NN` — `TX-01` is RF & radio spectrum,
  `TX-02` is nanometer-scale optical. Never cite a bare number across collections.

---

## 6. Rules of engagement (binds all bug-bounty playbooks)

Authorized testing only. GreyNOC operates as the submitting firm under platform programs
(e.g., HackerOne / YesWeHack) or direct written engagement.

1. **No activity without scope on file.** A signed SOW or an in-scope, in-policy bug-bounty
   program is a precondition. Out-of-scope assets, third-party dependencies not named in
   scope, and chained pivots beyond the authorized boundary are prohibited.
2. **Least-impact testing.** Prefer read-only inspection (handshake/cert/token observation)
   over anything state-changing. No DoS, no data exfiltration beyond minimal proof, no
   persistence, no lateral movement unless explicitly authorized.
3. **No fabrication.** Every reported finding must be independently reproducible from the
   evidence in the report. No speculative severity, no invented impact, no copied CVE text
   passed off as original analysis. If you cannot reproduce it, it is not a finding.
4. **Data handling.** Capture the minimum proof necessary. Never retain third-party PII,
   secrets, or message plaintext beyond what the program permits; redact in reports.
5. **Coordinated disclosure.** Follow the program's disclosure timeline. Do not publicize
   before remediation/authorization.
6. **Stop conditions.** On encountering evidence of a prior real-world compromise, customer
   PII at rest, or anything outside scope — stop, preserve, and escalate to the program owner.

---

## 7. AI-system testing addendum (binds Playbooks 15–20)

§6 applies in full. AI targets add failure modes that generic web ROE does not cover, so these
rules are additive and non-negotiable for any engagement against a model, an agent, an
AI-backed application, or the infrastructure serving them.

1. **Classify before you submit: security defect vs. model behavior.** Most AI programs scope
   *security* defects — broken authn/authz, injection that crosses a trust boundary, data
   exposure, tenancy failures, infrastructure compromise — and explicitly route *model behavior*
   (jailbreaks yielding disallowed content, hallucination, bias, refusal bypass) to a separate
   model-safety channel. A jailbreak is a **security** finding only when it produces a concrete
   security consequence: an unauthorized tool invocation, access to data the tester was not
   entitled to, a privilege change, or code execution. Submitting content-policy bypasses to a
   security queue is the fastest way to lose program standing.
2. **Never generate genuinely harmful content as proof.** Demonstrate the *control failure*, not
   the payload. Use an inert canary, a policy-marker string, or a benign no-op tool call. If
   proving a finding would require producing actually weaponizable material, stop and report the
   control gap with the boundary evidence already in hand.
3. **Self-scoped tenancy.** Test with your own accounts, tenant, documents, keys, and agents.
   Cross-tenant and cross-user claims must be demonstrated between **two tenants you control**;
   never between yours and a real customer's.
4. **Canary discipline.** Plant uniquely identifiable inert markers — format
   `GNBB-CANARY-<uuid4>` — so retrieval, leakage, and propagation claims are provable and
   attributable, and so the target's defenders can separate your traffic from a real adversary's.
5. **Denial-of-wallet is a real harm.** Inference is metered and shared. Stay inside documented
   rate limits, cap total requests up front, never run volumetric fuzzing, and demonstrate a
   missing consumption control with the **minimum** request count that shows it — not by actually
   exhausting the quota, the context window, or the GPU pool.
6. **Stochastic reproducibility.** Model output is nondeterministic; one successful prompt is not
   a finding. Every AI finding records model and version string, sampling parameters
   (temperature / top-p / seed where settable), trial count, success count, observed success rate
   with its confidence interval, and timestamps. **The GreyNOC bar is ≥2 successes from a clean
   context across a stated trial count**, with the full trial ledger in the report — a 2/50 result
   is reportable *as* 2/50, never as "reproducible."
7. **Data you will encounter.** RAG corpora, agent memory, vector stores, and inference logs can
   contain third-party PII, secrets, and conversation content. Capture the minimum proof (a hash,
   a redacted fragment, a record count), never bulk-collect, never retain, and report immediately.
   Discovery of real user data is a §6 stop condition.
8. **Model artifacts are untrusted code.** Never load, unpickle, deserialize, or execute a model
   artifact, adapter, notebook, or config obtained from a target. Inspect statically, offline, in
   an isolated environment.
9. **Agent and tool boundaries.** A test agent must hold the least-privileged tool set that can
   prove the point, prefer echo/no-op tools for proof, and never chain into out-of-scope systems.
   You are responsible for every action your agent takes, including ones an injection induced.
10. **Be identifiable.** Where the program permits it, mark traffic (identifying header or user
    agent) and register test accounts, so defenders do not burn incident-response cycles on you.
11. **Additional stop conditions.** Stop, preserve, and escalate on: evidence another party is
    exploiting the same defect; any probe that begins to affect other tenants' sessions, outputs,
    or costs; a training-data or memory extraction that starts returning real user content; or a
    finding that cannot be proven without generating genuinely harmful content.

---

## 8. Defect-class registry and AI evidence notation

### 8.1 Defect-class prefixes

Every bug-bounty playbook in this library numbers its defect classes with a unique prefix, so a
class ID is globally unambiguous in a report, a ticket, or a triage queue. Never reuse a prefix.

| Prefix | Range | Owning playbook | Domain |
| --- | --- | --- | --- |
| `C` | C1–C15 | PB-08 | Cryptographic implementation & PQ migration defects |
| `L` | L1–L14 | PB-16 | LLM application layer |
| `S` | S1–S10 | PB-17 | AI supply chain & model artifacts |
| `G` | G1–G12 | PB-18 | Agentic systems, tools & the MCP boundary |
| `I` | I1–I10 | PB-20 | Inference infrastructure & multi-tenant isolation |

A finding cites exactly one primary class. Chains cite the primary class and list the others in
sequence (`L2 → L5 → L6`), because the chain is what carries the impact.

Three playbooks own no prefix by design. **PB-07** and **PB-15** are methodology, not catalogs —
their findings carry the class of whichever catalog the defect belongs to. **PB-19** covers model
*behavior*, which routes to a program's model-safety channel rather than its security queue (§7.1);
giving those findings a class ID would invite a triager to treat them as security defects.

**The TX (Transmission & Physical Layer) collection owns no prefix either.** `TX-01` and `TX-02` are
detection and response playbooks, not bug-bounty catalogs; their intrusion classes are descriptive
(*bend-tap*, *rogue-lambda*, *ROADM/monitor*, *impersonation*, *reception-anomaly*) and are cited by
name. A registry prefix would invite a triager to read a physical-medium event as an application
defect. Note also that `C10` in PB-08 covers **computational** side channels — timing, fault, and
secret residue. Electromagnetic emanation (`TX-01 §5.7`) and optical emission (`TX-02 §6.7`) are
different physical phenomena and are deliberately not filed under `C10`.

### 8.2 Canary tokens

Inert markers are the sanctioned proof mechanism for AI findings (§7.4). Format:

```
GNBB-CANARY-<uuid4>          e.g. GNBB-CANARY-3f2a1c68-9d47-4e2b-8a10-5c7e9b04d1f6
```

Canaries are registered in the engagement's canary registry before use, are unique per probe and
per tenant, and carry no semantic content. A retrieval, leakage, propagation, or tool-invocation
claim is proven by the canary appearing where it should not — not by narrative description.

### 8.3 Trial-ledger notation for stochastic findings

Per §7.6, AI findings report reproducibility as a ledger, never as an adjective. The canonical
short form in a report title or triage summary is:

```
successes/trials @ temperature (95% CI low–high)      e.g. 7/20 @ t=1.0 (0.18–0.57)
```

Report templates may label the interval `95% Wilson CI` where the form needs to be unambiguous; the
short form above stays canonical for titles and triage summaries.

The interval is a **Wilson score interval** — with the small trial counts an authorized,
rate-limited engagement can afford, a normal-approximation interval is wrong at the tails and a
bare percentage is meaningless. `2/50` is reported as `2/50`, and is still a real finding when
the consequence is real and the attacker's retry cost is low; severity comes from consequence and
retry economics, not from the rate alone.

---

## 9. Versioned reference baseline

These sources are the audit baseline for the collection. Record the retrieval date in any
compliance evidence package and re-check status before deployment:

- [NIST Post-Quantum Cryptography project](https://csrc.nist.gov/Projects/post-quantum-cryptography)
  — authoritative status for FIPS 203/204/205, FIPS 206 development, HQC selection, and future
  PQ standards.
- [NIST SP 800-227](https://csrc.nist.gov/pubs/sp/800/227/final) — KEM construction and
  implementation guidance.
- [NIST CSWP 39-upd1](https://doi.org/10.6028/NIST.CSWP.39-upd1) — final June 2026
  crypto-agility guidance.
- [IETF ECDHE-MLKEM TLS draft](https://datatracker.ietf.org/doc/draft-ietf-tls-ecdhe-mlkem/)
  and the [IANA TLS Supported Groups registry](https://www.iana.org/assignments/tls-parameters/)
  — current protocol status and code points; an Internet-Draft is not an RFC.
- [NIST AI RMF](https://www.nist.gov/itl/ai-risk-management-framework) and
  [NIST AI 600-1 GenAI Profile](https://doi.org/10.6028/NIST.AI.600-1) — enterprise AI
  governance, mapping, measurement, and management baseline.
- [NIST CSF 2.0](https://doi.org/10.6028/NIST.CSWP.29) — Govern, Identify, Protect, Detect,
  Respond, and Recover outcomes.
- [CISA JCDC AI Cybersecurity Collaboration Playbook](https://www.cisa.gov/news-events/alerts/2025/01/14/cisa-releases-jcdc-ai-cybersecurity-collaboration-playbook-and-fact-sheet)
  — AI incident coordination and information-sharing baseline.
- [OWASP Top 10 for LLM Applications 2025](https://genai.owasp.org/llm-top-10/) and
  [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
  — application and agentic risk cross-checks.
- [Executive Order 14412 fact sheet](https://www.whitehouse.gov/fact-sheets/2026/06/fact-sheet-president-donald-j-trump-secures-the-nation-against-advanced-cryptographic-attacks/)
  and [OMB M-23-02](https://www.whitehouse.gov/wp-content/uploads/2022/11/M-23-02-M-Memo-on-Migrating-to-Post-Quantum-Cryptography.pdf)
  — federal PQ migration direction; determine applicability before treating either as binding.
- [PCI SSC FAQ 1491](https://www.pcisecuritystandards.org/faqs/1491/) — PQ TLS is described as
  best practice; PCI DSS does not currently impose a general PQ migration mandate.

---

*GreyNOC — detection-engineering-first. Reproducible or it didn't happen.*
