# 15 — Bug Bounty: AI & LLM Attack-Surface Methodology (Authorized)

> **Authorization required.** Authorized testing only, GreyNOC as submitting firm, scope on
> file. See [CONVENTIONS §6 Rules of Engagement and §7 AI-system testing addendum](CONVENTIONS.md).
> AI targets add hazards generic web ROE does not cover — metered inference, other tenants'
> data in shared corpora, and proof that can itself be harmful. Least-impact, self-scoped,
> no fabrication, coordinated disclosure.

## Overview

This is the methodology spine for the AI bug-bounty collection: how to go from a program scope to
a reproducible, correctly-routed AI finding. It plays the role PB-07 plays for the crypto
collection — phases, harness discipline, evidence standard, report template — while the four
sibling catalogs (PB-16, PB-17, PB-18, PB-20) hold the defect classes themselves.

Two things make AI targets different from ordinary web targets, and both are procedural rather
than technical. First, **output is stochastic**, so a single successful prompt proves nothing;
evidence has to be a ledger, not a screenshot. Second, **most AI programs split their intake** —
security defects go to the security queue, model behavior goes to a model-safety channel — and
submitting to the wrong one is the fastest way to lose standing with a program. Everything below
is built around getting those two right.

## Catalog map

| Catalog | Prefix | Surface | Defensive twin |
| --- | --- | --- | --- |
| [PB-16](16-bugbounty-llm-application-defects.md) | `L1–L14` | The app around the model: prompts, RAG, output rendering, sessions, app authz | PB-06, D&R-09 |
| [PB-17](17-bugbounty-ai-supply-chain-model-artifacts.md) | `S1–S10` | What gets loaded and where it came from: weights, adapters, datasets, pipelines | PB-01, PB-11 |
| [PB-18](18-bugbounty-agentic-systems-mcp.md) | `G1–G12` | What the model is allowed to *do*: tools, connectors, the MCP boundary, autonomy | PB-06, D&R-09 |
| [PB-20](20-bugbounty-inference-infrastructure-isolation.md) | `I1–I10` | The serving plane: control plane, tenancy, caches, quotas, transport | PB-06, D&R-09; PB-02/PB-03 on `I10` |
| [PB-19](19-bugbounty-model-behavior-safety-boundaries.md) | *(none)* | Model behavior and safety boundaries — routes to model-safety, not security | PB-06 |

**Reference convention.** `PB-NN` means this collection (AI · Post-Quantum · E2EE), where the
numbering is independent of the Detection & Response collection. A twin in the other collection is
written `D&R-NN` — here, [D&R-09 AI / Automated Agent Abuse](09-ai-automated-agent-abuse.md), the
defensive detector for most of what this collection hunts.

This playbook owns no prefix either (§8.1): a methodology finding carries the class of whichever
catalog the defect belongs to.

## The routing decision (do this before you test, not after)

CONVENTIONS §7.1 is the rule; this is the procedure. For any candidate finding, ask whether the
behavior produces a **concrete security consequence**:

1. Did it cause an action across a trust boundary that the caller was not entitled to perform
   (a tool invocation, a write, a send, a payment, a deploy)?
2. Did it expose data the tester was not entitled to (another tenant's, another user's, a secret,
   an internal endpoint)?
3. Did it change a privilege, an identity, or an authorization decision?
4. Did it result in code or command execution?

**Any yes → security finding.** It belongs to an `L`/`S`/`G`/`I` class and goes to the security
queue with the full ledger.

**All no → no security consequence demonstrated *yet*.** Which of two things you have depends on what
you were looking at. If it is **model output** — a jailbreak, disallowed content, a refusal or filter
bypass that only changes emitted text — it belongs to PB-19 and goes to the program's model-safety
channel, however interesting the transcript looks. If instead you demonstrated a **missing or
fail-open control** — no consumption ceiling (`L12`, `G12`, `I7`), no human-in-the-loop gate on an
irreversible action (`G6`), provenance verification absent or failing open (`S2`, `S9`) — it stays a
security finding in its owning catalog. Those classes are proven by the *absence of the control*, not
by crossing it: ROE forbids exhausting the quota, firing the irreversible action, or executing the
artifact. Report the control gap you actually proved, at the severity that gap carries.

The trap is the jailbreak that "obviously could" lead to consequence 1–4 but didn't in your test.
That is not a security finding yet; it is a hypothesis. Either demonstrate the consequence
self-scoped, or report what you actually proved.

## AI surface map

| Surface | What to look at | Catalog |
| --- | --- | --- |
| Prompt & context assembly | what untrusted content reaches the context, what the system prompt is trusted to enforce | `L` |
| Retrieval / RAG | corpus write paths, retrieval scoping, per-caller entitlement at the vector store | `L` |
| Output path | how model output is rendered, parsed, or executed downstream | `L` |
| Memory & sessions | per-user memory, conversation IDs, share links, cache scoping | `L`, `G` |
| Model artifacts | weights, adapters, tokenizers, datasets, their provenance and load path | `S` |
| Build & registry | training/build pipelines, model registries, promotion gates, hub namespaces | `S` |
| Tools & connectors | tool schemas, MCP servers, OAuth scopes, human-in-the-loop gates | `G` |
| Agent runtime | execution tools, egress, agent state, sub-agent trust, budget controls | `G` |
| Serving plane | control plane, tenant routing, caches, batching, quotas, transport | `I` |
| Crypto on the path | signing of artifacts, TLS/KEM on inference and retrieval hops | `S9`, `I10` |

## MITRE mapping

| Technique | ID | Relevance |
| --- | --- | --- |
| LLM Prompt Injection | AML.T0051 | The dominant entry technique across `L` and `G` |
| LLM Jailbreak | AML.T0054 | Routing decision above; behavior unless it yields consequence |
| AI Agent Tool Invocation | AML.T0053 | Tool and connector abuse (`G`) |
| LLM Data Leakage | AML.T0057 | Context, transcript, and corpus exposure (`L`, `I`) |
| AI Supply Chain Compromise | AML.T0010 | Artifact and dependency path (`S`) |
| RAG Poisoning | AML.T0070 | Corpus write paths reachable by a lower-privileged party (`L7`) |
| AI Agent Context Poisoning | AML.T0080 | Memory and agent state that survive a session (`L8`, `G9`) |
| AI Agent Tool Poisoning | AML.T0110 | Tool metadata as a model-visible injection channel (`G1`) |
| AI Model Inference API Access | AML.T0040 | The access precondition for most of this collection |
| Discover AI Model Family | AML.T0014 | Phase 1 stack fingerprinting — model family and version strings, framework names |
| Discover AI Model Ontology | AML.T0013 | Phase 2 mapping of what the deployment will and will not do |
| Cost Harvesting | AML.T0034 | Denial-of-wallet classes (`L12`, `G12`, `I7`) |
| Exploit Public-Facing Application | T1190 | Serving-plane and app-layer exposure |
| Valid Accounts | T1078 | Self-owned test tenancy; also the tenancy-crossing classes |

*ATT&CK citations in this table were verified against ATT&CK Enterprise v19.2 on 2026-08-09. v19
retired the "Defense Evasion" tactic — TA0005 was renamed Stealth and TA0112 Defense Impairment was
split out — and renumbered several techniques, so ATT&CK carries its own stated version exactly as
ATLAS does. Cited against ATLAS collection 2026.06 per [CONVENTIONS §4](CONVENTIONS.md); both IDs
and names are versioned in both frameworks — re-map to your platform's collections at deployment.*

## Methodology (phased)

### Phase 0 — Scope, ROE & routing
- Confirm in writing: in-scope models, endpoints, agents, and tenants; allowed test types; rate
  limits and any spend cap; whether self-hosted infrastructure is in scope at all.
- Read the program's **intake split**: which channel takes security defects, which takes model
  behavior, and what the program explicitly excludes (usually hallucination, bias, refusal
  quality, and content-policy bypass without consequence).
- Identify shared infrastructure you must not touch: the upstream model provider, a shared vector
  database, a third-party connector's servers. A hosted model behind your target is almost never
  in your scope.
- Record the authorization reference in the evidence log before the first request.

### Phase 1 — Passive surface discovery
- Enumerate the AI-touching surface from documentation, changelogs, client bundles, public API
  specs, and job postings — not from intrusive scanning.
- Note the deployment model (hosted API, dedicated endpoint, self-hosted), because it determines
  which catalogs are realistically testable at all (see PB-20's deployment table).
- Fingerprint the stack where it is disclosed voluntarily: model family and version strings in
  responses, framework names in error text, connector and plugin lists in the UI.

### Phase 2 — Trust-boundary & data-flow mapping (the AI-BOM)
Write down, for the target, the answer to four questions. This artifact is the engagement's most
valuable output even when no finding lands.
1. **What untrusted content reaches the model's context?** User input, retrieved documents, tool
   results, file uploads, web fetches, other users' shared content.
2. **What does the model's output reach?** A renderer, an interpreter, a tool, a database, a
   downstream service, another agent, a human who will act on it.
3. **Whose identity is used at each hop?** The caller's, a service account's, an agent's own.
   Every place these differ is a confused-deputy candidate (`L11`, `G3`).
4. **What is shared across tenants?** Corpus, cache, memory, model instance, GPU, queue.

Each boundary you draw becomes a falsifiable hypothesis in Phase 4.

### Phase 3 — Harness setup
Do not send a probe until this exists. It is what turns a lucky transcript into evidence.

- **Two self-owned tenants.** Every cross-tenant claim must be demonstrable between tenants you
  control (§7.3). Set up the second one now; retrofitting it later invalidates your evidence.
- **Canary registry.** Pre-generate `GNBB-CANARY-<uuid4>` markers (§8.2), one per probe per
  tenant, and record where each was planted before planting it. A canary you generated after
  seeing the result is not evidence.
- **Trial ledger.** A per-hypothesis log: model and version string, sampling parameters
  (temperature, top-p, seed, max tokens), system-prompt state, clean-context flag, timestamp,
  request ID, outcome. Append every trial, including failures — a ledger with only successes is a
  fabricated ledger.
- **Cost cap and request budget.** Set the total request count and spend ceiling in advance and
  hold to it (§7.5). Write the numbers in the log before you start.
- **Identifiable traffic.** Where the program permits, mark requests with an agreed header or user
  agent and register test accounts (§7.10), so the target's defenders can separate you from a real
  adversary.
- **Full transcript capture.** Raw request and response bodies, not screenshots. Screenshots are a
  supplement, never the primary artifact.

### Phase 4 — Hypothesis & defect-class targeting
Form falsifiable hypotheses tied to a class, each stating the expected-secure behavior and the
observation that would **falsify** it:
- "Retrieval is scoped per caller; a document in tenant B is unreachable from tenant A." → `L7`
- "Tool invocation requires the caller's entitlement, not the agent's." → `G3`
- "The artifact load path verifies a signature and fails closed." → `S2`
- "Prompt cache is keyed per tenant; a canary in tenant A never surfaces in tenant B." → `I3`

A clean falsification is a real outcome and is recorded as one. Programs and clients both value a
documented negative on a boundary they were unsure about.

### Phase 5 — Controlled validation
- **Self-scoped, minimum footprint.** Your accounts, your documents, your agents, your keys. The
  minimum request count that demonstrates the control gap — never the count that exhausts it.
- **Clean context per trial.** A new conversation, no prior turns, no residual memory. Successes
  carried by earlier turns in the same session are a different (and weaker) claim; if the finding
  requires multi-turn setup, state that explicitly in the ledger.
- **The GreyNOC bar: ≥2 successes from a clean context across a stated trial count** (§7.6), with
  the full ledger in the report.
- **Canary-proven, not narrated.** The claim is proven by the marker appearing where it should not
  — in another self-owned tenant's response, in a tool call, in an outbound request to your own
  listener. Model output *describing* data is not evidence that the data was retrieved; models
  produce plausible-looking content on demand. Rule that out with the canary, every time.
- Stop at proof of concept. Do not escalate to see how far it goes.

### Phase 6 — Report & routing
- One finding per defect, one primary class, chains listed in sequence (§8.1).
- Route per the decision procedure above. If you are genuinely unsure, say so in the report and
  let the program triage it — an honest "I believe this is behavior, not a defect, but the tool
  call at step 4 may make it security" reads well. Guessing high does not.
- Score against demonstrated consequence and attacker retry economics, not against the success
  rate alone.

## Trial ledgers and the statistics

Report reproducibility as a ledger, never as an adjective (§8.3). The canonical short form is
`successes/trials @ temperature (95% CI low–high)`, with a **Wilson score interval** — at the trial
counts a rate-limited engagement can afford, a normal approximation is wrong at the tails and a
bare percentage is meaningless.

| Ledger | 95% Wilson CI | Reading |
| --- | --- | --- |
| 1/20 | 0.01–0.24 | Below the ≥2-success bar. Not yet a finding — extend trials or drop it. |
| 2/20 | 0.03–0.30 | Meets the bar. Real if the consequence is real; report as 2/20. |
| 2/50 | 0.01–0.13 | Meets the bar. Low rate, still a finding when retry cost is near zero. |
| 7/20 | 0.18–0.57 | Solid. The interval is still wide — do not round it to "35% reliable". |
| 10/10 | 0.72–1.00 | Deterministic-looking. Ten trials cannot prove the lower bound above 0.72. |

Reproduce the interval yourself; do not copy a number you did not compute:

```python
from math import sqrt
def wilson(k, n, z=1.96):
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    m = z / d * sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return max(0.0, c - m), min(1.0, c + m)
```

Severity comes from consequence and retry economics, not from the rate. A 2/50 unauthorized tool
invocation an attacker can retry for a fraction of a cent is worse than a 15/20 system-prompt leak.

## What "good" vs. "not a finding" looks like

- **Finding:** a canary planted in your tenant B surfaces in tenant A's response; an injected
  document causes a tool call the caller was never entitled to make; an artifact loads with an
  unverified signature; a serving control plane answers unauthenticated.
- **A finding, but low:** a system-prompt leak containing nothing sensitive is PB-16 `L3` at
  low or informational severity, and is frequently already known. Report it as that — never
  inflated, and never withheld because it is small.
- **Not a finding (yet):** a jailbreak with no consequence (→ PB-19); a single lucky generation; a
  model "confirming" it has access to something with no canary proving retrieval; a rate limit you
  bypassed by exceeding the documented one; hallucinated content presented as leaked data.
- **Never a finding:** anything you proved by touching a real customer's data, another program's
  infrastructure, or by generating genuinely harmful content.

## AI report template

The canonical template for this collection. Sibling catalogs extend it with surface-specific lines.

```
TITLE:          ____ (defect class — surface)
PROGRAM/SCOPE:  ____   (auth ref: ____ ; channel: security | model-safety)
DEFECT-CLASS:   L#/S#/G#/I# (primary)   CHAIN: ____ → ____ → ____
SEVERITY:       ____ (program scale + demonstrated exploitability, not potential)
TARGET:         app | agent | artifact | serving plane ; endpoint: ____
MODEL:          name + version string ; provider ; deployment: hosted | dedicated | self-hosted
SAMPLING:       temperature / top-p / seed / max-tokens ; system-prompt state: ____
TRIAL LEDGER:   __/__ @ t=__ (95% Wilson CI __–__) ; clean context: Y/N ; ledger attached: Y/N
CANARY:         GNBB-CANARY-<uuid4> ; planted at: ____ ; observed at: ____
TENANCY:        tenants used (both self-owned): ____
HYPOTHESIS:     expected-secure behavior: ____
OBSERVATION:    what actually happened: ____
REPRODUCTION:   exact, minimal, self-scoped steps (raw requests, not screenshots): ____
EVIDENCE:       transcripts / request IDs / captures, redacted of third-party data: ____
IMPACT:         concrete and demonstrated (no speculation): ____
RETRY ECONOMICS: cost and effort per attempt for an attacker: ____
REMEDIATION:    recommended fix (tie to the defensive playbook): ____
FALSIFIER:      what observation would have disproven this: ____
COST:           requests issued: ____ ; est. spend: ____ (§7.5 budget: ____)
```

## Stop conditions

CONVENTIONS §6.6 and §7.11 apply in full. Stop, preserve, and escalate to the program owner on:
real user data appearing in a retrieval, memory, or log result; any probe beginning to affect
another tenant's sessions, outputs, or costs; evidence another party is exploiting the same defect;
a model artifact or credential you would have to execute or use to "confirm" (§7.8); or a finding that
cannot be proven without generating genuinely harmful content. In that last case, report the
control gap with the boundary evidence you already hold — that is a complete finding, not a
partial one.

## Summary

AI targets reward process discipline more than cleverness. Map the trust boundaries before you
probe them, build the harness — two self-owned tenants, a pre-registered canary, a trial ledger, a
spend cap — before the first request, and decide security-versus-behavior routing before you write
the title. Prove retrieval and action with canaries rather than with model narration, report the
ledger as a ledger, and score on demonstrated consequence and retry economics. The catalogs in
PB-16, PB-17, PB-18, and PB-20 tell you what to look for; this playbook is what makes what you find
credible enough to be worth reporting.
