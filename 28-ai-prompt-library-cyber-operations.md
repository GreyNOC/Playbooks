# 28 — AI Prompt Library for Cyber Operations (Authorized)

> **Authorization required.** Authorized work only, GreyNOC as submitting firm or engaged party,
> scope on file. See [CONVENTIONS §6 Rules of Engagement and §7 AI-system testing addendum](CONVENTIONS.md).
> **These prompts are addressed to your own assistant, never to a target's model.** Driving a
> target's model is PB-15/16/18 scope and is bound by canary discipline. This playbook is
> **analyst tradecraft** — it produces drafts, analyses, and documents that a human verifies before
> use. Nothing here authorizes an action that the underlying engagement does not already authorize.

## Overview

Every other playbook in this collection tells you *what* to look for. This one covers the tool most
GreyNOC operators now have open beside the work: a language model used as a drafting, analysis, and
review aid across detection engineering, authorized offensive testing, bug-bounty triage, and
reporting.

That tool is an unreliable narrator with excellent recall of form and poor commitment to fact. Used
without a contract it produces confident, plausible, unverifiable output — which is precisely the
failure mode [CONVENTIONS §6.3](CONVENTIONS.md) exists to forbid. A hallucinated indicator in a
detection rule is a silent coverage gap. A hallucinated CVE in a report costs program standing. An
invented severity is fabrication whether a human or a model wrote it.

So the unit of this playbook is not "a prompt." It is a **prompt plus its output contract plus the
verification step that has to pass before the output is allowed to leave your machine.** A prompt
quoted from here without its verification step is being misused.

Five families, matching the five places this work actually happens:

| Family | Prefix | Covers |
| --- | --- | --- |
| Defense | `P-DEF` | Detection engineering, triage, hunting, guardrail review, purple-team validation |
| Offensive security | `P-OFF` | Authorized recon synthesis, attack-path reasoning, least-impact proof design, ROE gating |
| Bug bounty | `P-BTY` | Program scope parsing, target selection, dedupe, trial ledgers, submission gating |
| Bug analysis | `P-BUG` | Root cause, defect classification, chaining, falsification, fix review |
| Reporting | `P-REP` | Findings, impact, remediation, executive summary, evidence packaging, disclosure |

## Scope boundary — what belongs here vs. elsewhere

| Activity | Owner |
| --- | --- |
| Prompts **you** send to **your own** assistant to do security work | PB-28 (this playbook) |
| Probing a **target's** model or app with crafted input, under scope | PB-15 methodology; PB-16 `L` classes |
| Probing a target's **agent, tools, or MCP boundary** | PB-18 `G` classes |
| Probing a target's **serving plane** | PB-20 `I` classes |
| Content-policy behavior of a target's model, no security consequence | PB-19 → model-safety channel |
| Governing **your own** organization's approved AI tooling, vendors, and data flows | PB-21, PB-23 |
| Detecting **an adversary** abusing AI/agents in your estate | D&R-09; PB-06 |

The tiebreaker: **who is the model working for?** If it is working for you, on your evidence, to
produce your work product, it is PB-28. If you are sending input to a model to learn how *it*
behaves, you are testing a target and the `L`/`G`/`I` catalogs own it. The two get confused because
both involve typing into a chat box, and they carry completely different authorization requirements.

**Reference convention.** `PB-NN` / `D&R-NN` per [CONVENTIONS §5](CONVENTIONS.md).

## No MITRE mapping, by design

This playbook carries **no ATT&CK or ATLAS mapping table**, and that is deliberate rather than an
omission. ATT&CK and ATLAS catalog **adversary** behavior. The subject here is *analyst workflow*.
Tagging "draft a detection rule" with a technique ID would assert an adversary relationship that
does not exist, and [CONVENTIONS §4](CONVENTIONS.md) treats a forced or unverifiable mapping as a
defect rather than added rigor. Findings *produced* with these prompts carry the mapping of whatever
playbook owns the finding.

## This playbook owns no defect-class prefix

`P-DEF` / `P-OFF` / `P-BTY` / `P-BUG` / `P-REP` are **prompt** identifiers, not defect classes. They
are deliberately not in the [CONVENTIONS §8.1](CONVENTIONS.md) registry alongside `C`/`L`/`S`/`G`/`I`,
for the same reason PB-07, PB-15, PB-19, and the TX collection own no prefix: a class ID in a report
tells a triager "this is a defect I must assess." A prompt ID means "this is how the analyst worked."
Never cite a `P-` identifier as a finding class. Cite it, if at all, in the methodology section of a
report where AI assistance is disclosed (`P-REP-07`).

## The prompt contract (binds every prompt in this playbook)

These eleven rules are the reason this library is safe to use. A prompt used outside them is
freelancing.

1. **The assistant drafts; you decide.** No output here is authoritative. Every rule, command,
   severity, classification, and sentence of a report is yours once you ship it, and you own its
   errors. "The model said so" is not a defense and is not a citation.
2. **Evidence in, or nothing out.** Prompts that reason about a system must be given the actual
   evidence — logs, captures, responses, code, config. A prompt that asks the model to recall facts
   about a target from its own weights produces fiction. Every factual claim in an output must be
   traceable to something you supplied.
3. **No fabrication, enforced in the prompt.** Every analytical prompt here instructs the model to
   mark unsupported statements explicitly and to answer "not determinable from the supplied
   evidence" rather than fill a gap. If an output contains an unmarked claim you cannot trace,
   discard the output — do not repair it, because you cannot see what else it invented.
4. **Classify the data before it leaves your machine.** Client data, customer PII, secrets, keys,
   tokens, session material, message plaintext, and unredacted third-party findings do **not** go
   into a third-party assistant. Use a local model, or redact to structure — `<HOST-A>`,
   `<TOKEN-REDACTED>`, `<USER-1>`, RFC 5737/3849 example addresses per
   [CONVENTIONS §5](CONVENTIONS.md) — before you paste. Which assistants are approved for which data
   class is a PB-21 and PB-23 decision, not an operator preference.
5. **Cited references are unverified until you open them.** Models generate well-formed CVE IDs,
   RFC numbers, ATT&CK IDs, ATLAS IDs, and URLs that do not exist or do not say what was claimed.
   Every external citation in AI-assisted output is a **lead**, not a reference, until you retrieve
   the source. [CONVENTIONS §9](CONVENTIONS.md) is the baseline for this collection's own citations.
6. **Generated code and queries are untrusted until reviewed and tested.** Read every detection
   rule, script, and command before it runs. Never let an assistant's output execute directly
   against a production estate or a target. A generated query that silently matches nothing is the
   dangerous outcome, not the noisy one.
7. **Assistant output is untrusted input to your next step.** When you paste a target's content —
   a page, a ticket, a log, a document, a model response — into your assistant, you have imported
   that content's author into your workflow. Directive text in it can steer your assistant. This is
   the `L2` mechanism turned on the tester. Treat retrieved target content as data, fence it
   explicitly in the prompt, and be suspicious of an output that recommends an action you did not
   ask about.
8. **Never outsource the authorization decision.** No prompt in this library grants scope. `P-OFF-07`
   helps you *check* a planned action against the ROE; it does not approve it, and a model's opinion
   that something is in scope is worth nothing. Scope comes from the signed document.
9. **Never ask for a working attack payload.** The prompts here reason about attack surface,
   interpret observed behavior, and design minimum-impact proofs. Generating functional exploit code
   or evasion material is out of scope for this playbook. [CONVENTIONS §7.2](CONVENTIONS.md) is the
   governing rule: **demonstrate the control failure, not the payload** — and if proving a finding
   would require genuinely harmful material, that is a stop condition, not a prompting problem.
10. **Reproducibility survives the assistant.** An AI-assisted finding meets exactly the same bar as
    any other: reproducible from the evidence in the report, with the [§7.6](CONVENTIONS.md) trial
    ledger where the target is stochastic. The assistant does not lower the bar and does not count
    as a trial.
11. **Disclose the assistance.** Any deliverable that left an assistant carries the `P-REP-07`
    statement. This is not a disclaimer that moves liability; it tells a reviewer where to look
    hardest, and it is how we stay honest about how the work was done.

---

## Defense — `P-DEF`

### `P-DEF-01` — Draft a detection from a behavior description
- **Use when:** you have a described behavior and need a first-draft rule to review, not to deploy.
- **Supply:** the behavior, the exact log source and schema (field names and types), a sample of real
  events in that schema, the platform dialect, and your environment's known-benign producers.
- **Prompt:**
  ```
  You are assisting a detection engineer. Draft a detection for the behavior below.

  BEHAVIOR: <description>
  LOG SOURCE + SCHEMA: <source, field names, types>
  SAMPLE EVENTS: <5-20 real events, redacted>
  TARGET PLATFORM: <KQL | SPL | EQL | Sigma | ...>
  KNOWN BENIGN PRODUCERS IN THIS ESTATE: <list>

  Rules:
  - Use ONLY fields present in the schema I gave you. If you need a field that is not
    there, stop and name it as a telemetry prerequisite instead of inventing it.
  - Do not invent process names, paths, registry keys, user agents, or IDs. Every
    literal must come from my sample or be labelled <ASSUMPTION> for me to fill in.
  - State the detection logic in plain language BEFORE the query.
  - List every false-positive source you can derive from the benign producers I named.
  - State what an attacker changes to evade this, and what that evasion costs them.
  - End with the tuning knobs and the data volume this will scan.
  ```
- **Output contract:** plain-language logic, then query, then FP sources, then evasion cost, then
  tuning knobs, with `<ASSUMPTION>` markers and named telemetry prerequisites.
- **Verify before use:** confirm every field exists; run against historical data and check the hit
  count is neither zero nor absurd; confirm at least one true positive fires using a purple-team
  case (`P-DEF-07`); review FP list against your own estate. **A rule that has never matched a known
  true positive is not a detection.**
- **Feeds:** the D&R playbook that owns the behavior; your detection rule set.

### `P-DEF-02` — Adversarial review of an existing detection
- **Use when:** a rule exists and you want its weaknesses before an adversary finds them.
- **Supply:** the rule, its schema, its current hit statistics, and what it is supposed to catch.
- **Prompt:**
  ```
  Review the detection below adversarially. Your job is to find how it FAILS, not to
  praise it.

  RULE: <rule>
  SCHEMA: <fields>
  INTENDED COVERAGE: <what it should catch>
  CURRENT HIT STATS: <volume, TP/FP counts if known>

  Produce:
  1. Bypasses: concrete variations of the intended behavior this rule does NOT match,
     and for each, which clause lets it through.
  2. False-positive surface: benign activity that matches, and why.
  3. Brittleness: literals, orderings, case sensitivity, field presence, and timing
     assumptions that break on a version change or a locale change.
  4. Silent-failure modes: conditions under which this returns zero rows for a reason
     other than absence of the behavior.
  5. What telemetry would close the gaps you found.

  Do not rewrite the rule. Only analyse it. Mark any claim you cannot ground in the
  rule text or schema as <UNVERIFIED>.
  ```
- **Output contract:** five enumerated sections, bypasses tied to specific clauses, no rewrite.
- **Verify before use:** test each claimed bypass and each claimed FP against data before you accept
  it. A claimed bypass that does not reproduce is noise, and treating the list as findings without
  testing is exactly the fabrication §6.3 forbids.
- **Feeds:** rule hardening; detection-validation regression cases.

### `P-DEF-03` — Timeline assembly from raw events
- **Use when:** you have scattered events across sources and need a defensible sequence.
- **Supply:** the events with full timestamps and source labels, the timezone of each source, and
  the question the timeline must answer.
- **Prompt:**
  ```
  Build a timeline from the events below.

  EVENTS: <events, each with source label and raw timestamp>
  SOURCE TIMEZONES / CLOCK NOTES: <per source>
  QUESTION THIS MUST ANSWER: <question>

  Rules:
  - Normalise all timestamps to UTC and show the original beside the normalised value.
  - One row per event. Never merge two events into one row.
  - Add a CONFIDENCE column: DIRECT (the event states it), INFERRED (you concluded it
    from ordering or correlation), or UNSUPPORTED (you cannot tell).
  - Never fill a gap. Where the sequence has a hole, insert an explicit GAP row saying
    what evidence is missing.
  - After the table, list the three alternative explanations for this sequence and what
    evidence would separate them.
  ```
- **Output contract:** UTC-normalised table with original timestamps, per-row confidence, explicit
  GAP rows, and competing explanations.
- **Verify before use:** re-check each DIRECT row against the raw event; confirm clock-skew handling;
  confirm no INFERRED row has been promoted to DIRECT. Alternative explanations are the point — an
  incident narrative with one explanation has not been analysed.
- **Feeds:** D&R-19 AI incident response; any incident record.

### `P-DEF-04` — Threat-hunt hypothesis generation
- **Use when:** you have a technique or an intel report and need testable hunts for your estate.
- **Supply:** the technique or behavior, your actual available data sources, and your estate's
  relevant characteristics.
- **Prompt:**
  ```
  Generate threat-hunt hypotheses for the behavior below, for MY estate as described.

  BEHAVIOR / TECHNIQUE: <description>
  DATA SOURCES I ACTUALLY HAVE: <list with retention windows>
  ESTATE CHARACTERISTICS: <OS mix, identity provider, cloud, AI tooling in use>

  For each hypothesis give:
  - The falsifiable statement ("if X is happening, then Y is observable in Z").
  - The specific data source and field that tests it.
  - The pivot if it returns nothing, and the pivot if it returns too much.
  - The benign baseline you must establish FIRST for the result to mean anything.
  - Estimated analyst time.

  Order by (evidence strength x feasibility with the sources I listed). Discard any
  hypothesis my data sources cannot test and say explicitly which you discarded and why.
  ```
- **Output contract:** falsifiable hypotheses with source, pivots, required baseline, and an explicit
  discard list.
- **Verify before use:** confirm the retention window actually covers the hunt period; establish the
  baseline before interpreting any result. An unbaselined hunt result is an anecdote.
- **Feeds:** hunt program; coverage gaps back into `P-DEF-08`.

### `P-DEF-05` — Alert triage framing
- **Use when:** an alert needs a decision and you want the decision structured, not made for you.
- **Supply:** the alert, the rule that fired, surrounding context you have gathered, and your
  escalation criteria.
- **Prompt:**
  ```
  Frame the triage decision for this alert. Do NOT tell me whether it is malicious.

  ALERT: <alert>
  RULE THAT FIRED: <rule logic>
  CONTEXT GATHERED SO FAR: <asset, identity, recent activity, peer baseline>
  MY ESCALATION CRITERIA: <criteria>

  Produce:
  1. What this alert does and does not prove, given the rule logic.
  2. The benign explanations, ranked by prior likelihood in an estate like mine.
  3. The malicious explanations, ranked.
  4. For each explanation, the ONE piece of evidence that would most cheaply confirm or
     eliminate it, and where to get it.
  5. Which of my escalation criteria are met on current evidence, which are not, and
     which are not yet determinable.

  Mark every claim that rests on an assumption about my environment rather than on the
  evidence I supplied.
  ```
- **Output contract:** proof boundary, ranked benign and malicious explanations, cheapest
  discriminating evidence per explanation, criteria status. No verdict.
- **Verify before use:** collect the discriminating evidence yourself; the ranking is a prior, not a
  finding. Never escalate or close on this output alone.
- **Feeds:** D&R-19; the analyst triage workflow.

### `P-DEF-06` — Guardrail and AI-control review
- **Use when:** reviewing your own organization's AI application controls before an adversary or a
  bounty hunter reviews them.
- **Supply:** the architecture, the prompt-assembly code or template, the tool and retrieval
  configuration, and the trust boundaries as you understand them.
- **Prompt:**
  ```
  Review the AI application design below for security control gaps.

  ARCHITECTURE: <components, data flows>
  PROMPT ASSEMBLY: <template or code>
  TOOLS / RETRIEVAL CONFIG: <definitions, scopes, identities>
  TRUST BOUNDARIES AS I UNDERSTAND THEM: <list>

  For each gap:
  - Which trust boundary is crossed, and who authored the content that crosses it.
  - Whether the control is ENFORCED (code, authz, allowlist, separate context) or
    INSTRUCTED (text in a prompt asking the model to behave). Say this explicitly for
    every control you find.
  - The security consequence if it fails, or "no security consequence" where the only
    outcome is different text.
  - The enforced control that would replace the instructed one.

  Then list the boundaries I did NOT include that a design like this usually has.

  Do not produce attack strings. Describe the control failure and its consequence.
  ```
- **Output contract:** per-gap boundary, the ENFORCED/INSTRUCTED verdict, consequence or explicit
  "no security consequence," the enforced replacement, and the boundaries you omitted.
- **Verify before use:** confirm each claimed gap against the actual code and runtime config, not the
  description. The ENFORCED-vs-INSTRUCTED split is the whole value here: an instructed control is a
  suggestion with good marketing.
- **Feeds:** PB-06; PB-16 `L1`–`L14` as the defect list to review against; PB-22 design gates.

### `P-DEF-07` — Purple-team validation case design
- **Use when:** you need to prove a detection fires, with a safe, repeatable, authorized test.
- **Supply:** the detection, the behavior, the authorized test environment, and the blast-radius
  limits.
- **Prompt:**
  ```
  Design validation cases for the detection below, to run in the authorized test
  environment described. Safety and repeatability matter more than realism.

  DETECTION: <rule>
  BEHAVIOR IT SHOULD CATCH: <description>
  AUTHORIZED TEST ENVIRONMENT: <description, isolation properties>
  HARD LIMITS: <no production, no real credentials, no destructive action, ...>

  For each case give:
  - Setup, the observable action, expected telemetry, expected alert, teardown.
  - The benign TWIN case that must NOT alert (a validation suite without negative
    cases proves nothing).
  - Blast radius and why it stays inside my limits.
  - Deterministic pass/fail criteria.

  Use the least-impact action that produces the telemetry. Prefer an inert marker or a
  benign no-op over a functional attack action. If a case cannot be made safe in the
  environment I described, say so and drop it rather than weakening my limits.
  ```
- **Output contract:** paired positive and negative cases, explicit blast radius, deterministic
  pass/fail, and a drop list for cases that cannot be made safe.
- **Verify before use:** run in the isolated environment only; confirm teardown; confirm the negative
  twin does not alert. A suite of positives with no negatives measures nothing.
- **Feeds:** the detection-validation lab; regression history.

### `P-DEF-08` — Coverage gap analysis against a playbook
- **Use when:** you want an honest answer about what a playbook expects that you cannot see.
- **Supply:** the playbook's detection strategy and data-source requirements, plus your real
  onboarded sources with retention and field coverage.
- **Prompt:**
  ```
  Compare the playbook's detection requirements against my actual telemetry and report
  the gaps.

  PLAYBOOK REQUIREMENTS: <detection strategy, required data sources and fields>
  MY ONBOARDED SOURCES: <source, retention, fields actually populated, sampling rate>

  Produce a table: requirement | covered / partial / absent | the specific missing
  source or field | what becomes undetectable | cost class of closing it.

  Rules:
  - PARTIAL is the interesting verdict. A source that is onboarded but sampled, or
    missing the one field the logic needs, is partial, not covered. Say which field.
  - Do not assume a source contains a field because the vendor documents it. If I did
    not list the field as populated, treat it as absent.
  - End with the honest one-line summary of what an empty alert queue means in this
    estate today.
  ```
- **Output contract:** requirement-by-requirement table with partial called out at field level, and
  the "what an empty queue means" statement.
- **Verify before use:** confirm field population by querying, not by reading vendor docs. This
  playbook collection's standing position applies: an empty alert queue for an uninstrumented source
  is a coverage gap, not a clean result.
- **Feeds:** telemetry roadmap; PB-21 asset inventory.

---

## Offensive security — `P-OFF`

All `P-OFF` prompts presume a signed scope on file. None of them creates authorization, and
[§6.1](CONVENTIONS.md) is a precondition, not a formality.

### `P-OFF-01` — Extract the authorization boundary from the engagement document
- **Use when:** first hour of an engagement. Do this before recon, not after.
- **Supply:** the SOW or program policy text, the asset list, and the stated test window.
- **Prompt:**
  ```
  Extract the authorization boundary from the engagement document below into a
  decision table I can check an action against.

  DOCUMENT: <SOW / program policy text>
  ASSET LIST: <assets>
  TEST WINDOW: <dates, times, timezone>

  Produce:
  1. IN SCOPE: asset, permitted test classes, stated limits.
  2. OUT OF SCOPE: asset or activity, and the exact clause that excludes it.
  3. AMBIGUOUS: anything the document does not clearly resolve. Quote the clause and
     state the question to ask the program owner. Do NOT resolve an ambiguity yourself
     and do NOT default to permitted.
  4. PROHIBITED ACTIVITY: explicit prohibitions, quoted.
  5. REQUIRED NOTIFICATIONS: who must be told what, before or during.
  6. STOP CONDITIONS stated in the document.

  Quote the source clause for every row. If the document is silent on something, say
  SILENT rather than inferring.
  ```
- **Output contract:** six sections, every row carrying a quoted clause, ambiguity preserved as
  ambiguity.
- **Verify before use:** read the document yourself; get every AMBIGUOUS row answered in writing by
  the program owner before touching the asset. **Silence is not permission.**
- **Feeds:** every subsequent action; PB-15 Phase 0; PB-07.

### `P-OFF-02` — Attack-surface enumeration and ranking from recon output
- **Use when:** recon has produced data and you need a prioritised, scope-filtered test plan.
- **Supply:** the recon output, the `P-OFF-01` scope table, and your time budget.
- **Prompt:**
  ```
  Turn this recon output into a ranked, scope-filtered test plan.

  RECON OUTPUT: <data>
  SCOPE TABLE: <from P-OFF-01>
  TIME BUDGET: <hours>

  For each surface: asset, what it appears to be, the evidence in my data that says so,
  the defect classes worth testing, and the least-impact first probe.

  Rules:
  - Drop anything the scope table does not cover, and list what you dropped so I can
    see the boundary being enforced.
  - Rank by (likelihood of a real defect x impact if present) / effort. Show the
    reasoning, not just the rank.
  - Distinguish OBSERVED (in my data) from INFERRED (your guess about the stack).
    Never state an inferred technology as fact.
  - Flag any surface whose testing needs authorization my scope table does not show.
  ```
- **Output contract:** ranked surfaces with evidence citations, observed/inferred separation, an
  explicit dropped-as-out-of-scope list, and authorization flags.
- **Verify before use:** re-check the drop list against the scope document; confirm each INFERRED
  technology before relying on it. Fingerprints lie, and an inferred stack drives wasted hours.
- **Feeds:** PB-15 Phases 1–2.

### `P-OFF-03` — Trust-boundary and data-flow mapping
- **Use when:** you need the map that makes defect hypotheses possible, especially on an AI target.
- **Supply:** observed requests and responses, documented architecture, identities and roles you
  control, and the data classes involved.
- **Prompt:**
  ```
  Map the trust boundaries and data flows in the system below.

  OBSERVED BEHAVIOR: <requests, responses, timing>
  DOCUMENTED ARCHITECTURE: <if any>
  IDENTITIES I CONTROL: <accounts, roles, tenants>
  DATA CLASSES: <what data exists and whose it is>

  For each boundary:
  - What crosses it, in which direction.
  - Who AUTHORED the crossing content, and was that author authenticated.
  - Which identity the far side ACTS UNDER after the crossing (the confused-deputy
    question).
  - Whether the control on the boundary is enforced in code or asserted in text.
  - The evidence in my data that the boundary exists, or UNDOCUMENTED if I am inferring
    it from behavior.

  For an AI component, treat these as separate boundaries and do not collapse them:
  caller input; retrieved corpus content; tool and function RETURN values; memory
  carried across sessions; and operator instructions. They have different authors.

  End with the boundaries you suspect exist but my evidence cannot confirm, and the
  read-only observation that would confirm each.
  ```
- **Output contract:** per-boundary author, acting identity, control type, and evidence, with
  suspected-but-unconfirmed boundaries separated out.
- **Verify before use:** confirm each boundary by observation before building a hypothesis on it.
  Keep tool-return content separate from retrieved corpus content in the map; they are distinct
  injection carriers and collapsing them hides a class of defect.
- **Feeds:** PB-15 Phase 2 AI-BOM; `P-OFF-04`.

### `P-OFF-04` — Hypothesis formation for an observed behavior
- **Use when:** something looks wrong and you need testable hypotheses rather than a hunch.
- **Supply:** the observation, full request/response evidence, what you expected, and the boundary
  map.
- **Prompt:**
  ```
  Form testable hypotheses for this observation.

  OBSERVATION: <what happened>
  EVIDENCE: <full requests and responses, redacted>
  WHAT I EXPECTED: <expectation>
  BOUNDARY MAP: <from P-OFF-03>

  For each hypothesis:
  - The mechanism, stated concretely enough to be wrong.
  - The BENIGN explanation that produces the same observation. Always give one.
  - The single cheapest, least-impact, read-only-if-possible test that DISCRIMINATES
    between the two. Not a test that confirms the hypothesis - one that separates it
    from the benign case.
  - The defect class it would land in if confirmed (C / L / S / G / I), or "none, this
    is model behavior" where there is no security consequence.
  - Whether the discriminating test stays inside my scope.

  Rank by discriminating power per unit of impact on the target. Do not propose a test
  that changes state where an observational test would do.
  ```
- **Output contract:** hypotheses each paired with a benign twin, a discriminating least-impact test,
  a candidate class, and a scope check.
- **Verify before use:** run the discriminating test, not the confirming one. Confirmation bias is
  the main source of invalid submissions, and a test that cannot come out benign is not a test.
- **Feeds:** PB-15 Phase 4; the `P-BUG` family.

### `P-OFF-05` — Least-impact proof design
- **Use when:** you believe a defect is real and must prove it with minimum impact.
- **Supply:** the hypothesis, the evidence so far, the ROE limits, and the assets and tenants you
  control.
- **Prompt:**
  ```
  Design the minimum-impact proof for this suspected defect.

  HYPOTHESIS: <mechanism>
  EVIDENCE SO FAR: <evidence>
  ROE LIMITS: <from P-OFF-01>
  ASSETS AND TENANTS I CONTROL: <list>

  Produce, in order:
  1. The exact claim the proof must establish, in one sentence.
  2. The least-impact evidence that establishes it. Prefer: observation > read-only
     request > state change confined to my own account > anything else.
  3. The inert marker plan. Use GNBB-CANARY-<uuid4> per CONVENTIONS section 7.4, one
     per probe per tenant, registered before use.
  4. Exactly what to capture: requests, responses, timestamps, identities, and for a
     model target the version string, sampling parameters, and trial ledger fields.
  5. What NOT to do, specifically: the impact escalations a tester is tempted into here
     and why each is unnecessary to the claim.
  6. The stop condition specific to this proof.

  Constraints: cross-tenant claims use two tenants I control, never a real customer.
  Never propose producing genuinely harmful content as proof - if the claim cannot be
  proven without it, say so and stop. Demonstrate the control failure, not the payload.
  ```
- **Output contract:** one-sentence claim, minimum evidence, canary plan, capture list, an explicit
  do-not list, and a stop condition.
- **Verify before use:** check the design against [§7](CONVENTIONS.md) line by line; register canaries
  first; confirm the proof establishes the claim and nothing more. **Escalating impact to make a
  finding look better is how engagements end badly.**
- **Feeds:** PB-15 Phase 5; PB-16/17/18/20 confirm steps.

### `P-OFF-06` — Interpret captured traffic
- **Use when:** you have captures and need to know what they actually show.
- **Supply:** the captures in full, what you were doing, and the identities used.
- **Prompt:**
  ```
  Interpret the captured traffic below. Tell me what it PROVES, not what it suggests.

  CAPTURES: <full requests and responses, headers included, redacted>
  WHAT I WAS DOING: <actions>
  IDENTITIES USED: <accounts, tokens by role, redacted>

  Produce:
  1. PROVEN: statements the captures establish, each citing the specific field, header,
     status code, or body element that establishes it.
  2. SUGGESTED: statements consistent with the captures but not established, and the
     additional capture that would establish each.
  3. Where an authorization decision appears to be made: server-side, client-side, or
     indeterminate from these captures. Cite your evidence.
  4. Anything anomalous I did not ask about: timing, caching headers, inconsistent
     error shapes, identifiers that look sequential or guessable, tokens in URLs.
  5. What is absent that you would expect: missing security headers, absent cache
     directives, no rate-limit signal.

  Never promote a SUGGESTED item to PROVEN. If a single field is the whole basis for a
  claim, say so - one header is thin evidence.
  ```
- **Output contract:** a hard proven/suggested split with field-level citations, the authz-location
  verdict, unsolicited anomalies, and notable absences.
- **Verify before use:** re-read the cited field for every PROVEN row yourself. Only PROVEN rows go
  in a report.
- **Feeds:** `P-BUG-01`; PB-16.

### `P-OFF-07` — Pre-action ROE gate
- **Use when:** immediately before any action you have not already cleared. Cheap, and it is the
  control that prevents the expensive mistake.
- **Supply:** the exact planned action and the `P-OFF-01` scope table.
- **Prompt:**
  ```
  Gate-check this planned action against my authorization boundary. Be conservative.

  PLANNED ACTION: <exact action, target, parameters, expected effect>
  SCOPE TABLE: <from P-OFF-01>

  Answer in this order:
  1. Which scope-table row, if any, covers this action. Quote it.
  2. Does the action touch any asset, identity, tenant, or dataset not in that row.
  3. Is it state-changing. If yes, what is the least-impact alternative that yields
     the same evidence.
  4. Could it affect another tenant, another user, availability, or cost.
  5. Which ROE clauses are engaged: least-impact, data handling, denial-of-wallet,
     tenancy, artifact safety, identifiability.
  6. Verdict: COVERED / NOT COVERED / UNCLEAR, and the one question to ask the program
     owner if UNCLEAR.

  Default to UNCLEAR rather than COVERED when the scope table is silent. You are not
  authorizing anything - you are helping me find the reason to stop.
  ```
- **Output contract:** clause-quoted coverage, tenancy and cost impact, engaged ROE clauses, and a
  conservative verdict.
- **Verify before use:** a COVERED verdict is the assistant's reading, not authorization. On UNCLEAR,
  stop and ask the program owner. This prompt exists to catch you, and a model's permission is worth
  exactly nothing.
- **Feeds:** every action; PB-15 Phase 0.

### `P-OFF-08` — Engagement activity ledger
- **Use when:** continuously. The ledger is what makes your work auditable and separable from a real
  adversary's.
- **Supply:** your raw notes, commands, and timestamps for the period.
- **Prompt:**
  ```
  Turn these raw engagement notes into an audit-quality activity ledger.

  RAW NOTES: <notes, commands, timestamps>
  TEST WINDOW: <window>
  IDENTIFYING MARKERS IN USE: <header, user agent, registered test accounts>

  Produce one row per action: UTC timestamp | source identity and IP | target asset |
  action | intended purpose | observed result | scope-table row authorising it |
  canaries placed | cleanup status.

  Then flag, separately:
  - Any action with no authorising scope row.
  - Any action outside the stated test window.
  - Any canary placed and not yet removed.
  - Any state change not reverted.
  - Any gap in the notes where an action clearly occurred but is unrecorded.

  Do not invent a purpose for an action I did not explain. Write UNEXPLAINED.
  ```
- **Output contract:** per-action ledger tied to authorising rows, plus flagged exceptions and
  UNEXPLAINED entries.
- **Verify before use:** resolve every flag before the engagement closes. An unremoved canary or an
  unreverted state change is a §7 obligation, not paperwork, and an unauthorised row needs an answer
  before someone else asks the question.
- **Feeds:** the engagement record; `P-REP-05`.

---

## Bug bounty — `P-BTY`

### `P-BTY-01` — Parse a program policy into a testable scope matrix
- **Use when:** before hunting on any platform program.
- **Supply:** the full policy text, the asset table, and the reward and exclusion sections.
- **Prompt:**
  ```
  Convert this bug-bounty program policy into a testable scope matrix.

  POLICY TEXT: <full text>
  ASSET TABLE: <assets and tiers>
  REWARDS AND EXCLUSIONS: <sections>

  Produce:
  1. Asset matrix: asset | in/out | permitted test classes | explicit limits | reward
     tier.
  2. Excluded finding types, quoted, with the class of defect each excludes.
  3. Required conditions: test accounts, identifying headers, rate limits, notification
     duties, safe-harbour terms and their conditions.
  4. AI-specific terms if present: whether model behavior is in scope at all, which
     channel it routes to, stated limits on automation, volume, or agents.
  5. AMBIGUOUS: quoted clauses that do not resolve, and the question to ask.
  6. The single most restrictive clause in the policy, quoted. Testers miss this one.

  Quote, do not paraphrase, anything that constrains behavior. Never resolve an
  ambiguity toward permitted.
  ```
- **Output contract:** the six sections with quoted constraints and an explicit ambiguity list.
- **Verify before use:** read the policy yourself. Policies change without notice, so re-check the
  live page at session start. Safe harbour usually has conditions, and it protects you only if you
  met them.
- **Feeds:** PB-15 Phase 0; `P-OFF-01`.

### `P-BTY-02` — Target selection
- **Use when:** choosing where to spend hours, with saturation as the main enemy.
- **Supply:** the candidate assets, program age and resolved-report statistics, your skill profile,
  and your available hours.
- **Prompt:**
  ```
  Help me choose targets. Saturation is the problem, not difficulty.

  CANDIDATE ASSETS: <list with what I know of each>
  PROGRAM DATA: <age, resolved counts, average bounty, response times>
  MY SKILL PROFILE: <strengths>
  HOURS AVAILABLE: <hours>

  For each candidate:
  - Saturation estimate and the evidence for it: program age, report volume, how
    obvious the asset is, whether it appears in common wordlists and recon tooling.
  - New-surface signals: recent deploys, new subdomains, fresh API versions, newly
    added AI or agent features, recent acquisitions, technology migrations.
  - Fit against my skill profile.
  - Expected value reasoning, with your assumptions named.

  Rank them, then state which you would SKIP and why. Be explicit that saturation
  estimates are inferences, not measurements.
  ```
- **Output contract:** per-candidate saturation with evidence, new-surface signals, fit, ranked list,
  and a skip list.
- **Verify before use:** these are priors, not facts. New surface is the real signal, and an AI
  feature shipped in the last quarter is usually the least-examined surface on a mature program.
- **Feeds:** the hunt plan.

### `P-BTY-03` — Duplicate and known-issue screening
- **Use when:** before writing a submission. Every duplicate costs signal.
- **Supply:** your finding, the program's disclosed reports and changelog, and public advisories for
  the stack.
- **Prompt:**
  ```
  Screen this finding for duplicate and known-issue risk.

  MY FINDING: <mechanism, location, impact>
  PROGRAM DISCLOSED REPORTS: <list or summaries>
  PROGRAM CHANGELOG / RELEASE NOTES: <entries>
  PUBLIC ADVISORIES FOR THIS STACK: <what I have gathered>

  Assess:
  1. Overlap with each disclosed report: same root cause, same class different
     instance, or unrelated. Same class at a different location is usually NOT a
     duplicate - say which it is and why.
  2. Whether a changelog entry suggests this is known or already being fixed.
  3. Whether this is a known framework or library behavior rather than a defect in the
     target, and whether it is documented as intended.
  4. Whether it falls under an excluded finding type from the policy.
  5. What makes MY instance distinct, if anything, stated in one sentence.

  Base this only on the material I supplied. Do not recall advisories from memory - if
  you think one exists, say so as a lead for me to verify, clearly marked.
  ```
- **Output contract:** per-report overlap verdicts, known-behavior check, exclusion check, a
  one-sentence distinctness claim, and any advisory leads flagged as unverified.
- **Verify before use:** retrieve every advisory lead before relying on it. Model-recalled advisory
  IDs are frequently wrong, and citing a nonexistent CVE in a submission is worse than not citing
  one.
- **Feeds:** `P-BTY-07`; `P-REP-01`.

### `P-BTY-04` — Trial-ledger assembly for a stochastic finding
- **Use when:** the target is a model and the behavior does not reproduce every time. Required by
  [§7.6](CONVENTIONS.md).
- **Supply:** every trial, including failures, with the model version and sampling parameters.
- **Prompt:**
  ```
  Assemble the trial ledger for this stochastic finding.

  TRIALS: <every trial: timestamp, clean context yes/no, input summary, outcome>
  MODEL AND VERSION STRING: <exact>
  SAMPLING PARAMETERS: <temperature, top-p, seed if settable>

  Produce:
  1. The ledger table, every trial including failures. A ledger with failures omitted
     is not a ledger.
  2. Successes / trials, and the success rate.
  3. The 95% Wilson score interval. Show the computation. Wilson, not a normal
     approximation - at these trial counts the normal interval is wrong at the tails.
  4. The canonical short form: successes/trials @ temperature (95% CI low-high).
  5. Whether this meets the GreyNOC bar: at least 2 successes from a CLEAN context.
     State clean-context successes separately from total successes.
  6. Confounds: context carry-over, ordering effects, non-independent trials,
     parameters that changed mid-run, retries that were not clean.

  Do not characterise the rate in words. 2/50 is reported as 2/50, never as
  "reproducible" and never as "unreliable".
  ```
- **Output contract:** full ledger including failures, Wilson interval with shown computation,
  canonical short form, clean-context success count, and a confounds list.
- **Verify before use:** recompute the Wilson interval independently; confirm clean-context trials
  really were clean. Severity comes from consequence and the attacker's retry cost, not from the
  rate, and a low rate with a cheap retry is still a real finding.
- **Feeds:** PB-15 ledger section; `P-REP-01`.

### `P-BTY-05` — Severity reasoning
- **Use when:** you must justify a severity, not assert one.
- **Supply:** the proven finding, what you demonstrated versus inferred, the program's severity
  framework, and the affected data and users.
- **Prompt:**
  ```
  Reason through the severity of this finding. Justify, do not assert.

  FINDING: <mechanism and what I PROVED, distinguished from what I infer>
  PROGRAM SEVERITY FRAMEWORK: <CVSS version, or the program's own scale>
  AFFECTED DATA AND USERS: <what and whose, how many, evidenced how>
  PRECONDITIONS: <auth required, user interaction, positioning, timing>

  Produce:
  1. Severity based ONLY on what I proved. Score each factor with the evidence for it.
  2. Where the framework is ambiguous for this finding shape, say so rather than
     forcing a value.
  3. The higher severity a tester would be tempted to claim, and precisely what
     additional evidence would be required to justify it. Do not claim it.
  4. Preconditions that reduce severity, stated plainly - including ones I may be
     understating.
  5. For a stochastic finding, how the trial ledger and the attacker's retry cost bear
     on severity.
  6. The one sentence a triager will use to decide. Write it honestly.

  Never inflate. Unproven impact is not impact, and speculative severity is
  fabrication.
  ```
- **Output contract:** evidence-backed factor scoring, named ambiguities, the tempting-but-unjustified
  claim held separately, honest preconditions, and the triager sentence.
- **Verify before use:** check each factor against your proof. If you cannot point at the evidence,
  lower the score. Understating costs a little; overstating costs standing.
- **Feeds:** `P-REP-01`.

### `P-BTY-06` — Evidence hygiene and canary check
- **Use when:** before submission and before engagement close.
- **Supply:** your evidence package, the canary registry, and the program's data-handling terms.
- **Prompt:**
  ```
  Audit this evidence package for data-handling and canary hygiene.

  EVIDENCE PACKAGE: <inventory: captures, screenshots, logs, exports, notes>
  CANARY REGISTRY: <markers placed, where, removed yes/no>
  PROGRAM DATA-HANDLING TERMS: <terms>

  Check and report:
  1. Third-party PII, secrets, tokens, session material, or message plaintext present.
     Flag location and required action. Screenshots and HAR files are the usual
     offenders - check them specifically.
  2. Data retained beyond what the program permits.
  3. Redaction that is reversible: partial masks, visible lengths, recoverable
     identifiers, metadata in image files, full URLs with identifiers.
  4. Canaries placed and not removed, or placed anywhere not exclusively mine.
  5. Whether the package is the MINIMUM that proves the claim, and what should be cut.
  6. Any evidence that itself constitutes harm to hold.

  Assume I over-collected. That is the normal failure.
  ```
- **Output contract:** located PII and secret findings, retention violations, reversible-redaction
  flags, outstanding canaries, and a cut list.
- **Verify before use:** act on every flag before submitting. Unremoved markers and retained
  third-party data are §6.4 and §7.4 obligations, and discovery of real user data is a stop
  condition, not a note for the report.
- **Feeds:** `P-REP-05`; `P-OFF-08`.

### `P-BTY-07` — Submission readiness gate
- **Use when:** the last check before you submit.
- **Supply:** the draft report, the evidence package, the scope matrix, and the trial ledger where
  applicable.
- **Prompt:**
  ```
  Gate this submission. Find the reason to hold it.

  DRAFT REPORT: <report>
  EVIDENCE PACKAGE: <inventory>
  SCOPE MATRIX: <from P-BTY-01>
  TRIAL LEDGER: <if the target is stochastic>

  Check:
  1. Is every claim in the report supported by evidence IN the package. List any that
     is not, quoting the claim.
  2. Can a triager reproduce it from the report alone. Name the missing step.
  3. Is this a security defect or model behavior, and does it match the channel I am
     submitting to.
  4. Is the asset in scope and the finding type not excluded. Quote the clause.
  5. Is severity justified by proven impact only.
  6. Is the trial ledger complete, with clean-context successes stated.
  7. Is the evidence minimal and redacted.
  8. Is there an unstated assumption the whole finding rests on.

  Verdict: READY / HOLD. If HOLD, the specific thing to fix. Prefer HOLD. A withdrawn
  or downgraded report costs more than an hour of extra work.
  ```
- **Output contract:** claim-by-claim support check, reproducibility gap, routing and scope
  confirmation, and a READY/HOLD verdict with specifics.
- **Verify before use:** fix every HOLD item. Routing is the one to get right: a content-policy
  bypass with no security consequence submitted to a security queue damages standing, per
  [§7.1](CONVENTIONS.md).
- **Feeds:** the submission.

---

## Bug analysis — `P-BUG`

### `P-BUG-01` — Root-cause analysis from evidence
- **Use when:** you can reproduce something but cannot yet explain it.
- **Supply:** the reproduction, full evidence, the code if you have it, and what you expected.
- **Prompt:**
  ```
  Determine the root cause of this defect from the evidence.

  REPRODUCTION: <steps and observed result>
  EVIDENCE: <requests, responses, logs, stack traces>
  CODE IF AVAILABLE: <relevant code>
  EXPECTED BEHAVIOR: <expectation>

  Produce:
  1. Candidate root causes, each with the specific evidence supporting it and the
     evidence that would refute it.
  2. For each, the layer it sits in: input validation, authorization, state management,
     output handling, configuration, trust-boundary design, dependency.
  3. The ONE observation that best separates the leading candidates.
  4. Whether this is a single defect or several. Say so if the reproduction crosses
     more than one.
  5. Where else in a system of this shape the same root cause probably appears. This is
     the highest-value output - a root cause usually has siblings.
  6. What the evidence does NOT let you determine.

  Distinguish MECHANISM (what happens) from ROOT CAUSE (why it is possible). Do not
  report a mechanism as a root cause.
  ```
- **Output contract:** candidates with supporting and refuting evidence, layer assignment, the
  discriminating observation, a sibling-location list, and stated limits.
- **Verify before use:** make the discriminating observation before settling. The sibling list is a
  hypothesis list for `P-OFF-04`, not a set of findings.
- **Feeds:** `P-BUG-02`; `P-REP-01`.

### `P-BUG-02` — Classify into the defect registry
- **Use when:** a finding needs its class before it can be filed or routed.
- **Supply:** the finding, the proven impact, and the registry definitions.
- **Prompt:**
  ```
  Classify this finding against the GreyNOC defect-class registry.

  FINDING: <mechanism, root cause, proven impact>
  REGISTRY: C (crypto implementation, PB-08) | L (LLM application, PB-16) |
  S (AI supply chain and artifacts, PB-17) | G (agentic, tools, MCP, PB-18) |
  I (inference infrastructure and tenancy, PB-20) | none (model behavior, PB-19)

  Produce:
  1. The single PRIMARY class, with the reasoning. Apply the tiebreaker explicitly:
     delete the model from the design - if a recognisable web or API bug remains it is
     L; an action the system TOOK is G; what you LOADED is S; the box it RUNS ON is I.
  2. Secondary classes if this is a chain, in execution order, with the primary named.
     Score on the step proved, not on the chain's ceiling.
  3. Why each class you rejected does not fit. Adjacent classes are where
     misclassification happens.
  4. Whether this has NO security consequence and routes to model behavior instead.
  5. If nothing fits, say so and describe the gap rather than forcing a class.

  A finding cites exactly one primary class.
  ```
- **Output contract:** one primary class with tiebreaker reasoning, ordered secondaries, explicit
  rejections, a routing verdict, and an honest gap statement where nothing fits.
- **Verify before use:** check the class definition in the owning playbook yourself. A "nothing fits"
  result is worth attention: it is either a misread finding or a genuine catalog gap worth raising.
- **Feeds:** the owning playbook; `P-BUG-03`.

### `P-BUG-03` — Security defect or model behavior
- **Use when:** the finding involves a model doing something it should not. Do this **before** you
  submit anywhere.
- **Supply:** what you did, what the model produced, what you proved followed from it, and the
  program's channels.
- **Prompt:**
  ```
  Route this finding: security defect or model behavior.

  WHAT I DID: <input, conditions>
  WHAT THE MODEL PRODUCED: <output, characterised not reproduced if sensitive>
  WHAT I PROVED FOLLOWED FROM IT: <consequence, or none>
  PROGRAM CHANNELS: <security queue, model-safety channel, terms of each>

  Apply the test:
  - Did a concrete security consequence follow: an unauthorised tool invocation,
    access to data I was not entitled to, a privilege change, code execution, or a
    control crossing a trust boundary. Name it and the evidence, or say NONE.
  - If NONE, this is model behavior and routes to the model-safety channel. Say so
    plainly. Different text is not a security finding.
  - If a consequence exists, the finding is the CONSEQUENCE, not the model output. Name
    the class it belongs to and restate the finding around the consequence.

  Then:
  1. The routing verdict and the channel.
  2. The one sentence that makes the routing obvious to a triager.
  3. Whether proving it further would require generating genuinely harmful content -
     if so, say STOP and report the control gap with the boundary evidence in hand.

  Do not hedge to keep a security-queue option open. Wrong-queue submissions cost
  standing.
  ```
- **Output contract:** a named consequence or an explicit NONE, a routing verdict, the triager
  sentence, and a STOP flag where proof would require harmful output.
- **Verify before use:** be honest about the consequence. Most jailbreaks are not security findings,
  and per [§7.2](CONVENTIONS.md) you never generate genuinely harmful content as proof. A control
  gap reported from boundary evidence is a legitimate finding; a demonstration built out of harmful
  output is not.
- **Feeds:** PB-19 or the security queue; `P-BTY-07`.

### `P-BUG-04` — Chain construction
- **Use when:** individually minor findings might combine into real impact.
- **Supply:** each finding with its proof status, the target's architecture, and the identities you
  control.
- **Prompt:**
  ```
  Assess whether these findings chain into greater impact.

  FINDINGS: <each: mechanism, class, what is PROVED vs assumed>
  ARCHITECTURE: <components, boundaries, identities>
  IDENTITIES I CONTROL: <list>

  Produce:
  1. Viable chains as ordered sequences, with the precondition each step needs from
     the previous one.
  2. For each step: PROVEN or ASSUMED. A chain containing an assumed step is a
     hypothesis, not a finding. Label it as such.
  3. The impact the chain delivers that no single finding delivers.
  4. What it would take to prove each ASSUMED step, within ROE.
  5. Whether to report the chain as one finding or separately. Programs differ; state
     the trade-off.
  6. Chains you considered and rejected, with the reason.

  Score the chain on the steps PROVED, not on the ceiling it would reach if every
  assumption held.
  ```
- **Output contract:** ordered chains with per-step proof status, the chain-specific impact, proof
  plans for assumed steps, a reporting recommendation, and rejected chains.
- **Verify before use:** prove each step or label it assumed in the report. An unproven chain
  presented as real is fabrication, and citing the primary class with the sequence listed is the
  house convention.
- **Feeds:** `P-BTY-05`; `P-REP-01`.

### `P-BUG-05` — Falsify your own finding
- **Use when:** before every submission. This is the highest-value prompt in the library.
- **Supply:** the finding, the full evidence, and your reproduction method.
- **Prompt:**
  ```
  Your job is to REFUTE this finding. Argue that it is not a defect, or not mine to
  report, or not what I think it is. Do not validate it.

  FINDING: <claim>
  EVIDENCE: <everything I have>
  REPRODUCTION METHOD: <exact steps, including environment and identities>

  Attack it on every front:
  1. Intended behavior: documented, or a deliberate design decision.
  2. Test-environment artefact: my own configuration, my own account state, my own
     tooling or proxy, a debug or non-production setting.
  3. Reproduction flaw: context carry-over, cached response, a cookie or token I forgot
     about, a client-side effect I read as server-side, an identity that already had
     the access.
  4. Misattributed impact: the consequence comes from something other than the
     mechanism I am blaming.
  5. Pre-existing access: I already held the entitlement I claim to have bypassed.
     This is the most common invalid submission.
  6. Third-party or out-of-scope ownership: the defect is in a dependency or an asset
     that is not the program's.
  7. Non-reproducibility: my successes are consistent with chance given the trial count.

  For each, say whether my evidence RULES IT OUT or leaves it open. End with the
  strongest single argument a triager will make for closing this as invalid.
  ```
- **Output contract:** a per-angle ruled-out or left-open verdict, and the strongest closing
  argument a triager would make.
- **Verify before use:** close every "left open" angle before submitting, or state the limitation in
  the report. If the strongest counterargument survives your evidence, you do not have a finding
  yet. Pre-existing access is the angle to check hardest.
- **Feeds:** `P-BTY-07`.

### `P-BUG-06` — Fix and patch review
- **Use when:** validating a remediation, yours or a vendor's.
- **Supply:** the original defect, the fix, and the code or config if available.
- **Prompt:**
  ```
  Review this fix against the original defect.

  ORIGINAL DEFECT: <mechanism and root cause>
  FIX AS APPLIED: <patch, config change, or description>
  CODE / CONFIG IF AVAILABLE: <content>

  Assess:
  1. Does the fix address the ROOT CAUSE or only the reproduction path I reported.
     Blocking my exact input is not a fix.
  2. Variants that still work: encoding, alternate parameter, different entry point,
     another endpoint sharing the code path, a different content type.
  3. Is the control now ENFORCED (code, authz, allowlist, type system, separate
     context) or INSTRUCTED (text asking a model to behave). An instructed control is
     not a fix for an injection defect.
  4. New surface the fix introduces.
  5. Sibling locations with the same root cause that this fix does not touch.
  6. The regression test that would catch this defect returning, described concretely.

  If the fix is incomplete, say which specific variant defeats it. Do not write an
  exploit - describe the variant class and where to test it.
  ```
- **Output contract:** a root-cause-versus-symptom verdict, surviving variant classes, the
  ENFORCED/INSTRUCTED call, new surface, untouched siblings, and a regression test description.
- **Verify before use:** test each claimed surviving variant under the same authorization as the
  original work. Re-testing a fix is a new test and needs the same scope check.
- **Feeds:** `P-REP-03`; retest report; PB-22 change gates.

### `P-BUG-07` — Regression test authoring
- **Use when:** a defect is fixed and must stay fixed. Required for anything that ships.
- **Supply:** the defect, the fix, the test framework, and the existing test structure.
- **Prompt:**
  ```
  Write regression tests for this defect.

  DEFECT: <mechanism and root cause>
  FIX: <what changed>
  TEST FRAMEWORK AND CONVENTIONS: <framework, existing structure, naming>
  FIXTURES AVAILABLE: <what exists>

  Produce:
  1. The test that FAILS on the unfixed code and PASSES on the fixed code. State how
     you know it fails on the original - a regression test that never failed proves
     nothing.
  2. Variant tests covering the encoding, entry-point, and content-type variations of
     the same root cause.
  3. The negative test: legitimate behavior that must keep working, so the fix cannot
     be "fixed" by breaking the feature.
  4. Boundary cases at the edge of the fixed condition.
  5. Any test that needs a fixture I do not have, named as a prerequisite rather than
     invented.

  Use only the framework and fixtures I described. Do not invent helpers.
  ```
- **Output contract:** a red-then-green test with its failure basis stated, variant tests, a negative
  test, boundary cases, and named fixture prerequisites.
- **Verify before use:** confirm the test genuinely fails against the pre-fix code by running it
  there. A test that passes both ways is decoration.
- **Feeds:** the repository test suite; detection-validation regression history; PB-22.

---

## Reporting — `P-REP`

### `P-REP-01` — Draft a finding report
- **Use when:** the finding is proven, falsified, classified, and gated.
- **Supply:** the finding, the proof, the severity reasoning, the trial ledger where applicable, and
  the required template.
- **Prompt:**
  ```
  Draft a finding report from the material below. Use ONLY this material.

  FINDING: <mechanism and root cause>
  PROOF: <evidence, with what is PROVED marked distinctly from what I infer>
  SEVERITY REASONING: <from P-BTY-05>
  TRIAL LEDGER: <if stochastic>
  REQUIRED TEMPLATE: <program or client template>
  AUDIENCE: <triager | client security team | engineering>

  Rules:
  - Every factual claim traces to my material. Add nothing. If a section of the
    template has no supporting material, write NEEDS INPUT and name what is missing.
  - Reproduction steps must be complete enough for someone with my access level to
    follow without asking a question. Include environment, identities, and
    preconditions.
  - Impact states what was DEMONSTRATED. Potential impact, if the template has a place
    for it, goes in its own clearly labelled section and is never stated as fact.
  - No severity inflation, no speculative chaining, no invented references.
  - Include no more evidence than the claim needs.
  - Plain declarative prose. No adjectives doing the work of evidence.
  ```
- **Output contract:** the template filled from supplied material only, with NEEDS INPUT markers,
  demonstrated impact separated from potential impact, and complete reproduction steps.
- **Verify before use:** read every sentence against your evidence; resolve every NEEDS INPUT;
  confirm no citation appeared that you did not supply. Models add plausible references
  unprompted, so check the reference list specifically.
- **Feeds:** the submission or client deliverable.

### `P-REP-02` — Business impact statement
- **Use when:** a non-technical decision-maker must understand what the finding means.
- **Supply:** the technical finding, the proven impact, the business context, and the audience.
- **Prompt:**
  ```
  Write the business impact statement for this finding.

  TECHNICAL FINDING: <mechanism>
  PROVEN IMPACT: <what I demonstrated, precisely>
  BUSINESS CONTEXT: <what the system does, whose data, regulatory exposure I can
  actually substantiate>
  AUDIENCE: <executive | risk | product owner>

  Rules:
  - State the consequence in business terms without overstating the technical facts.
    The translation must not smuggle in impact I did not prove.
  - Separate DEMONSTRATED consequence from CONDITIONAL consequence, and state the
    condition for each conditional one.
  - No invented breach costs, no invented incident statistics, no invented regulatory
    penalties. If I did not supply a figure, do not produce one.
  - Name a regulation only if I named it and it plainly applies. Otherwise write
    "regulatory review required" and stop.
  - Six sentences or fewer.
  - No fear language. The facts are enough, and an executive who catches one
    exaggeration discounts the rest.
  ```
- **Output contract:** six sentences or fewer, demonstrated and conditional consequences separated,
  no unsourced figures or regulatory claims.
- **Verify before use:** check that no number or regulation appeared that you did not supply. This is
  where fabrication is most tempting and most damaging to credibility.
- **Feeds:** executive summary; client reporting; PB-14 and PB-21 governance reporting.

### `P-REP-03` — Remediation guidance
- **Use when:** the report needs a fix the receiving engineer can actually act on.
- **Supply:** the root cause, the technology stack, the constraints, and the affected locations.
- **Prompt:**
  ```
  Write remediation guidance for this defect.

  ROOT CAUSE: <cause, not just mechanism>
  STACK: <languages, frameworks, versions>
  CONSTRAINTS: <what cannot change, timelines, compatibility>
  AFFECTED LOCATIONS: <known instances>

  Produce, in this order:
  1. Immediate mitigation: reduces exposure now, and what it does NOT fix. Be explicit
     that a mitigation is not a fix.
  2. Root-cause fix: addresses why this was possible. Specify ENFORCED controls -
     authorization checks, allowlists, output encoding at the sink, type boundaries,
     context separation. Never propose instructing a model to behave as the fix for an
     injection defect.
  3. Verification: how the engineer confirms the fix works, including the negative case.
  4. Sibling locations to audit for the same root cause.
  5. What NOT to do: the tempting fixes that do not work here, and why. Input
     blocklists and blocking the reported string are the usual ones.
  6. Prerequisites and trade-offs the constraints create.

  Fit the stack I named. If a recommendation needs a version or component I did not
  list, say so as a prerequisite rather than assuming it.
  ```
- **Output contract:** mitigation with stated limits, an enforced root-cause fix, verification
  including a negative case, sibling audit list, an anti-pattern list, and named prerequisites.
- **Verify before use:** confirm the recommendation is valid for the exact stack version. Generic
  advice that does not compile in the target's framework wastes the engineer's trust.
- **Feeds:** the report; `P-BUG-06` retest.

### `P-REP-04` — Executive summary
- **Use when:** an engagement or assessment closes.
- **Supply:** all findings with severity and status, the scope actually tested, the limitations, and
  the audience.
- **Prompt:**
  ```
  Write the executive summary for this engagement.

  FINDINGS: <each: title, severity, status, proven impact>
  SCOPE ACTUALLY TESTED: <assets, test classes, time spent>
  SCOPE NOT TESTED AND WHY: <gaps, blockers, out-of-scope areas>
  LIMITATIONS: <access, time, telemetry, environment>
  AUDIENCE: <executive | board | client security leadership>

  Structure:
  1. What was tested and what was not. The gap is as important as the result and goes
     up front, not in an appendix.
  2. The overall picture in three sentences, grounded in the findings list.
  3. The findings that matter, by business consequence rather than by severity label.
  4. The systemic pattern across findings, if the evidence supports one. If it does
     not, say the findings are independent - do not manufacture a theme.
  5. What to do first, and why that order.
  6. Explicitly: what a clean result in the untested areas does NOT mean.

  No reassurance the findings do not support. No alarm they do not support. An absence
  of findings in an untested area is not a clean result and must not read as one.
  ```
- **Output contract:** tested-and-untested up front, a grounded three-sentence picture, consequence
  ordering, an honest systemic-pattern call, a prioritised action list, and the limits of a clean
  result.
- **Verify before use:** confirm every characterisation against the findings list. The
  untested-scope statement is the sentence most often softened in review, and the one that matters
  most if an incident later lands in an area you never examined.
- **Feeds:** the client deliverable.

### `P-REP-05` — Evidence package assembly
- **Use when:** packaging evidence for submission, a client, or an archive.
- **Supply:** the evidence inventory, the claims it must support, and the retention and handling
  rules.
- **Prompt:**
  ```
  Assemble and audit the evidence package.

  EVIDENCE INVENTORY: <every item, with what it shows>
  CLAIMS IT MUST SUPPORT: <claim list from the report>
  RETENTION AND HANDLING RULES: <program or contract terms>

  Produce:
  1. Claim-to-evidence map. Flag every claim with NO supporting evidence, and every
     evidence item supporting NO claim. Both are defects.
  2. The minimum set that supports all claims. Name what to cut.
  3. Redaction requirements per item, specifically: PII, secrets, tokens, session
     material, third-party content, internal hostnames, image metadata, full URLs
     carrying identifiers.
  4. Reversible-redaction risks: partial masking, preserved lengths, recoverable
     identifiers, redaction applied as an overlay rather than by removal.
  5. Chain-of-custody gaps: missing timestamps, unclear capture provenance, items with
     no recorded source.
  6. Items that should not be retained at all, and the disposal action.

  Assume I over-collected and under-redacted. That is the normal state.
  ```
- **Output contract:** a bidirectional claim-to-evidence map, a minimum set with a cut list,
  per-item redaction requirements, reversibility risks, custody gaps, and a disposal list.
- **Verify before use:** perform the redactions by removing data, not by covering it; verify by
  inspecting the file, not the rendered view. An overlay over text in a PDF or an image leaves the
  text in place.
- **Feeds:** the submission; the engagement archive; `P-BTY-06`.

### `P-REP-06` — Disclosure coordination message
- **Use when:** communicating with a program or vendor about timing, status, or escalation.
- **Supply:** the situation, the timeline so far, the program's stated policy, and your objective.
- **Prompt:**
  ```
  Draft the disclosure coordination message.

  SITUATION: <status, what has and has not happened>
  TIMELINE SO FAR: <dates: submission, acknowledgements, responses, commitments>
  PROGRAM DISCLOSURE POLICY: <stated terms>
  MY OBJECTIVE: <status request | timeline extension | escalation | publication
  discussion>

  Rules:
  - Professional, factual, cooperative. No pressure tactics, no deadline threats, no
    implied publication leverage unless the policy expressly provides for it and I
    asked for that.
  - State the timeline as dates and facts, not as grievance.
  - Reference the policy terms that apply, quoted.
  - Make the specific ask explicit and easy to answer.
  - Acknowledge what the other side has done.
  - Offer something concrete: retest, more detail, a call, extra time.
  - Under ten sentences.

  Coordinated disclosure means the other party gets to be slow sometimes. Write
  accordingly.
  ```
- **Output contract:** under ten sentences, factual timeline, quoted policy terms, an explicit ask,
  acknowledgement, and a concrete offer.
- **Verify before use:** confirm every date; confirm the quoted policy text. Never publish ahead of
  the policy timeline, per [§6.5](CONVENTIONS.md). Send it yourself after reading it.
- **Feeds:** the disclosure record.

### `P-REP-07` — AI-assistance disclosure statement
- **Use when:** any deliverable that an assistant touched. Required by the prompt contract, rule 11.
- **Supply:** which prompts you used, what the assistant produced, what you verified and how, and the
  deliverable type.
- **Prompt:**
  ```
  Write the AI-assistance disclosure statement for this deliverable.

  PROMPTS USED: <P- identifiers and purposes>
  WHAT THE ASSISTANT PRODUCED: <drafts, analyses, classifications>
  WHAT I VERIFIED AND HOW: <verification performed, per item>
  DELIVERABLE TYPE: <bounty submission | client report | internal record>

  The statement must say:
  - Where AI assistance was used, by function, not vaguely.
  - What a human verified, and how.
  - That all findings, severities, and conclusions are human-owned and independently
    reproducible from the evidence.
  - Any section where assistance was used and verification was LIGHTER than elsewhere.
    State it plainly - this is the part a reviewer needs.

  Three to five sentences. Factual. This is not a liability disclaimer and must not
  read as one - it tells a reviewer where to look hardest.

  If my verification notes do not cover something the assistant produced, say so
  explicitly rather than implying full verification.
  ```
- **Output contract:** three to five sentences naming functions, verification performed, human
  ownership, and any lighter-verified section called out.
- **Verify before use:** confirm the statement is true. An overstated verification claim is itself a
  fabrication, and the lighter-verification sentence is the one worth keeping honest.
- **Feeds:** every AI-assisted deliverable.

---

## Anti-patterns (do not do these)

| Anti-pattern | Why it fails |
| --- | --- |
| Asking the model what it knows about a target, instead of supplying evidence | Produces fluent fiction about a system it has never seen. Rule 2. |
| Pasting client logs, customer PII, secrets, or message plaintext into a third-party assistant | A data-handling breach independent of any finding. Rules 4, §6.4, §7.7. |
| Shipping a model-generated CVE, RFC, ATT&CK, or ATLAS citation unretrieved | Well-formed and nonexistent are not mutually exclusive. Rule 5. |
| Deploying a generated detection without a true-positive test | A rule that matches nothing looks identical to a quiet estate. `P-DEF-01`. |
| Treating an `L2`-shaped output as trustworthy after pasting target content in | You imported the target's author into your workflow. Rule 7. |
| Asking for a working exploit, payload, or evasion string | Out of scope. Demonstrate the control failure, not the payload. Rule 9, §7.2. |
| Letting the model decide scope | It cannot. Authorization comes from the signed document. Rule 8. |
| Using the assistant's agreement as reproduction | The assistant is not a trial. Rules 1, 10; §7.6. |
| Submitting AI-assisted severity without checking each factor against evidence | Speculative severity is fabrication whoever wrote it. `P-BTY-05`, §6.3. |
| Skipping `P-BUG-05` because the finding feels solid | Confidence is the precondition for the invalid submission, not a defense against it. |
| Running the same prompt until you like the answer | You have selected for agreement, not established anything. |
| Omitting the AI-assistance disclosure because the output was heavily edited | Rule 11. The reviewer decides what that means, not you. |

## Validation discipline (the GreyNOC bar)

An AI-assisted artifact meets the same bar as any other in this collection. Before anything leaves
your machine:

1. **Traceable.** Every factual claim traces to evidence you supplied or a source you retrieved.
2. **Retrieved.** Every external citation has been opened and says what the artifact claims.
3. **Tested.** Every rule, query, script, and command has run and produced the expected result,
   including the negative case.
4. **Falsified.** `P-BUG-05` has been run and every surviving counterargument is closed or disclosed.
5. **Reproducible.** A competent third party reproduces the result from the artifact alone, with the
   [§7.6](CONVENTIONS.md) trial ledger where the target is stochastic.
6. **Scoped.** Every action taken was covered by authorization at the time it was taken.
7. **Clean.** No unauthorised third-party data retained, no canary left in place, no state left
   changed.
8. **Disclosed.** The `P-REP-07` statement is present and true.

Failing any one of these means the artifact is not ready, regardless of how good it reads. **Fluency
is the specific risk here:** AI-assisted output reads finished before it is correct, which is exactly
why the verification step is part of every prompt rather than a final review pass.

## Stop conditions

Stop, preserve, and escalate when:

- An assistant output would need genuinely harmful content to prove ([§7.2](CONVENTIONS.md)).
- You cannot trace a claim in an output to supplied evidence and cannot rule out fabrication.
- Target content you pasted in appears to have steered your assistant toward an action you did not
  request. Preserve the exchange; it may itself be a finding about the target, and it is evidence
  about your own workflow.
- Evidence you supplied to a third-party assistant turns out to have contained client data, PII, or
  secrets. This is a disclosure obligation to the client or program, not a private cleanup.
- An action you already took fails a retrospective `P-OFF-07` gate check. Stop and notify before
  taking another.
- You discover real user data in material you gathered ([§6.6](CONVENTIONS.md), [§7.11](CONVENTIONS.md)).
- Any deliverable already sent is found to contain an unverified citation or an unsupported claim.
  Correct it proactively with the recipient.

## Summary

A language model is a competent drafter, a useful adversarial reviewer, and an unreliable witness.
This library is built around that asymmetry: prompts that ask it to *structure, enumerate, translate,
and argue against* are worth having, and prompts that ask it to *recall facts about a target* are
worth nothing.

The five families cover where the work happens — detection engineering and triage, authorized
offensive testing, bounty selection and gating, defect analysis, and reporting. The eleven contract
rules are what make them safe to use, and the per-prompt verification step is not optional
decoration: it is the part that converts fluent output into work product.

Three things to carry out of here. **Evidence in, or nothing out** — a prompt without supplied
evidence produces fiction. **The falsification prompt is the one that pays** — `P-BUG-05` prevents
more bad submissions than every other prompt here combined. And **the assistant never owns
anything** — not the severity, not the classification, not the scope decision, and not the sentence
you shipped.

Reproducible or it didn't happen. The assistant does not change that, and it does not get a vote.

---

*GreyNOC — detection-engineering-first. Reproducible or it didn't happen.*
