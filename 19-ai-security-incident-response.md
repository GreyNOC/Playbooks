# GreyNOC Security Playbook

## AI Security Incident Response & Evidence

---

### 1. Overview

AI incidents cross application, model, data, agent, identity, and provider boundaries. A normal
web incident runbook is necessary but insufficient: responders must preserve prompts, retrieved
context, model/version metadata, tool traces, model and corpus provenance, and the policy state
that governed the decision. This playbook provides the corporate incident-response twin for
PB-16 through PB-20 and operationalizes the CISA JCDC AI Cybersecurity Collaboration Playbook.

Use it for confirmed or suspected prompt-injection consequences, cross-tenant exposure, poisoned
RAG or model artifacts, agent actions outside user intent, model theft, inference-key compromise,
serving-plane isolation failures, or material model-safety events with a security consequence.

### 2. MITRE Mapping

| Technique | ID | Incident relevance |
| --- | --- | --- |
| LLM Prompt Injection | AML.T0051 | Untrusted instructions alter model or agent behavior |
| AI Agent Tool Invocation | AML.T0053 | Tool execution creates the security consequence |
| RAG Poisoning / False RAG Entry Injection | AML.T0070 / AML.T0071 | Retrieved knowledge is the persistence or delivery path |
| AI Agent Context Poisoning | AML.T0080 | Memory or context survives into later tasks |
| Exfiltration via AI Inference API | AML.T0024 | Output or serving path releases protected data |
| Exfiltration via Cyber Means | AML.T0044 | Model or artifact theft |
| Valid Accounts / Unsecured Credentials | T1078 / T1552 | Compromised identities or inference keys |
| Data from Information Repositories | T1213 | RAG, vector, training, prompt, or transcript stores |

ATLAS citations use collection 2026.06, and ATT&CK citations **ATT&CK Enterprise v19.2** (verified
2026-08-09), per [CONVENTIONS §4](CONVENTIONS.md). This table has no tactic column, so v19's
retirement of "Defense Evasion" does not reach it, but the ATT&CK names and IDs above were
re-verified against v19.2. Re-verify against the versions your platform carries.

### 3. Preconditions and Readiness

Before an incident, maintain:

- A current AI asset inventory and AI-BOM from PB-21, including owner, provider, model/version,
  data classes, connectors, tools, tenant boundary, and rollback path.
- Centralized, access-controlled logs for prompts, retrieved chunk identifiers and hashes,
  completions, policy decisions, tool calls/results, request and trace identifiers, model
  version, sampling parameters, identity, tenant, and deployment version.
- A provider contact matrix, contractual notification windows, legal/privacy contacts, and a
  documented evidence-request path for provider-held telemetry.
- Tested containment modes: disable one tool, revoke one connector, quarantine one corpus,
  pin or roll back one model, block one tenant, disable memory, rotate inference credentials,
  and enter safe degraded mode without taking the entire product offline.
- Evidence retention that reconciles forensic need with privacy, minimization, and deletion
  obligations. Do not create a permanent surveillance store merely to make response easier.

### 4. Detection and Intake

Open an AI incident record when any of these is observed:

- A model or agent executes a side-effectful action that is unauthorized, off-task, or not
  attributable to an explicit user approval.
- A completion contains another tenant's canary, protected data, secret, private prompt,
  internal model artifact, or content outside the caller's entitlement.
- A RAG, memory, training, adapter, registry, or model reference changes outside the approved
  pipeline, or behavior changes immediately after such a change.
- Request/response, cache, batch, scheduler, or timing evidence suggests cross-request or
  cross-tenant contamination.
- Inference credentials, signed model URLs, control-plane endpoints, or model weights are exposed.
- Usage and spend depart from the tenant, project, or agent budget and cannot be explained by
  approved demand.
- A model-safety report crosses the PB-19 routing line by producing a concrete security effect.

### 5. First 30 Minutes

1. Assign incident commander, technical lead, evidence custodian, provider liaison, and
   communications owner.
2. Record the affected AI artifact and system: application, model/provider/version, prompt or
   workload class, lifecycle phase, deployment, tenant(s), tools/connectors, data stores, and
   identities.
3. Preserve the minimum complete evidence package before changing state:
   request/response pairs, prompt and retrieved-context hashes, trace IDs, tool calls/results,
   policy decision, model/version, deployment digest, corpus/model reference, identity/tenant,
   sampling parameters, timestamps, and relevant configuration.
4. Choose the narrowest containment control from the matrix below. Preserve volatile agent
   scratchpads and in-flight traces before killing the runtime where safe.
5. If real third-party data appears, stop exploration, minimize retention, involve privacy/legal,
   and follow applicable notification obligations.

### 6. Containment Matrix

| Incident class | Preferred containment | Avoid |
| --- | --- | --- |
| Prompt injection with tool effect | Disable affected tool or require deterministic approval; revoke task/session | Deleting all prompts before preserving evidence |
| Poisoned RAG or memory | Quarantine identified objects/index partition; disable write path; restore known-good snapshot | Re-indexing over the only forensic copy |
| Model/adapter compromise | Pin known-good digest; block mutable reference; isolate registry/build pipeline | Loading the suspect artifact to “see what it does” |
| Cross-tenant serving leak | Drain affected deployment; disable cache/batching feature; isolate tenant route | Generating load to reproduce in production |
| Inference-key compromise | Revoke and rotate key; scope replacement to project/tenant; audit use | Testing the exposed key against additional resources |
| Agent runaway / denial of wallet | Stop task graph; disable recursive spawn; enforce hard budget and concurrency ceilings | Waiting for the quota to exhaust as proof |
| Provider-origin incident | Freeze deployment/version changes; open severity channel with evidence IDs | Assuming provider logs will remain available indefinitely |

### 7. Investigation

Build a time-ordered evidence graph:

1. **Entry:** user prompt, retrieved object, tool metadata/result, model artifact, API request,
   compromised identity, or control-plane change.
2. **Interpretation:** model/version, policy and guardrail decisions, retrieved context, memory,
   system instructions, sampling configuration, and any routing model.
3. **Action:** completion, tool selection, tool arguments, downstream interpreter, cache/batch
   behavior, or model/adapter load.
4. **Effect:** data read, mutation, egress, spend, tenant crossing, integrity change, or loss of
   availability.
5. **Propagation:** later sessions, other agents, shared memory, indexes, model deployments,
   downstream systems, and provider infrastructure.

Do not infer causality from a screenshot. Correlate client and server trace IDs, deployment
digests, identity, tenant, and timestamps. For nondeterministic reproduction, use the PB-15 trial
ledger without producing additional harm.

### 8. Evidence Package

Preserve, hash, and access-control:

- Raw request/response and streaming frames, with secrets and unrelated personal data minimized.
- Prompt, system-instruction, retrieved-chunk, memory, tool-definition, and tool-result records.
- Model/provider/version string, model or adapter digest where available, deployment image,
  policy bundle, tokenizer/runtime version, sampling parameters, and routing decision.
- Identity, tenant/project, authorization result, connector scopes, tool approval, request/trace
  IDs, cache/batch/scheduler IDs where available, and network path.
- AI-BOM snapshot, relevant change tickets, provenance attestations, corpus/index version, and
  known-good reference.
- Analyst actions and containment changes with exact timestamps.

### 9. Eradication and Recovery

- Remove the unauthorized write or control path; do not merely delete the poisoned object.
- Rotate exposed credentials and invalidate derived sessions, signed URLs, cached credentials,
  and agent task tokens.
- Restore corpus, model, adapter, policy, or deployment from a verified immutable reference.
- Rebuild affected indexes where content trust cannot be proven; preserve the forensic snapshot
  separately under restricted access.
- Re-run deterministic authorization, canary isolation, regression, and abuse tests before
  returning traffic. Compare against a known-good model and deployment baseline.
- Monitor for recurrence across the maximum persistence horizon of memory, cache, signed URL,
  credential, and index refresh.

### 10. Communications and External Coordination

The incident commander decides whether the event requires provider, customer, regulator, law
enforcement, insurer, sector ISAC, or CISA/JCDC coordination. Share the minimum necessary facts:
affected AI artifacts/systems, model and lifecycle phase, observed technique, timeline, affected
users/data, external systems reachable, containment, and evidence confidence. Separate confirmed
facts from hypotheses and record disclosure authority.

### 11. False Positives and Tuning

- Security research content may contain injection strings without being positioned for execution.
- Provider model changes may alter behavior without compromise; verify version and release record.
- Client-side stream merge bugs can resemble batch contamination; correlate server trace IDs.
- Expected failover can look like model substitution; compare against approved routing policy.
- Legitimate burst usage may resemble cost harvesting; evaluate tenant budget, task graph, and
  user intent before containment.

### 12. Escalation Criteria

Escalate to major incident when any of the following is confirmed or reasonably suspected:

- Cross-tenant data, prompt, model, memory, or tool-result exposure.
- Privileged or irreversible agent action outside the caller's authorization or explicit approval.
- Compromise of a production model, adapter, registry, training/fine-tuning pipeline, or
  serving control plane.
- Exposure of a provider-, org-, or fleet-scoped inference credential.
- Material outage, uncontrolled spend, safety-to-security crossover, or incident propagation
  into external systems.

### 13. Analyst Notes Template

```text
Incident ID:          AIIR-____
Commander / leads:    ____ / ____ / ____
App / deployment:     ____ / ____
Model/provider/ver:   ____ / ____ / ____
Lifecycle phase:      build | deploy | inference | monitoring | retirement
Tenants / identities: ____
Entry -> action -> effect: ____ -> ____ -> ____
Tools/connectors:     ____   approval observed? Y/N
Data/artifacts:       ____   third-party data? Y/N
Evidence refs/hashes: ____
Containment:          ____   timestamp: ____
Provider case:        ____
Notification analysis: ____
Recovery tests:       authz | isolation | provenance | regression | budget
Disposition:          contained | monitoring | recovered | major-incident
```

### 14. Exercise and Maintenance

Run at least semiannual tabletop exercises for indirect prompt injection with a tool consequence,
cross-tenant cache leakage, poisoned model/adapter, and provider-origin model substitution. After
each exercise or incident, update telemetry requirements, contact paths, containment automation,
AI-BOM fields, and recovery tests.

### 15. Summary

AI incident response must reconstruct the whole decision path, not just the final text. Preserve
model and deployment identity, untrusted context, policy decisions, tool traces, tenant binding,
and artifact provenance; contain at the narrowest safe boundary; coordinate externally from
evidence; and recover only after authorization, isolation, provenance, and regression tests pass.

---

*GreyNOC — detection-engineering-first security operations.*
