# GreyNOC Security Playbook

## AI Serving Plane & Multi-Tenant Isolation Detection and Response

---

### 1. Overview

This is the defensive twin for PB-20. It covers AI gateways, inference routers, model-serving
control planes, caches, continuous/dynamic batching, schedulers, accelerator pools, model and
adapter stores, quota enforcement, and inference transport. Its central question is whether the
serving plane preserves identity, authorization, tenant, request, model, and budget boundaries
from ingress through completion.

This playbook closes the explicitly documented gaps for gateway object authorization, cache-key
tenancy, request/batch contamination, and response-path timing channels.

### 2. MITRE Mapping

| Technique | ID | Serving-plane use |
| --- | --- | --- |
| Discover AI Model Ontology / Family | AML.T0013 / AML.T0014 | Model enumeration and routing oracles |
| Exfiltration via AI Inference API | AML.T0024 | Cross-tenant content or model data in responses |
| Exfiltration via Cyber Means | AML.T0044 | Model/weight extraction |
| Denial of AI Service / Cost Harvesting | AML.T0029 / AML.T0034 | Capacity and spend abuse |
| Exploit Public-Facing Application | T1190 | Exposed gateway or serving control plane |
| Valid Accounts / Steal Application Access Token | T1078 / T1528 | Over-scoped inference credentials |
| Endpoint Denial of Service / Resource Hijacking | T1499 / T1496 | Serving capacity exhaustion |

ATLAS citations use collection 2026.06, and ATT&CK citations **ATT&CK Enterprise v19.2** (verified
2026-08-09), per [CONVENTIONS §4](CONVENTIONS.md). This table has no tactic column, so v19's
retirement of "Defense Evasion" does not reach it, but the ATT&CK names and IDs above were
re-verified against v19.2 — `T1528` is *Steal* Application Access Token, distinct from `T1550.001`
*Use Alternate Authentication Material: Application Access Token* cited in §5. Re-verify against
the versions your platform carries.

### 3. Required Telemetry

Log at ingress and every routing boundary:

- Authenticated principal, credential ID, tenant/org/project, role, entitlement result, policy
  version, source, and request ID.
- Requested and resolved model/adapter, deployment/pool/worker, region, provider, routing reason,
  and immutable image/model/adapter digest where available.
- Cache namespace/key digest, cache decision, batch and scheduler identifiers, stream/channel ID,
  and request-to-output correlation.
- Token counts, accelerator/worker time, queue and service latency, retry count, quota counter,
  budget owner, rate-limit decision, and billed project.
- Response classification, data-loss-prevention decision, completion hash, error class, and
  streaming termination reason.
- Control-plane changes, model loads/unloads, signed URL creation, key creation/rotation, quota
  changes, and administrative reads.

Prompts and completions are sensitive. Store full content only when policy authorizes it; retain
hashes, classifications, canary identifiers, and restricted forensic access otherwise.

### 4. Detection Strategy

Correlate five invariants:

1. **Identity invariant:** the credential's principal and scopes remain bound to the request.
2. **Tenant invariant:** every object, model, cache key, batch, stream, and billed unit carries the
   same authorized tenant/project unless an explicit policy permits a transition.
3. **Request invariant:** every response frame and tool/model result maps to one originating
   request and trace.
4. **Artifact invariant:** the resolved model/adapter and runtime match approved immutable
   references.
5. **Budget invariant:** usage is charged to, limited by, and visible to the authorized project.

### 5. Detection Logic

```json
{
  "rule": "gateway_object_authorization_mismatch",
  "trigger": "requested_object.tenant != principal.tenant OR resolved_object.project NOT IN principal.entitlements",
  "correlate": ["request_id", "credential_id", "tenant", "project", "object_id", "policy_version"],
  "action": "deny + alert",
  "severity": "critical if content returned; high if request reached worker; medium if denied at gateway"
}
```

```json
{
  "rule": "cache_or_batch_tenant_contamination",
  "trigger_any": [
    "cache_hit AND cache_namespace.tenant != request.tenant",
    "batch_id contains more_than_one_tenant AND deployment.policy.single_tenant_batches == true",
    "response_frame.request_id != stream.origin_request_id",
    "completion_canary.owner_tenant != response.tenant"
  ],
  "action": "drain deployment + disable affected optimization + preserve correlation records",
  "severity": "critical if protected content crossed tenant"
}
```

```json
{
  "rule": "inference_artifact_or_budget_drift",
  "trigger_any": [
    "resolved_model_digest NOT IN approved_release.digests",
    "adapter_digest missing OR mutable_reference_used == true",
    "usage.billed_project != request.project",
    "quota_counter not_decremented OR project_limit_bypassed == true"
  ],
  "severity": "high"
}
```

### 6. Key Indicators

- Caller-supplied org/project/model identifiers disagree with token-bound identity but are accepted.
- Cache hits across tenant, project, authorization, model, adapter, policy, or privacy-mode changes.
- One batch, stream, or response carries mismatched request, tenant, or trace identifiers.
- Error body, status, token count, or latency reliably reveals another tenant's private model,
  object existence, cached prefix, or workload state.
- Serving workers fetch mutable model/adapter tags or load an unapproved digest.
- Signed model URLs, inference keys, or control-plane tokens are exposed client-side, unexpiring,
  org-scoped, or accepted outside their intended gateway.
- Usage is billed to the wrong project, quota counters diverge between paths, or agent recursion
  consumes resources outside the initiating task budget.
- Control-plane endpoints are internet-routable, weakly authenticated, or accessed by a serving
  identity that should only perform data-plane inference.

### 7. Investigation Steps

1. Confirm whether the mismatch exists in client instrumentation, gateway logs, or the serving
   stack. A client stream-merge bug is not a server isolation failure.
2. Correlate principal, tenant, project, request, trace, stream, cache, batch, scheduler, worker,
   model/adapter digest, and billed project end to end.
3. For cross-tenant content, preserve the smallest redacted fragment or canary plus its hash;
   stop retrieval and invoke D&R-19.
4. For cache behavior, reconstruct the complete cache-key dimensions and invalidation policy.
5. For batch/scheduler behavior, map each input slot to each output stream from server records;
   never generate production load to force contamination.
6. For timing/error differentials, evaluate pre-registered thresholds and distributions. A bare
   latency delta without a stable attributable fact is not a confirmed channel.
7. For artifact drift, compare runtime digest to the approved release attestation and registry
   event history.
8. For spend abuse, reconcile gateway, provider, quota, billing, and task-graph counters.

### 8. False Positives

- Client or SDK stream demultiplexing bugs.
- Approved shared public-model cache entries whose key excludes tenant by documented design and
  contains no tenant-derived state.
- Deliberate multi-tenant batching with cryptographic/request isolation and verified correlation.
- Deployment failover to an approved digest.
- Provider queue variability mistaken for a side channel.
- Delayed billing exports where real-time quota enforcement remained correct.

### 9. Tuning

- Make tenant, project, model, adapter, policy, privacy mode, authorization scope, and prompt-prefix
  provenance explicit cache-key dimensions; alert on missing dimensions.
- Require request/trace IDs on every streamed frame and fail closed on unknown or duplicate routing.
- Baseline timing by model, region, deployment, token shape, cache state, and load band before
  evaluating side-channel signals.
- Set separate per-key, user, project, tenant, agent, and global budgets; reconcile counters.
- Permit only immutable model/adapter digests in production and alert on tag resolution.
- Restrict control-plane identities and networks from data-plane workloads.

### 10. Response Actions

- Deny mismatched object requests at the gateway and invalidate any cached authorization decision.
- Drain the affected deployment; disable or scope the cache, batching, scheduler, or streaming
  optimization implicated by evidence.
- Revoke over-scoped keys and signed URLs; issue project-scoped, expiring replacements.
- Pin known-good model, adapter, runtime, and policy digests; isolate the artifact distribution path.
- Enforce hard quota ceilings and stop recursive task graphs without waiting for exhaustion.
- Invoke D&R-19 for cross-tenant content, credential compromise, artifact substitution, or
  material spend/outage.

### 11. Escalation Criteria

- Any confirmed cross-tenant prompt, completion, cache, model, adapter, memory, or tool-result leak.
- Serving control-plane compromise or unauthorized model/adapter load.
- Live org/fleet-scoped inference credential exposure.
- Response-path oracle revealing a protected tenant/model/object with reliable attribution.
- Capacity or cost incident exceeding enterprise thresholds or affecting other tenants.

### 12. Analyst Notes Template

```text
Incident / alert:     AISERVE-____
Gateway / deployment: ____ / ____
Principal / credential: ____ / ____
Tenant / project:     ____ / ____
Request / trace:      ____ / ____
Cache / batch / stream / worker: ____ / ____ / ____ / ____
Requested -> resolved model: ____ -> ____   digests: ____ -> ____
Authorization policy: ____   result: ____
Billed project / quota: ____ / ____
Cross-tenant evidence: none | canary | protected-data (minimal ref: ____)
Client merge excluded? Y/N
Containment:          deny | drain | disable-cache | disable-batch | rotate | pin
Disposition:          false-positive | control-gap | incident D&R-19
```

### 13. Summary

Serving-plane isolation is an end-to-end correlation problem. Bind identity, tenant, request,
artifact, and budget at every hop; instrument cache and batch internals; fail closed on correlation
loss; and treat canary-proven tenant crossing, artifact substitution, or control-plane compromise
as an AI incident under D&R-19.

---

*GreyNOC — detection-engineering-first security operations.*
