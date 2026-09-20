# 20 — Bug Bounty: Inference Infrastructure & Multi-Tenant Isolation (Authorized)

> **Authorization required.** Authorized testing only, GreyNOC as submitting firm, scope on file.
> See [CONVENTIONS §6 Rules of Engagement and §7 AI-system testing addendum](CONVENTIONS.md). Every
> probe here lands on shared, metered, live serving capacity, so a careless test degrades *other
> tenants*, not just you: §7.5 minimum-request-count discipline and the §7.11 stop conditions are
> mandatory, not advisory. This is a **defect-class catalog with validation guidance**, not tooling.

## Overview

This is the serving plane: gateway, router, scheduler, caches, accelerators, model store, and the
transport between them. Almost nothing here is a novel AI vulnerability class — it is ordinary
infrastructure security (management-surface authn, tenant binding, cache keying, credential scope,
consumption limits, transport crypto) with AI-shaped consequences, because the data is prompts and
outputs and the shared resource is an accelerator. It is high-yield because serving stacks go up fast
on single-tenant defaults in front of multi-tenant traffic. PB-15 is the methodology spine; this
catalog owns `I1–I12` alongside PB-16 (`L`), PB-17 (`S`), and PB-18 (`G`).

## Scope boundary — what belongs here vs. elsewhere

PB-15's catalog map assigns each surface to a prefix; this is the test that settles the borderline
cases. Rule of thumb: **if the defect would still exist with the model replaced by a stub that sleeps
and echoes its input, it is an `I` class.** A cross-tenant read decided by app code is `L`, by the
gateway `I2`; a malicious artifact is `S`, the path serving it unauthenticated is `I9`; the model's
own behavior is PB-19 and routes to the model-safety channel (§7.1), not here.

## Deployment models and what is actually testable

Most wasted effort on this surface is hunting classes the engagement cannot reach. Fix this in Phase 0.

| Engagement type | What the tester holds | Realistically in scope |
| --- | --- | --- |
| **Hosted multi-tenant API** | accounts, orgs/projects, keys, two self-owned tenants | I2, I3, I5, I6, I7, I8; I9 as API signal only; I10 at the edge only |
| **Dedicated / managed endpoint** | the above plus deployment config, endpoint names, storage, private networking | I1 (deployment management API), I2, I5, I7, I9, I10 (edge + documented internals) |
| **Self-hosted / on-prem / infra-level** | host, runtime, scheduler, model store, device, internal network | all of I1–I12 |

`I4` is unreachable from a hosted API, `I6` is rare everywhere, and `I10`'s internal hops are
provable only in the third row. Name your row in the report.

**Reference convention.** `PB-NN` is this collection and `D&R-NN` the Detection & Response
collection, per [CONVENTIONS §5](CONVENTIONS.md); the standing defensive twin cited below is
[D&R-09 AI / Automated Agent Abuse](09-ai-automated-agent-abuse.md).

## MITRE mapping

| Technique | ID | Relevance |
| --- | --- | --- |
| Exploit Public-Facing Application | T1190 | Unauthenticated management or metrics surface on a routable interface (I1) |
| Valid Accounts | T1078, AML.T0012 | Tenant/org id trusted from a client header or unbound token claim; one key across orgs (I2, I5) |
| Steal Application Access Token · Use Alternate Authentication Material: Application Access Token · Unsecured Credentials | T1528, T1550.001, T1552.001, T1552.005 | Keys in client bundles, CI artifacts, and manifests, used out of scope; worker metadata (I1, I5) |
| AI Model Inference API Access | AML.T0040 | The base access every class here is exercised through (all classes) |
| LLM Data Leakage · Discover AI Model Ontology | AML.T0057, AML.T0013 | Cache leakage, scheduler mis-routing, side channels, existence oracles (I2, I3, I6, I8) |
| Discover AI Model Family · AI Artifact Collection · Full AI Model Access | AML.T0014, AML.T0035, AML.T0044 | Model-store listing; artifacts and weights retrievable from the serving path (I1, I9) |
| Exfiltration via AI Inference API | AML.T0024 | Unbounded logprob and embedding surfaces as an extraction channel — economics, not a breach (I9) |
| Denial of AI Service · Cost Harvesting · Endpoint DoS · Resource Hijacking | AML.T0029, AML.T0034, T1499, T1496 | Missing consumption ceilings and quota bypass; capacity exhaustion the ROE forbids demonstrating (I5, I7) |
| Data from Information Repositories · Data from Local System | T1213, T1005 | Model stores, snapshot buckets, log tiers; device residue and on-host reads (I4, I9, I10) |
| Adversary-in-the-middle on internal hops · harvest-now-decrypt-later capture | — | Plaintext gateway→router→worker transport; classical-only key exchange on a prompt path (I10) |

> **Mapping discipline (`CONVENTIONS §4`).** ATT&CK citations in this table were verified against
> ATT&CK Enterprise v19.2 on 2026-08-09. Note that T1550.001 is now Lateral Movement only — v19
> retired the "Defense Evasion" tactic (TA0005 renamed Stealth, TA0112 Defense Impairment split
> out) and, for the T1550 family, dropped the second tactic outright rather than renaming it.
> Cited against ATLAS collection 2026.06 per [CONVENTIONS §4](CONVENTIONS.md); ATLAS IDs and names
> are both versioned — re-map to your platform's collection at deployment. Techniques without a
> cited ID appear by name only.

## Defect-class catalog

### I1 — Exposed serving control plane

- **What:** a management surface sits beside the inference route — load/unload, repo index, config
  reload, profiler, metrics. **Where it lives, whether it is enabled, and what it binds to are
  per-runtime configuration, not a universal default:** common stacks put management routes on the
  inference port under a path prefix, load/unload is frequently disabled behind an explicit
  control-mode flag, and separate-management-port designs have historically bound to loopback.
  Establish the runtime's actual documented defaults before writing the finding. The defect is the
  delta — the gateway authenticates the inference route while the management surface is reachable
  without that credential.
- **Recognize:** a management path or second port answering unauthenticated `GET`; an
  identity/version banner; metrics listing loaded models, queue depth, and batch size; the
  management surface published in ingress rather than kept on the internal service.
- **Confirm (least-impact):** one unauthenticated read of a health, metadata, or metrics path, with
  timestamp and full headers. **Never call load, unload, config reload, or profiler start on a
  target** (§6.2, §7.5) — if proving authz needs a state change, report reachability and say so.
- **Maps to:** T1190, AML.T0014, T1552.005; chains into I4 and I9. Twins PB-06, D&R-09.
- **Severity:** high where state-changing operations are reachable unauthenticated on production
  capacity — but that score is **argued from reachability plus the runtime's documented semantics,
  and is labelled in the report as argued-from-documentation rather than demonstrated**, because ROE
  forbids exercising the operation; if the program disputes the inference, the demonstrated finding
  is the unauthenticated read. Medium for metrics and identity alone; lower on a private segment
  reached from inside.

### I2 — Tenant and model routing failures

- **What:** the gateway picks *whose* model or deployment to serve from a client-supplied value
  (`X-Org-Id`, path segment, deployment name, token claim) rather than the authenticated credential.
- **Recognize:** tenant/org in an editable header, parameter, or body field; guessable deployment and
  fine-tune ids; one key valid against more than one org id; a 404/403 existence differential.
- **Confirm (least-impact):** two tenants you own (§7.3). Plant a registered `GNBB-CANARY-<uuid4>`
  in a B-owned artifact, then from A's clean context send A's credential with B's identifier; proof
  is B's canary in A's response. A real customer's org id is a §6.6 stop condition, not a test input.
- **Maps to:** T1078, AML.T0012, AML.T0013; PB-16 `L` owns this when the *app* resolves tenancy.
  Defensive side: [D&R-20](20-ai-serving-plane-isolation.md) is the dedicated twin and covers
  gateway-side object-level authorization directly — rule `gateway_object_authorization_mismatch`.
  D&R-09 additionally catches the traffic shape (calls referencing resources outside the caller's scope).
- **Severity:** critical for a demonstrated cross-tenant read or inference on another tenant's
  private model; high for existence disclosure alone; medium where only the error differential leaks.

### I3 — Cross-request cache leakage

- **What:** three different caches sit here and they fail differently. A **prefix/KV cache** reuses
  attention key/value tensors for a prefix *you also supplied*, so where the cache key is the verified
  token sequence, cross-tenant it yields a hit/miss and a timing oracle and nothing more. **That
  guarantee is a property of the key construction, not of prefix caching.** Mainstream engines key
  blocks on a *content hash*; where an implementation trusts that hash without verifying the underlying
  token ids, a collision — accidental or crafted — returns key/value state computed from tokens the
  requester never supplied, which is another tenant's computed state entering your forward pass. Read
  the block-key derivation at the pinned version before you conclude the ceiling is an oracle.
  A **semantic/response cache** stores a completion and returns it for a similar prompt; that is the
  one that can hand another caller's content to you. An **embedding cache** leaks at the vector
  level. Each is a defect when keyed on content alone rather than content plus tenant plus principal.
- **Recognize:** cached/prefix token counts in usage accounting; no stated tenancy boundary on a
  caching feature; byte-identical completions at nonzero temperature; TTFT collapse on unsent prefixes.
- **Confirm (least-impact):** two self-owned tenants, and **name which cache you are claiming, then
  match the proof to it.** *Response cache:* from B submit a canary-bearing prompt, from a clean A
  context submit its prefix — the canary in A's response is proof, and the response cache is the only
  one a canary proves. *Prefix cache:* the claim is hit/miss and needs the stated design below.
  *Embedding cache:* the claim is vector-level leakage, proven at the vector. A claim that a prefix
  cache emitted another tenant's tokens is **usually** a response-cache finding or I6 — but a
  demonstrated cache-key-derivation defect, where a content hash is trusted without verifying the token
  ids behind it, is a genuine prefix-cache finding in this class. Show the key derivation; do not let
  this heuristic misroute it.
  A latency delta or cached-token count is only an **indicator**. An indicator-only claim requires a
  design fixed before the first request — arm definitions, trial count, request interval, wall-clock
  window, interleaved ordering — and is reported as a **distribution comparison with the raw
  per-trial timings attached, not as a Wilson interval**: TTFT and inter-token gaps are continuous
  measurements while a Wilson interval is a binomial-*proportion* interval, so quoting one over
  latency is a category error; and non-overlapping intervals is the wrong test regardless, because
  non-overlap implies a difference but overlap implies nothing. If you binarize the claim to a
  hit/miss decision rule, **state the threshold in advance** — §8.3 then applies to that proportion,
  at the §7.6 bar of ≥2 successes across a stated trial count. Never push volume through a shared
  cache to force evictions; that degrades other tenants (§7.5, §7.11).
- **Maps to:** AML.T0057, AML.T0040; chains into I8. Defensive side:
  [D&R-20](20-ai-serving-plane-isolation.md) covers cache-key tenancy — rule
  `cache_or_batch_tenant_contamination`, with the required key dimensions in its tuning section. The
  serving stack's own cache-key audit remains the preventive control.
- **Severity:** critical for canary-proven cross-tenant leakage; medium for a proven cross-tenant
  hit/miss oracle; informational for a latency observation with no design fixed in advance.

### I4 — Accelerator and device isolation

- **What:** accelerators are shared three ways and the risk differs in each. **Hardware
  partitioning** adds enforced separation; the defect there is a partition that is nominal rather
  than enforced. **Cross-process sharing** comes in three forms with materially
  different guarantees, and collapsing them is the common analytic error. Default **time-slicing**
  gives separate contexts and separate virtual address spaces, and the driver zeroes *global* device
  memory before reassigning it to another process. **MPS** shares a scheduler; depending on
  architecture generation it may give per-client address spaces but not fault or error isolation, and
  older implementations shared a single context outright — do not assume driver-scrub reasoning applies
  to an MPS deployment. **Hardware partitioning** (MIG-style) is the only form that partitions compute,
  cache, and memory paths, and the defect there is a partition that is nominal rather than enforced.
  **Scope the scrub claim precisely:** the driver's guarantee covers global device memory. It does not
  cover GPU **local/shared memory, registers, or on-chip scratch**, and uninitialized local memory is
  where the published cross-process residue affecting several mainstream vendors actually recovered
  inference data. So a residue claim against global memory is extraordinary and must be sourced; a
  residue claim against local memory is a known class — establish which one you are making, and record
  the vendor, architecture, driver version, and sharing mode, because the answer is specific to all
  four. The other realistic defect is **intra-process buffer reuse**: one serving process recycling KV-cache blocks, activation
  buffers, or padding across tenants without clearing them. That is a framework bug, and where a
  workload reads a prior tenant's activations, KV cache, or weights out of a recycled buffer, the
  boundary sits below everything else you were testing.
- **Recognize:** driver, runtime, or device version disclosed in an error, profiling response, or
  metrics endpoint; a documented sharing mode; a serving process pooling KV blocks across tenants
  with no documented clear-on-release; co-scheduled tenants with no documented reset.
- **Confirm (least-impact):** **honest limit — you almost certainly cannot reach this from a hosted
  API, and no amount of prompting proves it.** In scope only for self-hosted or infrastructure-level
  engagements where you are authorized on the host — and the proof has to be *attributable*, which
  inspecting an allocation for non-zero bytes is not, since those bytes may be your own prior
  allocation. Plant a pattern instead: from a workload you own, write a distinctive **registered
  canary byte pattern** across a device allocation and exit; then from a second workload you own,
  running as a different OS user or container, allocate and search for that exact pattern *before
  writing to it*. The planted pattern is what makes residue attributable. Reading residue that is not
  yours is a §7.11 stop condition, not a proof step.
- **Maps to:** T1005, AML.T0040; PB-17 `S` for runtime and dependency provenance. Defensive side:
  [D&R-20](20-ai-serving-plane-isolation.md) scopes accelerator pools but carries **no residue
  detection** — this is the one gap in I1–I12 that its twin genuinely does not close, and the detecting
  control remains the framework's own buffer-lifecycle test. Say that precisely rather than "no
  defensive coverage exists," which is false for the rest of this catalog.
- **Severity:** critical where residue holding another workload's data is demonstrated on shared
  hardware in an authorized host engagement; low for the version disclosure that is the only
  hosted-API form — never file that at the theoretical severity.

### I5 — Gateway key and quota controls

- **What:** key scope, expiry, rotation, where keys may live, and where quota limits are actually
  enforced — org-wide scope where per-project exists, no expiry, a key shipped in a client bundle.
- **Recognize:** a key in a JS bundle, mobile app, public repo, or CI artifact; a key authenticating
  after the console shows it rotated; a `429` on one route and none on streaming, batch, or regional.
- **Confirm (least-impact):** for an exposed key, prove scope and liveness with one lowest-cost
  read-only call and stop — do not spend the budget you just proved you could spend; report location,
  hash, and redacted prefix, never the full value. For quota controls, **establish the enforcement
  point read-only first**: the documented limits, and the `x-ratelimit-*` and usage-accounting headers
  on path A versus its streaming, batch/async, prior-version, and regional siblings. **A path
  returning no limit headers and no counter increment is the reportable signal**, and it costs nothing
  to obtain. Crossing a documented limit on any path requires **written program authorization naming
  that path and a request cap, recorded in PB-15 Phase 0** (§7.5); without it the finding is the
  missing enforcement point, not the crossing — PB-15 files "a rate limit you bypassed by exceeding
  the documented one" under *Not a finding*. Never sustain a bypass even where it is authorized.
- **Maps to:** T1528, T1550.001, T1552.001, AML.T0012, AML.T0034, T1496; PB-18 `G`; twin D&R-09.
- **Severity:** critical for a live, org-scoped, unexpiring key retrievable unauthenticated; high for
  a cross-project scope violation; medium for a quota bypass with a demonstrated cost consequence.

### I6 — Batching and scheduler contamination

- **What:** continuous/in-flight batching and multiplexed streaming put many tenants' sequences in
  one forward pass, so indexing bugs mis-route them: a token appended to the wrong sequence, a
  response returned against the wrong request id, a slot reused uncleared. (**Speculative decoding needs care here.** A draft
  model proposes tokens for your own sequence and the target verifies them, so the *logical* unit is one
  request — but in a continuous-batching engine the draft forward pass and the verification pass are
  themselves batched across requests, so the mechanism does interleave tenants and does present the same
  slot-indexing surface as the rest of this class. It matters where the draft/verify state is mis-indexed,
  and also where a draft model or prompt-lookup cache is **shared across tenants**, which is a second
  key/value surface extending I3. A further channel sits in I8, not here: the per-step accepted-token
  count is content-dependent and observable in streaming cadence and packet sizing.)
- **Recognize:** a coherent response answering a question you did not ask; a stream changing topic
  mid-generation; usage accounting inconsistent with your prompt. Rule out your own client first —
  most field reports of this are harness stream-merge bugs.
- **Confirm (least-impact):** self-owned tenants only, request-id correlation from the first request.
  Hard evidence bar: full request/response pair, client-issued and server-returned request or trace
  ids, headers, millisecond timestamps, version string, and your in-flight set. A screenshot is not
  this finding. Report as a ledger even at 2/500; never generate load to induce it (§7.5).
- **Maps to:** AML.T0057, AML.T0040; PB-16 `L` for session mixing inside one app. Defensive side:
  [D&R-20](20-ai-serving-plane-isolation.md) covers request and batch contamination — rule
  `cache_or_batch_tenant_contamination`, whose batch, stream, and request-id triggers are exactly this
  class. Request-id correlation in the serving stack remains the preventive control.
- **Severity:** critical when another tenant's content is proven in your response with the
  correlation evidence above; not reportable at all without it.

### I7 — Denial of service and denial of wallet at the serving layer

- **What:** inference cost is asymmetric, so missing consumption controls bite hard: no ceiling on
  context length or input-driven expansion, no server-side output-token cap, unbounded expensive
  parameters (large `n`/best-of, logprob depth), no per-tenant concurrency cap, billing for
  undelivered work.
- **Recognize:** the schema accepts values far above documented maxima and the server honors them;
  usage records counting aborted or duplicated generations; a batch route with absent limits.
- **Confirm (least-impact):** **§7.5 governs this class, and it is where a tester most easily causes
  real harm: demonstrate the missing control, never the outage.** Send the minimum requests showing
  the value is accepted and the work billed — one request modestly above the documented ceiling, plus
  a projection labelled as such. Never exhaust a quota, pool, or GPU capacity; never sustain load.
- **Maps to:** AML.T0029, AML.T0034, T1499, T1496; PB-18 `G` where an agent loop drives the spend.
- **Severity:** high for a missing per-tenant control with a multi-order cost asymmetry from a single
  request; medium where billing caps bound it; low with no measured consequence — a projection alone
  is never severity evidence.

### I8 — Side channels in the response path

- **What:** response metadata leaking work that is not yours — token-emission timing under batching,
  response length and TTFT as a function of shared cache state, streaming cadence, and error
  differentials separating "exists but not yours" from "does not exist" or "over quota".
- **Recognize:** TTFT varying systematically with a prefix this tenant never sent; inter-token cadence
  varying with **background** load you did not create — an observation, never an induced one;
  distinguishable errors for existent resources.
- **Confirm (least-impact):** two self-owned tenants and a design fixed *before* the first request —
  arm definitions, trial count, interval, wall-clock window, interleaved ordering, model and version
  string — with confounders recorded (network path, provider autoscaling, other tenants' load, a model
  version changing mid-run). **Do not generate concurrency to modulate a shared scheduler.** If the
  channel is real, the load that would prove it degrades every co-scheduled tenant: that is I7 misuse
  (§7.5) and a §7.11 stop condition, and it is the same rule I6 states. You may correlate against load
  you did not create; you may not create it. Report to the I3 bar — a continuous timing claim is a
  distribution comparison with the raw per-trial timings attached, and only a claim binarized against
  a threshold stated in advance is reported as a proportion under §8.3. **This class is the most
  over-reported here and routinely submitted on weak statistics**; if the arms do not separate, falsify.
- **Maps to:** AML.T0057, AML.T0013; chains from I3 and I7 (see the chains section — there is no
  `I6 → I8` chain). Defensive side: [D&R-20](20-ai-serving-plane-isolation.md) covers response-path
  timing channels — its investigation step on pre-registered timing and error-differential thresholds,
  and its tuning requirement to baseline timing by model, region, deployment, token shape, cache state,
  and load band. D&R-09 additionally covers the enumeration shape of the error-differential half.
- **Severity:** high only where the channel carries another tenant's content or a specific
  attributable fact; medium for a reliable existence oracle; informational for a bare timing delta.

### I9 — Model and weight exposure through the serving path

- **What:** two things never to conflate. **(a) Provable exposure** — the artifact is retrievable: an
  unauthenticated model-repository path or object store, a listable model store, an exposed
  checkpoint, an over-scoped signed URL, an adapter or system prompt served as a static asset.
  **(b) Extraction economics** — an API returning full-vocabulary logprobs or unbounded embeddings.
- **Recognize:** (a) a storage host or path in an error, config, or manifest response; a listable
  bucket; an artifact URL working without the gateway credential; a weights-sized `Content-Length`.
  (b) full-vocabulary logprobs, or an unbounded embeddings route.
- **Confirm (least-impact):** (a) prove retrievability at the *header* level — an unauthenticated
  `HEAD` for status and response headers (`Content-Length`, `Content-Type`), plus **one** ranged
  first-bytes `GET` where a format marker is needed, since a `HEAD` returns no body and yields
  neither a marker nor a hash. Hash only the bytes actually retrieved. **Do not download the
  artifact**; per §7.8 never load, unpickle, or execute anything from a target. (b) prove the signal
  is returned, in one request. **No extraction campaign** — volumetric, a §7.5 breach, and an
  incident you caused.
- **Maps to:** AML.T0044, AML.T0035, AML.T0014, AML.T0024, T1213; PB-17 `S` owns provenance.
- **Severity:** critical for a retrievable proprietary artifact proven at the header level; high for
  an exposed system prompt or adapter the program treats as confidential; **informational to low for
  extraction economics with no artifact retrieved** — filing that as a breach is fabrication (§6.3).

### I10 — Transport and at-rest crypto on the inference path

- **What:** prompts and outputs are long-shelf-life confidential data on a path with more hops than a
  normal web request (client → edge → gateway → router → worker → store, cache, log). Defects: TLS
  terminating at the edge with plaintext onward; mesh mTLS assumed but not enforced; caches, prompt
  logs, or traces written unencrypted; classical-only key exchange on those hops; no CBOM entry.
- **Recognize:** the edge negotiates a hybrid group (`X25519MLKEM768`, `0x11EC`) but an internal hop
  does not, or nothing on the path offers one; documented plaintext hops or an unencrypted log tier;
  traces disclosing internal hop addresses (`192.0.2.0/24`, `2001:db8::/32`).
- **Confirm (least-impact):** read-only negotiation observation on authorized hosts, **two probes per
  hop, per PB-03**. (1) A **full-group-list** handshake, reading the actually-negotiated group out of
  the session output — this is the offered-versus-negotiated comparison, and the only one of the two
  that can show a downgrade. (2) The CONVENTIONS §2 single-group probe (`openssl s_client -groups
  X25519MLKEM768`), which restricts the `ClientHello` to one group and therefore answers *does this
  host support hybrid* and nothing else — a failed handshake there is a negative, not a downgrade.
  Then compare probe (1) taken directly against the origin with probe (1) taken through the
  production path: a hybrid-capable origin serving classical-only through the edge localizes the
  stripper. Internal hops are provable only self-hosted. Never intercept another party's traffic.
  State HNDL exposure factually per PB-02 — data class, retention, and that a recorded classical-only
  exchange is decryptable by a future CRQC — with no sourceless timeline.
- **Maps to:** PB-02 (HNDL exposure), PB-03 (hybrid downgrade), PB-01 (CBOM coverage of the inference
  path), and PB-17 `S9` where the same classical-only posture covers artifact signatures; T1213.
  Defensive twin PB-03.
- **Severity:** medium to high by the shelf-life of what transits the path and whether a plaintext hop
  is third-party-reachable; high where prompt or output content is stored unencrypted under long
  retention; the classical-only-KEX component alone is a migration finding, scored as one.

### I11 — Vector-store and embedding tenancy at the store

- **What:** a shared index, collection, or namespace serving multiple tenants where the tenant boundary
  is not enforced *by the store*. Forms: a tenant filter carried as ordinary metadata that the query
  path may omit; a filter applied **after** ranking, so neighbours from other tenants are retrieved and
  then discarded, and timing or result-count still discloses them; a namespace or collection id taken
  from a client-supplied value; store credentials scoped to every tenant's collection because the
  serving role needs breadth; and direct reachability of the store's own API from outside the serving
  path. Reconstruction of source text from retrieved vectors belongs here too — an embedding is not
  anonymous by default.
- **Recognize:** one index name across tenants; a filter expression built in the request path rather
  than injected by a trusted layer; a collection or namespace parameter in the API; a vector-database
  port or console reachable from a network position you hold; `top_k` results whose count varies with
  another tenant's data volume; a store with no per-tenant credential at all.
- **Confirm (least-impact):** two tenants you own. Seed a registered `GNBB-CANARY-<uuid4>` document into
  tenant A's corpus, then query as tenant B and prove either the canary's content, its identifier, or a
  count or latency that only its presence explains. Query through the store's own API as well as through
  the app, because the finding is *which layer enforces the boundary*: if the app filters correctly and
  the store does not, the defect is still here and any second consumer of that store inherits it. Read
  only your own canary; a query that begins returning real tenant content is a §7.11 stop condition.
- **Boundary with PB-16 `L7`:** `L7` owns retrieval scope decided by **app code** — the app resolves the
  wrong corpus for an entitled caller. `I11` owns the boundary the **store** was supposed to enforce.
  This class exists because `L7` and `L14` both route store-level tenancy to PB-20 and, before `I11`,
  landed on `I2`, which covers model and deployment routing only and has no store content.
- **Maps to:** AML.T0057, AML.T0085.000, T1213, T1078; PB-16 `L7` for the app-side half; chains into I8
  where the only crossing you can prove is a count or a latency. Defensive twin
  [D&R-20](20-ai-serving-plane-isolation.md) for the cache-key and tenancy dimensions; PB-23 owns the
  governance side of embedding retention.
- **Severity:** critical for canary-proven cross-tenant retrieval of content; high for retrieved-then-
  discarded neighbours, because the data left the boundary regardless of what the client saw; medium for
  a count or timing oracle alone. Do not report a shared index as a finding on its own — shared indexes
  are a normal design, and the finding is the absent enforcement.

### I12 — Telemetry, trace and evaluation tenancy at the platform tier

- **What:** the platform's own observability, evaluation, and analytics tier holding prompts,
  completions, retrieved context, and tool arguments, with a weaker boundary than the inference path it
  instruments. Forms: a shared tracing or APM project where one tenant reads another's spans; guessable
  or sequential trace and request ids; an unauthenticated debug, trace, or metrics endpoint on the
  serving **platform** rather than the application; prompt and completion bodies in a shared log sink or
  error-tracking project; an evaluation, annotation, or feedback store carrying production content under
  looser access control than production; and retention on that tier exceeding the retention promised for
  the inference path.
- **Recognize:** a trace id echoed in responses or headers that is short, sequential, or timestamp-
  derived; a platform console, `/metrics`, `/debug`, or trace-viewer route reachable with your
  credentials or none; request bodies visible in an observability vendor's UI; an eval or feedback
  dataset built from production traffic; a documented inference-path retention that the trace tier
  contradicts.
- **Confirm (least-impact):** your own traffic, carrying a registered canary, and your own two tenants.
  Prove the canary is readable from a position that should not reach it — tenant B's console, an
  unauthenticated endpoint, or a third-party origin in your own browser traffic. For an id-guessability
  claim, demonstrate the derivation on **your own** ids and stop; do not enumerate into the id space,
  because the first hit is another tenant's content and a §7.11 stop condition. Never pull other
  tenants' entries to size the exposure, and quote the documented retention statement any
  contradiction claim rests on.
- **Boundary with `I10` and PB-16 `L14`:** `I10` owns whether the path is **encrypted** — transport and
  at-rest crypto. `I12` owns **who can read** the telemetry tier once it is stored. `L14` owns the
  application's own logging and its third-party analytics. `L14` routed platform-tier log handling to
  `I10`, which is crypto-only; `I12` is where that reference now lands.
- **Maps to:** AML.T0057, T1213, T1078; PB-16 `L14` for the application half; PB-23 for retention and
  deletion governance; PB-17 `S8` where the same content appears in build or image layers. Defensive
  twin [D&R-20](20-ai-serving-plane-isolation.md).
- **Severity:** high to critical for an unauthenticated platform endpoint returning prompts or
  completions; high for proven cross-tenant trace reads; medium for id guessability demonstrated on your
  own ids without a crossing; low-to-informational for content in a first-party tier with correct access
  control, which is a hygiene and retention finding — calling that a breach is the inflation triagers
  punish.

## Chains that carry impact

These are attacker impact paths, not test procedures. The self-scoped equivalent of each hop is in
its class entry, and where a chain names another party's identifier there is no authorized way to
reproduce it end to end.

- `I5 → I2 → I9` — an over-scoped key from a client bundle selects another project's org id and
  retrieves that project's private adapter. Cross-tenant IP loss, no model interaction anywhere.
- `I1 → I4 → I9` — an unauthenticated management surface discloses runtime version, sharing mode, and
  the model-repository path; on a self-hosted host that path serves the weights. Infra compromise.
- `I3 → I8` — content-only cache keying gives a hit/miss oracle, and timing turns it into
  confirmation that a specific document was submitted by another tenant.
- `PB-18 G-class (agent holds the org's gateway credential) → I5 → I7` — an injected instruction
  reaching the agent spends the org's inference budget through a key with no per-project scope,
  against an endpoint with no per-tenant concurrency cap. Denial of wallet, tenancy boundary intact.
- `I7 → I8` — **co-residency is a precondition to demonstrate, never to assume.** Where it can be
  established (self-hosted or infra-level, both workloads pinned to a known device or replica), the
  occupancy cost of one expensive request may be visible in a second self-owned tenant's inter-token
  cadence, so absent per-tenant scheduler isolation a tenant's activity level is inferable by anyone
  co-resident. On a hosted API you hold two accounts and cannot establish or verify that they land on
  the same worker, so this chain does not belong in a hosted-row report.

## Hunting workflow

1. **Fix the deployment model and the ROE** (PB-15 Phase 0) using the table above; hosted-API and
   host-level ROE are different documents with different stop conditions.
2. **Pick one class, write the falsifiable hypothesis** — expected-secure behavior plus the
   observation that would disprove it (Phase 4).
3. **Fingerprint read-only** (Phase 1–2): routes, API versions, regions, streaming variants, headers,
   usage accounting, error differentials, model/version strings. Nothing state-changing.
4. **Stand up the harness** (Phase 3): two tenants you own, a canary registry entry per probe per
   tenant, the trial ledger, and a request budget and cost cap agreed *before* the first request.
5. **Validate self-scoped at the minimum request count** (Phase 5): for I3/I6/I8 fix trial count,
   interval, and interleaving in advance; for I7 one request above the ceiling; I1/I9 headers only.
6. **Record the falsifier either way** — a clean negative on I4 or I6 is a real engagement outcome.
7. **One finding per defect**, one primary class id, chain members in sequence (§8.1); route
   model-behavior observations to the PB-19 channel, not the security queue (§7.1).

## Anti-patterns (do not do these)

- **Using an org, tenant, or project id belonging to a real customer "just to confirm the check is
  missing".** That is testing on a third party: a §7.3 violation and a §6.6 stop condition. Two
  tenants you own, or it did not happen.
- **Reporting a latency difference as cross-tenant leakage.** Without arms, trial count, interval,
  and wall-clock window fixed before the first request, a timing delta is noise with a narrative
  attached. The canary is proof; timing is an indicator (`I3`).
- **Proving a timing channel by generating the load that makes it visible.** Concurrency you create
  to modulate a shared scheduler degrades every co-scheduled tenant — `I7` misuse, a §7.5 breach,
  and a §7.11 stop condition. Correlate against background load you did not create, or falsify the
  hypothesis and move on.
- **Load-testing an endpoint and calling it a denial-of-service finding.** Volume you generated is
  not a defect report, it is an outage you caused. The finding is the *missing* control, shown at
  the minimum count (`I7`).
- **Reporting extraction economics as a demonstrated breach.** "Enough logprobs are exposed that a
  determined attacker could distill this model" is an argument, not a retrieval. Report what you
  could actually reach, at header level, and say plainly that the rest is inference (`I9`).
- **Downloading the weights to "confirm" the artifact is really there.** Reachability is provable
  from status and headers; pulling the artifact is unnecessary collection, and executing anything
  you pull is a §7.8 violation regardless of where you run it.

## Validation discipline (the GreyNOC bar)

Stochastic classes (I3, I6, I8) meet §7.6 — **≥2 successes from a clean context across a stated trial
count** — full ledger, arms interleaved, and §8.3's Wilson interval quoted only where the claim is a
proportion, never over raw latency. Cross-tenant claims are proven between **two tenants you own**
and attributed by registered canary (§7.4). Every finding names the deployment model, the
model/version string, and the falsifier that would have killed it.

## Report template

Use the PB-15 AI report template, then add these lines:

```
DEFECT-CLASS:     I1–I12 (one primary; chain listed in sequence, e.g. I5 → I2 → I9)
DEPLOYMENT-MODEL: hosted-API | dedicated-endpoint | self-hosted/infra
TENANCY-PROOF:    two-tenants-owned: Y/N · canary IDs: GNBB-CANARY-<uuid4> (A) / <uuid4> (B)
TRIAL-LEDGER:     successes/trials @ temperature (95% CI low–high) · interval · interleaved: Y/N
TIMING-CLAIMS:    arms · trials/arm · raw per-trial timings attached: Y/N · threshold pre-stated: Y/N
CONSUMPTION:      requests: N · tokens: N · est. cost: $N · limit crossed: Y/N (if Y: auth ref + cap)
EVIDENCE-BASIS:   demonstrated | argued-from-documentation (state which, per class)
```

## Stop conditions

Stop on any real cross-tenant content, production secret or model material, shared-service
degradation, worker/accelerator access outside explicit host scope, or timing/load experiment that
would exceed the pre-approved request budget. Preserve correlation identifiers and invoke the
program contact under [CONVENTIONS §6–§7](CONVENTIONS.md).

## Summary

The serving plane is high-yield for an unglamorous reason: multi-tenant inference stacks are deployed
at speed on defaults designed for single-tenant lab use, so an unauthenticated management surface, a
tenant id trusted from a header, a cache keyed on content alone, and a limit with no enforcement
point keep landing in front of production traffic. The honest limit of this catalog is reach — I4 and
the internal-hop half of I10 are not testable from a hosted API, and I6 will not appear on demand —
so name your deployment row and report each class in the form you could actually prove.
