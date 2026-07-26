# 17 — Bug Bounty: AI Supply Chain & Model Artifact Defects (Authorized)

> **Authorization required.** Authorized testing only, GreyNOC as submitting firm, scope on file.
> See [CONVENTIONS §6 Rules of Engagement and §7 AI-system testing addendum](CONVENTIONS.md).
> **A target's model artifact is untrusted code and is never loaded, unpickled, deserialized, or
> executed — §7.8 is the hard boundary of this entire catalog.** This playbook is a **defect-class
> catalog with validation guidance**, not exploit tooling.

## Overview

PB-15 is the methodology spine; this catalog owns **what a system loads and where it came from** —
weights, adapters, tokenizers, datasets, the registries serving them, the pipelines building them,
the transport delivering them. It yields real defects now because the AI supply chain was assembled
at speed on package-manager habits (mutable names, unverified pulls, code-bearing archives) the
software world spent a decade learning to distrust. The framing idea: **most findings here are
provable by read-only inspection of public metadata**, which gives the class unusually high
signal-to-noise — there is no stochastic ledger to argue over, just a reference, a format, and a
missing gate. It is the deterministic counterpart to PB-16 (`L`, the app around the model), PB-18
(`G`, what the model may do), and PB-20 (`I`, the plane it runs on).

## Scope boundary — what belongs here vs. elsewhere

| Finding | Prefix | Owner |
| --- | --- | --- |
| Artifact format, origin, provenance, pinning, registry, cache, model-build pipeline | `S1–S10` | **PB-17 (here)** |
| Prompt handling, RAG retrieval at inference, output handling, sessions, app-level authz | `L1–L14` | PB-16 |
| Tool/function invocation, agent autonomy, MCP server trust, agent credential scope | `G1–G12` | PB-18 |
| Serving plane: GPU/process isolation, cache and batching leakage, endpoint authn, tenancy | `I1–I10` | PB-20 |
| Jailbreak, disallowed content, refusal bypass with no security consequence | none | PB-19 → model-safety channel |

Tiebreaker, consistent with PB-16's: **what you loaded and where it came from** is `S`; a recognizable
web or API bug that survives deleting the model from the design is `L`; *an action the system took* is
`G`; *the box it runs on* is `I`. Disambiguators: a poisoned document retrieved by RAG at query time is
`L`, the same document entering a *training* corpus is `S5`; a shared artifact **cache** is `S10`, a
shared **serving process** is `I`; secrets in a model repo or container layer are `S8` even though they
look like a recognizable repo bug, because the surface is the artifact path.

## Static-only inspection rule

CONVENTIONS §7.8 in operational terms, because this catalog lives or dies on it.

**You may inspect**, offline and in an isolated environment: file headers and magic bytes; archive
listings without extract-and-import — torch ≥1.6 zipfile serialization gives a `.pt` a ZIP central
directory, while a legacy non-ZIP `.pt`/`.ckpt` is a raw pickle stream where the safe inspection is
opcode disassembly (`pickletools.dis` reads opcodes, which is inspection; invoking `Unpickler` is
execution); the safetensors header (8-byte little-endian length + JSON header); manifests,
`config.json`, `tokenizer_config`, chat templates; model card and README; repository file listing and
rename history; dependency manifests and lockfiles; public CI config; container image manifests and
layer metadata. Hash what you inspect.

**You must never** load, unpickle, `torch.load`, `joblib.load`, `np.load(..., allow_pickle=True)`,
`from_pretrained`, `load_model`, import a repo's modeling code, set `trust_remote_code=True`, run a
demo notebook, `docker run` the image, or start the serving container. "I ran it in a VM" is the same
§7.8 violation with extra steps, turning your evidence chain into an unexplained code-execution event
on your own infrastructure. If a claim cannot be made from metadata, it is not a claim you make.

**Reference convention.** `PB-NN` is this collection, `D&R-NN` the Detection & Response collection
([CONVENTIONS §5](CONVENTIONS.md)); the standing defensive twin cited below is
[D&R-09 AI / Automated Agent Abuse](09-ai-automated-agent-abuse.md).

## MITRE mapping

| Technique | ID | Relevance |
| --- | --- | --- |
| AI Supply Chain Compromise | AML.T0010 | Umbrella: any untrusted element in the model path |
| AI Supply Chain Compromise: Model | AML.T0010.003 | Substituted or tampered weights/adapters (S2–S4, S6) |
| AI Supply Chain Compromise: Data | AML.T0010.002 | Dataset dependencies with no provenance gate (S5) |
| AI Supply Chain Compromise: AI Software | AML.T0010.001 | Loaders, conversion tools, serving runtimes (S1, S7) |
| User Execution: Unsafe AI Artifacts | AML.T0011.000 | Deserialization-as-execution (S1) |
| Poison Training Data | AML.T0020 | User-content, scraped, and feedback/RLHF ingress (S5) |
| Publish Poisoned Models | AML.T0058 | Model published into a namespace a consumer resolves (S3) |
| Publish Poisoned Datasets | AML.T0019 | Dataset dependencies pulled by name from a public source (S5) |
| AI Supply Chain Rug Pull | AML.T0109 | Artifact changing under the consumer after trust is established (S4, S6) |
| Manipulate AI Model | AML.T0018 | End state S6 enables (maturity *Realized*); rarely provable in-engagement |
| Supply Chain Compromise: Compromise Software Supply Chain | T1195.002 | Registry, promotion, mirror, delivery path |
| Command and Scripting Interpreter | T1059 | Code executed by the loader during deserialization (S1) |
| Unsecured Credentials: Credentials In Files | T1552.001 | Notebooks, configs, model cards, layers (S8) |
| Subvert Trust Controls: Code Signing | — | S9's remediation surface; mapped by impact per PB-11 |

*Cited against ATLAS collection 2026.06 per [CONVENTIONS §4](CONVENTIONS.md); ATLAS IDs and names
are both versioned — re-map to your platform's collection at deployment. Techniques without a cited ID
appear by name only.*

## Defect-class catalog

### S1 — Code-executing artifact formats loaded without isolation
- **What:** in pickle-derived formats deserialization *is* execution — `.pkl`, `.pt`/`.bin`, `joblib`,
  `np.load(allow_pickle=True)`, Keras `Lambda` layers where the loader runs `safe_mode=False` (Keras 3
  defaults it `True`, which blocks that), and `trust_remote_code`/`auto_map` repo imports. `.ckpt` is
  not exclusively pickle — TensorFlow checkpoints use the extension too — so read the header, not the
  suffix. Safetensors and GGUF have no deserialize-to-code path **by design**, a claim about the format
  and not the parser: reader memory safety is a separate question. And **"safe format" is not "trusted
  content"** — weights can still be backdoored, safetensors ships config alongside the weights, and GGUF
  carries its metadata *inside* the container, `tokenizer.chat_template` included, so a data-only file
  still delivers template text onto the prompt-assembly path (S6).
- **Recognize:** `.bin`/`.pt`/`.ckpt` with no safetensors equivalent; **record the pinned torch version,
  because the default flipped in 2.6** — `torch.load` has defaulted to `weights_only=True` since
  PyTorch 2.6, so the finding is an explicit `weights_only=False`, a pre-2.6 pin, or a `joblib.load` /
  `np.load(allow_pickle=True)` call, not the bare presence of `torch.load`; `trust_remote_code=True` or
  `auto_map`; any user-supplied checkpoint path. `weights_only=True` is a type allowlist, not a sandbox:
  cite it as a mitigating control, never as proof of safety.
- **Confirm (least-impact):** static and offline — archive listing and metadata, never the object graph
  (§7.8). The finding is the *path*: show from the consumer's code or docs that an untrusted-origin
  artifact reaches a code-bearing loader inside a service boundary, proving acceptance only with your
  own benign `GNBB-CANARY-<uuid4>`-tagged artifact in your own tenant. Never load the target's artifact.
- **Maps to:** PB-06, D&R-09; chains to `G` (PB-18), `I` (PB-20). **Severity:** high–critical when an
  untrusted-origin artifact reaches a code-bearing loader in a service boundary (RCE-equivalent);
  medium when all consumed artifacts are first-party and digest-pinned — a hardening item, filed as one.

### S2 — Absent or unverified artifact provenance
- **What:** weights, adapters, tokenizers, and datasets consumed with no signature, attestation, or
  checksum comparison — or with verification that **fails open**: digest logged but never compared,
  signature checked only when a `.sig` exists, the exception caught and the pull continued.
- **Recognize:** fetch-then-load with no digest comparison between the calls; checksums in a README no
  code reads; a CI log reading "signature not found, continuing"; a verify branch that logs and returns.
- **Confirm (least-impact):** read the fetch/verify path and specifically its **error branch** —
  fail-open lives in the exception handler. Where you control a source a self-hosted or trial
  deployment pulls from, publish a canary-tagged artifact with a deliberately wrong digest and observe
  whether it proceeds. The source **and** the consuming deployment must both be yours; never substitute
  an artifact on a path a real customer consumes. §7.3's two-tenant rule does not apply here — S2 is a
  fail-open verification defect in a single consumer's fetch path, with no tenancy dimension.
- **Maps to:** PB-11 (verification as a pipeline gate), PB-01 (CBOM). **Severity:** high when it is the
  only gate between an untrusted origin and a loaded artifact, inheriting S1's severity by chaining;
  medium where a digest pin or first-party egress allowlist holds — name which one you verified.

### S3 — Registry and namespace abuse paths
- **What:** the name a consumer resolves is not bound to the publisher they believe — typosquat
  adjacency, an abandoned or deleted namespace **where that registry's documented policy permits
  re-registration**, rename-and-reclaim **where the platform leaves the old path resolvable to a new
  claimant**, stale org membership, unclaimed hub orgs mirroring the brand. Name-reuse behavior is
  per-platform, not a universal mechanic: GitHub redirects after a rename but retires the namespace for
  popular repos, npm blocks name reuse after unpublish, PyPI restricts deleted project names, and model
  hubs differ again.
- **Recognize:** production pull paths in a personal namespace or an org the target does not obviously
  control; a pre-rename path still referenced; a hub org with no members and no verification marker.
- **Confirm (least-impact):** read-only resolution — record whether the namespace exists, who the hub
  reports as owner, whether it is verified, and which consumer reference resolves to it. Record the
  platform's **documented** name-reuse policy as evidence; do not assume the GitHub mechanic. **Never
  register, claim, reserve, or "defensively hold" a name that impersonates the target, and never
  publish into a namespace the target's consumers resolve** — availability *is* the finding, and taking
  the name is impersonation nobody authorized. Report it; let the program claim it.
- **Maps to:** PB-11, PB-01; PB-06 defensively. **Severity:** high when a dangling namespace is on a
  production model path, medium when only in docs; a digest pin (absence of S4) defuses most of it.

### S4 — Mutable references in the model path
- **What:** the consumer pulls `main`, `latest`, a branch, or a moveable tag instead of a pinned
  revision or content digest, so the artifact reviewed is not necessarily the artifact loaded — a
  floating container tag with a bigger blast radius, the object landing in a privileged runtime.
- **Recognize:** `from_pretrained("org/model")` with no `revision=`; `:latest` on a model-server image;
  IaC referencing an object-store path with no version id; a registry accepting a re-push; a lockfile
  pinning every Python dependency and no model.
- **Confirm (least-impact):** static read of manifests, IaC, deployment config, and the registry's
  immutability policy; record the exact reference form per artifact. Where you own a registry
  namespace, confirm mutability by re-pushing benign canary-tagged content **to a version you own**.
  Never overwrite anything another consumer reads.
- **Maps to:** PB-13 (pinning as migration hygiene), PB-11. **Severity:** medium alone — a control gap,
  not a compromise; high or critical with S2 (change goes unchecked) or S3 (someone else can make it).
  Do **not** title an unpinned reference "supply chain compromise" — state the chain instead.

### S5 — Training and fine-tuning data ingress
- **What:** content reaching training, fine-tuning, or embedding corpora with no provenance gate —
  user-contributed content (tickets, wikis, reviews, uploads), scraped corpora with no source allowlist,
  RLHF feedback loops, dataset dependencies pulled by name.
- **Recognize:** docs stating user content may be used for model improvement; a feedback endpoint
  persisting raw text with no review; datasets pulled by mutable name; a fine-tune or "custom
  knowledge" upload with no content review; a documented retrain cadence.
- **Confirm (least-impact):** prove the **ingress**, not a behavior change. Place an inert
  `GNBB-CANARY-<uuid4>` in content submitted through the documented user path in your own tenant, then
  show from docs, an API response, an export, or a later retrieval that it entered a corpus feeding
  training or an index with no gate between. Minimum volume, benign content only (§7.2).
- **Honesty caveat:** demonstrating true model-behavior change from poisoning is out of reach in a
  bounty engagement — you control neither retraining cadence, dataset mixture, nor the eval gate, and
  one canary in a large corpus will not measurably move weights. **Report the ingress-control gap you
  can prove; never infer a behavioral impact you did not observe** — "I poisoned the model" off a
  canary in a support ticket is fabrication under §6.3.
- **Maps to:** PB-06, D&R-09; `L` (PB-16) when the corpus is retrieved at inference. **Severity:**
  medium as an ingress gap; high only where the pipeline is documented to train on the content with no
  review and the population is broad. Never scored on inferred model impact.

### S6 — Post-training modification surface
- **What:** anything altering behavior *after* the base artifact cleared its integrity gate —
  LoRA/adapter loading, third-party quantized or converted re-publications, plugin and preset packs,
  tokenizer swaps, and config bundles including chat templates. The base checkpoint is often signed
  and pinned while the modifier on top of it is pulled from a mutable reference, unverified.
- **Recognize:** adapter paths configurable at runtime or per tenant; docs pointing at a community
  quantization repo rather than the base publisher; a plugin or preset marketplace; chat templates and
  system-prompt bundles loaded from a separate, less-governed path.
- **Confirm (least-impact):** statically compare the governance on the base artifact against each
  modifier — signed? digest-pinned? provenance-checked at all? Where an adapter upload exists in **your
  own tenant**, upload a benign canary-tagged modifier and show it loads without passing the gate the
  base model passed. Never upload a modifier engineered to alter safety behavior: the finding is the
  missing gate, and a behavior demo routes to PB-19, not here. **If the deployment is a shared or pooled
  serving process rather than per-tenant, stop before uploading** — the finding is provable from the
  upload-acceptance path and the governance diff alone, and pushing an artifact into shared capacity is
  a §7.11 stop condition, not a proof step.
- **Maps to:** PB-11, PB-06; `G` (PB-18) where the modifier changes tool-selection behavior.
  **Severity:** high where a per-tenant or user-supplied modifier loads into a shared serving process
  (chains to `I`), medium where modifiers are first-party but unpinned. Chat templates warrant specific
  attention — config, almost never signed, sitting directly on the prompt-assembly path.

### S7 — Model build and CI pipeline exposure
- **What:** the pipeline producing and promoting artifacts is a **write path into the model** — build
  runners with broad credentials, self-hosted runners reachable by fork-triggered workflows, promotion
  between registries with no re-verification, and unprotected branches or workflow files that change
  what the build reads.
- **Recognize:** public CI config showing fork-triggered workflows with secrets in scope, self-hosted
  runner labels, or a deploy step pushing to a registry; missing protection on the branch the build
  reads; a promotion job copying staging → production without re-checking signature or digest.
- **Confirm (least-impact):** read-only inspection of public CI config, branch-protection state,
  workflow permissions, and the promotion step's verification logic. Demonstrate a trigger condition
  only in **a project you own** that reproduces the config. **Never open a PR against the target's repo
  to trigger a runner and never exercise a pipeline you do not own** — that is a write, not a read.
- **Maps to:** PB-11, PB-01; PB-06/D&R-09 defensively. **Severity:** critical where an unprivileged
  outside party can influence what the production model path serves, high where credentials are
  over-scoped but the trigger requires an insider. Anchor on the trigger condition you verified.

### S8 — Secrets exposure in AI repos and containers
- **What:** credentials across the AI development surface — hub read/write tokens, cloud keys,
  experiment-tracking API keys (tracking servers hold artifacts and can often write them),
  inference-endpoint keys, vector-store credentials — in notebook source *and cell outputs*, model
  cards, README snippets, `.env` files baked into container layers, image build args, and config.
- **Recognize:** a notebook output containing an authorization header; a token literal in a committed
  config; a layer adding a credentials file; a model-card snippet carrying a live-looking endpoint key;
  git history retaining a secret a later commit "removed."
- **Confirm (least-impact):** **minimum proof, zero use.** Record location, the key's identifiable
  prefix, its length, and a hash — never the full value. **Never validate it against the provider, never
  make one API call with it, never enumerate what it reaches** — that is unauthorized access regardless
  of scope, and a live secret is a §6.6/§7.7 stop-and-report. Report it immediately; retain no copy.
- **Maps to:** PB-01, PB-06; `I` (PB-20) for an inference-endpoint key. **Severity:** driven by the
  credential's scope **as the program confirms it**, not as you assume — say what you found, where, and
  explicitly that you did not validate it. A write-capable hub token on a production model path is
  critical, but you write "write-capable if the token type is as labeled."

### S9 — Classical-only integrity on long-lived artifacts
- **What:** weights, adapters, datasets, and their loaders integrity-protected by RSA/ECDSA/EdDSA — or
  by SHA-256 digests inside a classically signed manifest — with no PQ signing path and no agility to
  add one. The gap: an artifact's **trust lifetime** (how long a verifier still accepts that signature
  as proof of origin) outruns the classical signature's assurance horizon — checkpoints are re-consumed
  for years, edge models ship *inside firmware support windows* (precisely PB-11's problem), and a
  signature is **retrospective**: unlike a TLS session it cannot be renegotiated later.
- **Recognize:** RSA-PSS/ECDSA across every signature in the model path; an attestation format with a
  fixed algorithm field and no negotiation; a **hardcoded algorithm literal** in the verifier — non-agile
  even while the algorithm is currently fine (PB-01's agility axis); no dual-signing; device support
  windows exceeding the migration plan. A checksum with **no** signature is S2, not S9.
- **Confirm (least-impact):** read-only. Enumerate the signature algorithm on every artifact in the path
  — weights, adapters, tokenizer, image, attestation — plus the verifier's accepted-algorithm policy,
  and record trust-lifetime years per class. Score as PB-01 does (algorithm × lifetime × exposure ×
  agility); where a PQ roadmap exists, the finding is usually that the model path is **absent from it**.
- **Maps to:** PB-11 (PQ code signing & firmware) — the right remediation target, and where scheme
  selection (ML-DSA-65, SLH-DSA, LMS/XMSS per SP 800-208) and PQ-signature-size handling (PB-08's C7)
  belong; also PB-05 (verifier policy), PB-01 (CBOM), PB-13 (agility). On CNSA 2.0: where the program is
  subject to it, *argue* that a model artifact shipping inside a firmware or boot chain falls under its
  software/firmware signing obligation, labelled as your reading rather than a settled one; outside
  National Security Systems, cite it as the applicable precedent for artifact-signing timelines, not a
  binding requirement. The omission from the signing plan is the finding either way.
  **Severity:** low–medium as posture; medium–high where the artifact ships to devices with a multi-year
  window and no agility to re-sign. **Never critical without a demonstrated present break** — there is
  none here, nobody is forging ECDSA today, and implying otherwise fabricates impact under §6.3. Report
  it as a migration and assurance gap with the trust-lifetime number attached: never a forgery claim,
  never "quantum-broken" bare, never a CRQC date. Dramatized, it is PB-08's anti-pattern of inflating
  severity by asserting future-quantum impact without demonstrating present exploitability. Programs
  routing it informational is a correct outcome; the value is the model path entering the CBOM.

### S10 — Distribution and delivery weaknesses
- **What:** everything between publisher and loader — unauthenticated pull paths (plain HTTP, or TLS
  with verification disabled), mirrors and CDN edges trusted as origins, model caches shared across
  tenants or across build and runtime stages, and download helpers following a redirect to an origin
  outside the allowlist.
- **Recognize:** fetch code with `verify=False` or a custom CA bundle; a mirror/endpoint env var
  pointing at an unauthenticated internal proxy; a cache volume mounted into multiple tenants' jobs or
  into both build and runtime; redirects followed without re-checking host; a mutable cache key.
- **Confirm (least-impact):** static read of the fetch client's TLS, redirect, and cache configuration
  plus the cache's mount and isolation model. Where you control two tenants, write a canary-named
  artifact into **your own** cache namespace and observe whether the second tenant's job can read it —
  a two-tenant isolation proof that belongs here when the shared object is the artifact cache and in
  PB-20 (`I`) when it is the serving plane. **Never poison a shared cache anyone else reads.**
- **Maps to:** PB-20, PB-03 (transport downgrade), PB-06. **Severity:** critical where an
  unauthenticated or attacker-influenceable pull path feeds a code-bearing loader (S1), high for a
  cross-tenant readable or writable cache, medium where transport is authenticated but the key mutable.

## Chains that carry impact

- `S3 → S4 → S1 → code execution in the model-loading service` — an unowned namespace resolved by an
  unpinned reference delivers a code-bearing checkpoint to a loader with no isolation.
- `S8 → S7 → S2 → attacker-published artifact promoted into the production model path` — an exposed
  pipeline credential reaches the promotion job and the missing provenance gate hides the substitution.
- `S4 → S6 → G (PB-18, agent tool boundary) → unauthorized tool invocation` — an unpinned adapter changes
  tool-selection behavior in an agent runtime, turning a pinning gap into an unauthorized action.
- `S10 → S1 → I (PB-20, shared serving plane) → cross-tenant compromise` — a shared, mutable artifact
  cache feeds a code-bearing artifact onto a multi-tenant host, so one tenant's pull lands in another's.
- `S5 → S2 → S6 → untrusted content becomes a distributed artifact` — user content reaches a fine-tune
  with no provenance gate and the adapter is republished ungated; the provable consequence is that
  unreviewed input entered the trusted artifact path, **not** that behavior changed.

## Hunting workflow

1. **Pick the class, write the falsifiable hypothesis** (PB-15 Phase 4): expected-secure behavior plus
   the observation that would kill it.
2. **Build the artifact side of the AI-BOM** (PB-15 Phase 2): every artifact the target loads, with
   origin, reference form (name / tag / revision / digest), format, and the verification it *claims*.
3. **Fingerprint read-only** under the Static-only inspection rule: hub file listings, config JSON, model
   cards, dependency manifests, public CI config, image manifests — nothing loaded, nothing executed.
4. **Stand up the harness** (PB-15 Phase 3): two tenants you own, a canary registry with a unique
   `GNBB-CANARY-<uuid4>` per probe, a trial ledger, and a request/cost cap set before the first probe.
5. **Validate self-scoped at minimum footprint** — every artifact you *write* is yours and every
   namespace you publish to is yours; the target's artifacts are only ever inspected.
6. **Record the falsifier**: a pinned digest, a signature check that fails closed, an isolated loader, a
   claimed namespace — each kills its hypothesis cleanly, and a clean negative is a real outcome.
7. **One finding per defect**, chains citing the primary class first, then the sequence (§8.1).

## Anti-patterns (do not do these)

- **"The repo uses pickle" filed as critical RCE** with no evidence the target's loader ever consumes an
  artifact from an origin an outsider can influence. Format alone is hardening; the path is the finding.
- **Claiming model poisoning from a canary that only proves data ingress.** State what you proved (S5);
  inferred behavioral impact is fabrication and the fastest way to lose standing on a program.
- **S9 severity inflation** — "quantum-vulnerable model signing" filed as critical with no trust-lifetime
  number, no agility assessment, and no demonstrated present break. This is PB-08's anti-pattern of
  inflating severity by asserting future-quantum impact without demonstrating present exploitability.
- **Registering, claiming, or "defensively holding" a namespace to prove S3.** That is impersonating the
  target and nobody asked you to. Report availability; the program claims it.
- **Bulk-cloning model repos or dumping every container layer to grep for secrets**, then filing the
  volume as findings. Minimum collection (§7.7), no retention, and a pile of reports is not a record.

## Validation discipline (the GreyNOC bar)

- **Everything you wrote comes back out.** Every artifact, adapter, cache object, and canary you
  published or uploaded is removed when the probe ends, and the removal is recorded — §6.2 no
  persistence, §7.4 canary discipline. Where removal is **not in your control** — content already
  ingested into a training, fine-tuning, or embedding corpus (S5) — say so plainly, name the exact
  canary and the ingress path in the report, and ask the program to purge it. An unremovable marker you
  did not disclose is a persistence violation.
- **Pin your own evidence even where the target does not.** Every artifact claim carries the exact
  reference inspected (`org/model@<revision-or-digest>`, `image@sha256:…`, path in the repo tree) with a
  UTC timestamp and a hash — S4 means `main` moves, and an unpinned citation is how a true finding gets
  closed not-reproducible a week later.

## Report template

Use the PB-15 AI report template. Add these lines:

```
DEFECT-CLASS:     ____   (S1–S10 primary; full chain sequence if any)
ARTIFACT-REF:     org/model@<revision|digest> · image@sha256:… · exactly as inspected + UTC ts
ARTIFACT-FORMAT:  safetensors | gguf | code-bearing (.pt/.bin/.ckpt/.pkl/.joblib) | container | config
VERIFY-GATE:      signature | attestation | digest-pin | none  →  enforced | fails-open | absent
STATIC-ONLY:      target artifact loaded/executed: N (required) · canary: GNBB-CANARY-____
CLEANUP:          artifacts / canaries / cache objects removed: Y/N · what, where, when
UNREMOVABLE:      markers the program must purge (S5 corpus ingress): ____
```

## Summary

The discipline that makes a submission here credible is narrow and concrete: static-only inspection of
the target, self-scoped writes for anything that changes state, cleanup of everything you wrote,
minimum proof and zero use on discovered secrets, ingress-gap honesty on S5, lifetime-anchored honesty
on S9. The honest limit is that this catalog proves **control gaps in the path to the model**, not that
a model was compromised — asserting the latter from a supply-chain gap turns a strong finding into a
fabricated one. Report the gap you proved, name the chain that would carry it, and let severity come
from the consequence you can demonstrate.
