# 16 — Bug Bounty: LLM Application-Layer Defects (Authorized)

> **Authorization required.** Authorized testing only, GreyNOC as submitting firm, scope on file.
> See [CONVENTIONS §6 Rules of Engagement and §7 AI-system testing addendum](CONVENTIONS.md).
> **Injected content persists and fires in sessions that are not yours** — never plant directive text
> in a shared corpus, mailbox, queue, or memory store real users read, and remove every marker you
> place. This playbook is a **defect-class catalog with validation guidance**, not exploit tooling.

## Overview

This catalog covers the **application around the model** — how prompts are assembled, what is
retrieved into context, who authored that content, what the app does with the completion, and whose
identity the backend acts under. That layer is where most reportable AI findings land, because it is
ordinary broken access control, injection, and output handling wearing new vocabulary. "The model
said something bad" is **not** this catalog: a content-policy bypass with no security consequence
routes to PB-19 per [CONVENTIONS §7.1](CONVENTIONS.md). PB-15 is the methodology spine — scope,
AI-BOM, harness, ledger, routing — and this is the class list you target once Phase 2 has mapped the
boundaries; PB-17, PB-18, and PB-20 own the artifact, agent, and serving-plane surfaces.

## Scope boundary — what belongs here vs. elsewhere

| Finding shape | Owner | Prefix |
| --- | --- | --- |
| Prompt assembly, RAG retrieval, output rendering, conversation authz, app-level authz | PB-16 | `L1–L19` |
| Model weights, adapters, datasets, registry provenance, artifact deserialization | PB-17 | `S1–S12` |
| What the model may **do**: tool definitions, MCP servers, agent loops, action scope | PB-18 | `G1–G14` |
| Serving plane: GPU/tenant isolation, KV-cache and batching cross-talk, hosting endpoints | PB-20 | `I1–I12` |
| Jailbreak-for-content, hallucination, bias, refusal bypass with **no** security consequence | PB-19 | none |

Tiebreaker: delete the model from the design, and if a recognizable web or API bug is still there, it
is `L`. An *action the system took* is `G`; *what you loaded* is `S`; *the box it runs on* is `I`.

**Reference convention.** `PB-NN` / `D&R-NN` per [CONVENTIONS §5](CONVENTIONS.md); the defensive
twin cited throughout is [D&R-09 AI / Automated Agent Abuse](09-ai-automated-agent-abuse.md).

## MITRE mapping

| Technique | ID | Relevance |
| --- | --- | --- |
| LLM Prompt Injection | AML.T0051 | Umbrella for L1 and L2 |
| LLM Prompt Injection: Direct | AML.T0051.000 | L1 — caller override of privileged instructions |
| LLM Prompt Injection: Indirect | AML.T0051.001 | L2; delivery vector for L7, L8, L11 |
| LLM Jailbreak | AML.T0054 | L13 — the routing test decides if it is a security finding at all |
| LLM Data Leakage | AML.T0057 | L3, L4, L14 |
| AI Agent Tool Invocation | AML.T0053 | L6/L11 where the app hands model output to an integration |
| Exfiltration via AI Inference API | AML.T0024 | L5 — the inference surface itself carrying content out |
| Discover AI Model Ontology | AML.T0013 | L3 — recon on prompt, tool, and retrieval structure |
| RAG Poisoning · False RAG Entry Injection | AML.T0070 · AML.T0071 | L7 (b) — contributor-poisoned corpus |
| Data from AI Services: RAG Databases | AML.T0085.000 | L7 (a) — retrieval scope and store access |
| AI Agent Context Poisoning: Memory | AML.T0080 · AML.T0080.000 | L8 — persistence into long-lived memory |
| Cost Harvesting · Denial of AI Service | AML.T0034 · AML.T0029 | L12 — spend and amplification |
| Exploit Public-Facing Application | T1190 | L10 — ingestion and parser defects |
| Valid Accounts | T1078 | L9, L11 — access under an identity that should not reach the data |
| Unsecured Credentials | T1552.001 · T1552.005 | L4 secrets in prompt assets; L10 SSRF to metadata |
| Steal Application Access Token | T1528 | L4 where the leaked credential is an application token |
| Command and Scripting Interpreter | T1059 | L6 — model-authored code reaching an interpreter |
| Data from Information Repositories | T1213 | L7, L14 |
| Exfiltration Over Web Service | T1567 | L5 — markdown-image and link egress channels |
| LLM Prompt Obfuscation | AML.T0068 | L13 — encoding and format channels around a filter |
| Obfuscated Files or Information | T1027 | L13 — the ATT&CK analogue for the same channel |
| Resource Hijacking | T1496 | L12 where free inference is consumed for the caller's workload |

> **Mapping discipline (`CONVENTIONS §4`).** ATT&CK citations in this table were verified against
> ATT&CK Enterprise v19.2 on 2026-08-09 — including T1027, which v19 moved to the Stealth tactic when
> it retired "Defense Evasion" (TA0005 renamed Stealth, TA0112 Defense Impairment split out). Cited
> against ATLAS collection 2026.06 per [CONVENTIONS §4](CONVENTIONS.md); ATLAS IDs and names are
> versioned — re-map to your platform's collection at deployment. Where an ID is cited to support
> severity or plausibility, quote that technique's `maturity` value from your collection alongside it
> (§4).
>
> **No ID is forced onto a web-vulnerability primitive.** Cross-site scripting (`L5`), SSRF (`L10`),
> and IDOR (`L9`) are cited **by name only** — neither framework carries a technique for the primitive
> itself, and inventing one would be the forced mapping §4 treats as a defect. Where a row above does
> cite an ID against one of those class numbers, it is tagging the *outcome* that class reaches, not
> the primitive: `T1552.001`/`T1552.005` tag the **credential exposure** SSRF arrives at in L10,
> `T1567` tags the **egress** an L5 sink performs, and `T1078` tags the **identity** an L9 or L11
> authorization failure acts under. Cite the outcome ID if your platform needs one; never label the
> XSS, the SSRF, or the IDOR itself with it.

## Defect-class catalog

### L1 — Direct prompt injection across a trust boundary
- **What:** the app uses the system prompt as an access control. Caller text shares one context with
  operator instructions and no privilege separation, so precedence is probabilistic, not enforced.
- **Recognize:** instruction-phrased guards ("never reveal X"); behavior that flips on imperative user
  text; one flat context mixing operator text, retrieved data, and caller input.
- **Confirm (least-impact):** name the privileged instruction and its consequence first, then seed a
  `GNBB-CANARY-<uuid4>` in your own tenant's prompt and prove release of that exact string from a clean
  context. Never chain the override into a tool call to dramatize impact — that is PB-18 scope.
- **Maps to:** PB-06 (guardrail twin), D&R-09; L3, L6, L11; PB-18 `G3` once the override hits a tool.
- **Severity:** none-to-informational when the outcome is only different text; rises with consequence —
  unentitled data, privilege change, executed action. **No consequence = PB-19, not security (§7.1).**

### L2 — Indirect prompt injection via ingested content
- **What:** instructions arrive inside retrieved content — RAG documents, web pages, emails, tickets,
  calendar entries, code comments, document metadata, image alt text and OCR — **and inside tool and
  function return values**, which are model-visible text from a third party exactly as a retrieved
  document is. The author is not the caller, so the model obeys a party nobody authenticated.
  Consistently high-yield, because most apps never model this boundary at all.
- **Recognize:** any "summarize this page / ticket / inbox / repo" feature; any index a lower-privileged
  party can write to; retrieved text concatenated into the operator-instruction field; a tool return
  spliced into context with no provenance label separating it from operator text.
- **Boundary with PB-18 `G1`:** the split is *what you are testing*, not *where the bytes came from*.
  The **app splicing a return value into a privileged context with no provenance label is `L2`** — it is
  content entering the context, and deleting the model leaves an ordinary trust-boundary bug. The **tool
  definition, its description text, and the agent acting on the injected instruction are `G1`/`G3`**.
  Test the splice here; hand the action to PB-18 and cite the chain.
- **Confirm (least-impact):** own the content end to end — your document, your ticket from your own
  low-privilege account, your host — with an inert directive that only emits a registered canary, and
  two accounts you own as author and reader. Never plant directive text in shared or production stores:
  one left behind fires in a real user's session, a §7.11 stop condition.
- **Maps to:** PB-06, D&R-09; L5, L6, L7, L8, L11; PB-18 `G1` chains.
- **Severity:** set by what you demonstrated the *reader's* session actually did — medium where it
  altered one summary. Tool access, cross-tenant retrieval, or an egress path in that session is a
  hypothesis for a separate finding, not a severity multiplier: prove the consequence in its own class
  (`L5`, `L7`, or PB-18 `G`), cite the chain, and score on the step you proved.

### L3 — System-prompt and configuration disclosure
- **What:** the operator instruction block, tool schema, retrieval config, or feature flags recoverable
  from output, via direct request, format shift, or debug and error echoes.
- **Recognize:** output quoting operator-voice text verbatim; errors containing the assembled prompt; a
  debug or "show context" parameter; truncation messages leaking block sizes.
- **Confirm (least-impact):** recover twice from a clean context and diff — paraphrase is not disclosure,
  verbatim recovery is, and a canary seeded in your own prompt rules out reconstruction. Models fabricate
  plausible system prompts on request; never report one you have not proven verbatim.
- **Maps to:** AML.T0013, AML.T0057; PB-06; L1, L4, L11.
- **Severity:** low or informational alone — the prompt is not a secret store, and treating it as one is
  the design defect, not the finding. It rises to what it leaks: secrets or tokens (route to L4), authz
  logic and its bypass conditions, internal endpoints and tool schemas that widen other classes.

### L4 — Secrets and credentials resident in prompt context
- **What:** API keys, connection strings, bearer tokens, signing keys, internal URLs, or tool credentials
  sitting in a system prompt, tool description, or context block where model output can reach a user.
- **Recognize:** L3 disclosure containing key-shaped material; connector or tool descriptions with auth
  inline; client bundles or docs showing the prompt assembled from environment values.
- **Confirm (least-impact):** validate the *shape*, never the credential — do not authenticate with it,
  call the API it belongs to, or probe its scope. Proof is a redacted fragment plus a hash and the
  issuer/prefix form, reported immediately under §6.6 / §7.7. Rotation is the vendor's action.
- **Maps to:** T1552.001, T1528; PB-01/PB-05 for key material; L3, L14; PB-20 `I5` for inference keys.
- **Severity:** high-to-critical by what the credential reaches and its blast radius. A read-only key
  scoped to public data is not critical — say which one it is, with evidence.

### L5 — Insecure output handling in the rendering path
- **What:** model output rendered as HTML, markdown, or JS without the treatment untrusted input gets:
  stored and reflected XSS; markdown image and link syntax that makes the client fetch an attacker-chosen
  origin with conversation content in the URL; link smuggling where text and destination diverge.
- **Recognize:** a client rendering markdown or raw HTML; images auto-loading from arbitrary origins; no
  CSP `img-src` / `connect-src` allowlist on the chat surface; output written via `innerHTML`.
- **Confirm (least-impact):** canary in your own conversation, an origin you control, and the proof is the
  arriving request in *your* server log, at the minimum request count. Never egress anything real, use
  another user's transcript, or leave an auto-firing payload in a shared thread.
- **Maps to:** T1567, AML.T0024; PB-06; L2 as delivery, L14 as the adjacent exposure class.
- **Severity:** score it as the web vulnerability it is — XSS with session impact is high, a markdown
  channel egressing whole conversations off-origin is high, a link that merely looks wrong is low.

### L6 — Model output consumed by a downstream interpreter
- **What:** generated SQL, shell, code, template, or filter expression executed downstream with no
  validation, because the model is treated as a trusted producer — text-to-SQL, "run this analysis",
  template-rendered notifications, dynamic filters, natural-language-to-API layers.
- **Recognize:** features that run queries or code from natural language; errors echoing generated SQL or
  an interpreter stack trace; a sandbox described in docs but never evidenced in behavior.
- **Confirm (least-impact):** aim for a syntactically valid, semantically inert construct against your own
  data — a benign literal, a row count on your own tenant, a canary echoed through the interpreter.
  Proving it executed model-authored text *is* the finding; never read other tenants' rows, write, drop,
  or attempt sandbox escape "to show real impact".
- **Maps to:** T1059, AML.T0053; PB-06; L1/L2 as delivery; PB-18 `G7` if the interpreter is a tool.
- **Severity:** high-to-critical when execution touches a shared datastore or host; medium when confined
  to the caller's own data behind an allowlist. Severity comes from the *interpreter's* privileges.

### L7 — Retrieval-scope and RAG corpus violations
- **What:** two defects on one surface. (a) **Scope violation** — retrieval returns documents the caller is
  not entitled to, because the tenant/ACL filter lives in the prompt, is applied after ranking, or never
  reaches the vector query. (b) **Corpus poisoning** — a low-privileged contributor writes content that a
  high-privileged reader's retrieval surfaces.
- **Recognize:** citations naming documents you cannot open directly; result counts implying a broader
  index than your entitlement; revocations not reflected in retrieval — stale ACL metadata on the index,
  or a permission filter refreshed on a schedule rather than on write; any index taking writes from a role
  below its readers.
- **Confirm (least-impact):** two tenants you own — canary-only document in tenant A, query from tenant B,
  and the canary in B is the finding; one crossing proves it. For (b) the poisoned document lives in your
  own workspace with an inert marker; for stale ACLs, revoke your own access and re-query. Never enumerate
  the index or pull neighbors to "measure scope".
- **Maps to:** AML.T0085.000 (a), AML.T0070 · AML.T0071 (b), T1213; PB-06, D&R-09; L2, L8, L11;
  PB-20 `I11` if the crossing is in the store — `I2` covers model and
  deployment routing, not retrieval backends.
- **Severity:** high-to-critical for tenant crossing — plain broken access control. Poisoning severity
  depends on the reader's privilege and how open the write path is.

### L8 — Persistent memory poisoning
- **What:** content written into long-lived per-user or per-workspace memory — profile facts, "remember
  that…" stores, scratchpads, summary caches — that survives the session and is re-injected later, so an
  instruction written once executes on turns the attacker is not present for.
- **Recognize:** a memory feature or settings page listing stored facts; behavior persisting into a fresh
  session; and the actual bug — memory writes triggered by *ingested content*, not by a user action.
- **Confirm (least-impact):** on your own account, drive a benign canary-bearing fact in through the indirect
  path (L2 delivery), close the session, open a clean one, observe the canary. Record persistence duration
  and memory scope (user / workspace / org), then delete your entries and say so. Never write into
  workspace- or org-scoped memory that real colleagues' sessions read.
- **Maps to:** AML.T0051.001, AML.T0080.000 Memory; PB-06, D&R-09; L2 delivery, L11; PB-18 `G9`.
- **Severity:** one step above the delivering class where you demonstrated the injected instruction
  re-firing in a clean session, and no higher without a demonstrated consequence in that later session.
  Record measured persistence duration and memory scope as the evidence for the bump. Workspace- or
  org-scoped memory another real user reads is a §7.11 stop condition, not a severity argument you get
  to make by testing it.

### L9 — Conversation and session isolation failures
- **What:** transcripts, threads, attachments, or cached context reachable by the wrong principal — IDOR on
  conversation/thread/message IDs, cache keys coarse enough that content bleeds between users, transcripts
  readable after a role or membership change, share links permanent, unrevocable, or over-scoped.
- **Recognize:** sequential or guessable IDs in URLs and API calls; sharing with no expiry or revocation;
  session-restore behaviors; and the loudest signal, a response containing content you never sent.
- **Confirm (least-impact):** two accounts you own — request account A's conversation as account B,
  unauthenticated, and as a removed member; canary content in A makes the crossing unambiguous. If you
  surface a third party's content, **stop, preserve minimally, escalate** (§7.11) — never enumerate.
- **Maps to:** T1078; PB-06; L14; PB-20 `I3` if the cause is a serving-plane cache, not app authz.
- **Severity:** high — broken access control over conversation data, which routinely holds the user's most
  sensitive material. Post-revocation access stays high even when it needs the old ID.

### L10 — Ingestion pipeline defects
- **What:** the non-model half of file and URL intake. SSRF through fetch-this-URL features, including
  redirect and rebind paths into internal ranges and the cloud metadata endpoint; parser abuse in document,
  spreadsheet, image, and archive handling (external-entity expansion, formula/macro handling, decompression
  bombs, archive-entry traversal); traversal in attachment naming; missing size and depth limits.
- **Recognize:** any URL input; any upload feeding a text-extraction step; error text naming a parser and
  version; latency or error-class differences between an internal target and an unroutable one.
- **Confirm (least-impact):** point the fetcher at a listener you control — shown here as `203.0.113.10`
  per [CONVENTIONS §5](CONVENTIONS.md), which is documentation space and routes nowhere, so substitute
  your real host — and read your own request log for the arriving connection, its user agent, and whether
  it followed the redirect. Prove metadata reachability with **one** request to a **non-credential path** —
  the metadata root, or `/latest/dynamic/instance-identity/document` — recording only the status code, the
  response class, and whether the endpoint rejected the unauthenticated GET. Never request a credentials
  path: on that path the response body *is* the secret, and "I did not keep it" is not minimum capture
  under §7.7. **"Instance identity" is not a safe category wholesale:** the sibling paths
  `instance-identity/pkcs7`, `/signature`, and `/rsa2048` return *signed* identity documents that real
  systems accept as an authentication credential — HashiCorp Vault's `aws` auth method, `ec2` type,
  authenticates on the PKCS7 document — so treat those three as credentials paths and do not request them.
  When recording the rejection, note *which* gate rejected you: a token-requiring variant (IMDSv2, token via
  `PUT /latest/api/token`) answers a tokenless GET with `401`, while a header-gated variant (GCP
  `Metadata-Flavor: Google`, Azure `Metadata: true`) answers a bare GET with `403` for a different reason.
  Reading a header-gate `403` as "not reachable" is a false negative. Test size limits with one oversized
  inert file rather than a bomb.
- **Maps to:** T1190, T1552.005; PB-06; L4; PB-18 `G8` where the fetch runs from an agent runtime
  rather than the app's ingestion path.
- **Severity:** SSRF reaching an internal service or the metadata endpoint is high-to-critical on its own
  merits. Parser findings score on what the parser yields — file read, execution, or a crash; a crash is low
  unless the worker is shared.

### L11 — Authorization delegated to the model
- **What:** confused deputy at application level. The app asks the model to decide what the caller may see or
  do ("only show this user their own records"), or the backend runs the model's requested call under a
  service identity broader than the caller's. Access control becomes an inference, and inference is
  influenceable by everything in L1 and L2.
- **Recognize:** authorization rules written in prompt text (usually surfaced via L3); one service account
  behind every model-initiated backend call; a retrieval or tool layer whose parameters carry no caller
  identity; role behavior that shifts under persuasive user text.
- **Confirm (least-impact):** as a low-privileged account you own, request something the model is instructed
  to withhold but the backend would return anyway — the backend returning it is the finding. Canary-tag the
  privileged record in tenant A; prove the identity gap exists without walking through it toward real data.
- **Maps to:** T1078, AML.T0053; PB-06, D&R-09; L1/L2 delivery, L7 retrieval; PB-18 `G3` tool perms.
- **Severity:** high-to-critical. A broken-access-control finding in an AI costume, scored on that basis —
  not discounted because the mechanism happens to be a prompt.

### L12 — Missing consumption controls (denial of wallet)
- **What:** no per-user or per-tenant ceiling on metered work — unbounded spend within one request
  (caller-controlled context size, output length, model choice, loop depth), no quota across requests, and
  amplification where one cheap request triggers expensive downstream work: recursive retrieval, multi-step
  chains, whole-corpus re-embedding on edit.
- **Recognize:** caller-controlled `max_tokens`, model selection, or iteration depth; no visible quota, credit,
  or rate ceiling on an unauthenticated or free-tier path; cost and latency scaling with an input you control.
- **Confirm (least-impact):** **demonstrate the missing control at the minimum request count per
  [CONVENTIONS §7.5](CONVENTIONS.md), and state that count explicitly in the report** — normally a handful of
  requests establishing per-request cost plus evidence that no counter decrements, then extrapolation with the
  arithmetic shown. Never exhaust a quota, drain a credit balance, or run volumetric load: causing the outage
  is the harm you are reporting, and an ROE violation besides.
- **Maps to:** AML.T0034, AML.T0029, T1496; D&R-09; PB-20 `I7` for capacity-level effects.
- **Severity:** medium by default; rises when the path is unauthenticated, when one request consumes a
  disproportionate share, or when spend lands on a tenant that cannot cap it. Many programs scope this class
  out entirely — read the policy before spending effort.

### L13 — Guardrail and classifier bypass with a security consequence
- **What:** input or output filters routed around by *channel* rather than content — encodings, homoglyphs,
  base64/hex wrapping, zero-width tricks, low-resource-language translation, content carried in images or
  audio the filter never sees, and format channels (code blocks, structured-output and tool-argument fields)
  that skip the checker. The defect is that the filter and the model do not see the same input.
- **Recognize:** an observable classifier — canned refusal text, a distinct blocking response, a latency step
  — behaving differently across encodings or modalities; filtering applied to the user turn but not to
  retrieved content or tool output.
- **Confirm (least-impact):** **run the §7.1 routing test before spending a single request.** If the bypass
  yields only disallowed content it is a PB-19 model-behavior report and does not belong in the security queue,
  however elegant the encoding. It is a security finding *here* only when the bypassed filter stood in front of
  a security consequence — an injection filter preventing L2/L11, or an output scanner preventing L4/L5 egress.
  Prove that consequence with a canary and ledger it.
- **Maps to:** AML.T0068, AML.T0054, T1027; PB-06 (the guardrail its twin builds); L1, L2, L5.
- **Severity:** inherits from the class it unlocks and drops to nothing if it unlocks nothing. A bypass of the
  sole control on a high-severity path is scored as that path.

### L14 — Prompt, completion, and telemetry exposure
- **What:** conversation content leaving the boundary the user was told it stays inside — prompts and
  completions in application logs, APM traces, error pages, third-party analytics and session replay, an
  unauthenticated debug or trace endpoint, a shared log sink; training/improvement opt-in whose default or
  scope is misrepresented; support tooling reading transcripts beyond documented policy.
- **Recognize:** prompt text in client-visible errors; conversation IDs and content in browser network calls to
  third-party origins; verbose trace parameters; an observability integration listed in settings; a privacy
  statement or DPA whose data-use claim contradicts observed behavior.
- **Confirm (least-impact):** your own conversation seeded with a canary, then read your own browser network
  traffic and any log surface you are authorized to read; the canary arriving at a third-party origin or an
  unauthenticated endpoint is the proof. Never access a log store you were not granted or pull other users'
  entries to size the exposure, and quote the documented statement any policy-contradiction claim rests on.
- **Maps to:** AML.T0057, T1213; PB-06; L4, L9; PB-20 `I12` for platform-tier telemetry
  tenancy — `I10` covers only whether that path is encrypted, not who can read it.
- **Severity:** driven by who can reach the content and what conversations contain. An unauthenticated debug
  endpoint returning transcripts is high; content in a first-party log with correct access control is a hygiene
  finding, and calling that a data breach is the inflation triagers punish.

### L15 — Prompt-template and role-delimiter injection in the assembler
- **What:** caller text reaching the **prompt template itself** rather than the model's input. Two forms, both
  server-side. **(a) Server-side template injection:** user input interpolated into a Jinja2, Handlebars, ERB,
  or f-string template that the assembler then renders, yielding template-expression evaluation on the app
  server — file read, environment access, or the template context object holding the system prompt, tool
  schemas, and API credentials. **(b) Role and control-token forgery:** a concatenating assembler that does not
  escape chat delimiters or special tokens, so caller text containing `<|im_start|>system`, `[INST]`, `</s>`, or
  the target's channel markers closes the user turn and opens a *genuine* system turn. This is not L1's
  probabilistic precedence problem — the forged turn is structurally real in the serialized prompt.
- **Recognize:** template syntax echoed or evaluated in output; errors naming a template engine and line
  number; a system prompt assembled by string concatenation or f-string rather than a typed message array;
  user text appearing inside the operator block after a round trip; the chat template exposed as a
  user-editable setting; special-token strings surviving into the prompt instead of being escaped.
- **Confirm (least-impact):** for (a) submit the engine's arithmetic probe (`{{7*7}}` and its polyglot
  equivalents) and confirm **evaluation**, not echo — `49` in the output is the finding, `{{7*7}}` is not.
  Escalate only as far as proving evaluation: read one non-sensitive context attribute, stop, and never attempt
  command execution to raise severity. For (b) seed a `GNBB-CANARY-<uuid4>` in your own tenant's operator block
  and prove the forged system turn releases that exact string, then show the serialized prompt (from a debug
  echo, an error, or your own deployment of the same template) with your delimiter intact.
- **Not stochastic.** Both forms are **deterministic** — they are string handling, not sampling. Report
  `TRIAL LEDGER: deterministic — n/n` and do not dress a template bug in Wilson intervals; applying the §7.6
  stochastic apparatus to a deterministic defect invites a triager to think you did not understand it.
- **Maps to:** T1190, T1059 where template evaluation reaches an interpreter; L3 (the context object holds the
  system prompt), L4 (it holds credentials), L1 (the probabilistic sibling this class is *not*).
- **Severity:** (a) is high-to-critical on ordinary web terms — it is remote code or file access on the app
  server, and the model is incidental. (b) scores as L1 does, on consequence, but the structural forgery makes
  the "precedence is probabilistic" defense unavailable to the vendor.

### L16 — Structured-output and schema coercion
- **What:** the app constrains the model's output **shape** and then trusts its **values**. A JSON schema,
  function-argument spec, or constrained/grammar-guided decoder guarantees a parseable object; it guarantees
  nothing about `recipient`, `amount`, `account_id`, `path`, `role`, `tenant`, or `is_admin` inside it. Where
  the app performs no server-side re-authorization on those fields, injected content anywhere upstream fills
  them and the backend acts. Second form: a **parser differential** between the validator and the consumer —
  duplicate keys, `__proto__`, unicode escapes, numeric coercion, or leading-zero and big-integer handling
  where the two parsers disagree about what the document says.
- **Recognize:** strict mode, JSON mode, or a schema presented in documentation as a safety property; a
  function-call argument used directly as an identifier, path, or authorization subject; validation that
  checks types and required fields only; two different libraries validating and consuming the same payload.
- **Confirm (least-impact):** with two accounts you own, produce a schema-valid object whose value field names
  the *other* account's resource, and prove the backend acted on it rather than re-checking entitlement. The
  finding is the **missing server-side check**, not the model's cooperation — so state the request that should
  have been rejected and was not. For a parser differential, show the same document read two ways with both
  outputs side by side.
- **Maps to:** T1190; PB-18 `G3` once the coerced value becomes an *action the agent takes* — the boundary is
  that `L16` is the app parsing and trusting, `G3` is the agent acting under the wrong authority.
- **Severity:** scores as broken access control, because that is what it is — delete the model and this is an
  API trusting a client-supplied field. Frequently the most triager-credible finding in an AI application,
  precisely because it needs no AI vocabulary to explain.

### L17 — Streaming and partial-output delivery ahead of the guardrail
- **What:** the server streams tokens to a client that renders incrementally, while output moderation, DLP,
  or redaction reads the completion as a whole. The scan verdict therefore lands **after** the bytes are in the
  DOM — and after any markdown-image or link fetch in them has already left the browser. A time-of-check /
  time-of-use defect on output sanitization. Related forms: abort or stop-generation leaving pre-redaction
  content rendered and in the network log, and a redaction applied by overwriting displayed text while the
  original remains in the response body or the client-side store.
- **Recognize:** token-by-token rendering; server-sent events or chunked transfer on the completion endpoint;
  a visible "removed for policy" replacement that appears *after* text was already shown; a moderation verdict
  arriving as a separate later event; content still present in the raw stream after the UI redacts it.
- **Confirm (least-impact):** in your own session, capture the **raw stream** alongside the rendered view and
  show the pre-redaction bytes present in the response body. Where the chain is egress, prove the client issued
  the request before the verdict arrived by timestamping your own listener hit against the redaction event.
  Both halves are your own traffic, so no third-party data is involved.
- **Deterministic enough to state plainly.** The race is timing-dependent, not sampling-dependent: report the
  observed win rate as a plain count of attempts (`8/10 renders before verdict`) rather than a Wilson interval
  over model sampling, and state the network conditions.
- **Maps to:** T1567 where the pre-verdict render performs egress; L5 (this is why an L5 egress chain fires on a
  target that *does* run an output scanner), L14.
- **Severity:** informational where the only outcome is a briefly visible string; rises to the severity of the
  underlying leak or egress the scanner existed to prevent. This class is usually the missing step that makes
  an otherwise-rebutted L5 finding stand up.

### L18 — Non-text input as an instruction carrier
- **What:** instructions reaching a native multimodal encoder with **no text-extraction step** to inspect. Not
  L2's alt text and OCR, which produce a text artifact a filter could see: here the directive exists only as
  pixels or as a waveform, consumed directly by a vision or audio tower. Forms include text rendered into an
  image at low contrast or in a corner, text in a visual code or chart label, instructions in an audio track or
  ultrasonic band, and directives in document *page images* where the app rasterizes before ingesting.
- **Recognize:** any image, audio, video, or screenshot upload feeding a model that is natively multimodal; a
  document pipeline that rasterizes pages; a "describe this screenshot" or "listen to this" feature; a filter
  stack that inspects the transcript or extracted text but not the raw media.
- **Confirm (least-impact):** your own media, your own tenant, two accounts you own as author and reader. The
  proof obligation is higher than L2's: you must show the `GNBB-CANARY-<uuid4>` **survived the encoder** rather
  than an extraction step, so state whether the pipeline performs OCR or transcription and show that the canary
  is not present in any extracted-text artifact the app produces. If OCR is in the path, this is L2.
- **Route it correctly.** This is **not** a filter-evasion finding and does not belong in `L13`. The defect is
  that content from an unauthenticated author enters a privileged instruction channel with no provenance
  label, which is L2's shape in a medium the app never inspects. Filing it as evasion invites the model-safety
  routing under §7.1 and loses the security finding.
- **Maps to:** AML.T0051.001, AML.T0068 where the medium is itself the obfuscation; L2 (same boundary, text
  medium), L5, L7, L11; PB-18 `G1` once the carried instruction reaches a tool.
- **Severity:** as L2 — set by what the reader's session actually did, proven in its own class. The carrier
  raises exploitability, not impact: a directive no filter can see is cheaper to deliver, which is a retry-cost
  argument, not a severity multiplier.

### L19 — Provenance loss across summarization and context compaction
- **What:** the app compacts a long conversation to fit the window — summarizing earlier turns, or rewriting
  them into a running state note — and the summarizer consumes operator instructions, caller text, and
  retrieved content **together**. What re-enters the context is unlabeled prose in a single voice: text that
  was quoted and fenced as untrusted becomes indistinguishable from operator instruction, and guard clauses can
  be dropped outright as redundant detail. Taint is lost across a re-serialization, and the next turn inherits
  a context whose provenance structure no longer exists.
- **Recognize:** any long-conversation or long-document feature with a context-management step; a visible
  "summarizing earlier messages" indicator; a running-summary or state-note field; truncation notices; behavior
  that changes after a conversation passes a length threshold; guard instructions that stop being honored late
  in a session but work in a fresh one.
- **Confirm (least-impact):** in your own session, plant a fenced, explicitly-untrusted block containing a
  registered canary directive early, drive the conversation past the compaction threshold, then show that the
  post-compaction context treats it as operator-voice text — the canary released, or the directive followed,
  where it was refused pre-compaction. The **pre- and post-compaction pair from the same session is the
  evidence**; one side alone proves nothing.
- **Tiebreaker note, stated honestly.** This passes on PB-16's scope table ("how prompts are assembled") more
  cleanly than on the delete-the-model test, since the lossy transformation is itself model-driven. The nearest
  ordinary analogue is taint loss across a re-serialization boundary. It is filed here because the *control*
  that fails is the app's provenance labeling, which is app code — but expect a triager to push on that, and
  lead with the labeling failure rather than the summarizer's behavior.
- **Maps to:** AML.T0051.001; L1 (the flat-context sibling), L2 (the carrier that gets laundered), L3, L8 —
  and note the distinction from L8: a compaction summary is a **context transformation**, not a persistent
  memory store, so a finding that survives a new session is L8 and one that dies with the session is L19.
- **Severity:** as the consequence in the post-compaction session, proven in its own class. The class is worth
  reporting on its own where the laundered instruction defeats a guard the vendor relies on, because the fix is
  structural — labels must survive compaction — and not another instruction.

## Chains that carry impact

- `L2 → L5 → conversation content egresses to an attacker-controlled origin` — a directive in a retrieved
  document makes the model emit a markdown image whose URL carries transcript content, and the client fetches
  it automatically. The chain this catalog is most often used for.
- `L2 → L11 → PB-18 (G) tool-invocation class → action executed under a service identity broader than the
  caller's` — an injected instruction reaches a layer that asks the model what the user may do, and the
  backend performs it under that broader identity. Primary class is `L11`; the `G` step carries the impact.
- `L10 → L4 → PB-20 (I) serving-plane class` — a fetch-this-URL feature reaches the instance metadata endpoint,
  where an attacker would retrieve an inference-plane credential and the exposure stops being application-scoped.
  Prove reachability on a non-credential path only; the credential step is the chain's premise, not your evidence.
- `L7 → L8 → cross-session persistence` — a low-privileged contributor poisons a shared corpus, a
  higher-privileged reader's session writes the injected fact into long-lived memory, and it re-executes in
  later sessions without the attacker present.
- `L3 → L1 → L6 → model-authored SQL executed against the application database` — disclosure reveals the tool
  schema and exact guard phrasing, making a targeted override reliable, and the override reaches an interpreter
  that trusts its input.

## Hunting workflow

1. **Fingerprint read-only** (Phase 1): render path and markdown/HTML handling, ingestion inputs, retrieval
   citations, memory features, ID shapes, model and version string, visible quota controls. No payloads yet.
2. **Map boundaries before picking a class.** Per PB-15 Phase 2, build the AI-BOM row per feature: who authors
   the input, who reads the output, whose identity the backend acts under, what renders the result — each
   boundary you draw becomes a Phase 4 hypothesis.
3. **Stand up the harness** (Phase 3): two tenants you own, one registered `GNBB-CANARY-<uuid4>` per probe, the
   trial ledger open, and a request cap and cost cap agreed in advance.
4. **Write the falsifiable hypothesis** (Phase 4) — expected-secure behavior plus the observation that would
   disprove it — then apply the §7.1 routing test immediately, before the first probe. A hypothesis with no
   security consequence goes to PB-19 *now*, not after a day of work.
5. **Validate self-scoped at the minimum request count** (Phase 5): clean context per trial, sampling parameters
   recorded, ≥2 successes before believing anything, and stop at the canary — you are proving the boundary
   crossed, not demonstrating what could be done next.
6. **Record the falsifier result either way.** A clean negative against a class is a real engagement outcome.
7. **One finding per defect** (Phase 6), any chain listed as a sequence alongside the single primary class.
   Remove every canary, document, and memory entry you planted; state the removal.

## Anti-patterns (do not do these)

- **Submitting a jailbreak with no security consequence.** "I made it say a forbidden word" is a PB-19
  model-behavior report; routing it to the security queue is the fastest way to lose program standing (§7.1),
  and it is the most common low-quality submission on this surface.
- **One lucky generation, no ledger.** A result you got once, at temperature 1.0, from a context you had been
  steering for twenty turns, is not reproducible. The bar is ≥2 successes from a **clean** context across a
  stated trial count, reported as `successes/trials @ t (95% CI low–high)`. A 2/50 is a legitimate finding
  reported as 2/50 — never as "reproducible".
- **Screenshot-only evidence.** A chat screenshot is not a reproduction. Triage needs the exact request, model
  and version string, sampling parameters, canary value, and the ledger (§6.3).
- **Claiming exfiltration the model actually hallucinated.** Asked for other users' data, a model will
  cheerfully produce realistic names, emails, and record IDs that were never in any store — a genuinely common
  false report. Rule it out the same way every time: the claim holds only if the returned value is a
  **pre-registered canary planted in tenant A**, never typed into tenant B's session, and it survives a
  clean-context re-run. If the "leaked" data is not verifiable against a known record, you have a PB-19
  hallucination report at best.
- **Leaving live payloads in shared systems, or proving denial of wallet by causing it.** Directive text in a
  production corpus, mailbox, or shared memory fires in real users' sessions; an actually exhausted quota is the
  outage you were supposed to be warning about. Both are §7 ROE violations regardless of the finding.
- **Cross-tenant claims demonstrated against a real customer.** Two tenants you control, or it does not get
  tested (§7.3). Discovering genuine third-party data is a stop condition, not a milestone.

## Validation discipline (the GreyNOC bar)

The PB-15 Phase 5 bar (≥2 clean-context successes, full ledger, self-scoped tenancy) applies unchanged. What is
specific here: every retrieval, leakage, persistence, and egress claim resolves to a registered
`GNBB-CANARY-<uuid4>` appearing where it should not — model narration is not evidence — and every canary,
document, and memory entry you planted is removed, with the removal and the measured request cost stated.

## Report template

Use the **PB-15 AI report template** as-is. It already carries `DEFECT-CLASS:` with its `CHAIN:`
field, `TRIAL LEDGER:`, `CANARY:`, and the routing decision as the `channel:` element of
`PROGRAM/SCOPE:` — do not redeclare any of them here, and do not rename `TRIAL LEDGER:` to
`TRIAL-LEDGER:`, because a report carrying both spellings has two ledger fields and a triager cannot
tell which is authoritative.

Add only these two application-layer lines, which the canonical template does not have:

```
BOUNDARY:       who authored the input | whose identity the backend used | who read the output
CLEANUP:        canaries / documents / memory entries removed: Y/N — details
```

Fill `DEFECT-CLASS:` from this catalog's range, `L1`–`L19`, primary class first. For a deterministic
class (`L15`, `L16`, `L17`) write `TRIAL LEDGER: deterministic — n/n` rather than leaving it blank:
the field is there to show the reader you established reproducibility, and "not applicable" reads as
an omission.

## Stop conditions

Stop on real third-party data, effects outside either self-controlled tenant, uncontrolled memory
or RAG propagation, live credentials, shared-service degradation, or any proof that would require
harmful content or an irreversible action. Preserve the minimum evidence and follow
[CONVENTIONS §6–§7](CONVENTIONS.md).

## Summary

Nearly everything reportable at this layer reduces to a familiar class — broken access control, injection into
a downstream interpreter, unsafe output rendering, secret sprawl — reached through a new front door, and should
be scored as the web bug it is rather than discounted or inflated because a model is involved. The catalog's
honest limit is that it stops at the application edge, and the stochastic layer means a real defect can still
present as 2/50 — which remains a finding when the consequence is real and the retry cost is near zero.
