# 18 — Bug Bounty: Agentic Systems, Tools & the MCP Boundary (Authorized)

> **Authorization required.** Authorized testing only, GreyNOC as submitting firm, scope on file.
> See [CONVENTIONS §6 Rules of Engagement and §7 AI-system testing addendum](CONVENTIONS.md). The
> hazard unique to this surface is that a successful test *takes a real action in the world* — you
> own every action your agent performs, including ones an injection induced, so proof stops at a
> no-op or a self-owned target. This playbook is a **defect-class catalog with validation
> guidance**, not exploit tooling.

## Overview

This catalog covers the agentic boundary: the tool layer, the connector and MCP surface, the agent
runtime, and the controls that sit between a model's intent and a privileged action. That boundary
is where a model's *output* becomes an *action*, and that transition is what converts an
interesting model behavior into a real security finding. Text a model produces is a curiosity; the
same text arriving as an authenticated tool call that sends, pays, deletes, deploys, or reads
another tenant's data is a defect with an owner and a severity. PB-15 is the methodology spine
(Phase 0 scope through Phase 6 report) and this is one of its four class catalogs, alongside PB-16
(the app around the model), PB-17 (what the model is built from), and PB-20 (the plane it runs on).
Work by class, form the falsifiable hypothesis at PB-15 Phase 4, validate self-scoped at Phase 5.

## Scope boundary — what belongs here vs. elsewhere

[PB-15's catalog map](15-bugbounty-ai-attack-surface-methodology.md) has the full split; this
catalog owns `G1–G12`. Routing rule: if it changes what the model *says* it is `L` (PB-16); if it
changes what the system *does* — a tool fires, a connector reaches something, a runtime executes —
it is `G`. Malicious content arriving inside an artifact or dependency is `S` (PB-17); a crossing
between tenants on shared serving infrastructure is `I` (PB-20). Model-behavior findings carry no
class and route to PB-19's channel.

## The agent-under-test contract

CONVENTIONS §7.9 binds every test here. Operationally:

- **Least-privileged tool set.** Grant only the tools the one hypothesis needs; if the class is
  "the runtime follows redirects to internal hosts," it does not need a mail tool. Every extra tool
  is an action you might have to own.
- **Prefer echo/no-op tools for proof.** Register a `gnbb_echo`-style tool whose whole behavior is
  returning its argument; a canary in its arguments proves the model's output became an
  authenticated invocation with nothing happening on the other side.
- **A dedicated test agent, never your working one.** Separate account and tenant, isolated
  workspace, memory cleared before each trial, no credential in its environment that is not
  disposable and scoped to your own test tenancy.
- **Egress to your own listener only**, and only where the program permits callbacks — a host you
  control inside your own scope, correlated by canary, never a third-party interaction service
  unless the program names one. Never chain into out-of-scope systems: an agent that *could* reach
  an adjacent connector is not authorization to reach it. Record reachability and stop.
- **Full transcript logging**, plus a budget cap and kill switch set before the first run (§7.5):
  every prompt, tool call with arguments, result, timestamp, model and version string, and sampling
  parameters. On this surface the transcript *is* the evidence artifact.

**Reference convention.** `PB-NN` and `D&R-NN` per [CONVENTIONS §5](CONVENTIONS.md); the standing
defensive twin cited below is [D&R-09 AI / Automated Agent Abuse](09-ai-automated-agent-abuse.md).

## MITRE mapping

| Technique | ID | Relevance |
| --- | --- | --- |
| LLM Prompt Injection: Indirect | AML.T0051.001 | Instructions in tool metadata, tool results, fetched content, agent memory (G1, G8, G9) |
| LLM Prompt Injection: Direct | AML.T0051.000 | Operator-supplied steering of the agent under test (G1, G6) |
| LLM Prompt Injection | AML.T0051 | Injected instructions propagating between agents and delegation hops (G10) |
| LLM Prompt Self-Replication | AML.T0061 | Prompt content built to reproduce itself across agents and hops (G10) |
| AI Agent Tool Invocation | AML.T0053 | The agent invoking a tool the requester was not entitled to have invoked (G1, G3, G5) |
| AI Agent Tool Poisoning | AML.T0110 | Poisoned tool name, description, schema, or result steering the agent (G1) |
| Poisoned AI Agent Tool | AML.T0011.002 | A poisoned tool obtained and installed as an artifact (G1, G5) |
| Publish Poisoned AI Agent Tool | AML.T0104 | Publishing a poisoned tool or server for others to install (G1, G5) |
| AI Supply Chain Compromise: AI Agent Tool | AML.T0010.005 | The tool and connector supply chain as delivery path (G1, G5) |
| AI Agent Context Poisoning | AML.T0080 | Injected content retained in the agent runtime's own state (G9) |
| AI Agent Context Poisoning: Memory | AML.T0080.000 | Agent memory specifically as the retaining store (G9) |
| LLM Data Leakage | AML.T0057 | Secrets and other-context data surfacing in transcripts and tool traces (G9, G11) |
| Exfiltration via Cyber Means | AML.T0025 | Agent runtime as the egress path to an attacker-named endpoint (G8) |
| Cost Harvesting | AML.T0034 | Metered inference as the consumption target (G12) |
| Cost Harvesting: Agentic Resource Consumption | AML.T0034.002 | Agent loops and recursive spawning as the consumption path (G12); maturity *Feasible* |
| Denial of AI Service | AML.T0029 | Absent rate and loop limits as an availability gap — observed, never induced (G12) |
| External Harms | AML.T0048 | Irreversible real-world action executed with no human gate (G6) |
| Exploit Public-Facing Application | T1190 | Remote tool/MCP endpoint reachable without authentication (G2) |
| Exploitation for Privilege Escalation | T1068 | Confused-deputy delegation across an entitlement boundary (G3) |
| Steal Application Access Token | T1528 | Connector access and refresh tokens reachable from model context (G4, G11) |
| Command and Scripting Interpreter | T1059 | Shell, code, and interpreter tools in the agent runtime (G7) |
| Unsecured Credentials: Cloud Instance Metadata API | T1552.005 | Fetch tool reaching the instance metadata endpoint (G8) |
| Unsecured Credentials: Credentials In Files | T1552.001 | Config, `.env`, and mounted secrets readable by a tool (G11) |
| Data from Information Repositories | T1213 | Connectors reading repositories the caller is not entitled to (G3, G4) |
| Confused deputy (delegation) | — | Named pattern behind G3; no single technique ID is cited for it |
| Tool namespace shadowing | — | Named pattern behind G5 |

*Cited against ATLAS collection 2026.06 per [CONVENTIONS §4](CONVENTIONS.md); ATLAS IDs and names
are both versioned — re-map to your platform's collection at deployment. Techniques without a cited
ID appear by name only. Where an ID is cited to support severity or plausibility, quote that
technique's `maturity` value from your collection rather than implying in-the-wild use (§4).*

## Defect-class catalog

### G1 — Tool metadata as an injection channel
- **What:** Tool names, descriptions, parameter schemas, and returned tool output are model-visible
  text on the same channel as the user's instructions, so anyone who can influence any of them
  steers the agent — description poisoning at registration, instructions smuggled into a result.
- **Recognize:** descriptions rendered verbatim into context; server-supplied schemas accepted
  unreviewed; results interpolated with no provenance framing; descriptions that change after
  install with no re-approval; another user's free text echoed into a tool's output.
- **Confirm (least-impact):** put `GNBB-CANARY-<uuid4>` in the influenceable field — a record you
  own, a self-hosted page, your own test server's description — with a benign directive to call your
  registered no-op tool; the canary in that tool's *arguments* is the finding. Never aim the induced
  call at a tool with a real side effect, and never plant instruction text other users will read.
- **Maps to:** AML.T0110 *AI Agent Tool Poisoning*; AML.T0011.002 *Poisoned AI Agent Tool* when it
  arrives as an installed artifact and AML.T0104 *Publish Poisoned AI Agent Tool* when one is
  published for others; PB-06, D&R-09; PB-16 `L2` for the retrieval-side entry; G6/G8 for the
  action half.
- **Severity:** medium alone, high to critical once the induced call crosses a boundary. **Commonly
  mis-reported:** an injection that only changes the model's prose is PB-19, not `G1`.

### G2 — Exposed or weakly authenticated tool/MCP endpoints
- **What:** The tool transport is reachable by someone who should not reach it — a local transport
  bound beyond loopback, a remote server with no auth or a bearer token in a client-readable
  location, a discovery/registration endpoint that accepts unauthenticated servers.
- **Recognize:** an in-scope host answering on a tool/MCP port on a routable interface; a documented
  server URL returning a capability listing with no credential; static tokens in client config; a
  local server that does not validate the `Origin` header on every incoming connection, or that
  binds beyond loopback — the two controls the MCP specification names against DNS rebinding. MCP
  standardizes **stdio** and **Streamable HTTP**; a websocket origin policy is usually absent by
  design, so its absence is not the finding.
- **Confirm (least-impact):** on in-scope infrastructure only, complete **one** unauthenticated
  capability listing and record the response — that listing is the finding. A spec-compliant server
  rejects requests before `initialize`, so the minimum is **three messages** (`initialize` →
  `notifications/initialized` → `tools/list`); ledger it as three, because §7.5 makes request counts
  load-bearing on this surface. Do not invoke the tools you enumerate; do not touch an endpoint that
  is not named in scope.
- **Maps to:** D&R-09; G5 and G3 for what follows; PB-20 `I1` when the endpoint is serving-plane.
- **Severity:** high when unauthenticated access exposes tools with real capability — but that score
  is **argued from the enumerated capability and the runtime's documented semantics, and must be
  labelled in the report as argued-from-documentation rather than demonstrated**, because ROE
  forbids invoking those tools. If the program disputes the inference, the demonstrated finding is
  the unauthenticated read and enumeration. Informational when the endpoint is loopback-only, holds
  no privileged tools, and is a documented local component.

### G3 — Confused-deputy delegation
- **What:** The agent holds broader privilege than the requesting user and does not re-check the
  caller's entitlement before acting, so downstream systems see the agent's service identity rather
  than the requester's. The classic AI privilege-escalation shape and the highest-value class here.
- **Recognize:** one service principal or shared connector behind all users; downstream logs
  attributing every action to the agent; a low-privileged user's request returning data their own UI
  does not show; no per-request entitlement check documented in the tool layer.
- **Confirm (least-impact):** two accounts you own in one tenant, one high-privileged and one low.
  Place a canary in a resource only the high account can read, then ask the agent as the low
  account; the canary surfacing to the low account proves the re-check is missing. Never demonstrate
  this between your account and a real customer's (§7.3).
- **Maps to:** D&R-09, PB-06; PB-16 `L11` for authorization defects that stop short of the tools.
- **Severity:** high to critical — a direct authorization bypass, scaled by the privilege delta and
  the sensitivity of what the agent can reach.

### G4 — Connector authorization and token handling
- **What:** The connector layer grants more than the feature needs, leaks what it was granted, or
  accepts what it was never issued: over-broad OAuth scopes, refresh tokens reachable from model
  context, consent that binds a connector to the wrong principal (installer instead of caller,
  tenant-wide instead of per-user), and token passthrough in **both** directions — outbound, a
  server forwarding the agent's token verbatim downstream; **inbound, an MCP server accepting a
  token that was not issued for it**, which is the form the specification prohibits outright,
  because it defeats audience validation and is the confused-deputy enabler.
- **Recognize:** write or admin scopes for a read-only feature; one admin's consent serving a whole
  workspace; tokens visible in tool arguments, error strings, or debug panes; downstream calls
  carrying the agent's token rather than one minted for the callee and audience-restricted to it; no
  protected-resource metadata published and no resource indicator on the token request, so nothing
  binds a token's audience to the server that will accept it.
- **Confirm (least-impact):** record the scope set from your own consent flow and diff it against
  documented capability — the delta is a read-only finding. For the inbound form, present a token of
  your own whose audience is a *different* server you also own and observe whether the server
  accepts it; acceptance is the whole finding and needs no privileged call behind it. For binding
  defects, connect as one account you own and observe whether a second account you own inherits it.
  Do not exercise the excess scopes; the grant is the finding.
- **Maps to:** D&R-09, PB-06; G3 for the delegation half, G11 for runtime exposure.
- **Severity:** high; critical when the token reaches systems outside the AI product's blast radius,
  or when one user's consent silently authorizes the tenant. That escalation is argued from the
  enumerated scope set, so label it `argued-from-documentation` per G2 — ROE forbids exercising the
  scopes. The demonstrated finding is the read-only scope delta or the observed token acceptance.

### G5 — Cross-server shadowing and namespace collision
- **What:** Two registered servers offer the same tool name and the resolution rule decides which
  code runs — later registration overriding an earlier one, a low-trust server claiming a name a
  high-trust server owns, or a client that resolves a bare tool name to the wrong server.
- **Recognize:** no namespacing or origin qualifier on tool names in the transcript; no warning on
  duplicate registration; resolution order documented as "last wins" or not documented at all;
  installed-server lists with no trust tier.
- **Confirm (least-impact):** register two servers **you own** in your own agent exporting the same
  tool name, each returning a distinct canary, call by name, and record which canary returns — that
  is the resolution rule, empirically. Never register a shadowing name against a third party's
  server or in a shared workspace.
- **Maps to:** AML.T0010.005 *AI Agent Tool* for the tool supply chain and AML.T0104 *Publish
  Poisoned AI Agent Tool* when the shadowing server is published for others to install; D&R-09,
  PB-06; G1 for the description channel; G2 when unauthenticated registration is what allows the
  collision.
- **Severity:** high when shadowing changes which code executes for a call the user believed was
  trusted; medium when it produces only UI ambiguity with no execution change.

### G6 — Missing human-in-the-loop on irreversible actions
- **What:** Send, pay, delete, publish, deploy, or grant executes with no confirmation — or with a
  confirmation the model itself can satisfy. A gate that is another tool call, a structured field
  the model fills, or a yes/no the agent answers for the user is not a gate.
- **Recognize:** irreversible tools in the same permission tier as read tools; blanket "always
  allow" settings; confirmation text that is model-generated and therefore attacker-influenceable;
  autonomous or batch modes that suppress prompts; an executed action with no interleaved user turn.
- **Confirm (least-impact):** the target must be a benign no-op or something you own end to end — a
  self-addressed message, a scratch record in your own tenant, a draft created for this trial. The
  evidence is the transcript: induced instruction, no user turn, completed call. **Never** prove
  this with a real irreversible action: no payment, no deletion of anything you did not create for
  the test, no publication to a real audience, no grant to a real principal. If the only available
  proof would cause a real effect, report the control gap on the configuration evidence you hold.
- **Maps to:** D&R-09, PB-06; PB-16 `L2` when the inducing content entered through the app.
- **Severity:** the severity of the action, not of the injection — self-addressed mail is medium;
  money movement, destructive operations, and permission grants are critical. Lower it honestly when
  a genuine out-of-band confirmation exists that the model cannot satisfy.

### G7 — Execution surface in the agent runtime
- **What:** Shell, code-interpreter, and build tools plus the isolation around them: argument
  injection into a tool that shells out, sandbox escape paths, writable host mounts, container
  privilege, and a runtime identity holding more rights than the sandbox implies.
- **Recognize:** tools accepting free-form commands or paths; parameters interpolated into a shell
  string; documented mounts or shared volumes; a runtime that can see a cloud role, a socket, or a
  registry credential; errors disclosing absolute host paths.
- **Confirm (least-impact):** stop at the least-impact proof — a benign marker file named for your
  canary in a scratch directory, or the canary echoed back through the injected argument — and
  record the canary, the path, and the identity the runtime ran as. Never write a real payload,
  install anything, persist across sessions, or pursue escape past the single observation that
  shows the boundary is not where the product claims. If you wrote a marker file, **remove it before
  the session ends and state the removal in the report** (§6.2); if the sandbox is not ephemeral and
  you cannot remove it, do not write the file at all — the echoed-argument proof is sufficient on
  its own.
- **Maps to:** PB-16 for the injection entry, D&R-09 for detection; G11 for what the runtime can
  read; PB-17 `S7` when the runtime can reach an artifact registry.
- **Severity:** critical for demonstrated escape or host access; high for arbitrary execution inside
  a sandbox holding usable credentials. **Commonly mis-reported:** a documented interpreter feature
  running code in its own sandbox with nothing crossing out is the product working.

### G8 — Egress and SSRF from the agent runtime
- **What:** Fetch, browse, and webhook tools that reach whatever host they are handed — internal
  services, the cloud instance metadata endpoint, non-scoped hosts. Redirect-following and
  DNS-rebinding behavior turn an allowlist into a suggestion when the destination is checked once
  and not re-resolved and pinned at connect time.
- **Recognize:** a fetch tool with no destination allowlist; documented outbound access; redirects
  followed without re-validating the target; hostname-based allowlists; fetched content rendered
  back into context, which makes this an injection channel as well.
- **Confirm (least-impact):** point the tool at a listener you control in your own scope
  (`192.0.2.10`, or `2001:db8::10`) with `GNBB-CANARY-<uuid4>` in the path and record the hit; for
  internal reachability, one request to one in-scope internal address plus its status or timing
  differential is the whole proof. If a metadata endpoint responds, **stop** — record that it
  responded, do not retrieve credentials, escalate under §6. No range scanning.
- **Maps to:** D&R-09, PB-06; G11 when the egress carries secrets; G1 when fetched content steers.
- **Severity:** high when an internal service or credential-bearing endpoint is reached; medium for
  blind outbound egress with no reachable internal target demonstrated; informational when the tool
  only reaches public hosts and that is documented behavior.

### G9 — Agent state and memory persistence across boundaries
- **What:** The agent runtime's own state — task memory, scratchpads, plan and todo files, vector
  memory, cached tool results — retains injected instructions and replays them into later runs. The
  defect is not that memory exists; it is that it crosses a boundary it should not: a later run
  after a clean reset, another user, another workspace or tenant.
- **Recognize:** persistent plan or memory files in the runtime; a "remember this" path with no
  provenance on what wrote the entry; vector memory keyed by workspace rather than user; new
  sessions recalling content the UI claims was cleared.
- **Confirm (least-impact):** write a canary into agent state through the normal path, end the
  session, start a clean one, observe replay; cross-user claims use two accounts you own (§7.3).
  **Plant only inert canary text, with no directive that could act if another principal reads it** —
  the hypothesis under test is that this entry crosses a boundary, so write it as if it will. Record
  the exact write path and content; remove the entry through the product's own deletion path at the
  end of the trial; verify removal from a clean session; and list in the report what was planted and
  whether removal succeeded (§6.2). If the product offers no deletion path, that is itself part of
  the finding — and you plant nothing further until the program says otherwise. **Boundary vs
  PB-16:** app-level *user* memory in the product UI is `L8`; `G9` is the agent runtime's own state
  — plan files, scratchpads, task memory, tool-layer caches. Cite the one you actually demonstrated.
- **Maps to:** AML.T0080 *AI Agent Context Poisoning*, sub-technique AML.T0080.000 *Memory*; PB-16
  `L8` (app-layer twin), D&R-09, PB-06; G10 when state is shared between agents.
- **Severity:** medium when confined to one user's own runtime; high when injected state survives
  across users, tenants, or workspaces, or silently re-arms after a documented reset.

### G10 — Multi-agent and delegation trust
- **What:** Trust assumptions between agents — sub-agent spawning that inherits or widens the
  parent's privilege, agent-to-agent messages accepted without authentication, injected instructions
  propagating from one agent's output into another's input, prompt content built to reproduce itself.
- **Recognize:** orchestrator/worker topologies where worker output returns as trusted instructions;
  a spawn tool with no privilege ceiling; a shared queue or bus any participant can write to; no
  origin authentication on inter-agent messages; sub-agents inheriting connectors wholesale.
- **Confirm (least-impact):** two agents you own. Place a canary and a benign no-op directive in the
  first agent's output surface and observe whether the second both ingests it and **acts** on it —
  the action is the finding, ingestion alone is not; cap hop count and trial budget first.
  Propagation maps to *LLM Prompt Injection* (`AML.T0051`) and self-replicating content to *LLM
  Prompt Self-Replication* (`AML.T0061`), both verified against the 2026.06 collection per §4. Never
  release self-replicating content where it could reach an agent you do not own.
- **Maps to:** D&R-09, PB-06; G3 for the privilege half; G12 when propagation drives unbounded spawn.
- **Severity:** high when an unauthenticated inter-agent message causes a privileged action; medium
  when instructions propagate but no boundary-crossing action results.

### G11 — Secrets in the agent runtime
- **What:** Credentials the model, or a tool the model controls, can read: environment variables,
  mounted config and `.env` files, connector tokens in the tool trace, secrets interpolated into
  debug output, errors echoing an authorization header — and secrets leaving via the transcript,
  the log pipeline, or a support bundle.
- **Recognize:** an execution tool with environment access; verbose handlers returning upstream
  responses verbatim; tool traces or debug panes displaying request headers; log fields carrying
  `Authorization`; runtimes with cloud roles attached and no scoping.
- **Confirm (least-impact):** demonstrate *reachability*, not the secret — that the runtime can
  enumerate the variable name or file path, or that a redacted prefix appears in output you can see.
  Capture a hash or truncated fragment (§7.7), never the full value; never use a recovered
  credential; if a live production or third-party secret surfaces, stop, preserve, escalate.
- **Maps to:** D&R-09, PB-06; G7 for how the model reaches the filesystem; G4 for connector tokens.
- **Severity:** by what the secret unlocks — high to critical for a live credential to a real system,
  argued from its identified type and documented scope, so label it `argued-from-documentation` per
  G2 — ROE forbids using the credential, and the demonstrated finding is the read reachability
  itself. Low when it is a public
  client identifier or a scoped test token that was already yours; say which, honestly, rather than
  filing every string that looks like a key.

### G12 — Autonomy, budget, and blast-radius controls
- **What:** The controls bounding how much an agent does before a human sees it — loop and step
  limits, recursion depth on sub-agent spawning, per-task cost caps, rate limits on tool invocation,
  a ceiling on records touched per task. The defect is their absence.
- **Recognize:** autonomous or background modes with no stated step ceiling; a spawn tool callable
  by the agent it spawns; no invocation counters in the transcript; no per-task budget in the
  product's own settings; retry logic with no backoff or attempt cap.
- **Confirm (least-impact):** **demonstrate the missing control, never the exhaustion.** Fix `N` in
  advance, write `N` in the trial ledger *before* the run, and stop at `N` — there is no mid-run
  judgement about when unboundedness has become "plain". The absence of a declared step ceiling is
  shown by the product's own settings and documentation **plus** a bounded `N`-iteration run the
  agent shows no sign of terminating; spawn depth is shown by two nesting levels with no ceiling
  enforced. Record exact counts, elapsed time, and cost against the §7.5 budget. **Never actually
  exhaust a quota, rate limit, context window, GPU pool, or billing balance**: absence of the limit
  is provable without reaching it, and reaching it is denial-of-wallet against a shared system. Halt
  on any sign of impact on a tenant that is not yours.
- **Maps to:** AML.T0034.002 *Agentic Resource Consumption* (maturity *Feasible* — quote that when
  it carries severity); D&R-09, PB-06; PB-16 `L12` and PB-20 `I7`, the denial-of-wallet trio PB-15
  groups with this class — `L12` for app-request-level spend, `I7` when consumption lands on shared
  serving hardware.
- **Severity:** usually medium, anchored to demonstrated cost or availability consequence;
  informational when neither is demonstrated. **Commonly mis-reported:** theoretical
  denial-of-wallet with no measured cost and no shown loop, or a DoS you did not and must not cause.

## Chains that carry impact

These are attacker impact paths, not test procedures: the self-scoped equivalent of each hop is in
its class entry, and where a chain names another party's identifier or a registration on a target
there is no authorized way to reproduce it end to end.

- `L8 → G6` — a poisoned app-level user memory entry survives into the next agent run and an
  irreversible action fires with no interleaved user turn. Insert `G9` in the middle only where the
  replay is carried by the agent runtime's own state rather than app memory, and `G1` only where the
  instruction re-enters through a tool description or a tool result.
- `G2 → G5 → G3` — an unauthenticated registration endpoint accepts an attacker-defined server that
  shadows a trusted tool name, and calls the user believed were trusted run at the agent's privilege.
- `G1 → G8 → G11` — instruction text in a tool result steers the fetch tool at an internal
  credential-bearing endpoint, and the response lands in a transcript and log pipeline.
- `G7 → G11 → S7 (PB-17)` — argument injection into an execution tool exposes a registry or CI
  token in the runtime environment, opening a push path into the model-artifact supply chain PB-17
  catalogs; stop at reachability and escalate rather than exercising the token.
- `G10 → G12 → I7 (PB-20)` — an unauthenticated inter-agent message triggers recursive spawning
  with no depth ceiling, and the consumption becomes a cost and availability problem on the shared
  serving plane.

## Hunting workflow

1. **Pick the class and write the falsifiable hypothesis** (PB-15 Phase 4). "The tool layer
   re-checks the caller's entitlement before reading" falsifies cleanly; "the agent seems too
   powerful" does not.
2. **Fingerprint the tool surface read-only** (Phase 2) — tools, transports, auth modes, connector
   scopes, execution and fetch capability, autonomy settings, and which actions are irreversible.
   This inventory is the agentic-layer entry in the AI-BOM.
3. **Stand up the harness** (Phase 3) under the agent-under-test contract: dedicated test agent,
   least-privileged tool set, no-op tool registered, second account or tenant where the class needs
   one, canary registry populated, trial ledger open, cost cap set.
4. **Validate self-scoped at the minimum request count** (Phase 5), clean context each trial. The
   pass condition is constant: a canary on the far side of a boundary, or an action in a transcript
   with no authorizing human turn.
5. **Record the falsifier either way** — the entitlement check fired, the allowlist held, the
   confirmation could not be model-satisfied. A clean negative is a real outcome.
6. **One finding per defect** at the GreyNOC bar, primary class cited, chain in sequence, transcript
   attached and redacted. Route model-behavior observations to PB-19's channel, not into the report.

## Anti-patterns (do not do these)

- **Testing an MCP server you found on the internet that is not in program scope.** Discoverable is
  not in scope. An open tool endpoint located through OSINT belongs in a scope-expansion request or
  a coordinated-disclosure note to its owner, never in a test session — a §6.1 violation ends
  program standing faster than any technical mistake.
- **Running an agent with production credentials during testing.** The test agent gets disposable,
  scoped credentials in your own tenancy and nothing else; production credentials mean an injection
  you induced can reach systems you were never authorized to touch, and §7.9 makes that your action.
- **Chasing an induced action into a real side effect "to make the impact clear"** — real mail, real
  money, real deletions, real publication convert a finding into an incident you caused.
- **Filing one injection five times** because it reached five tools. That is one defect in the
  tool-trust boundary, with the reachable tool set listed as impact.

## Validation discipline (the GreyNOC bar)

PB-15 Phase 5 and [CONVENTIONS §7.3, §7.5, §7.6, §8.3](CONVENTIONS.md) carry the bar in full: the
≥2-success ledger, canary proof rather than narration, self-scoped tenancy, request budget, full
transcript. The one requirement specific to this surface is **per-trial state reset** — fresh
session, cleared agent memory, re-registered tool set, before *every* trial. Stale agent state is
the most common false positive here, and a success carried by a previous trial's memory is not a
finding.

## Report template

Use the PB-15 AI report template, then add these lines:

```
DEFECT-CLASS:      G1–G12 primary; chain in sequence (e.g. G1 → G8 → G11)
AGENT-UNDER-TEST:  harness/product + version · model + version string · tool set granted
TOOL-SURFACE:      transport + auth (local stdio | loopback HTTP | remote HTTPS + bearer) · tools invoked
ACTION-CROSSED:    what the output actually became (call | read | write | send | spend | exec | egress)
HITL-STATE:        confirmation required Y/N · model-satisfiable Y/N · target no-op/self-owned Y/N
EVIDENCE-BASIS:    demonstrated | argued-from-documentation (state which, per class)
CLEANUP:           marker files / memory entries / registered tools planted → removed: Y/N · path +
                   deletion method · removal verified from a clean session: Y/N
```

## Stop conditions

Stop on any non-test external action, real credential, third-party data, effect in another user's
session/cost, uncontrolled delegation, or tool path that cannot be bounded to an inert no-op.
Disable the test agent if safe, preserve the transcript, and follow
[CONVENTIONS §6–§7](CONVENTIONS.md).

## Summary

Work the catalog by class, keep the agent under test least-privileged and fully logged, and hold the
line that the finding is the action that crossed a boundary, not the injection that suggested it.
The submissions that earn standing are the ones whose transcript shows a canary, a completed call,
and nothing else that had to happen. The honest limit of this catalog is that it stops at
reachability: G7, G8, and G11 are proven by showing a boundary is not where the product claims it
is, and a disciplined report says exactly that rather than walking the last step to a real
consequence.
