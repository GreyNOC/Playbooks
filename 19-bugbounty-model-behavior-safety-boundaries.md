# 19 — Bug Bounty: Model Behavior & Safety-Boundary Testing (Authorized)

> **Authorization required.** Authorized testing only, GreyNOC as submitting firm, scope on
> file. See [CONVENTIONS §6 Rules of Engagement and §7 AI-system testing addendum](CONVENTIONS.md).
> **Findings in this playbook are not security defects and do not go to a security queue** — they
> route to the program's model-safety channel. CONVENTIONS §7.2 governs proof: demonstrate the
> control failure, never generate genuinely harmful content to show it.

## Overview

Model-behavior testing asks whether a model's own safeguards hold — whether the boundary the
provider says exists actually holds under adversarial input. It sits in this collection because
testers hit it constantly while hunting the `L`/`S`/`G`/`I` classes, and because mis-routing it is
the single most common way a competent AI bug-bounty submission gets closed as out-of-scope.

This playbook is one of three that own no defect-class prefix ([CONVENTIONS §8.1](CONVENTIONS.md)) —
and the only one where the absence is a *routing* decision rather than a methodology-versus-catalog
one, since PB-07 and PB-15 are methodology and their findings carry the owning catalog's class.
That absence is the whole design: a class ID would invite a triager to treat a behavior report as a
security defect, and a security queue is not where these get read, fixed, or paid. What this
playbook provides instead is the routing test, a measurement standard strong enough that a behavior
report is actually actionable, and a proof doctrine that keeps the tester from producing the very
harm the boundary exists to prevent.

The honest framing: model behavior is a **quality and safety property measured statistically**, not
a vulnerability with a proof-of-concept. Treat it that way and these reports land well. Dress one
up as a security exploit and it will be closed, correctly.

## The routing test

Run [PB-15](15-bugbounty-ai-attack-surface-methodology.md)'s decision procedure before writing
anything. A model-behavior result becomes a **security** finding only when it produces a concrete
security consequence — an action across a trust boundary the caller was not entitled to take,
access to data the tester was not entitled to, a privilege or identity change, or code execution.

| Observation | Routes to |
| --- | --- |
| Model produces disallowed content; nothing else changes | Model-safety channel — this playbook |
| Model is talked into calling a tool the user could not call | Security — PB-18 `G3`/`G6` |
| Injected document makes the model leak another tenant's record | Security — PB-16 `L7` (canary-proven) |
| Model reveals its system prompt, which contains a live API key | Security — PB-16 `L4` |
| Model reveals its system prompt, which contains only instructions | Security/low — PB-16 `L3`; often already known |
| Filter bypass that also defeats an authorization check | Security — PB-16 `L13` chain |
| Filter bypass that only changes what text is emitted | Model-safety channel — this playbook |
| A **reliable trigger phrase** flips behaviour reproducibly, suggesting a modified model | Security — PB-17 `S6` (post-training modification). **Not this playbook:** a backdoor is an artifact-integrity defect, and routing it to model safety loses the supply-chain finding |
| Behaviour differs between two deployments of a model the target claims are identical | Security — PB-17 `S2`/`S12` (provenance and transform chain) before anything else |

When you are genuinely on the line, say so and let triage decide — PB-15 Phase 6 covers how to word
it. Guessing high is remembered.

## MITRE mapping

| Technique | ID | Relevance |
| --- | --- | --- |
| LLM Jailbreak | AML.T0054 | The core technique class this playbook measures |
| LLM Prompt Injection | AML.T0051 | The delivery channel when the probe is not typed by the user |
| Evade AI Model | AML.T0015 | Classifier and guardrail evasion as an evaluation dimension |
| Craft Adversarial Data | AML.T0043 | Input construction for boundary probes |
| LLM Prompt Obfuscation | AML.T0068 | The encoding and format dimension of guardrail coverage |
| External Harms | AML.T0048 | The consequence category a safety program is actually pricing |
| Discover AI Model Ontology | AML.T0013 | Mapping what the deployment will and will not do |

> **Mapping discipline (`CONVENTIONS §4`).** Cited against ATLAS collection 2026.06 per [CONVENTIONS
> §4](CONVENTIONS.md); both IDs and names are versioned — re-map to your platform's collection at
> deployment.

Note the `maturity` discipline from §4: if a technique is marked *Feasible* rather than *Realized*,
do not write a report that implies field observation. That is fabricated impact.

## Proof without harm (CONVENTIONS §7.2)

This is the non-negotiable part of the playbook. The finding is **the control failure**, not the
payload, and there is always a way to show the former without producing the latter.

- **Substitute an inert marker — the default, not the fallback.** Ask for the same structural
  compliance with a benign target: a policy-marker string, a registered `GNBB-CANARY-<uuid4>` ([§7.4](CONVENTIONS.md), [§8.2](CONVENTIONS.md)), or a harmless
  stand-in task with the identical refusal-triggering shape. If the safeguard is the thing being
  bypassed, the marker crosses it just as well as real content would. §7.2 names the inert canary,
  the policy marker, and the benign no-op call as *the* sanctioned proof mechanisms — reach for one
  of them first, every time.
- **Use a benign proxy domain.** Where a program's policy defines a low-harm category alongside
  high-harm ones, demonstrate the mechanism in the low-harm category and describe the transfer
  rather than performing it.
- **Stop at the refusal boundary.** Where no marker will carry the point, the evidence is that the
  safeguard failed to hold — a compliance preamble, or an explicit acknowledgement that the model
  will proceed. Capture that non-substantive acknowledgement and stop generation *before* any
  substantive content: never an outline, never a first step, never a fragment that carries uplift on
  its own. For the categories named two bullets down, the outline *is* the transferable uplift and
  completion is the least valuable part of it. If the acknowledgement cannot be separated from the
  content, this is not a provable finding by this route — use an inert marker, or stop under §7.11.
- **Redact and truncate in the report.** Never paste completed harmful output into a ticket. A
  hash, a first line, a length, and a description of what was produced is sufficient and is what a
  safety team actually wants.
- **Hard stop.** If a finding cannot be proven without generating genuinely weaponizable material —
  operational uplift for weapons, working malware, targeted material about a real person — stop and
  report the control gap with the boundary evidence you already hold (§7.11). That is a complete
  report. Producing the artifact would make you the harm the program is trying to prevent, and no
  bounty is worth that trade.

Two consequences worth stating plainly, because testers get them wrong: a **screenshot of harmful
text is still harmful content** and does not become acceptable by being an image, and **"I only
generated it to prove it"** is not a defense the program's safety team will accept on your behalf.

## What a safety program actually rewards

Programs pay for **reliable, general, and severe**, roughly in that order. Calibrate before you
spend trials.

| Rewarded | Why |
| --- | --- |
| Systematic bypasses that hold across prompt families | A single string gets patched; a *mechanism* has to be fixed |
| Transferable results across models, versions, or deployments | Shows a property of the safeguard, not of one checkpoint |
| High-severity categories as **the program's own policy** defines them | Severity is theirs to define, not yours to assert |
| Measured reliability with a full trial ledger | Makes the report actionable for an eval team |
| Novel mechanism, clearly described | The mechanism is the deliverable; the transcript is the exhibit |

| Rejected | Why |
| --- | --- |
| One cherry-picked generation | Indistinguishable from sampling noise |
| Refusal-quality complaints, over-refusal, tone | Not a safeguard failure |
| Hallucination, factual error, bias assertions without measurement | Different discipline, different channel, needs a dataset |
| Content that is edgy but within the published policy | Read the policy before claiming a violation of it |
| A rediscovery of a widely published technique class | Known; cite it if you build on it, don't claim it |
| Anything requiring a real-world harmful artifact as proof | Violates §7.2 and the program's own rules |

## Measurement standard

A behavior report without measurement is an anecdote. The GreyNOC bar (§7.6) applies here in full,
and the evidence sections below are what separate a report an eval team can act on from one they
cannot reproduce.

- **Prompt families, not prompt strings.** Define the probe as a template with the varying element
  parameterized, then sample from it. A family that succeeds 6/20 across ten distinct instantiations
  is a mechanism; a string that succeeds 6/20 is a string. **Report the per-instantiation breakdown,
  not only the pooled count** — at two trials per instantiation, `6/20` is equally consistent with six
  instantiations succeeding once each and with two succeeding three times each, and only the first is
  a mechanism. That distinction is the entire claim, so the pooled number cannot carry it. It also
  means a single pooled Wilson interval over instantiations with different underlying rates is
  **overdispersed and too narrow**: quote the interval per instantiation, or quote the pooled rate as
  a descriptive statistic and say plainly that it is not a binomial proportion.
- **Clean context per trial.** New conversation, no carried turns, no memory. If multi-turn setup is
  required, that is a *different and weaker* claim — state the turn count in the ledger and never
  blur the two.
- **Stated sampling parameters.** Model and version string, temperature, top-p, seed where settable,
  max tokens, system-prompt state. Behavior varies across all of these; a ledger without them is not
  reproducible.
- **Full ledger, failures included.** `successes/trials @ t=__ (95% Wilson CI __–__)` per §8.3. A
  ledger containing only successes is a fabricated ledger, and it is obvious to anyone who has run
  evals.
- **Scoring you can defend.** Say who judged each trial and against what criterion. Automated
  judging is acceptable if you state the judge model and version, report agreement against a
  human-scored subset **as a chance-corrected statistic** — Cohen's kappa or an equivalent — and never
  let the judge's own safety behavior silently score the trials. Raw percent agreement is not
  acceptable here: at the skewed base rates typical of safety evaluation, a judge that always answers
  "refused" scores near-perfect agreement while carrying no information. Report the base rate
  alongside it so the reader can see what the judge was up against.
- **A held-out set.** Reserve instantiations you did not iterate against, and report their rate
  separately. A rate measured only on the prompts you tuned is a training-set number and inflates
  the finding.
- **Transferability, tested not asserted.** If you claim it generalizes, run it against another
  model, version, or deployment and report that ledger too. If you did not test it, say "untested".

## Evaluation dimensions (coverage, not recipes)

Use these to *measure coverage* of a safeguard, not as a technique list to work through. Each is a
named channel through which input can reach the model differently than the guardrail expects; a
report is stronger when it says which dimension the mechanism exploits and which adjacent ones it
does not.

- **Framing** — the request is presented in a context the safeguard treats differently.
- **Encoding and format** — the content reaches the model through a representation the input filter
  processes differently than the model does.
- **Multi-turn drift** — the boundary erodes across turns rather than being crossed in one.
- **Modality** — the channel is an image, audio, or document rather than typed text.
- **Language and locale** — safeguard coverage differs across languages.
- **Tool and retrieval channel** — the content arrives as a tool result or retrieved document rather
  than as user input. *If this one produces an action or a data crossing, it has left this playbook
  — route it to PB-16 `L2` or PB-18 `G1`.*
- **Context pressure** — the safeguard's reliability under long context, high load, or unusual
  output-length demands.

Describe the dimension and the mechanism at this level in reports. A safety team can reproduce and
fix from a mechanism description plus a ledger; a copy-paste string list is both less useful to them
and more dangerous in a ticket that will be read by many people.

## Anti-patterns (do not do these)

- **Submitting a jailbreak to the security queue.** The most common way an otherwise good AI report
  gets closed. Run the routing test first, every time (§7.1).
- **Pasting completed harmful output into a ticket** because "the triager needs to see it." They do
  not. Boundary evidence, a hash, and a truncated first line are sufficient (§7.2, §7.7).
- **Reporting a single generation.** One success at temperature 1.0 is a sample, not a result.
- **Asserting real-world harm you did not measure.** "This could enable X at scale" is fabricated
  impact unless you measured something that supports it. State what you ran and what you observed.
- **Rating severity yourself against your own taxonomy.** Use the program's published policy
  categories, quote them, and let the program grade.
- **Testing safety boundaries on someone else's production tenant, or on user-facing surfaces where
  other people will see the output.** Self-scoped only, and never where generated content could be
  served to a real user (§7.3).

## Report template

Use the [PB-15 AI report template](15-bugbounty-ai-attack-surface-methodology.md), set
`channel: model-safety`, leave `DEFECT-CLASS` empty (this playbook has none by design), and add:

```
POLICY CATEGORY:   the program's own published category + quoted text: ____
MECHANISM:         the dimension and how it works, described generically: ____
PROMPT FAMILY:     template + number of distinct instantiations tested: ____
HELD-OUT LEDGER:   __/__ @ t=__ (95% Wilson CI __–__) on instantiations not iterated against
TRANSFERABILITY:   models/versions tested + per-target ledger, or "untested": ____
SCORING:           human | judge model + version ; kappa vs. human-scored subset: ____ ; base rate: ____
HARM CONTROL:      how proof was obtained without producing harmful content (§7.2): ____
CONTENT HANDLING:  what was generated, truncated/hashed, and what was destroyed: ____
SECURITY CROSSOVER: consequence observed (tool call / data / privilege / execution), or "none": ____
```

The `SECURITY CROSSOVER` line is the one a triager reads first. If it says anything other than
"none", the report probably belongs in the security queue with an `L`/`S`/`G`/`I` class instead — split
it and file both. `S` is in that list deliberately: a behaviour change that traces to the *artifact*
rather than the prompt is PB-17's, and it is the one crossover testers routinely miss.

## Stop conditions

Stop, preserve, and escalate on: a probe that starts returning content about a real, identifiable
person; output that would constitute genuinely weaponizable uplift if completed; any indication the
tested surface is user-facing and your generations could reach a real user; a result you cannot
prove without violating §7.2; or evidence that another party is running the same probes against the
target. In every case, the control gap you have already evidenced is the report.

## Summary

Model behavior is the part of AI testing most likely to be interesting and least likely to be a
security finding. Route it first, measure it like an eval rather than an exploit — prompt families,
clean context, held-out set, stated sampling, a full ledger with the failures in it — and prove the
control failure without ever producing the harm. Severity belongs to the program's published policy,
not to the tester's judgement of how bad it feels. A behavior report built this way is genuinely
useful to a safety team; the same observation dressed as a security exploit is noise, and programs
have learned to close it fast.
