# 23 — AI Data Governance, Privacy, Retention & DLP

## Overview

AI systems copy and transform data across prompts, retrieval stores, embeddings, memory,
fine-tuning sets, evaluation corpora, safety/abuse review, provider telemetry, caches, and outputs.
This playbook governs those flows end to end. It complements the security defect catalogs without
turning privacy, intellectual-property, or records issues into vulnerability claims.

## Data-flow inventory

For every AI asset, map:

- Data source, subject/owner, classification, purpose, lawful or contractual basis, permitted
  users, geography, and retention/deletion obligation.
- Transformation into prompt, chunk, embedding, feature, label, adapter, model update, completion,
  transcript, feedback, evaluation example, cache, and log.
- Provider/subprocessor receipt, training or service-improvement reuse, human review, region,
  encryption, isolation, return/deletion, and evidence.
- Downstream actions, exports, integrations, analytics, and records systems.

An embedding is not anonymous by default. A prompt hash can still be identifying. Classify derived
artifacts by recoverability, linkability, sensitivity, and access—not by file format.

## Control requirements

1. **Purpose limitation:** use data only for the registered purpose and approved model operations.
2. **Minimization:** remove fields and content not required before model/provider submission.
3. **Deterministic authorization:** retrieval, memory, transcript, evaluation, and export access
   are enforced outside the model.
4. **Provider controls:** training/reuse, retention, human review, subprocessors, and region match
   the approved configuration and contract.
5. **Lifecycle:** retention and deletion cover primary, derived, cached, indexed, backed-up, and
   provider-held copies with documented exceptions.
6. **Transparency and rights:** applicable notices, access, correction, deletion, appeal, and
   human-review processes are mapped to system capabilities and owners.
7. **Records/legal hold:** holds are authorized, scoped, access-controlled, and reconciled with
   deletion schedules; they do not silently become permanent AI training corpora.

## DLP and egress controls

Apply classification-aware controls before provider/model submission and before output/export:

- Secret, credential, regulated identifier, customer/employee data, source code, legal privilege,
  export-controlled data, and contract-restricted content detection.
- Approved-provider, model, region, account, tenant, and feature allowlists.
- Blocking or step-up approval for prohibited data classes and connector destinations.
- Tokenization/redaction with controlled rehydration outside model context.
- Output authorization and minimum necessary disclosure; never rely on “do not reveal” prompting.

Tune for context: a detector finding a credential pattern in a security ticket should prevent the
live value from reaching a model without suppressing the incident itself.

## RAG, memory, and evaluation governance

- Bind every indexed object and chunk to source, owner, tenant, classification, authorization,
  provenance, retention, and deletion state.
- Apply authorization before retrieval and again before response; filtering only after retrieval
  can leak through context, logs, cache, or timing.
- Define user/workspace/org memory scopes, provenance, expiry, visibility, edit/delete, and
  administrative access. Disable persistent memory where no approved purpose exists.
- Build evaluation datasets from authorized, minimized, versioned sources. Restrict access and
  prevent evaluation prompts/completions from being silently reused for training.
- Propagate source deletion to chunks, embeddings, indexes, caches, evaluations, feedback queues,
  and provider copies where required; record residual backups and expiry.

## Privacy impact review

Perform a DPIA or equivalent review when required by jurisdiction, policy, contract, risk tier, or
use case. At minimum assess affected people, reasonable expectations, data sensitivity, decision
significance, monitoring, inference of new attributes, vulnerable populations, human oversight,
rights handling, security controls, provider roles, international transfers, and residual risk.

Security review does not replace privacy review, and privacy approval does not prove security.

## Detection logic

```json
{
  "rule": "ai_data_policy_violation",
  "trigger_any": [
    "input.data_class NOT IN ai_asset.approved_input_classes",
    "provider_or_region NOT IN ai_asset.approved_destinations",
    "provider.training_reuse != ai_asset.approved_training_reuse",
    "retrieved_object.tenant != principal.tenant",
    "memory.retention > approved_retention",
    "deleted_source still_present_in index_or_cache_after_sla"
  ],
  "action": "block_or_quarantine + alert + record_policy_version"
}
```

## Investigation

1. Identify the exact data and all transformations/copies; do not stop at the visible prompt.
2. Confirm purpose, authority, data class, principal, tenant, provider account/region, and policy.
3. Trace prompt, retrieval, memory, cache, transcript, feedback, evaluation, training, backup, and
   output paths using stable IDs and hashes.
4. Determine whether the data reached a provider, human reviewer, other tenant, downstream system,
   or model update.
5. Minimize evidence; invoke D&R-19 for compromise, unauthorized access, or reportable exposure.
6. Execute deletion, correction, containment, notification, and provider coordination through the
   appropriate privacy/security owners.

## Metrics

- Data-flow inventory coverage and percentage of flows with owner, purpose, class, region,
  retention, reuse, and deletion propagation.
- Blocked sensitive submissions and false-positive rate by business process.
- Retrieval/memory authorization failures and cross-tenant canary results.
- Deletion SLA success across primary and derived artifacts.
- Provider configuration/contract drift and unapproved training/reuse events.
- Access to restricted transcripts/evaluation data and overdue access reviews.

## Escalation criteria

- Real third-party or cross-tenant data returned, indexed, retained, or used for training outside
  authorization.
- Provider reuse, human review, region, or retention contradicts approved terms.
- Deletion cannot propagate to a material derived artifact within the approved SLA.
- AI use of data with no owner, purpose, authority, or approved classification.
- Legal/records conflict or affected-person rights cannot be executed.

## Data governance record

```text
AI asset / data flow: AI-____ / ____
Source / owner:       ____ / ____
Subjects/classes:     ____ / ____
Purpose / authority:  ____ / ____
Transformations:      prompt | chunk | embedding | memory | output | eval | training | log
Provider/region/reuse: ____ / ____ / ____
Retention/deletion:   ____ / ____   propagation SLA: ____
Access/tenant policy: ____
DLP controls/results: ____
Privacy review:       required Y/N   ref: ____
Incident/referral:    none | privacy | D&R-19
Disposition:          approve | minimize | block | delete | escalate
```

## Summary

AI data governance follows data through every derivative—not just the prompt box. Register purpose
and authority, minimize before submission, enforce access outside the model, control provider use,
propagate deletion, govern RAG/memory/evaluation data, and connect privacy events to D&R-19 when
they become security incidents.
