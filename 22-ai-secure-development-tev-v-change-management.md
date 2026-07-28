# 22 — AI Secure Development, TEVV & Change Management

## Overview

This playbook integrates AI threat modeling, secure development, test/evaluation/validation/
verification (TEVV), release gates, and change management. It applies to model-backed
applications, RAG, fine-tuning, agents, classifiers, and serving infrastructure. The objective is
not to prove that an AI system is universally safe; it is to define its intended operating
conditions, measure relevant failure modes, and prevent unreviewed changes from invalidating the
evidence that supported release.

## Secure lifecycle gates

| Gate | Required evidence |
| --- | --- |
| Concept | Registered AI asset, purpose, prohibited uses, preliminary tier and data classes |
| Design | Architecture/data-flow, trust boundaries, abuse cases, supplier assumptions, threat model |
| Build | Pinned dependencies/artifacts, secrets controls, provenance, code review, test harness |
| Predeployment | TEVV results, security tests, safety routing, privacy review, rollback and monitoring |
| Pilot | Bounded users/data/actions, enhanced logging, success/stop criteria, incident contacts |
| Production | Approval, immutable release identity, dashboards/alerts, runbooks, capacity and fallback |
| Change | Impact analysis, regression delta, approval proportional to materiality |
| Retirement | PB-24 exit, deletion, revocation, archive and dependency removal evidence |

## AI threat model

Map:

- Trust boundaries among user, application, system prompt/policy, retrieval, memory, model,
  routing model, tools/connectors, downstream interpreters, provider, and serving control plane.
- Assets: prompts, secrets, protected data, model weights/adapters, corpora, embeddings,
  evaluation data, identities, permissions, decisions, audit records, compute, and spend.
- Entry paths: direct/indirect prompt injection, poisoned content/artifacts, compromised identity,
  dependency/provider change, malicious tool metadata/result, control-plane access, and side channel.
- Security outcomes: unauthorized read/write/action, tenant crossing, code execution, model theft,
  integrity loss, denial of service/wallet, repudiation, or compliance/privacy breach.
- Human factors: approval fatigue, misleading explanations, automation bias, ambiguous identity,
  and inability to attribute an action to user, model, policy, or tool.

Map test hypotheses to PB-16 through PB-20 and defensive controls to PB-06, D&R-09, D&R-19,
and D&R-20.

## TEVV plan

Every test plan records:

- Intended use, populations, environments, data and action boundaries, prohibited conditions,
  and acceptance thresholds.
- Model/provider/version, system prompt and policy digest, RAG/index version, tool set, serving
  deployment, sampling parameters, and evaluation dataset version.
- Functional quality plus security, privacy, robustness, isolation, misuse, human-oversight,
  reliability, accessibility, and recovery measures proportionate to risk tier.
- Deterministic tests and stochastic trial counts with confidence intervals where appropriate.
- Baseline comparator, known limitations, residual risks, owners, and expiry/change triggers.

No single aggregate score can hide a critical failure. A cross-tenant read, unauthorized action,
or inability to recover is a release blocker even if the average benchmark improves.

## Security test minimum

- Direct and indirect prompt injection with inert canaries.
- Authorization outside the model; tenant, session, RAG, memory, and cache isolation.
- Output handling and downstream interpreter safety.
- Tool/connector scope, approval, confused-deputy, egress, SSRF, secret, and irreversible-action tests.
- Model/artifact provenance, mutable-reference, unsafe-format, pipeline, and registry controls.
- Gateway/control-plane, credential, quota, cache, batch, routing, artifact, and transport controls.
- Privacy and retention tests from PB-23.
- Incident containment and recovery tests from D&R-19 and PB-24.

## Release identity and reproducibility

Production releases use immutable identifiers for application, model, adapter, container,
prompt/policy bundle, evaluation suite, corpus/index snapshot, and tool manifest. Record the
provider-hosted model version as precisely as the provider exposes it and record any alias that can
move. If a release cannot be reconstructed or attributed, its assurance cannot be reproduced.

## Change classification

Material changes require impact analysis and regression testing:

- Model/provider/version or routing/fallback behavior.
- System prompt, policy, guardrail, classifier, tool schema, connector scopes, or autonomy.
- RAG source, chunking, embedding, index, memory scope, training/fine-tuning data, or adapter.
- Data class, purpose, affected population, decision/action, geography, or user experience.
- Serving runtime, cache, batching, quantization, hardware, region, cryptography, or supplier.

Emergency changes may use an expedited gate, but still require an owner, evidence capture,
rollback, time-limited approval, and retrospective review.

## Monitoring and drift

Track data, retrieval, behavior, quality, safety/security, tool/action, cost, and infrastructure
drift against the approved baseline. Distinguish:

- Expected population or seasonality change.
- Provider/version movement.
- Corpus/index or prompt/policy change.
- Adversarial probing or poisoning.
- Model or concept drift.
- Instrumentation failure.

Drift alerts must lead to an owned decision: accept with evidence, tune, restrict, roll back,
re-evaluate, or invoke D&R-19.

## CI/CD control logic

```json
{
  "gate": "ai_release",
  "require": [
    "registered_ai_asset",
    "approved_immutable_component_set",
    "threat_model_current",
    "security_privacy_tev_v_pass",
    "critical_findings == 0",
    "rollback_tested",
    "monitoring_and_incident_runbook_ready"
  ],
  "block_if": [
    "mutable_model_or_adapter_reference",
    "unapproved_tool_or_scope",
    "cross_tenant_test_failed",
    "evaluation_metadata_incomplete",
    "material_change_without_impact_review"
  ]
}
```

## Evidence and metrics

- Release-gate pass/fail and waived controls by tier and owner.
- Evaluation coverage by risk, population, boundary, and deployment.
- Critical regressions, time to detect, time to rollback, and recurrence.
- Percentage of production traffic on an approved immutable release identity.
- Provider aliases or components that moved without an approved change.
- Drift alerts with disposition and overdue re-evaluations.

## Escalation criteria

- Any failed tenant/authz, privileged-action, provenance, or recovery blocker.
- Material production change without impact analysis or attributable release identity.
- Provider change that invalidates TEVV and cannot be pinned or rolled back.
- Repeated waiver of the same critical control or expired evidence on a Tier 1/2 system.
- Evidence of exploitation or compromise: invoke D&R-19.

## Release record template

```text
AI asset / tier:      AI-____ / ____
Release ID / date:    ____ / ____
App/model/adapter:    ____ / ____ / ____
Prompt/policy/index:  ____ / ____ / ____
Tools/scopes:         ____
Threat model:         ____ current? Y/N
TEVV suite/results:   ____ / ____
Critical blockers:   ____
Privacy review:       ____
Rollback / safe mode: ____ tested: Y/N
Monitoring/runbooks:  ____ / D&R-19,D&R-20
Material changes:     ____
Decision / approver:  release | conditional | block / ____
Evidence expiry:      ____
```

## Summary

Secure AI development depends on explicit boundaries, immutable release identity, risk-based TEVV,
critical-failure gates, and change-triggered re-evaluation. Measure what matters, preserve enough
metadata to reproduce the decision, and treat rollback and incident readiness as release criteria.
