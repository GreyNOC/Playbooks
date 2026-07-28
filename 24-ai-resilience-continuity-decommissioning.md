# 24 — AI Resilience, Business Continuity & Decommissioning

## Overview

AI dependencies fail differently from ordinary services: provider aliases move, model behavior
changes without application code, quotas and regional capacity disappear, safety controls regress,
and an agent may continue acting after the user-facing request has ended. This playbook defines
safe degraded modes, provider/model failover, recovery objectives, kill controls, continuity
testing, and complete retirement.

## Business impact analysis

For each AI asset, record:

- Business process and maximum tolerable disruption.
- RTO/RPO for service, prompt/policy configuration, RAG/index, memory, model/adapter, audit logs,
  and pending agent actions.
- Consequence of wrong output or action versus no output.
- Manual or deterministic fallback, staffing/capacity, and data/action limitations.
- Provider, model family, region, serving, identity, data, connector, and cryptographic
  dependencies plus concentration risk.

For many high-risk uses, “unavailable” is safer than an untested fallback model. Availability
objectives never override authorization, isolation, or safety blockers.

## Resilience modes

| Mode | Use | Required controls |
| --- | --- | --- |
| Normal | Approved model and dependencies healthy | Full monitoring and budgets |
| Degraded-read-only | Tools/actions unavailable or uncertain | No mutations; disclose limitations |
| Deterministic fallback | AI unavailable but rule/workflow can serve | Versioned tested rules; human escalation |
| Alternate model/provider | Primary unavailable or compromised | Pre-approved data terms, TEVV, routing and rollback |
| Human/manual | Critical process continues without AI | Capacity, procedures, identity and records controls |
| Safe stop | No fallback meets control baseline | Kill tasks, preserve state/evidence, communicate outage |

## Kill and containment controls

Support independently:

- Stop one task, agent, tool, connector, tenant, deployment, model/adapter, provider route, or
  memory write path.
- Prevent new work while allowing evidence-preserving drain.
- Revoke task tokens, connector credentials, signed URLs, inference keys, and queued approvals.
- Freeze recursive spawn and downstream actions; enumerate and reconcile in-flight/committed work.
- Enter read-only or safe-stop mode without depending on the model being contained.

Kill controls require authenticated, audited break-glass access, separation of duties for broad
actions, and regular tests. A dashboard button that calls the same compromised agent is not a kill
switch.

## Failover requirements

Before enabling alternate model/provider/region:

- Register it in PB-21 with approved data, region, supplier, security, privacy, and contract terms.
- Run proportionate PB-22 TEVV, including behavioral delta, authz/isolation, tool compatibility,
  context limits, output schema, cost, and recovery.
- Pin model and policy identity where possible; never silently move to an unknown alias.
- Confirm PB-23 retention, reuse, deletion, and DLP enforcement.
- Test rollback and prevent oscillating routes or duplicate agent actions.

## Backup and recovery

Back up and verify restoration of:

- System prompts/policy bundles, tool schemas and allowlists, routing, budgets, evaluation suites,
  incident configuration, and AI-BOM.
- RAG sources plus provenance and authorization metadata; indexes may be rebuilt only if the source
  and exact pipeline are reproducible.
- Model/adapter artifacts by immutable digest where licensing and architecture permit.
- Essential audit and trace records under approved retention.

Do not back up secrets inside prompts or model artifacts. Encrypt backups, separate recovery
credentials, test integrity, and include PQ migration dependencies from PB-25.

## Continuity scenarios

Exercise:

- Provider or region outage; quota exhaustion; inference latency collapse.
- Provider alias or model behavior changes without notice.
- Compromised model/adapter or RAG index requiring known-good restoration.
- Cross-tenant serving incident requiring cache/batching disablement and deployment drain.
- Connector compromise or agent runaway requiring scoped kill and reconciliation.
- Loss of AI telemetry while service remains available.
- PQ algorithm/provider break affecting model signing, transport, or backup key wrapping.

Capture recovery time, data loss, duplicate/missed actions, control degradation, communication,
manual capacity, and residual risk.

## Monitoring and activation

Activate a resilience mode on:

- Availability, latency, error, queue, quota, cost, or provider status threshold.
- Model/version/digest or behavior change outside approval.
- Critical security/privacy/safety control failure.
- Missing telemetry that makes authorization, isolation, or attribution unverifiable.
- D&R-19 containment decision.

Every activation records authority, reason, mode, affected scope, start/end, data/action
restrictions, user communication, and return-to-normal tests.

## Decommissioning workflow

1. Freeze new users, data, connectors, memory, training reuse, and material changes.
2. Export required business records and portable configuration under approved data handling.
3. Revoke provider, inference, connector, service, CI/CD, registry, and break-glass credentials.
4. Stop deployments, agents, queues, scheduled jobs, webhooks, routes, caches, and monitoring.
5. Delete or disposition prompts, transcripts, RAG/index, memory, evaluation/training data,
   models/adapters, logs, backups, and provider copies per PB-23; retain only authorized records.
6. Remove DNS, certificates, secrets, firewall rules, OAuth grants, cloud roles, code dependencies,
   vendor access, and procurement renewals.
7. Obtain provider deletion/closure evidence where applicable.
8. Update AI-BOM, CMDB, data maps, risk register, incident contacts, and business procedures.
9. Verify no traffic, credentials, spend, stored data, or orphaned dependencies remain.

## Metrics and escalation

- Recovery test pass rate and achieved RTO/RPO by component.
- Percentage with tested safe mode, scoped kill, fallback, rollback, and manual process.
- Unapproved failovers or duplicate/missed agent actions during recovery.
- Provider/model concentration and manual fallback capacity.
- Retired assets with residual credentials, spend, traffic, data, or supplier access.

Escalate when a Tier 1/2 asset has no safe stop or viable continuity path; failover would violate
data/security terms; kill controls cannot stop actions; recovery cannot reproduce trusted state;
or decommissioning leaves live credentials, protected data, or external access.

## Continuity record

```text
AI asset / tier:       AI-____ / ____
Scenario / activation: ____ / ____
RTO/RPO targets:       ____ / ____
Mode:                  degraded | deterministic | alternate | manual | safe-stop
Kill scope/result:     ____ / ____
Fallback identity:     provider/model/policy/digest ____
Data/action limits:    ____
Recovery evidence:     config ____ data/index ____ artifact ____ logs ____
Duplicate/missed work: ____
Return-to-normal tests: authz | isolation | behavior | privacy | telemetry | budget
Decommission checks:  creds | data | routes | jobs | spend | supplier | records
Owner / disposition:   ____ / ____
```

## Summary

Resilient AI fails safely and visibly. Define when no answer is safer than a fallback, test scoped
kill controls, pre-approve alternate models and data terms, preserve reproducible recovery state,
reconcile in-flight actions, and retire every credential, route, artifact, data copy, and supplier
dependency—not just the user interface.
