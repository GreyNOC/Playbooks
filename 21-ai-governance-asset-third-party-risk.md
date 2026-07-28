# 21 — AI Governance, Asset Inventory & Third-Party Risk

## Overview

An organization cannot secure AI it has not approved, inventoried, owned, or classified. This
playbook establishes the enterprise AI system of record, risk-tiering gates, ownership model,
shadow-AI discovery, exception handling, and supplier controls. It is the governance spine above
PB-06, PB-15 through PB-20, D&R-19, and D&R-20.

The operating model follows NIST AI RMF's **Govern / Map / Measure / Manage** functions and NIST
CSF 2.0's Govern and Identify outcomes. It does not turn voluntary guidance into a mandate;
applicability and authority are recorded per system.

## Governance outcomes

Every production or material internal AI use case has:

- A named business owner, technical owner, security owner, data owner, and accountable executive.
- A stable AI asset ID and AI-BOM covering application, model/provider/version, prompts and policy
  bundles, RAG stores, training/fine-tuning data, adapters, tools/connectors, serving infrastructure,
  identities, suppliers, evaluation suites, and cryptographic dependencies.
- A documented purpose, users, affected populations, decisions/actions, data classifications,
  external dependencies, geographic scope, and prohibited uses.
- A risk tier with approval authority, control baseline, evaluation depth, monitoring cadence,
  incident threshold, change threshold, and retirement requirements.
- A lifecycle state: `proposed | sandbox | approved-build | pilot | production | restricted |
  suspended | retiring | retired`.

## AI inventory schema

```json
{
  "ai_asset_id": "AI-____",
  "purpose": "approved business outcome",
  "owners": {"business":"", "technical":"", "security":"", "data":"", "executive":""},
  "lifecycle_state": "production",
  "risk_tier": "1-critical | 2-high | 3-moderate | 4-low",
  "components": {
    "application": "", "model_provider": "", "model_id_version": "",
    "system_prompt_policy_digest": "", "rag_indexes": [], "adapters": [],
    "tools_connectors": [], "serving_deployments": [], "identities": []
  },
  "data": {"input_classes":[], "output_classes":[], "retention":"", "training_reuse":false},
  "dependencies": {"suppliers":[], "regions":[], "cryptography_cbom_refs":[]},
  "assurance": {"threat_model":"", "tev_v_report":"", "last_review":"", "next_review":""},
  "operations": {"monitoring":"", "incident_runbook":"D&R-19", "rollback":"", "exit_plan":""}
}
```

## Risk-tiering decision

Tier 1 includes AI that can materially affect safety, regulated rights, critical operations,
financial movement, privileged access, another person's data, or irreversible actions. Tier 2
includes sensitive data, externally visible decisions, write-capable enterprise tools, or material
provider dependency. Tier 3 is bounded, reviewed assistance without privileged action. Tier 4 is
non-sensitive experimentation with no external effect.

Risk tier is driven by consequence and exposure, not model size or marketing category. A small
classifier controlling access can be Tier 1; a large model drafting public copy may be Tier 4.

## Discovery and shadow-AI detection

Correlate procurement, expense, SSO/OAuth, CASB/SSE, DNS/proxy, endpoint, browser-extension,
source/dependency, container, cloud marketplace, API gateway, secrets-scanning, and data-egress
telemetry. Flag:

- AI provider traffic or API keys without an AI asset ID.
- OAuth consent to AI services outside the approved catalog.
- Source dependencies, hosted endpoints, local model runtimes, browser extensions, or containers
  that invoke models but have no owner.
- Sensitive-data egress to an AI provider whose approved data classes do not include it.
- An approved asset using an unregistered model, region, connector, adapter, or provider feature.

Shadow AI is triaged, not automatically punished: identify the business need, contain prohibited
data/action paths, then approve, replace, or retire it with an owner and deadline.

## Third-party and procurement controls

Before purchase or renewal, record:

- Model/service identity, hosting regions, subprocessors, data flows, training/reuse terms,
  retention/deletion behavior, isolation model, encryption, logging, incident response, and
  vulnerability-disclosure path.
- Notification commitments for breach, model/version change, safety/security regression,
  subprocessor change, and service retirement.
- Evidence rights: audit/assessment reports, penetration testing, model and data provenance,
  availability metrics, deletion confirmation, and incident log access.
- Portability and exit: export format, prompt/RAG/config portability, data return/deletion,
  replacement lead time, and safe fallback.
- PQ roadmap and cryptographic dependencies for long-lived data or artifacts, linked to PB-14.

Contracts do not prove control effectiveness. Bind each assurance claim to evidence and an
expiration/review date.

## Review workflow

1. Register the use case before material data, users, or actions enter the system.
2. Map purpose, data, people, decisions/actions, dependencies, and foreseeable misuse.
3. Assign tier and control baseline; identify applicable law, contract, policy, and guidance.
4. Require PB-22 threat model and TEVV, PB-23 data/privacy review, D&R-19 readiness, and PB-24
   continuity/exit evidence proportionate to tier.
5. Approve with explicit conditions, owners, evidence expiry, monitoring, and change triggers.
6. Reassess on model/provider/version, data, purpose, population, tool, connector, autonomy,
   hosting, cryptography, or supplier change.
7. Suspend or retire when evidence expires, purpose changes, controls fail, or ownership disappears.

## Metrics and indicators

- Inventory coverage by spend, traffic, OAuth consent, repositories, endpoints, and business unit.
- Percentage with complete AI-BOM, current tier, named owners, current TEVV, D&R-19 readiness,
  data review, supplier evidence, rollback, and exit plan.
- Shadow-AI mean time to owner and disposition.
- Exceptions past expiry; supplier evidence past freshness SLA.
- Production changes that bypassed governance triggers.
- Concentration risk by provider, model family, region, and critical business process.

## Response and escalation

- Unknown asset with sensitive data or privileged action: restrict egress/action, preserve evidence,
  assign owner, and initiate expedited review.
- Ownerless Tier 1/2 asset, expired critical evidence, or provider without viable incident/exit
  terms: suspend new use and escalate to the accountable executive and enterprise risk.
- Confirmed data or security event: invoke D&R-19.
- Repeated bypass of registration or approval: address the process/control failure, not only the
  individual instance.

## Governance record template

```text
AI asset / state:     AI-____ / ____
Purpose / users:      ____ / ____
Owners:               business ____ technical ____ security ____ data ____ executive ____
Risk tier / rationale: ____ / ____
Model/provider/ver:   ____ / ____ / ____
Data classes / reuse: ____ / Y|N
Tools/actions:        ____   irreversible? Y/N
Suppliers/regions:    ____ / ____
Authority map:        binding ____ contractual ____ policy ____ guidance ____
Assurance refs:       threat ____ TEVV ____ privacy ____ incident ____ continuity ____
Change triggers:      ____
Decision / expiry:    approve | conditional | restrict | suspend | retire / ____
```

## Summary

AI governance is an evidence-backed operating system: inventory every use, assign accountable
owners, tier by consequence, bind approvals to current evidence, discover shadow AI from multiple
planes, govern suppliers and exit paths, and re-open review whenever the system materially changes.
