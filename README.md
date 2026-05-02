# GreyNOC Security Playbooks

Production-ready detection and response playbooks authored by the GreyNOC detection-engineering team. Each playbook follows a consistent structure: overview, MITRE ATT&CK mapping, detection strategy, indicators, sample logic, example data, investigation steps, false positives, tuning, response actions, escalation criteria, an analyst notes template, and a closing summary.

These are written for SOC analysts, incident responders, and detection engineers. They focus on behavior-based detection over signatures, and on operational clarity over theory.

---

## Index

| # | Playbook | Focus |
|---|----------|-------|
| 01 | [Password Spraying](01-password-spraying.md) | Distributed credential access against IdPs |
| 02 | [Brute Force Attack](02-brute-force.md) | Single-target authentication abuse |
| 03 | [Distributed Port Scan](03-distributed-port-scan.md) | Multi-source coordinated reconnaissance |
| 04 | [Credential Stuffing](04-credential-stuffing.md) | Leaked-credential replay against web/SaaS |
| 05 | [Impossible Travel](05-impossible-travel.md) | Geographic velocity + risk-feature composite |
| 06 | [Privilege Escalation](06-privilege-escalation.md) | Identity, endpoint, and cloud elevation |
| 07 | [Suspicious PowerShell Execution](07-suspicious-powershell.md) | Encoded, in-memory, and parented PowerShell abuse |
| 08 | [Malware Beaconing](08-malware-beaconing.md) | Periodic C2 traffic detection |
| 09 | [AI / Automated Agent Abuse](09-ai-automated-agent-abuse.md) | Adversary automation and owned-AI-feature abuse |
| 10 | [Coordinated Multi-Stage Attack](10-coordinated-multi-stage-attack.md) | Kill-chain correlation across entities |

---

## Conventions

- **MITRE ATT&CK** technique IDs are referenced for every playbook; ATLAS IDs are used where AI-system techniques apply.
- **Sample detection logic** is JSON-shaped pseudocode — not tied to any specific SIEM query language. Translate to KQL, SPL, EQL, Sigma, or your platform of choice.
- **Example event data** is simplified for clarity and uses RFC 5737 / RFC 3849 documentation address space where applicable.
- **Severity** is suggested, not prescriptive. Tune to your environment and risk model.
- **Tuning guidance** favors composite features over per-rule suppression. Suppressing a base detector to clean up noise blinds you to other intrusions; suppressing or weighting at the correlation/escalation layer does not.

---

## How to Use

1. Read the playbook end-to-end before deploying the rule.
2. Map the data sources to your environment; verify telemetry sufficiency before relying on a detection.
3. Translate the sample logic to your platform; validate on historical data where possible.
4. Adopt the analyst-notes template into your case-management workflow.
5. Apply the escalation criteria to your on-call and incident-response procedures.
6. Revisit tuning after every confirmed true positive and false positive.

---

*GreyNOC — detection-engineering-first security operations.*
