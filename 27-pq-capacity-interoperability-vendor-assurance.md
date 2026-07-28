# 27 — PQ Capacity, Interoperability & Vendor Assurance

## Overview

PQC artifacts are larger, implementations mature at different speeds, protocol profiles are still
evolving, and critical products may depend on suppliers that control firmware, cryptographic
modules, or hosted termination. This playbook turns capacity, interoperability, and vendor
readiness into measured migration gates rather than last-minute exceptions.

It complements PB-13 migration operations: PB-13 governs waves and rollback; this playbook defines
the test matrix, capacity model, protocol/network failure analysis, and supplier evidence that
decide whether a wave is ready.

## Capacity model

Measure end to end:

- Key generation, encapsulation/decapsulation, signing/verification throughput and tail latency.
- HSM/KMS sessions, operations/second, queue, partition capacity, HA/failover, backup/restore,
  firmware limits, and audit volume.
- Handshake/message/certificate/token/package/firmware size and processing time.
- Network MTU, fragmentation, UDP/TCP behavior, loss/retransmit, middlebox/proxy/WAF/LB limits,
  header/frame/object size, timeout, memory, and connection concurrency.
- CPU, memory, accelerator, power/battery, startup/boot, storage, bandwidth, log/SIEM, CT,
  revocation, archive, and backup impacts.
- Operational cost under normal, peak, failover, rotation, re-encryption, and incident conditions.

Use production-representative distributions and tail percentiles. A median-only benchmark hides
the client, region, device, or chain that will fail migration.

## Interoperability matrix

Rows are client/device/library/OS/firmware/proxy/gateway/provider versions; columns are:

- Classical-only, PQ-only where standardized/supported, and each approved hybrid profile.
- Algorithm/parameter/OID/context/prehash variant.
- Direct and through every TLS/VPN/email/identity/service-mesh termination path.
- Certificate/chain/signature/token/artifact sizes at typical and maximum supported bounds.
- Success, negotiated profile, validation semantics, error, fallback reason, latency, and telemetry.
- Rotation, revocation, recovery, failover, downgrade detection, and rollback.

Record **unsupported**, **draft-only**, and **unknown** separately. Do not turn unknown into ready.

## Network and middlebox validation

- Capture ClientHello/ServerHello or protocol equivalents at both sides of each authorized
  termination to locate stripping/downgrade.
- Test representative MTUs, IPv4/IPv6, loss, mobile/satellite/VPN paths, proxies, inspection,
  load balancers, API gateways, and UDP-based protocols where applicable.
- Watch fragmentation drops, amplification risk, truncated headers, frame limits, timeouts,
  retry storms, PMTUD failure, and classical fallback.
- Prefer safe synthetic environments for worst-case sizes and failure injection. Production
  canaries use bounded, reversible tests.

## Performance gate

Each migration wave defines:

- Baseline and target profile.
- Workload/client/path coverage.
- SLO and error-budget limits for success, p50/p95/p99, throughput, capacity, cost, and recovery.
- Security non-negotiables: no policy-invalid fallback, single-component hybrid verification,
  unapproved provider/module, or loss of telemetry.
- Headroom under peak plus failover, rotation/re-encryption, and incident load.
- Hold, rollback, and exception thresholds with owner and expiry.

Capacity failure must not trigger silent cryptographic downgrade. It triggers scale, hold,
approved exception, or rollback to the last allowed policy.

## Vendor assurance

For each material product/service, obtain dated evidence:

- Exact algorithms/parameter sets/profiles, standard/draft status, product versions, module
  boundaries, FIPS validation status where required, and default/optional configuration.
- Roadmap dates by capability: inventory/export, hybrid/PQ support, key management, certificates,
  code signing, backup/recovery, telemetry, interoperability, and retirement of classical paths.
- Dependencies and subcontractors, HSM/firmware/hardware constraints, upgrade prerequisites,
  licensing/cost, support lifecycle, incident/vulnerability channel, and migration rollback.
- Test results and known limitations for sizes, performance, failure, fallback, HA/DR, and mixed fleets.
- Contract commitments for notification of algorithm/profile/provider changes and security defects.

An attestation without affected product/version, named owner, date, limitation, and delivery
milestone is not a roadmap.

## Procurement requirements

- Crypto-agile interfaces and externally governed policy; no unchangeable algorithm literals.
- Exportable CBOM evidence and machine-readable negotiated/validation telemetry.
- Approved immutable provider/module versions and a supported rollback path.
- Customer-controlled keys/tenant separation where required; documented seed/key backup/recovery.
- Capacity and maximum-size specifications with representative benchmark method.
- Standards-status labeling; drafts and experiments cannot be sold as final compliance.
- Exit/portability and secure data/key destruction.

## Detection logic

```json
{
  "rule": "pq_rollout_capacity_or_interop_gate",
  "hold_if_any": [
    "interop_coverage < required_coverage",
    "policy_invalid_fallback_count > 0",
    "p99_or_error_rate > gate",
    "hsm_headroom_under_peak_failover < minimum",
    "middlebox_path_unknown == true",
    "vendor_evidence_expired_or_product_mismatch == true",
    "target_profile.status in ['draft-only','unknown'] AND production_policy.requires_final"
  ],
  "action": "hold_wave + owner + dated remediation_or_exception"
}
```

## Indicators

- PQ works direct but fails through CDN, WAF, proxy, VPN, service mesh, email gateway, or load balancer.
- Handshake/certificate/signature growth crosses packet, header, token, firmware, CT, or archive limits.
- Retry/timeouts increase while negotiated PQ/hybrid ratio falls.
- HSM/KMS queues saturate during signing, rotation, failover, or recovery.
- Vendor roadmap says “PQC ready” without product/version/profile or relies on oqs-provider for
  a FIPS-obligated production path.
- A product supports pre-standard Kyber/Falcon variant but not final ML-KEM or the eventual final profile.
- Exception fleet grows because device replacement or firmware capacity was not funded.

## Investigation and response

1. Reproduce on a representative test path and identify the exact failing component/version/limit.
2. Confirm whether the target uses final standards, an IETF draft, private profile, or pre-standard
   algorithm variant.
3. Compare offered, selected, validated, logged, and policy-required algorithms at every termination.
4. Quantify load and headroom under normal, peak, failover, rotation, and recovery.
5. Hold or roll back the wave if security semantics or recovery fail; do not loosen policy silently.
6. Open a vendor evidence/remediation item with product/version, trace, measured limit, owner, date,
   workaround, and exit risk.

## Escalation criteria

- Silent classical fallback or partial hybrid verification caused by capacity/interoperability.
- Critical path has no supported standards-based migration target or vendor commitment.
- HSM/KMS/network capacity cannot meet peak plus recovery without weakening controls.
- Vendor misrepresents draft/experimental support or validation status.
- Exception population or supplier concentration makes mandated/negative-Mosca migration infeasible.

## Analyst notes

```text
PQCAP-ID:           CAP-____
Protocol/use/owner: ____ / ____ / ____
Target profile/status: ____ / final | draft | experimental
Matrix coverage:    clients ____ paths ____ versions ____
Size/MTU limits:    ____ / ____
Baseline -> target: success ____ -> ____  p99 ____ -> ____  cost ____ -> ____
HSM/KMS headroom:   normal ____ peak ____ failover ____
Fallbacks/security: ____
Vendor/product/ver: ____ / ____ / ____
Evidence/roadmap:   ____ dated ____ owner ____ milestone ____
Gate decision:      promote | hold | rollback | exception(expires ____)
```

## Summary

PQC rollout readiness is the intersection of standards status, every relying component,
worst-path artifact size, peak-plus-recovery capacity, observable security semantics, and dated
supplier evidence. Test the matrix, fund headroom, hold on silent fallback, and make procurement
buy crypto agility and evidence—not “PQC ready” marketing.
