# 25 — Post-Quantum Key Management & Data-at-Rest Migration

## Overview

PQC migration is not complete when network handshakes become hybrid. Databases, object stores,
backups, archives, file systems, application envelopes, KMS/HSM roots, and exported key packages
can preserve classical wrapping and signature dependencies for decades. This playbook governs PQ
key/seed lifecycle and the rewrap/re-encryption program for data at rest.

Symmetric encryption remains the data-encryption mechanism; the PQ transition affects key
establishment, wrapping/export, escrow, recovery, signatures/attestation, and long-term parameter
strength. Prefer AES-256 for long-retention classes per organizational policy and
[CONVENTIONS §1](CONVENTIONS.md).

## Scope and inventory extension

Extend the CBOM (PB-01) with a data-at-rest/key-management plane:

- KMS/HSM/secret manager, module/firmware/version, validation status, region/partition/tenant,
  supported algorithms/parameter sets, import/export and backup capabilities.
- Root, KEK, DEK, seed, signing, wrapping, escrow, recovery, and attestation keys; owner, purpose,
  algorithm, size, origin, hardware protection, extractability, rotation, cryptoperiod, and status.
- Database TDE, column/field encryption, object storage, block/file encryption, backup, archive,
  data-lake, message/file envelope, tokenization, and application-layer encryption dependencies.
- Data class, shelf life, size, replicas, backups, legal holds, recovery tier, business owner,
  current wrapping/signing chain, migration target, and verification evidence.

## Target architecture

- Separate data-encryption keys from key-encryption/wrapping and signing/attestation keys.
- Version envelopes with explicit algorithm/parameter/context identifiers and authenticated
  metadata. Do not infer algorithm from key length or provider default.
- Support read-old/write-new during bounded migration; set a dated end condition and measure
  residual legacy reads.
- Keep algorithms behind governed provider interfaces and policy (PB-13), while binding each
  ciphertext/envelope to the exact scheme used.
- Use immutable, attributable key states: `pre-active | active | decrypt/verify-only | suspended |
  compromised | destroyed`.
- Design recovery and escrow so a restored KMS/HSM does not roll back LMS/XMSS state or revive
  destroyed/compromised material.

## Key and seed lifecycle

1. **Generate:** approved DRBG and module; record provenance, parameter set, tenant, purpose, and
   attestation. Treat ML-KEM/ML-DSA seeds as private key material.
2. **Distribute/use:** least-privileged identities, purpose-bound APIs, non-exportable keys where
   required, rate and anomaly monitoring, and explicit algorithm/context.
3. **Rotate:** overlap old decrypt/verify with new encrypt/sign only as long as necessary; prevent
   silent fallback to compromised algorithms.
4. **Back up/recover:** authorized encrypted backup, separation of duties, tested restore,
   inventory reconciliation, and stateful-signature safeguards.
5. **Revoke/suspend:** propagate to caches, replicas, signers, gateways, offline recovery, and
   disaster-recovery environments.
6. **Destroy:** verify primary, replica, backup-expiry, HSM slot, exported package, and application
   cache disposition; retain non-secret audit evidence.

## Migration workflow

### Phase 0 — Classify and plan

Prioritize by Mosca margin (PB-14), data shelf life, exposure, consequence, recovery tier, volume,
and current key dependency. Define rewrap versus full re-encryption:

- **Rewrap** changes KEK/envelope protection without decrypting bulk data where the DEK and
  symmetric scheme remain adequate.
- **Re-encryption** creates a new DEK/ciphertext and is required when the symmetric scheme,
  nonce practice, metadata binding, compromise state, or data architecture is inadequate.

### Phase 1 — Prove recoverability

Before bulk change, restore a representative backup into isolation, validate keys and application
reads, and prove rollback does not require a vulnerable/retired component that will disappear.

### Phase 2 — Canary

Migrate self-contained objects/partitions with known hashes and business validation. Measure
throughput, latency, HSM/KMS load, egress, cost, backup impact, application errors, and recovery.

### Phase 3 — Wave rollout

Use idempotent jobs with object/version checkpoints, dual control, bounded concurrency, retry
classification, and immutable audit. Never log plaintext, DEKs, seeds, or unredacted envelopes.

### Phase 4 — Verify and retire

Verify cryptographic metadata, object count/size/hash, application semantics, replicas, backups,
DR, legal-hold exceptions, and restored reads. Move old keys to decrypt-only, measure legacy use,
then destroy at the approved gate.

## Detection logic

```json
{
  "rule": "pq_key_or_data_migration_control_failure",
  "trigger_any": [
    "new_write uses legacy_or_unapproved_wrap",
    "key_export outside approved_recovery_workflow",
    "restored_key.state != authoritative_key.state",
    "destroyed_or_compromised_key successfully_used",
    "migration_object verified == false",
    "legacy_read_rate not_declining_after_wave",
    "same_seed_or_public_key across independent_tenants"
  ],
  "action": "stop_wave + preserve_checkpoint + alert"
}
```

## Indicators

- PQ private seed in application config, environment variable, log, crash dump, backup manifest,
  or CI artifact.
- Identical public key fingerprints across installations expected to be independently keyed.
- Algorithm or parameter omitted from envelope metadata; provider default changes interpretation.
- Restored DR environment accepts a key revoked/destroyed in primary.
- Re-encryption job skips replicas/backups or cannot reconcile object counts/hashes.
- HSM/KMS capacity causes fallback to classical wrapping or bypass of hardware protection.
- Old decrypt-only key continues encrypting/signing after cutover.
- State backup/restore can repeat LMS/XMSS state.

## Investigation and response

1. Freeze the affected migration wave and key-state changes; preserve checkpoints and audit.
2. Determine whether exposure is metadata/control drift or secret compromise. Never test a
   discovered production secret.
3. Reconcile authoritative key state across primary, replica, DR, caches, jobs, and providers.
4. Scope all data/envelopes, backups, artifacts, and signatures reachable by the key/seed.
5. For compromise, rotate/rewrap/re-encrypt by consequence; revoke identities and exported
   packages; invoke incident response where required.
6. For migration integrity failure, restore from known-good, fix idempotency/checkpoint logic,
   repeat canary, and independently validate before resuming.

## False positives and tuning

- A public key in configuration is expected; distinguish it from private seed/key material.
- Decrypt-only legacy use during a bounded transition is allowed; alert on new encryption/signing.
- Backup expiry can delay physical deletion; track documented residual copy and expiry.
- KMS aliases may move by design; require the resolved immutable key version in evidence.

## Escalation criteria

- Private PQ seed/key exposed outside its approved protection boundary.
- Cross-tenant key/seed reuse or key-state rollback.
- Compromised/destroyed key remains usable.
- Migration corrupts or loses data, recovery cannot restore trusted state, or HNDL-priority data
  lacks a viable rewrap/re-encryption plan.
- FIPS/contractual path uses an unapproved module or draft algorithm as a compliance claim.

## Analyst notes

```text
KEYMIG-ID:          KM-____
Data class / owner: ____ / ____
Store / volume:     ____ / ____
Current -> target:  wrap ____ -> ____   data cipher ____ -> ____
Key/seed / provider: ____ / ____   module/version/validation: ____
State / cryptoperiod: ____ / ____
Extractable/backup: Y/N / ____
Rewrap or reencrypt: ____   wave/checkpoint: ____
Counts/hashes:      source ____ target ____ verified Y/N
Replica/backup/DR:  ____ / ____ / ____
Legacy read/write:  ____ / ____
Disposition:        continue | hold | rollback | rotate | destroy | incident
```

## Summary

Treat PQ seeds and private keys as first-class assets, make envelope algorithms explicit, prove
recovery before migration, rewrap or re-encrypt in verified waves, reconcile every replica and
backup, and retire old keys only after legacy use reaches the approved gate.
