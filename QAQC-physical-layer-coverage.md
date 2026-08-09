# QA/QC — Physical-Layer & Transmission-Medium Coverage

**Audit scope.** Whether the GreyNOC playbook library covers the physical transmission layer —
radio-frequency and optical media — as a detection and response domain.

**Audited artifact set.** All 50 Markdown files at repository root (20 Detection & Response,
27 AI · Post-Quantum · E2EE, plus `README.md`, `CONVENTIONS.md`, `SECURITY.md`) as of this audit.

**Verdict.** **Gap confirmed — the library had zero physical-layer coverage before this audit.**
Every playbook in both collections begins at Layer 2 or above and treats the transmission medium
as trusted, unexamined substrate. Two new playbooks (`TX-01`, `TX-02`) were authored to close the
highest-consequence portion of that gap; the remainder is enumerated in §5 as open work.

Per the house rule — *reproducible or it didn't happen* — every finding below carries the command
that produces it.

---

## 1. Method

The audit is a term-presence sweep with word boundaries, followed by manual context review of
every hit. Word boundaries matter: an unanchored `grep -ric "RF"` returns 163 hits across the
library and an unanchored `LTE` returns 53, but **all** of them are substring artifacts
(`su**rf**ace`, `pe**rf**orm`, `fi**lte**r`, `a**lte**rnate`). A naive sweep would have reported
this domain as covered. It is not.

Reproduce with:

```bash
for t in 'radio' 'RF' 'spectrum' 'wireless' 'Wi-?Fi' '802\.11' 'bluetooth' 'cellular' 'LTE' '5G' \
         'GNSS' 'GPS' 'jamming' 'SDR' 'antenna' 'optical' 'photonic' 'fibre?' 'laser' 'DWDM' \
         'OTDR' 'Li-Fi' 'TEMPEST' 'EMSEC' 'air-?gap' 'satellite' 'microwave' 'physical layer' \
         'side-channel' 'QKD'; do \
  printf "%-16s %3s  %s\n" "$t" "$(grep -riEo "\b($t)\b" *.md | wc -l)" "$(grep -riEl "\b($t)\b" *.md | tr '\n' ' ')"; \
done
```

---

## 2. Findings

### F-01 — Zero coverage of radio-frequency media *(pre-existing, now partially closed)*

Twenty-four of the thirty terms swept returned **zero** matches across all 50 files:
`radio`, `RF`, `spectrum`, `wireless`, `802.11`, `bluetooth`, `LTE`, `5G`, `GNSS`, `GPS`,
`jamming`, `SDR`, `antenna`, `microwave`, `TEMPEST`, `EMSEC`, `air-gap`, `physical layer` — and,
per F-02, the entire optical set.

**Consequence.** The library's Detection & Response collection claims coverage "across the
intrusion lifecycle," but a documented initial-access path — an adversary who never touches a
network port — had no playbook. `D&R-03 Distributed Port Scan` presumes an IP reconnaissance
surface; `D&R-17 Data Exfiltration` enumerates cloud, C2, and alternate *protocols* but no
alternate *medium*. ATT&CK `T1011 Exfiltration Over Other Network Medium` and `T1200 Hardware
Additions` were unmapped anywhere in the library.

**Disposition.** Closed for the enterprise-relevant RF bands by
[TX-01 — RF & Radio-Spectrum Intrusion](TX-01-rf-spectrum-intrusion.md). Residual gaps in §5.

### F-02 — Zero coverage of optical media *(pre-existing, now closed)*

`optical`, `photonic`, `fiber`/`fibre`, `laser`, `DWDM`, `OTDR`, `Li-Fi`, and `QKD` each returned
**zero** matches across all 50 files.

**Consequence — this is the more serious of the two.** The AI · PQ · E2EE collection is built on
the harvest-now-decrypt-later threat model, and `PB-02 Harvest-Now-Decrypt-Later Exposure` is
explicitly a *bulk-capture detection* playbook. A passive fiber tap is the single highest-yield
bulk-capture position available to a well-resourced adversary — it is silent, it is upstream of
every application control, and it sees the aggregate. The collection reasoned about what an HNDL
adversary would *do with* captured ciphertext without ever addressing where the capture happens.
`PB-02` had no counterpart describing how the traffic gets harvested at the medium.

**Disposition.** Closed by
[TX-02 — Nanometer-Scale Optical Data Transmission, Reception & Intrusion Handling](TX-02-optical-nm-data-transmission-intrusion.md),
which is cross-referenced from the HNDL threat model.

### F-03 — All six incidental hits are contextual, not coverage

Six word-boundary matches exist across four terms. Every one was manually reviewed; none
constitutes physical-layer detection content:

| File | Line | Term | Actual context | Coverage? |
| --- | --- | --- | --- | --- |
| `01-password-spraying.md` | 105 | Wi-Fi | Guest Wi-Fi as a shared-NAT **false-positive** source | No |
| `05-impossible-travel.md` | 117 | satellite | Satellite ISPs as a **geolocation-accuracy** caveat | No |
| `08-malware-beaconing.md` | 128 | Wi-Fi | MDM check-ins over Wi-Fi as a **false positive** | No |
| `12-pq-e2ee-realtime-media.md` | 154 | Wi-Fi, cellular | Wi-Fi ↔ cellular handoff as a **renegotiation FP** | No |
| `08-bugbounty-crypto-implementation-defects.md` | 97, 197 | side-channel | `C10` — **computational** side channels (timing, fault, residue), not electromagnetic | No |
| `20-ai-serving-plane-isolation.md` | 152 | side-channel | Inference **timing/cache** side channels | No |
| `27-pq-capacity-interoperability-vendor-assurance.md` | 48 | satellite | Satellite paths as an **interop test condition** | No |

The pattern is consistent and worth naming: where the physical layer appears at all, it appears
as *something that generates false positives* — never as something that generates detections.

**Note on `C10` and §8.1.** The pre-existing `C10 — Side-channel, fault and secret-residue
exposure` class in `PB-08` covers computational side channels only. TX-01's electromagnetic
emanation (TEMPEST) material and TX-02's optical-emission material are a different physical
phenomenon and are deliberately **not** filed under `C10`. Do not merge them; a triager reading
`C10` expects a timing or fault oracle.

### F-04 — `CONVENTIONS.md` §5 cross-reference notation was two-collection-only *(now closed)*

§5 stated that "the two collections number independently" and defined only `PB-NN` and `D&R-NN`.
Adding a third collection without amending §5 would have made `TX-NN` an undefined citation form
and reintroduced exactly the bare-number ambiguity §5 exists to prevent.

**Disposition.** `CONVENTIONS.md` §5 amended to define `TX-NN` and to restate the rule as
*three* independently numbered collections. `CONVENTIONS.md` §8.1 amended to record that the TX
track intentionally owns no defect-class prefix.

### F-05 — Detection-telemetry honesty applies with unusual force to this track *(advisory)*

`README.md` step 2 already warns that PQ/E2EE detection "depends on handshake- and key-level
visibility that many estates do not yet log." For the physical layer the problem is a category
worse: the telemetry frequently **cannot be produced at all** without hardware the organization
does not own — spectrum sensors, WIPS overlays, OTDR ports, tapped optical monitor ports.

Both new playbooks therefore lead with a telemetry-tier model that states plainly what is
detectable at each level of investment, and both state which intrusion classes remain
**undetectable** at Tier 0. A playbook that implies a detection an estate cannot actually run is
a fabrication under the house rule, whether or not the logic itself is sound.

---

## 3. Coverage matrix — transmission medium × library

| Medium | Before this audit | After |
| --- | --- | --- |
| Ethernet / IP / application protocols | Covered (D&R-01–18, PB-03/09/12) | unchanged |
| Wi-Fi (802.11) | **None** | TX-01 §5.1 |
| Bluetooth / BLE | **None** | TX-01 §5.2 |
| Cellular (LTE / 5G NR) | **None** | TX-01 §5.3 |
| GNSS reception | **None** | TX-01 §5.4 |
| Sub-GHz ISM / LPWAN (LoRa, Zigbee, Z-Wave, 433/868/915 MHz) | **None** | TX-01 §5.5 |
| Microwave / satellite backhaul | **None** | TX-01 §5.6 |
| Electromagnetic emanation (TEMPEST) | **None** | TX-01 §5.7 (scoped, detection-limited) |
| Single-mode / multimode fiber | **None** | TX-02 §6 |
| Free-space optical & laser links (incl. orbital ISL) | **None** | TX-02 §6.5 |
| Visible-light comms / Li-Fi / IR | **None** | TX-02 §6.6 |
| Optical air-gap covert channels | **None** | TX-02 §6.7 |
| Ultrasonic / acoustic covert channels | **None** | **still open** — see §5 |
| NFC / RFID | **None** | **still open** — see §5 |
| Power-line / conducted emissions | **None** | **still open** — see §5 |
| **Below the medium** — the silicon executing the cryptography | **None** | TX-03 (added after this audit; see §7) |

---

## 4. Conformance check — new TX track against `CONVENTIONS.md`

Both new playbooks were checked against every convention the library enforces:

| Requirement | Source | TX-01 | TX-02 |
| --- | --- | --- | --- |
| GreyNOC detection structure (overview → mapping → strategy → indicators → logic → example data → investigation → FP → tuning → response → escalation → analyst notes → summary) | `README.md` ¶3 | Pass | Pass |
| ATT&CK cited as ID + name; no forced tags where mapping is absent | §4 | Pass — unmapped phenomena listed explicitly | Pass — same |
| ATLAS citations carry collection version | §4 | N/A — no ATLAS mapping | N/A |
| Example addresses in RFC 5737 / RFC 3849 space | §5 | Pass | Pass |
| Detection logic is JSON-shaped pseudocode, not a SIEM query | §5 | Pass | Pass |
| Cross-references use the `PB-NN` / `D&R-NN` / `TX-NN` form, never a bare number | §5 (as amended, F-04) | Pass | Pass |
| Standardized PQC names (ML-KEM / ML-DSA), submission names only as aliases | §1 | N/A | Pass |
| No defect-class prefix invented outside the §8.1 registry | §8.1 | Pass — no prefix | Pass — no prefix |
| ROE §6/§7 applicability | §6, §7 | N/A — neither is a bug-bounty playbook | N/A |

**Two conformance notes carried forward as deliberate deviations:**

1. **ATT&CK tactic placement is annotated, not asserted.** Both playbooks map ICS-matrix
   techniques (`T0860`, `T0887`, `T0830`, `T0814`) alongside Enterprise ones. ICS tactic
   placement differs from Enterprise and both move between ATT&CK versions, so each mapping
   table carries a re-verification note rather than a bare tactic claim. This follows §4's
   "say so rather than forcing a tag."
2. **Physical-measurement thresholds are parameterized, never hardcoded as universal.** Optical
   tap-loss and RF noise-floor thresholds depend entirely on link budget, hardware, and
   environment. Both playbooks require the reader to establish a local baseline and state the
   detection threshold as a deviation from it. A published absolute number would be unreproducible
   in any estate but the one it came from.

---

## 5. Residual gaps — open work

The TX track does **not** yet cover the following. Each is a legitimate candidate for `TX-03`+;
none is closed by TX-01 or TX-02, and no playbook should be read as covering them.

- **NFC / RFID** — badge cloning, relay attacks against physical access control. Adjacent to
  `D&R-06` and `D&R-15` but a distinct medium with distinct telemetry.
- **Ultrasonic and acoustic covert channels** — air-gap bridging via speakers/microphones,
  ultrasonic cross-device tracking beacons.
- **Power-line and conducted emissions** — data over power, and conducted EM leakage.
- **Specialist RF protocol families** — ADS-B/avionics, marine AIS, TETRA/P25 land mobile radio,
  DECT. High consequence in specific verticals, out of scope for a general enterprise track.
- **Optical-layer quantum key distribution as an operational detection surface.** TX-02 §9 states
  the policy position (QKD is not a substitute for PQC, and PQC per `CONVENTIONS §1` remains the
  GreyNOC default) but does not provide QKD-specific monitoring content.
*(One gap listed here at first audit — the TX track's absence from the compiled PDF — was closed
during remediation; see §6.5.)*

---

## 6. Actions taken

1. Authored [`TX-01-rf-spectrum-intrusion.md`](TX-01-rf-spectrum-intrusion.md) — closes F-01.
2. Authored [`TX-02-optical-nm-data-transmission-intrusion.md`](TX-02-optical-nm-data-transmission-intrusion.md) — closes F-02.
3. Amended `CONVENTIONS.md` §5 (three-collection cross-reference notation) and §8.1 (TX track
   owns no defect-class prefix) — closes F-04.
4. Added the Transmission & Physical Layer collection to `README.md` and `index.html`.
5. Extended the PDF builder to a multi-publication pipeline
   (`scripts/build_ai_pqc_pdf.mjs` → `scripts/build_playbook_pdfs.mjs`), adding a `transmission`
   publication (`GN-PUB-TXPHY-001`, v1.0.0). The AI/PQC publication rebuilt at an **identical 151
   pages**, confirming the refactor is output-preserving; its byte size grew by the
   `CONVENTIONS.md` §5/§8.1 edits it carries as a source. The new
   `GreyNOC_Transmission_Physical_Layer_Playbooks.pdf` is 39 pages with 80 outline entries.
6. Logged residual gaps in §5 above rather than implying the medium is now fully covered.

---

## 7. Addendum — the track extended below the medium (TX-03)

This audit scoped *transmission media*. A subsequent review found the adjacent gap that scoping
missed: the library had no coverage of the **silicon in which the post-quantum algorithms actually
execute** — the layer below every medium, where a key is a voltage rather than an integer.

[`TX-03`](TX-03-pq-nanometer-silicon-physical-attack.md) closes it, and carries two findings that
change positions taken elsewhere in the library:

- **A FIPS 140-3 validated ML-KEM module carries no side-channel assurance.** FIPS 140-3 introduced
  a "non-invasive security" requirement area; CMVP never populated it. SP 800-140F approves no test
  metrics, its Revision 1 draft was never finalized, and the Implementation Guidance's Section 8 and
  Annex F are empty. Any procurement or vendor-assurance artifact (`PB-27`) that treats FIPS
  validation as evidence of physical resistance is overstating it.
- **The most damaging published break of a NIST PQC implementation was caused by a compiler and is
  network-reachable** (CVE-2024-37880, CVSS 7.5, `AV:N`). Constant-time source, variable-time
  binary. This makes "verify the binary, not the source" a build-pipeline control rather than a
  research curiosity.

TX-03 also settles the **physical floor** of the track: Planck-scale intrusion is not an attack
surface, the claim is recorded as a fabrication indicator rather than a threat, and the reproducible
negative search behind that conclusion is published with it. That question is now closed and should
not be re-litigated.

TX-03 introduces an evidence-grading convention (`[hw]`/`[sim]`/`[norm]`/`[adv]`/`[relayed]`/
`[vendor]`) now recorded in `CONVENTIONS.md` §8.1. The residual gaps in §5 above are unaffected —
TX-03 covers a different axis (depth), not the media still missing.

---

*GreyNOC — detection-engineering-first. Reproducible or it didn't happen.*
