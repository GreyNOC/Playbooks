# GreyNOC Security Playbook

## TX-03 — Post-Quantum Cryptography at the Nanometer Scale: Silicon, Physical Attack & the Physics Floor

---

### 1. Overview

`TX-01` covers the radio medium. `TX-02` covers the optical medium. This playbook goes *below* the
medium, into the silicon where ML-KEM and ML-DSA actually execute — where a key is not an abstract
integer but a voltage on a wire, a charge in a cell, and a pattern of switching current that
radiates.

The organizing fact is this: **the post-quantum migration replaced algorithms whose implementation
security had twenty-five years of attack literature behind it with algorithms whose implementation
security is being written right now.** The mathematics of ML-KEM and ML-DSA is the most scrutinized
part of the transition. The silicon is the least.

**None of the attacks in §7–§9 break the lattice problem, and none of them care whether a quantum
computer exists.** Beyond that shared property they divide three ways, and the distinction matters
when you decide what to fix: some target a *correct* implementation of a standardized algorithm
(the side-channel and fault work in §7.2–§7.4, §8 and §10); some exploit a *defective*
implementation, whether written that way (KyberSlash) or produced that way by a compiler (Clangover,
§7.1); and some subvert the implementation or the silicon outright, so no algorithm is being
attacked at all (§9's trojans and malicious key generation). Note also that §7.3's software-reachable
power and frequency channels have no published application to ML-KEM or ML-DSA specifically — that
is recorded there as a gap, not extrapolated.

Three findings drive everything below, and each is verifiable from a primary source:

1. **The most damaging published break of a NIST PQC implementation to date was caused by a
   compiler, is reachable over a network, and needed no laboratory.** CVE-2024-37880 (CVSS 7.5,
   `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`), quoted in full: "The Kyber reference implementation before
   `9b8d306`, when compiled by LLVM Clang through 18.x with some common optimization options, has a
   timing side channel that allows attackers to recover an ML-KEM 512 secret key in minutes. This
   occurs because `poly_frommsg` in `poly.c` does not prevent Clang from emitting a vulnerable
   secret-dependent branch." Constant-time source, non-constant-time binary.
2. **A FIPS 140-3 validated ML-KEM module carries no side-channel assurance whatsoever.** FIPS 140-3
   created a "non-invasive security" requirement area and CMVP has never populated it — SP 800-140F
   approves no test metrics, and the Implementation Guidance's Section 8 and Annex F are empty. This
   is a procurement fact with immediate contractual consequences (§11).
3. **There is no Planck-scale attack surface, and the claim that there is one is a fabrication
   indicator.** Appendix A settles this with numbers rather than assertion, because the physical
   floor of this track needed to be documented once, properly, so it never has to be argued again.

**Related:** `TX-01`, `TX-02` (the media above this layer), `PB-01` (CBOM — extend it to silicon),
`PB-05` (PQ signature and token integrity — this is the layer where those signatures are computed),
`PB-11` (PQ code signing and firmware — the LMS/XMSS state hazards in §10.5 are its physical
counterpart), `PB-13` (crypto-agility), `PB-14` (Mosca margin — drives which keys justify which
controls), `PB-25` (key management — the rotation path when a device is compromised), `PB-27`
(vendor assurance — §11 is its evidence base), `D&R-19` (AI security incident response — the nearest
IR twin in the library, but note its evidence and containment steps are AI-specific and do not cover
physical-custody incidents).

---

### 2. Scope

**In scope.** Physical and physically-derived attacks against implementations of the post-quantum
standards — ML-KEM (FIPS 203), ML-DSA (FIPS 204), SLH-DSA (FIPS 205), FN-DSA/Falcon (FIPS 206, in
development), and the stateful hash-based signatures LMS/XMSS (SP 800-208) — across three access
tiers: software-reachable (§7), bench/laboratory (§8), and fabrication/supply chain (§9). Plus the
assurance regime that is supposed to govern them (§11), and the physical limits that bound the whole
subject (Appendix A).

**Explicitly out of scope.** Naming these matters as much as naming what is in, because this subject
has unusually porous edges:

1. **Quantum-gravity phenomenology as a threat model.** Any claimed attack requiring physics beyond
   the Standard Model plus general relativity is out of scope as a threat and retained only as a
   fabrication indicator (§3, Appendix A).
2. **The cryptanalytic quantum threat** — Shor, Grover, HNDL, CRQC timelines. That is `PB-02` and
   `PB-14`. This playbook is about implementations, not algorithms.
3. **Mathematical cryptanalysis** of the PQC schemes — lattice reduction, MLWE hardness, parameter
   selection.
4. **The transmission medium** — RF (`TX-01`), fiber/FSO/ROADM (`TX-02`). This playbook begins below
   the medium.
5. **General transient-execution and microarchitectural attacks** — Spectre, Meltdown, MDS, and
   cache side channels. Hertzbleed, PLATYPUS, Plundervolt and Rowhammer stay **in**, because they
   are *physical* mechanisms reached from software. The boundary is physics, not privilege.
6. **Non-silicon emanations** — acoustic, thermal-at-range, screen emanation, classical TEMPEST.
   Route to `TX-01 §5.7`.
7. **Attacks on quantum hardware** — QKD implementation attacks, quantum-computer control planes.
8. **Building or operating attack equipment.** No FIB recipes, laser-rig construction, beamtime
   procedures, or hammering primitives. Capability is characterized for defense, procurement and
   risk rating only.
9. **Unauthorized testing.** `CONVENTIONS §6` ROE binds everything here. Destructive analysis is
   performed only on assets the operator owns or is contracted to destroy.
10. **Speculative capability with no demonstrated instance** — notably cryptographic key recovery by
    X-ray or gamma fault injection. No published work demonstrates it; it is recorded as a negative,
    date-stamped, and not modeled as a live threat.

---

### 3. Provenance discipline and fabrication indicators

This subject mixes four unrelated physics regimes and a marketing vocabulary, and the failure mode
is not error — it is *plausible* error that survives review. The following rules are normative for
any GreyNOC artifact derived from this playbook. They are written to be quoted directly into a
report.

> **Every length carries its provenance: measured, projected, derived, or marketing. A process-node
> name is a marketing label and is never used as a dimension.**

> **"Quantum" in ML-KEM and ML-DSA denotes an adversary's computational model.** No mechanism in
> this playbook depends on quantum-gravitational physics, and none of the attacks described changes
> if quantum gravity is or is not real.

> **A null result is reported as "not observed at the stated sensitivity, with the exclusion bound
> quoted" — never as "does not exist."**

> **The Planck length is a limit on measurement, not an interface.** It bounds what any probe can
> resolve; it does not describe anything an adversary can address, modulate, or exfiltrate through.

> **Resolution is not capability.** An imaging or beam-spot figure is admissible only alongside the
> demonstrated outcome it produced, on a named target, with the sample preparation stated.

> **Every quoted number is labeled measured / simulated / relayed / vendor-stated.** Relayed figures
> are never presented as the citing authors' own measurements. Where a paper attacks a
> proof-of-concept the authors implemented themselves, the artifact says so in the same sentence as
> the result.

> **If a claim's only support is that a number is very small or very large, it is not a claim.**

> **The phrases "Planck-length intrusion", "Planck-scale attack surface" and "sub-Planck side
> channel" have no referent in information security.** Their appearance in a report, finding, or
> vendor claim triggers a provenance review of the entire document, not a technical investigation.

**Evidence grades used throughout.** Every attack in §7–§10 carries one:

| Grade | Meaning |
| --- | --- |
| `[hw]` | Demonstrated on real hardware, with the platform named |
| `[sim]` | Demonstrated in a leakage model or simulation only — no measured traces |
| `[norm]` | Normative standard text ("shall") |
| `[adv]` | Advisory standard text ("should", "care must be taken") |
| `[relayed]` | The citing authors quote a third party; not their own measurement |
| `[vendor]` | Vendor-stated, unaudited |
| `[analysis]` | Analytical or formal result — a proof, model, or standards analysis; no implementation demonstrated |

An attack at `[sim]` is never tabulated beside one at `[hw]` without the grade visible. This single
convention prevents most of the overclaiming this field is prone to.

---

### 4. The length-scale ladder

Four different physics, one word ("small"). Putting these on a single mental ladder is the most
common error in this subject.

| Scale | Value | What it is | Provenance |
| --- | --- | --- | --- |
| Fiber C-band | 1530–1565 nm | The medium of `TX-02` | measured |
| Optical probing / LFI | 1064–1300 nm | Light that penetrates bulk silicon backside | measured |
| Optical prober / LFI spot | ~1 µm without SIL; ~200 nm with | What an optical prober resolves — set by objective NA and, for laser fault injection, by the optical path. **Not a diffraction floor** (§8.2) | measured / `[relayed]` |
| Photon emission band | above ~1 µm | Where silicon is transparent to its own emission | measured |
| SRAM / BBRAM cell | 1.9 × 2.5 µm to 3.1 × 2.8 µm | What actually has to be resolved to read a bit | measured |
| Metal / gate pitch | 23–50 nm | Real device dimensions | measured (vendor/analyst) |
| Node *name* | "3 nm", "2 nm" | **A marketing label. Not a dimension.** | marketing |
| EUV exposure wavelength | 13.5 nm | Lithography light | measured |
| Physical gate length floor | ~12 nm | Projected saturation | **projected** (IRDS roadmap target) |
| X-ray imaging of ICs | nanometre-class | Non-destructive inspection | measured |
| Planck length | 1.616255(18) × 10⁻³⁵ m | A limit on measurement | derived constant |

Two entries deserve emphasis because both have caused published errors:

- **Node names decoupled from physical dimensions in the mid-1990s.** IEEE Spectrum (Samuel K.
  Moore, 21 July 2020) quotes Paolo Gargini — IEEE Life Fellow, Intel veteran, IRDS chair — that a
  node name has "nothing to do with any dimension that you can find on the die"; Intel's 22 nm
  FinFET generation had a 26 nm gate length, 40 nm half-pitch and 8 nm fin width. Real published
  pitches: Intel 4's scaled high-performance library offers a 50 nm gate pitch, 30 nm fin pitch and
  30 nm minimum metal pitch (VLSI 2022); analyst reporting on TSMC's IEDM 2022 papers gives a 45 nm
  contacted gate pitch for N3 and a 23 nm minimum metal pitch for N3E. **Dividing an optical spot
  size by a node name produces a number that means nothing** — a mistake made during the research
  for this very playbook and caught in adversarial review.
- **IRDS `GxxMxx/Tx` figures are projected roadmap targets**, not measured pitches. IRDS 2024
  projects physical channel length saturating near 12 nm. Cite them as projections.

---

### 5. MITRE ATT&CK Mapping

| Technique | ID | Matrix | Tactic |
|-----------|----|--------|--------|
| Hardware Additions | T1200 | Enterprise | Initial Access |
| Supply Chain Compromise: Compromise Hardware Supply Chain | T1195.003 | Enterprise | Initial Access |
| Weaken Encryption | T1600 | Enterprise | Defense Impairment |
| Unsecured Credentials: Private Keys | T1552.004 | Enterprise | Credential Access |
| Exploitation for Privilege Escalation | T1068 | Enterprise | Privilege Escalation |
| Subvert Trust Controls: Code Signing | T1553.002 | Enterprise | Defense Impairment |
| Pre-OS Boot: System Firmware | T1542.001 | Enterprise | Persistence, Stealth |
| Forge Web Credentials | T1606 | Enterprise | Credential Access |

> **Mapping discipline (`CONVENTIONS §4`).** This table was verified against **ATT&CK Enterprise
> v19.2** on **2026-08-09**, row by row. That version matters: **v19 retired the "Defense Evasion"
> tactic**, renaming TA0005 to **Stealth** and splitting out **TA0112 Defense Impairment**. Any
> artifact carrying a "Defense Evasion" tag for `T1600`, `T1553.002` or `T1599` is mapped against a
> pre-v19 collection and must be re-mapped, exactly as `CONVENTIONS §4` requires for ATLAS. Note
> that `T1542.001` and `T1553.002` landed on **opposite sides** of that split, so neither can be
> inferred from the other — and that v19 also renumbered techniques outright (`T1562` and
> `T1070.001` no longer exist). Re-verify against the version your platform carries.

**Deliberately unmapped.** Per `CONVENTIONS §4`, these have no clean technique and are described
rather than tagged: **side-channel key extraction** (power/EM/timing/photonic — `T1552.004` covers
the *outcome*, not the mechanism), **fault injection**, **Rowhammer**, **optical probing**,
**dopant- or analog-level hardware trojans**, **malicious key generation**, and **hardware key-store
extraction** (`T1555 Credentials from Password Stores` describes *software* credential stores and
does not cover pulling a key out of an HSM or secure element — it is deliberately not tagged here).
Tag these with the descriptive class name in the heading of the §7–§9 subsection they belong to
(for example *compiler-emitted branch*, *Rowhammer fault delivery*, *optical probing*,
*malicious key generation*) and describe the mechanism. These classes are deliberately **not** given
a defect-class prefix under `CONVENTIONS §8.1` — that registry belongs to the bug-bounty catalogs,
and a prefix here would invite a triager to read a silicon-level event as an application defect.

---

### 6. Attack tiers — and what each actually yields a defender

Actionability collapses sharply as physical access increases. Being explicit about this is what
separates a usable playbook from a literature review.

| Tier | Access required | Runtime detection? | What a defender actually gets |
| --- | --- | --- | --- |
| **A — Software-reachable** (§7) | Unprivileged or privileged code on the target; sometimes only network | **Yes** — patchable, testable, telemetry exists | Nearly all deployable controls live here |
| **B — Bench / laboratory** (§8) | Unattended physical possession of the device | **No** | Design-time and procurement requirements only |
| **C — Fabrication / supply chain** (§9) | Access to design, mask, fab, or distribution | **No** (post-fab detection is inspection, not monitoring) | Provenance, inspection sampling, procurement |

**Say the quiet part in every report built on this playbook:** for Tier B and Tier C there is *no
runtime detection*. The compensating control is blast-radius reduction — per-device keys, short
validity, no global signing key resident on a fielded device, revocation that functions, and
attestation that fails closed. If a report implies a SOC can detect an optical probing attack in
progress, it is wrong.

---

### 7. Tier A — software-reachable physical attacks

No laboratory. No physical possession. This is where the CVEs are.

#### 7.1 Compiler-induced timing leakage — the defining defect class

**KyberSlash.** `[hw]` Two timing vulnerabilities exploiting secret-dependent division timings in
several Kyber/ML-KEM implementations *including the official reference code*, demonstrated on
Raspberry Pi 2 (Arm Cortex-A7) and Arm Cortex-M4. Kyber secret keys were "reliably recovered within
minutes for KyberSlash2 and a few hours for KyberSlash1" (Bernstein et al., TCHES 2025).

**Clangover / CVE-2024-37880** is a **separate defect from KyberSlash**, and the record that should
change procurement language: the Kyber reference implementation before commit `9b8d306`, **when
compiled by LLVM Clang through 18.x with some common optimization options**, has a timing side
channel allowing recovery of an ML-KEM-512 secret key in minutes — "because `poly_frommsg` in
`poly.c` does not prevent Clang from emitting a vulnerable secret-dependent branch." CVSS 7.5,
vector `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`.

**Keep the two straight, because they patch separately.** KyberSlash is a *source-level* defect —
secret-dependent **division** — fixed by library patches. Clangover is a *compiler-emitted*
**branch** in `poly_frommsg`, fixed by commit `9b8d306`, which replaced the vulnerable construct so
Clang could no longer lower it to a branch. **A KyberSlash-patched library is not necessarily past
`9b8d306`.** Verify both.

Three properties make this the most important single entry in the playbook:

- **NVD scored it `AV:N/PR:N/UI:N`** `[relayed — an NVD scoring judgement, not a demonstrated
  remote exploit]`. The published proof of concept is a *local* attack using end-to-end
  decapsulation timing; no network-side demonstration has been published. Both facts belong in a
  report — the rating drives triage, the demonstration drives realism.
- **It recovers the long-term secret key**, not a session key.
- **The source was constant-time; the compiler was not.** Reviewing source code would not have
  found it. This is the property that makes it a build-pipeline problem rather than a coding one.

**The control follows directly: verify the binary, not the source.** The KyberSlash authors patched
Valgrind to detect variable-time instructions operating on secret data and ran it across more than
1,000 cryptographic primitive implementations in SUPERCOP, reporting multiple findings. That is a
reproducible method a defender can adopt.

#### 7.2 Rowhammer as a fault-injection delivery vehicle

Rowhammer converts "physical fault injection" from a lab capability into a software one, and two
published attacks turn it directly into PQC key compromise.

**Phoenix (CVE-2025-6202).** `[hw]` "Vulnerability in SK Hynix DDR5 on x86 allows a local attacker
to trigger Rowhammer bit flips impacting the Hardware Integrity and the system's security. This
issue affects DDR5: DIMMs produced from 2021-1 until 2024-12." CVSS 4.0 base 7.1,
`AV:L/AC:H/AT:N/PR:L/UI:N/VC:N/VI:H/VA:N/SC:H/SI:H/SA:H`. The research team reports **all 15 SK Hynix
DDR5 DIMMs tested were vulnerable** to one of two patterns, average time to privilege escalation
5 min 19 s (fastest 109 s).

**On-die ECC does not save you, and the reason is worth understanding.** The researchers state bit
flips "accumulate over time as ODECC only corrects bits after writing data or after a certain time
(e.g., every 24 hours)." Treating DDR5 on-die ECC as a Rowhammer mitigation is a documented error.

Mitigation with a measured cost: tripling the refresh rate (tREFI ≈ 1.3 µs) stops the attack at an
overhead of 8.4% running SPEC CPU2017.

**Crowhammer against FN-DSA/Falcon.** `[analysis]` A *single* targeted bit flip in Falcon's
hardcoded reverse cumulative distribution table (RCDT) for the base Gaussian sampler suffices for
full signing-key recovery, given on the order of a few hundred million signatures; more flips reduce
the signature requirement (CRYPTO 2025). **Grade this honestly:** the paper is a cryptanalytic
result that *proves the resulting distribution is skewed enough to recover the key* assuming the
flip has occurred — the authors report no first-party Rowhammer attack on physical DRAM and name no
platform, and they note the same vulnerability "can also be triggered with other types of persistent
fault attacks on memory like optical faults." The fault-delivery half of the chain is §7.2's
Phoenix-class capability; the cryptanalysis half is this paper. Do not cite it as a demonstrated
end-to-end hardware attack.

**SLasH-DSA against SLH-DSA.** `[hw]` Universal forgery against SLH-DSA by a **software-only**
Rowhammer attack on commodity hardware with no physical access, demonstrated end-to-end against
OpenSSL 3.5.1.

That last pair is the point of this section: the two hash- and lattice-signature schemes chosen
partly for conservative security margins are both breakable through a memory-controller defect,
without touching the cryptography.

#### 7.3 Software-reachable power, frequency and voltage channels

Physical channels reached with no instrumentation. All CVE records below were verified against NVD.

| Attack | Grade | CVE | Description (NVD, verbatim) | CVSS / vector |
| --- | --- | --- | --- | --- |
| Hertzbleed (Intel) | `[hw]` | CVE-2022-24436 | "Observable behavioral in power management throttling for some Intel(R) Processors may allow an authenticated user to potentially enable information disclosure via network access." | 6.5 `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` |
| Hertzbleed (AMD) | `[hw]` | CVE-2022-23823 | "A potential vulnerability in some AMD processors using frequency scaling may allow an authenticated attacker to execute a timing attack to potentially enable information disclosure." | 6.5 `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` |
| Hertzbleed (Ampere) | `[hw]` | CVE-2022-35888 | "Ampere Altra and Ampere Altra Max devices through 2022-07-15 allow attacks via Hertzbleed, which is a power side-channel attack that extracts secret information from the CPU by correlating the power consumption with data being processed on the system." | 6.5 `AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N` |
| PLATYPUS (driver) | `[hw]` | CVE-2020-8694 | "Insufficient access control in the Linux kernel driver for some Intel(R) Processors may allow an authenticated user to potentially enable information disclosure via local access." | 5.5 `AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` |
| PLATYPUS (RAPL) | `[hw]` | CVE-2020-8695 | "Observable discrepancy in the RAPL interface for some Intel(R) Processors may allow a privileged user to potentially enable information disclosure via local access." | 5.5 `AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` |
| Plundervolt | `[hw]` | CVE-2019-11157 | "Improper conditions check in voltage settings for some Intel(R) Processors may allow a privileged user to potentially enable escalation of privilege and/or information disclosure via local access." | 6.7 `AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H` |

**Note the vectors, they carry the whole threat model.** All three Hertzbleed CVEs are `AV:N`
(network). Both PLATYPUS CVEs and Plundervolt are `AV:L` (local), and Plundervolt additionally
requires `PR:H` — a privileged attacker, which matters because its target was SGX, where the threat
model assumes exactly that.

**No published work applies these specific software-reachable channels to ML-KEM or ML-DSA
implementations as of this writing.** That is stated as a gap, not extrapolated into a claim. The
mechanism is scheme-agnostic and the schemes are new; treat absence of published work as absence of
research attention, not as evidence of resistance.

#### 7.4 Entropy-source manipulation

The entropy source is the floor under every key on the device, and it is physically manipulable.
NIST SP 800-90B governs entropy-source design, health tests (startup, continuous, on-demand) and
validation. FIPS 203 requires approved randomness; ML-DSA hedged signing and SLH-DSA randomized
signing consume it continuously.

`[hw]` Ring-oscillator TRNGs are susceptible to frequency-injection locking, in which an injected
supply frequency destroys jitter entropy (Markettos & Moore, CHES 2009). *The specific keyspace-reduction
figures widely quoted from that paper are not reproduced here — the PDF could not be retrieved for
verbatim verification during research, and per §3 an unverified number is omitted rather than
repeated.* The mechanism is well established; the magnitudes require a first-party read before they
appear in a GreyNOC artifact.

**Control:** require SP 800-90B validated entropy with continuous health tests, and treat power-rail
filtering and on-chip regulation as *security* controls rather than EMC controls.

---

### 8. Tier B — bench and laboratory attacks

Requires unattended physical possession. **No runtime detection exists for anything in this
section.** Its value is design-time and procurement requirements, and an honest actor-tier rating.

#### 8.1 Why light gets into a chip at all

Silicon's room-temperature bandgap is about 1.12 eV, corresponding to roughly 1110 nm; above that
wavelength single-photon absorption is forbidden, so silicon becomes transparent. Absorption falls
steeply but does not switch off around 1100 nm — measured coefficients are 64 /cm at 1000 nm,
16.3 /cm at 1050 nm, 3.5 /cm at 1100 nm, 0.68 /cm at 1150 nm, 0.022 /cm at 1200 nm.

This single material property is why the backside of a die is an attack surface, why 1064 nm is the
standard backside laser wavelength, and why **the probing band overlaps the fiber-optic bands of
`TX-02`** — 1.3 µm optical probing sits in the same spectral neighborhood as O-band transport. The
two playbooks describe the same photons doing different jobs.

A frequently-cited "700 µm penetration depth at 1.06 µm" figure appears in Skorobogatov & Anderson
(CHES 2002) — but `[relayed]`, they cite it to a third party, and the sentence immediately following
says focusing "is restricted by dispersion to several micrometers, and this is not precise enough."
Quoting the depth without the focusing caveat inverts the paper's meaning.

#### 8.2 Laser fault injection

`[hw]` Frontside attacks use 532 nm; backside attacks use 1064 nm, and the split is set by the
absorption behavior above. Commercial tooling is openly sold — the Keysight DS1112A is a 1064 nm
multimode fault-injection laser `[vendor]` rated 30 W pulse power, pulse width as small as 2 ns, up
to 50 MHz (Keysight datasheet figures, unaudited).

Reported spot sizes cluster at 0.5–1 µm. **This is a tooling limit, not a diffraction limit** —
NetSPI attributes its spot to "a low-cost, manually adjustable optical path," and Krachenfels et al.
report ~1 µm without a solid immersion lens. Describing it as diffraction-limited overstates the
physics and understates how much better a funded adversary can do.

Two-photon-absorption LFI uses sub-bandgap wavelengths with femtosecond pulses, where the absorption
coefficient is almost zero and penetration depth exceeds 10⁵ µm; the nonlinear response can be
narrower than the Abbe limit. At equal power, 1064 nm single-photon absorption generates roughly 6×
higher electron-hole density, leading to latch-up and unwanted damage — which is why TPA is
preferred for precision work.

Historical baseline worth keeping for perspective: `[hw]` a $30 second-hand camera flashgun and an
$8 laser pointer could set or reset any individual SRAM bit in a Microchip PIC16F84 after standard
depackaging (CHES 2002) — while the paper notes the best-designed secure microcontrollers of that
era already resisted single laser flashes.

**Against PQC specifically:** `[hw]` laser fault injection against the random-seed pointer used in
polynomial sampling yields full key and message recovery for ML-KEM and signature forgery for
ML-DSA, with success rates up to 100%, on an STM32H7 — and the affected code pattern is reported
present in pqm4, liboqs, PQClean and wolfSSL (ePrint 2025/2009). That is a source-level finding a
defender can act on today.

#### 8.3 Photonic emission analysis

`[hw]` Switching CMOS transistors emit photons through hot-carrier luminescence at the drain edge,
dominant in n-type devices, with generation rate proportional to supply voltage and switching
frequency. Emission must be observed from the backside because frontside metal blocks the photons;
InGaAs sensors work above ~1 µm where silicon is transparent, so **substrate thinning becomes
unnecessary**.

Demonstrated outcomes: a full AES-128 key recovered from an ATmega328P via SRAM row-decoder
emissions with the backside polished to ~25 µm remaining substrate and 120 s emission images
(CHES 2012 — noting the target was a proof-of-concept AES implementation the authors wrote); and
100% of the secret key bits of 2048-bit RSA keys recovered with as few as 4,000 decryptions, with
Montgomery's Ladder the most susceptible of the three implementations tested (ePrint 2017/108).

**Two countermeasure facts that routinely surprise architects:** memory encryption and scrambling
have no effect on optical emission, and scrambling can make the attack *easier*. Shields and meshes
generally protect only the frontside.

#### 8.4 Optical probing — EOFM, LLSI, LVP/LVI

`[hw]` Electro-optical frequency mapping scans >1 µm light through the backside; transistor electric
fields modulate the reflected light's amplitude and phase, and narrow-band filtering yields a 2-D map
of nodes switching at a chosen frequency. Laser logic-state imaging extends this to recover *static*
logic state with no switching activity, by modulating the core supply so only on-state transistors
respond.

Demonstrated: laser voltage probing at 1.3 µm on a 60 nm Altera Cyclone IV recovered the plaintext
"red key" of a PUF-protected bitstream-encryption scheme (CHES 2016) — **a proof-of-concept the
authors built themselves, not a shipped product**. And backside optical contactless probing broke
commercial 28 nm FPGA bitstream encryption at ~1 µm resolution, without silicon polishing, in under
10 days of analysis (CCS 2017).

**Silicon light sensors are structurally blind to this attack at practical probing intensities** —
silicon barely absorbs sub-bandgap light (§8.1 gives the measured coefficients: 0.68 /cm at 1150 nm,
0.022 /cm at 1200 nm), so no meaningful photocurrent trips the sensor. Stated as a bound rather than
an absolute, per §3. This is the load-bearing defensive fact of the section:
the standard on-die countermeasure does not apply.

**Why advanced nodes do not save you, stated correctly.** Detecting a bit is not the same as
resolving a transistor: optical probing only requires the response image to differ between logic 0
and 1. Memory cells do not scale with the logic node — measured examples include 2.8 × 3.1 µm BBRAM
on a 20 nm FPGA and 2.5 × 1.9 µm SRAM on a 180 nm MCU. Resolution is ~1 µm without a solid immersion
lens and approximately 200 nm with one (`[relayed]` — Krachenfels et al. cite this figure to others;
their own measured value is the 1 µm without-SIL number). Optical probing is reported as reaching
obsolescence at "sub-7nm" nodes, motivating electron-beam probing at roughly 20× better spatial
resolution (ISTFA 2023) — *"sub-7nm" there is the source's node-generation label, used as a
technology boundary and not as a dimension, per §3.*

Bare-die flip-chip packages need no preparation at all for backside access, and flip-chip is
increasingly prevalent at 20 nm and below.

#### 8.5 Actor tiering — who can actually do this

Capability without cost is fearmongering. Published figures:

- A combined thermal-laser-stimulation + LLSI setup ~$1M; TLS-only ~$100k; **a laser scanning
  microscope can be rented for about $300/hour including an operator.** Rented capability is a
  distinct actor tier and should be modeled as one.
- Integrated PICA systems started around €1M in 2012; the CHES 2012 alternative cost approximately
  the price of a mid-range oscilloscope.
- **JIL** ("Application of Attack Potential to Smartcards and Similar Devices") classifies
  failure-analysis-grade equipment — FIB, SEM, abrasive laser — as *Bespoke*, the second-highest of
  four tiers (rating points: None 0/0, Standard 1/2, Specialized 3/4, Bespoke 5/6, Multiple Bespoke
  7/8), notes only a small number of experts operate it, and allows renting to reduce the rating.
- **PSA Certified Attack Methods v1.3** rates laser fault injection only *specialized* equipment with
  an attack rating of 21 or more — "unlikely to be in scope for Level 3", and required consideration
  for Level 4.

The number to put in a risk register is not the per-tool rating but the **escalation rule**: where
clearly different specialized benches are needed for distinct attack steps, the rating escalates.
A real invasive chain escalates; do not let "low-end FIB is only Specialized" stand alone.

---

### 9. Tier C — fabrication and supply chain

#### 9.1 Hardware trojans — what was actually demonstrated

Precision matters here more than anywhere else in the playbook, because this area is heavily
mythologized.

**Dopant-level trojans** `[sim]` (Becker et al., CHES 2013) are built by flipping the dopant polarity
of existing transistors, adding no gates, transistors or wires. Evaluated against a post-processing
block derived from Intel's Ivy Bridge RNG and an iMDPL AES SBox. The RNG trojan sets all flip-flops
storing the AES key to constants and (128−n) of the 128 flip-flops storing the input to constants,
leaving n bits of real entropy while output still passes the NIST statistical test suite at n = 32;
the design's own BIST was defeated at a cost of about 2³¹ offline tries against a 32-bit CRC.

**This work was never fabricated in silicon.** It was layout-level in the 45 nm Nangate Open Cell
Library, verified with DRC, Calibre PEX and HSpice, with the side-channel attack conducted on
*simulated* power traces. And the stealth claim was specific — against optical reverse engineering
and golden-chip comparison — not against all physical inspection.

**The stealth assumption was subsequently contradicted.** Sugawara et al. (ePrint 2014/508)
demonstrated detection using SEM and FIB imaging exploiting passive voltage contrast after
delayering to the contact layer — though note they measured a dedicated chip built on the same
principle, not a Becker-trojaned device.

**A fabrication-time trojan *has* been demonstrated in real fabricated silicon:** the A2 analog
trojan `[hw]`, built in 65 nm CMOS inside an OR1200 processor and weaponized as remotely triggerable
privilege escalation, at a cost of as little as one gate (IEEE S&P 2016). When a threat model needs a
demonstrated fabrication-time trojan, this is the citation — not the dopant work.

#### 9.2 Malicious key generation — the PQC-native supply-chain attack

`[analysis]` A generic backdoor mechanism applies to LWE-like public-key cryptosystems including
ML-KEM (Kyber), ML-DSA (Dilithium), FrodoKEM and HQC: key generation is manipulated so an adversary holding secret
backdoor information can recover private keys from public keys, while the output is
**indistinguishable from legitimate key generation** to the user (Hemmert, BSI, ePrint 2022/1381).

This is far cheaper and far more valuable than a dopant-level trojan, and it is the bridge between
§9.1 and the algorithms. The proposed countermeasure is directly actionable: derive both public and
private keys pseudorandomly from a single seed included in the private key, so a user can
**regenerate the keypair with an independent implementation** and detect the subversion.

**Procurement question this creates:** for any device that generates its own long-lived PQC keys, can
you regenerate and verify that keypair from a seed using independent software? If not, you are
trusting the generator absolutely.

#### 9.3 Counterfeits and provenance

Counterfeit types are classified into **seven** categories — recycled, remarked, overproduced,
out-of-spec/defective, cloned, forged documentation, and **tampered** (die-level trojan, package
level, or software/firmware). The seventh is what links counterfeiting to §9.1 and is the one most
often dropped from summaries. Recycled and remarked jointly account for more than 80% of incidents
(`[relayed]` — an industry estimate carried into a survey).

Detection splits into physical inspection (low-power visual, X-ray, SEM, SAM, decapsulation,
XRF/FTIR/EDS) and electrical inspection (parametric, Iddq, path-delay fingerprinting via clock
sweeping, one-class classifiers trained on new devices only). Avoidance is distinct from detection:
CDIR aging odometers, PUFs, secure split test, hardware metering, package IDs.

#### 9.4 What attestation does and does not cover

This is the most consequential misunderstanding in hardware supply-chain security.

- **RFC 9334 (RATS Architecture) is Informational**, not Standards Track, and deliberately does not
  standardize how an Attester's signatures are validated.
- **The hardware root of trust is not itself attested.** RATS defines roots of trust as the
  components for which no Evidence is generated, and which must be vouched for by manufacturer
  Endorsement.
- **Evidence covers operational status, health, configuration, construction claims and code/memory
  measurements — not silicon provenance, mask integrity, or absence of fabrication-time
  modification.**
- **Caliptra explicitly places out of its threat model:** manufacturing operational security, foundry
  IP integration, physical design countermeasures, OSAT test/initialization, and invasive
  depackaging/delayering attacks. (Caliptra does use dual ECC secp384r1 + ML-DSA-87 signatures in its
  certificates and supports LMS verification for firmware — good PQ hygiene, orthogonal to the
  physical threat.)

**So: attestation tells you what software is running on the silicon you were given. It tells you
nothing about whether that silicon is what you ordered.** Any risk register that treats attestation
as supply-chain assurance has a gap exactly the size of §9.1 and §9.2.

#### 9.5 Concentration risk

EUV lithography exposes at 13.5 nm, roughly 15× shorter than the 193 nm ArF DUV it supplements. As
of its FY2021 Form 20-F, ASML stated it is "the world's only manufacturer of EUV lithography
systems", and its 2025 Annual Report identifies Carl Zeiss SMT as sole supplier of critical optical
components. Date-stamp any statement of this kind rather than asserting it in the present tense.

A cautionary note for threat modeling: the most widely cited alleged real-world hardware implant in
commercial servers was publicly contradicted by DHS and the UK NCSC. Hardware-implant claims require
the same evidence bar as any other finding.

---

### 10. PQC exposure by scheme

Published, verified attacks against implementations of the standards. Platform is ARM Cortex-M4
unless stated. Every entry is graded per §3.

#### 10.1 ML-KEM (FIPS 203)

| Attack | Grade | Recovers | Notes |
| --- | --- | --- | --- |
| Compiler-emitted secret-dependent branch in `poly_frommsg` (Clangover / CVE-2024-37880) | `[hw]` | **Long-term secret key** | Network vector; minutes; reference code before `9b8d306` |
| Secret-dependent division timing (KyberSlash1 / KyberSlash2) | `[hw]` | **Long-term secret key** | Source-level defect, **distinct from CVE-2024-37880 and separately patched**; minutes (KS2) to hours (KS1) |
| Generic EM chosen-ciphertext on CCA decapsulation | `[hw]` | Long-term secret key | "In minutes", pqm4 implementations |
| CPA + lattice reduction, two-step | `[hw]` | Long-term secret key | ≤15 traces, ~9–10 min, all three parameter sets |
| FO re-encryption leakage as plaintext-checking oracle | `[hw]` | Long-term secret key | Works against masked implementations |
| Instruction-skip fault in message decoding | `[hw]` | Long-term secret key | ~6,500 faulty decapsulations, clock glitch |
| Instruction-skip defeating the FO equality test | `[hw]` | Turns KEM into a decryption oracle | Also NTRU, Saber, BIKE, SIKE |
| Laser FI on random-seed pointer | `[hw]` | Key **and** message | Up to 100%; pattern present in pqm4, liboqs, PQClean, wolfSSL |
| Chosen-ciphertext *k*-trace on masked CCA2 | `[sim]` | Long-term secret key | **Leakage model only — no measured traces** |
| Single-trace template on the NTT | `[hw]` | **Session key only** | 213 templates; targets *encryption*, so the long-term key is not exposed |
| Single-trace power on message encoding | `[hw]` | Session key | 100% for Kyber and Saber |
| DL power analysis vs 5th-order masked Kyber | `[hw]` | **Session key (message)**, not long-term key | Widely misreported as a full key break |
| Voltage FI + DL vs masked *and* shuffled | `[hw]` | Session key | Success 0.122 → 0.887 with 32 key bits enumerated |

Two rows are commonly overstated in secondary sources and are corrected here: the NTT single-trace
attack targets encryption and therefore recovers only the transmitted symmetric key, and the
fifth-order masked break is a *message*-recovery attack. Both are serious; neither is long-term key
recovery.

#### 10.2 ML-DSA (FIPS 204)

| Attack | Grade | Outcome |
| --- | --- | --- |
| Single-trace SCA on rejection sampling | `[hw]` | Private key, 100% success, seconds to minutes, all three levels |
| Non-profiling attack using public-data templates built on the target device | `[hw]` | Key recovery in ~300 traces (96 for challenge recovery); works in hedged mode |
| Profiled template on an intermediate signing vector | `[hw]` | Universal forgery; 700,000-message corpus |
| DFA on **deterministic** signing | `[hw]` | Secret key element from a single random fault; up to 65.2% of signing time vulnerable |
| Correction faults on **randomized** signing | `[hw]` | Key from 512–1024 faulty signatures |
| Single-fault attack on **hedged** signing | `[hw]` | Secret key vector, p = 0.582 in a single trace |
| EMFI on bit-sliced NTT | `[hw]` | ~10% exploitable faults (667 MHz Cortex-A9) |
| Formal fault analysis of hedged ML-DSA | `[analysis]` | Resists faults at certain I/O points; key recovery at others |

**Signing-mode policy is auditable today, and the honest statement is two-sided.** RFC 9882 states
that ML-DSA signers SHOULD NOT use the deterministic variant on platforms where side-channel or
fault attacks are a concern — and randomized ML-DSA is also *cheaper* to protect, so security and
performance point the same way. But hedged mode is a **partial** countermeasure, not a fix: the
single-fault break at p = 0.582 and the ~300-trace non-profiling recovery both operate against
hedged signing. Recommend hedged; do not claim it closes the class.

#### 10.3 FN-DSA / Falcon (FIPS 206, in development)

`[hw]` "Falcon Down" (Karabulut & Aysu, DAC 2021) is a known-plaintext differential electromagnetic
attack targeting the floating-point multiplications inside Falcon's FFT via an extend-and-prune
strategy, mapping recovered sign, mantissa and exponent values back to secret-key coefficients.
Approximately **10,000 measurements** suffice to extract the entire key from the NIST reference
software on a Cortex-M4, and the key permits forging signatures on arbitrary messages. Notably it
requires no pre-characterization of the device.

Combined with Crowhammer (§7.2), FN-DSA/Falcon has both a demonstrated lab-grade EM attack `[hw]`
and a cryptanalytic single-bit-flip key-recovery result `[analysis]` whose fault could be delivered
by Rowhammer or by optical means. Per `CONVENTIONS §1`, FIPS 206 remains in development —
do not claim FIPS 206 compliance, and weigh this implementation-security picture when considering
Falcon for new designs.

#### 10.4 SLH-DSA (FIPS 205)

- `[hw]` Software-only universal forgery via Rowhammer against OpenSSL 3.5.1 (§7.2).
- `[analysis]` A single random bit flip anywhere in SPHINCS+ signing substantially degrades security
  with high probability, and **the resulting faulty signature is not detected by the standard
  verification procedure**; the caching countermeasure can be circumvented with a tolerable number
  of queries.
- `[hw]` DPA recovered at least a 32-bit chunk of the SPHINCS-256 secret key from the hardware
  implementation evaluated in ePrint 2018/673. Name the specific device in any derived report — §3
  requires a named platform for an `[hw]` grade, and "a hardware implementation" does not meet it.

The conservative, hash-based scheme is not physically conservative.

#### 10.5 LMS / XMSS (SP 800-208)

For stateful hash-based signatures the dominant hazard is **state handling, not leakage** — DPA
resistance of XMSS reduces to that of its underlying PRNG, and current versions are not threatened
unless a customized PRNG is used.

- `[norm]` SP 800-208 §8.1 requires the module to update the private-key state in non-volatile
  storage **before** exporting a signature or accepting another signing request. It further binds
  key and signature generation to hardware modules at FIPS 140-2/140-3 Level 3+ physical security,
  non-modifiable or limited operational environment, no bypass mode, no export of private keying
  material, and the entropy source inside the module boundary. **This is the only place in the PQC
  standards corpus where physical security is normatively mandated** — use it.
- `[norm]` HSS/XMSS^MT implementations that re-sign a subtree root on every signature reuse a
  one-time key and are fault-injectable; sign each tree root exactly once.
- `[hw]` Faulting the WOTS+ checksum enables existential and, in advanced settings, universal forgery
  against LMS, XMSS and SPHINCS+, affecting both signing and verification. A laser fault injection
  attack on WOTS as used in XMSS has been practically evaluated on a standard microcontroller in a
  BSI-commissioned Fraunhofer AISEC study.
- Operational hazard that is pure cloud practice, not physics: process forking, VM cloning, snapshot
  restore, and backup restoration can silently reintroduce a used one-time key
  (`draft-ietf-pquip-hbs-state`, which replaced the expired `draft-wiggers-hbs-state`).

---

### 11. The assurance gap — the headline procurement finding

FIPS 140-3 was published 22 March 2019 and is not a standalone technical standard: it adopts
ISO/IEC 19790:2012/Cor.1:2015 for requirements and ISO/IEC 24759:2017 for testing. **Its own text
states that its major change relative to FIPS 140-2 was the introduction of non-invasive physical
requirements** — and it treats "physical security" and "non-invasive security" as two separate
requirement areas among eleven.

That requirement area was never populated:

- **SP 800-140F** — the CMVP document that replaces ISO/IEC 19790 Annex F — in its final published
  form (March 2020) approves **no test metrics at all**.
- A **draft Revision 1** (August 2021) would have adopted ISO/IEC 17825, ISO/IEC 20085-1 and
  ISO/IEC 20085-2 as approved metrics. **It has never been finalized.**
- The current FIPS 140-3 Implementation Guidance (last updated 16 April 2026) contains an **entirely
  empty Section 8 "Non-invasive security"** and an **entirely empty Annex F**. The strings
  "side-channel", "side channel" and "leakage" do not appear anywhere in the document.
- **CAVP algorithm validation tests only input/output behavior**, so an unhardened implementation and
  a heavily masked one are indistinguishable to it.
- CMVP is meanwhile actively validating PQC algorithms — the IG carries detailed self-test (CAST)
  requirements for ML-KEM, ML-DSA and SLH-DSA — while approving **no side-channel test metric** for
  them or for anything else. One indirect hook does exist and is worth knowing: IG 12.A "Mitigation
  of Other Attacks" provides that where a module has been *purposely designed, built and publicly
  documented* to mitigate a specific attack, that claim is documented and assessed. It is
  vendor-initiated and claim-scoped, not a level-driven mandate, and it approves no metric — so it
  does not convert a validation into side-channel assurance. Ask what was claimed, not whether the
  module is validated.

**Therefore: a FIPS 140-3 validated ML-KEM module, and an ACVP/CAVP certificate for an ML-KEM
implementation, convey no side-channel assurance whatsoever.** That sentence belongs verbatim in
procurement documents and vendor questionnaires.

**What the PQC standards themselves say.** FIPS 203 (ML-KEM) contains **no mention** of side-channel,
timing, power or fault attacks anywhere in the document — a full-text search of the published PDF for
"side-channel", "side channel", "timing attack", "power analysis" and "fault" returns nothing, and
that search is recorded here so the negative is reproducible rather than asserted. FIPS 204
addresses them only as advisory
prose — hedged signing helps, the deterministic variant "should not be used" where side-channel
attacks are a concern. FIPS 205 has a run-in paragraph headed "Side-channel and fault attacks."
inside §3.2 Implementation Considerations, using "care must be taken" rather than a normative
"shall". SP 800-227 (final, September 2025) places side-channel protection in §3.3 under a heading
reading "Additional Requirements" — but uses "should", and its own glossary reserves "shall" for
requirements tested by a CMVP laboratory. `[adv]` throughout, `[norm]` nowhere.

**The ISO track has moved ahead of the US track.** ISO/IEC 19790:2025 (third edition, 2025-02)
folds ISO/IEC 17825 into its Annex F, and ISO/IEC 24759:2025 normatively references ISO/IEC 20085-1
and -2. FIPS 140-3 still points at the 2012 and 2017 editions, so none of this reaches a CMVP
validation. ISO/IEC 17825:2024 covers timing analysis, SPA/SEMA and DPA/DEMA for security levels 3
and 4 only, restricts itself to first-order attacks, and — creditably — **states in its own
Introduction that the achievable confidence level is "low to medium"** and that more sophisticated
attacks can still succeed against a module that passes. Peer-reviewed work has additionally found
that its fixed-versus-random methodology does not transfer cleanly to lattice KEMs, because public
and private key components are tightly linked.

**The lever that does exist.** Common Criteria AVA_VAN.5 is a white-box activity — it depends on
ADV_IMP.1, so evaluators receive implementation representation in addition to conducting independent
penetration testing — and smartcard/secure-element practice is governed by JIL v3.2.1 (February
2024), built around AVA_VAN.5 with a dedicated side-channel section. **But JIL v3.2.1 contains no
post-quantum content at all**: a full-text search returns no occurrences of "quantum", "lattice",
"ML-KEM", "ML-DSA" or "Kyber".

**Procurement position, stated plainly:**

1. Require **CC AVA_VAN.5 under JIL** for any device holding a long-lived PQC key.
2. Because JIL has no PQC content, **demand PQC-implementation evidence explicitly** — do not assume
   the scheme covers it. Ask which of the §10 attack classes were tested, against which parameter
   set, on which silicon.
3. For LMS/XMSS you already hold a mandate: **SP 800-208 §8.1**. Cite it.
4. Treat FIPS validation as evidence of algorithmic correctness only, and say so in the risk
   register.

**The assurance you should demand is obtainable — this is not a hypothetical ask.** On 24 January
2025 the German BSI certified Infineon's ML-KEM implementation on a TEGRION 28 nm security
controller at **Common Criteria EAL6**, announced as the first CC certification of a post-quantum
algorithm on a security controller, with BSI explicitly citing resistance to classical attacks
including **fault attacks** alongside quantum-computer attacks. CC EAL6 mandatorily includes
AVA_VAN.5.

That matters more than a negative would have. It means a procurement team asking for AVA_VAN.5
evidence on a PQC implementation is asking for something a vendor has already delivered and a
national scheme has already certified — so "nobody does that yet" is not an acceptable answer.
Verify the specific certificate covers the specific implementation, algorithm and parameter set you
are buying, and check its date: certification is per-product, and one certificate does not
generalize across a vendor's catalog.

---

### 12. Detection strategy — and what cannot be detected

**Tier A is detectable and testable.** Everything else is not, and the playbook says so.

**A1 — Build-chain constant-time assurance.** The most valuable control in this document, because
CVE-2024-37880 was a compiler defect:

- Pin and record compiler, version and optimization flags in the SBOM for every PQC implementation.
- Run dynamic constant-time analysis **on the shipped binary**, not the source.
- Confirm libraries are past the Kyber `9b8d306` remediation (Clangover / CVE-2024-37880) **and**
  separately carry the KyberSlash patches — these are two defects with two fixes, and clearing one
  does not clear the other.
- Make "constant-time verified with what tool, at what optimization level, on what target" a
  mandatory vendor answer, and re-verify on every toolchain bump.

**A2 — Rowhammer telemetry.** Performance-counter-based hammer detection is deployable; treat known
evasion and false-positive behavior as tuning work, not as a reason to skip it. Inventory DRAM by
vendor and manufacture date against CVE-2025-6202's 2021-01 to 2024-12 range. **Never record on-die
ECC as a mitigation.**

**A3 — Software-reachable power and frequency interfaces.** Restrict RAPL/energy telemetry to
privileged users, apply the relevant microcode, and treat DVFS-derived timing as a reason to pin
frequency or require frequency-independent implementations on key-handling hosts.

**A4 — Signing-mode and state audit.** Assert hedged ML-DSA in configuration; for LMS/XMSS, verify
state-update atomicity and hunt for the cloning hazards — snapshot restores, VM clones, forked
signer processes, restored backups — which are ordinary infrastructure telemetry.

**A5 — Entropy health.** *Sustained* health-test failures, and any persistent anomaly in
noise-source output, are security events rather than hardware-maintenance events. Isolated failures
are expected: SP 800-90B's continuous tests carry a deliberate non-zero false-positive rate, so
alert on a threshold sustained across windows, never on a single failure (§14 rule 3).

**A6 — Verifier-side fault resistance.** Signature *verification* is an attack target, not just
signing: faulting the WOTS+ checksum affects **both signing and verification** for LMS, XMSS and
SPHINCS+ (§10.5), and a faulted SPHINCS+ signature is not caught by the standard verification
procedure (§10.4). Every other control in this playbook is signer-side, which leaves the more widely
deployed half of the deployment unaddressed — there are far more verifiers than signers. For any PQ
verifier on a physically reachable device (firmware bootloader, secure element, vehicle ECU, set-top
box, smart meter), require the vendor to state what fault resistance the *verifier* carries, and
treat "the signer is in an HSM" as a non-answer.

**Undetectable at runtime, stated for the record:** optical probing, photonic emission analysis,
laser fault injection on a device out of your possession, FIB edit, dopant/analog trojans, and
malicious key generation. For these, detection is replaced by (a) custody and tamper evidence,
(b) inspection sampling, (c) provenance verification, and (d) blast-radius reduction. A device that
left your control and came back is not "clean because nothing alerted."

---

### 13. Key Indicators

What an analyst actually looks for. Grouped by where the observable lives, and honest about the
fact that the invasive tiers contribute *state* indicators rather than *event* indicators — there is
nothing streaming to watch.

**Build and dependency plane**

- A PQC implementation in the SBOM at or below a known remediation floor — Kyber reference code
  predating commit `9b8d306`, or a library that has not taken the KyberSlash patches.
- No constant-time verification record for a shipped PQC binary, or a record that targeted the
  *source* rather than the binary.
- Compiler identity or optimization flags absent from the SBOM, or changed since the last
  verification run.
- A constant-time tool reporting a variable-time instruction or a secret-dependent branch on a
  secret operand — a `BR` hit in `poly_frommsg` being the CVE-2024-37880 signature specifically.
- Divergence between `-O0` and `-O2` verification results for the same source tree.

**Platform and memory plane**

- DRAM in the fleet matching a published Rowhammer-vulnerable vendor and manufacture window, with
  no refresh-interval override applied.
- On-die ECC recorded as the sole Rowhammer mitigation.
- Row-activation rates and clustered aggressor patterns above the site baseline, especially on a
  host that signs.
- A step change in corrected-error rate on a single DIMM.
- Unrestricted RAPL or energy-telemetry interfaces readable by unprivileged users.
- Software-writable voltage/frequency MSRs on a host holding keys, or missing microcode for the
  Plundervolt and PLATYPUS mitigations.

**Cryptographic configuration and state plane**

- ML-DSA configured for deterministic signing on a platform whose physical exposure is not
  controlled.
- Two LMS/XMSS signatures sharing a `(keypair, leaf index)` pair over **different message digests** —
  definitive one-time-key reuse, a cryptographic break rather than a hygiene issue. Note the
  persisted index legitimately runs *ahead* of the last signature emitted, because SP 800-208 §8.1
  mandates persisting before export; a signature at index N alongside a persisted index of N+1 is
  the correct state, not a finding.
- The persisted leaf index moving **backwards** between observations — state rollback from a
  restore, clone, or corrupted state store.
- A signature exported while the persisted index had *not* yet advanced past it.
- A signature emitted after a state-store write failure, or state persisted *after* rather than
  before export.
- Any HSS/XMSS^MT signer re-signing a subtree root more than once.
- VM clone, snapshot restore, backup restore, or process fork touching a stateful-HBS signer.
- A long-lived PQC keypair generated on-device that cannot be regenerated from a seed with
  independent software.
- SP 800-90B continuous health-test failures, or a step change in noise-source bias, on a
  key-generating device.

**Physical and supply-chain plane** — *state, not events; none of these stream*

- Broken or missing tamper evidence on a module holding a code-signing, device-identity or root key.
- A device holding long-lived keys returning from any period outside verified custody.
- Module vendor, part number, serial or firmware failing reconciliation against the procurement
  record — reconciled against procurement, never against what the part reports about itself.
- An unexplained in-service transceiver or secure-element firmware change.
- Bare-die flip-chip packaging on a device whose threat model assumed physical inaccessibility
  (no preparation is needed for backside access).
- A vendor threat model that excludes depackaging, delayering, foundry IP integration or
  manufacturing operational security — which is the documented default, not an exception.

**Assurance plane**

- FIPS 140-3 validation cited as evidence of side-channel resistance (§11) — an indicator of a
  documentation defect, and the most common one in this domain.
- No CC AVA_VAN.5 evidence for a device holding a long-lived PQC key, or AVA_VAN.5 evidence that
  predates and therefore does not cover the PQC implementation.
- Any claim of a "Planck-scale", "sub-Planck" or comparable attack surface — a provenance defect in
  the source document (§3), never a technical finding.

---

### 14. Sample Detection Logic (JSON-style)

```json
{
  "rule_name": "PQC - Non-Constant-Time Binary or Unremediated Implementation",
  "description": "Flags deployed PQC implementations whose binary has not been verified constant-time, or which predate known remediations. Targets the CVE-2024-37880 defect class where constant-time source compiles to variable-time code.",
  "data_source": ["SBOM.Component", "BuildPipeline.Metadata", "CTVerify.Report", "Asset.Inventory"],
  "pqc_library_set": [
    "pq-crystals/kyber", "pq-crystals/dilithium", "liboqs", "PQClean",
    "pqm4", "wolfSSL", "BoringSSL", "OpenSSL", "mlkem-native"
  ],
  "remediation_floor": {
    "_comment": "MAINTAIN THIS TABLE LOCALLY. Populate from each project's own security advisories and record the date you last refreshed it - a stale floor silently disables this rule.",
    "pq-crystals/kyber": "commit >= 9b8d306 (CVE-2024-37880 / Clangover) AND KyberSlash1+2 patches applied - two separate remediations",
    "_others": "record per-component remediated version, date, and source advisory URL"
  },
  "ctverify_tooling": {
    "options": [
      "patched Valgrind for variable-time-instruction detection on secret data (the KyberSlash authors' method, applied across 1000+ SUPERCOP primitives)",
      "dudect / ctgrind / TIMECOP-style dynamic checks"
    ],
    "requirement": "the analysed artifact MUST be the shipped binary at the shipped optimization level"
  },
  "logic": {
    "for_each": "pqc_implementation",
    "trigger_any": [
      "component.name in pqc_library_set and component.version < remediation_floor[component.name]",
      "ctverify.report absent or ctverify.report.target_artifact != 'binary'",
      "build.compiler_id + build.optimization_flags not recorded in SBOM",
      "build.compiler_id + build.optimization_flags changed since last ctverify.report",
      "ctverify.findings.variable_time_on_secret > 0",
      "ctverify.findings.secret_dependent_branch > 0"
    ],
    "escalate_if_any": [
      "asset.exposure == 'network_reachable'",
      "asset.holds_key_class in ['long_term_decapsulation','code_signing','device_identity']",
      "component.name == 'pq-crystals/kyber' and component.commit predates '9b8d306'"
    ]
  },
  "notes": "Source-level review does NOT satisfy this rule. The defect class is created by the compiler, so the verified artifact must be the shipped binary at the shipped optimization level. Track BRANCH findings and DIVISION findings separately - they map to two different defects with two different patches.",
  "severity": "critical_when_escalated_else_high",
  "tags": ["CVE-2024-37880", "TX-03-7.1-compiler-induced-timing-leak", "pqc_implementation_defect"]
}
```

```json
{
  "rule_name": "PQC - Rowhammer Exposure and Hammering Activity",
  "description": "Correlates DRAM fleet exposure with live hammer-pattern telemetry; Rowhammer is the delivery vehicle for software-only breaks of FN-DSA/Falcon and SLH-DSA.",
  "data_source": ["Hardware.Inventory.DIMM", "PerfCounter.MemoryActivation", "EDAC.CorrectedErrors", "Platform.Config"],
  "logic": {
    "window": "1h",
    "exposure_assessment": {
      "_comment": "AND, not OR. DDR5 default tREFI is ~3.9 us and almost no fielded host overrides it, so an OR here would flag the entire DDR5 estate and make the inventory work meaningless.",
      "trigger_all": [
        "dimm.dram_manufacturer_id == 'SK Hynix'",
        "dimm.module_mfg_date within 2021-01..2024-12",
        "platform.trefi_override == false"
      ],
      "_field_note": "Key on the DRAM DIE manufacturer (DDR5 SPD bytes 552-553), NOT the module vendor (SPD 512-513 / SMBIOS Type 17). CVE-2025-6202 scopes to SK Hynix DDR5 dies, which ship under many module brands - dmidecode alone will misclassify.",
      "posture_flag_separately": "platform.mitigation_claimed == 'on_die_ecc_only'  // a documentation defect, not evidence of hammering"
    },
    "activity_detection": {
      "_deployability": "NOT AVAILABLE AS FLEET TELEMETRY on commodity x86. Per-DRAM-row activation counts are not exposed; uncore IMC counters give aggregate ACT/CAS per channel with no row address. The only published mechanism (ANVIL, ASPLOS 2016) is an out-of-tree kernel module inferring row locality from PEBS-sampled LLC misses. Treat this block as a design target for platforms that DO expose the counters, and do not represent its absence as 'no hammering detected'.",
      "where_available": {
        "compute": {
          "row_activation_rate": "activations_per_row_per_refresh_window",
          "aggressor_pattern_score": "clustered_activation_entropy(row_addresses)"
        },
        "having": {
          "row_activation_rate_gte": "site_hammer_threshold",
          "aggressor_pattern_score_gte": "site_pattern_threshold"
        }
      },
      "practical_proxy": "EDAC corrected-error rate step-change on a single DIMM - weak, lagging, and not specific, but it is what most estates actually have"
    },
    "escalate_if_any": [
      "host runs a signing service using SLH-DSA or FN-DSA/Falcon",
      "host holds a code-signing or device-identity private key",
      "concurrent unexplained privilege escalation on the same host",
      "EDAC corrected-error rate step-change on the same DIMM"
    ]
  },
  "notes": "On-die ECC is NOT a mitigation - published work shows flips accumulate because ODECC corrects only on write or on a long periodic cycle (e.g. every 24 h). A platform whose sole claimed mitigation is ODECC is exposed, not protected. Exposure assessment here is INVENTORY work and is fully deployable; activity detection largely is not - report the two separately so an empty activity queue is never read as assurance.",
  "severity": "critical_when_escalated_else_medium",
  "tags": ["CVE-2025-6202", "TX-03-7.2-rowhammer-fault-delivery", "fault_injection_via_software"]
}
```

```json
{
  "rule_name": "PQC - Signing-Mode, HBS State and Entropy Integrity",
  "description": "Audits the configuration and runtime invariants that published fault and side-channel attacks depend on.",
  "data_source": ["CryptoConfig", "HSM.Audit", "Signer.StateStore", "Entropy.HealthTest", "Virt.Events"],
  "logic": {
    "halt_signing_immediately": {
      "_comment": "Cryptographic-break conditions only. These are unambiguous and justify stopping production signing.",
      "_leaf_index_semantics": "SP 800-208 8.1 requires the state to be persisted BEFORE the signature is exported, so a HEALTHY signature using index N is observed only once the persisted state already reads N+1. A naive 'observed <= persisted' test is therefore true for every correct signature and would halt the entire fleet. Detect reuse, not the mandated advance.",
      "trigger_any": [
        "exists two signatures with same (keypair_id, leaf_index) over DIFFERENT message digests   // definitive one-time-key reuse",
        "hbs.persisted_leaf_index decreased between observations   // state rollback: restore, clone, or corrupted state store",
        "hbs.signer observed_leaf_index >= hbs.persisted_leaf_index at export time   // state was not advanced before export, violating SP 800-208 8.1",
        "hbs.tree_root signed more_than_once",
        "signature emitted after a state-store write failure",
        "hbs.state_update_ordering != 'persist_before_export'",
        "entropy.health_test_permanent_failure == true"
      ],
      "action": "halt_signing + preserve_state_store + alert",
      "severity": "critical"
    },
    "alert_only": {
      "_comment": "Real signals that must NOT auto-halt production. SP 800-90B continuous health tests (Repetition Count, Adaptive Proportion) are specified with a deliberate non-zero type-I error rate, so isolated failures are expected behaviour, not evidence of attack.",
      "trigger_any": [
        "entropy.health_test_failures >= site_threshold sustained across >= 2 consecutive windows (site_threshold derived from the module's documented type-I error rate and sample rate)",
        "entropy.noise_source_output_anomaly == true",
        "mldsa.signing_mode == 'deterministic' and asset.physical_exposure != 'controlled'"
      ],
      "action": "alert",
      "severity": "high"
    },
    "escalate_if_any": [
      "virt.event in ['vm_clone','snapshot_restore','backup_restore','process_fork'] affecting hbs.signer",
      "key_class == 'firmware_signing'"
    ]
  },
  "posture_assertions": {
    "_comment": "NOT detections. These are Tier C design properties with no runtime telemetry - asserted in the CBOM and reviewed at onboarding and change, per S12 and S17. Expressing them as runtime alerts would fire permanently across any HSM estate and create false assurance.",
    "seed_regenerable_keypair": "pqc_keypair.generated_on_device implies pqc_keypair.seed_regeneration_supported == true (S9.2 malicious key generation)",
    "review_points": ["device onboarding", "key ceremony", "vendor change", "annual attestation review"]
  },
  "notes": "The leaf-index regression and the clone events are the practical LMS/XMSS failure mode - far more likely than a laser. Separating halt-worthy breaks from alert-worthy anomalies matters operationally: a rule that halts a production signing service on a single expected health-test blip will be disabled within a week, taking the leaf-index check with it.",
  "tags": ["SP-800-208", "TX-03-10.5-hbs-state-integrity", "TX-03-9.2-malicious-keygen", "hbs_state_integrity"]
}
```

---

### 15. Example Evidence

```
SBOM / build metadata - constant-time verification gap
  component: kyber-reference   version/commit: 3c8b5b1 (predates 9b8d306)
  compiler:  clang 17.0.6      flags: -O2
  ctverify:  ABSENT
  asset:     tls-terminator-07  exposure: network_reachable
  key_class: long_term_decapsulation
  -> CVE-2024-37880 defect class. AV:N. Source review would not have caught this.

Constant-time analysis on the shipped binary (illustrative tool output shape)
  fn: poly_frommsg        compiler-emitted secret-dependent branch      BR     HIT
  fn: poly_tomsg          variable-time instruction on secret operand   DIV    HIT
  fn: poly_compress       variable-time instruction on secret operand   DIV    HIT
  -> 3 findings at -O2 (clang 17.0.6). Same source at -O0: 0 findings.  <-- the whole point
     BR hit in poly_frommsg  = CVE-2024-37880 (Clangover), fixed by commit 9b8d306
     DIV hits                = KyberSlash defect class, fixed by separate library patches
     Two defects, two patches. Passing one check does not clear the other.

DRAM fleet exposure
  host: sign-svc-03  DIMM vendor: <V>  mfg: 2023-07  trefi_override: false
  claimed_mitigation: on_die_ecc
  role: SLH-DSA firmware signing service
  -> In CVE-2025-6202 exposure window; ODECC is not a mitigation; host performs
     exactly the operation SLasH-DSA forges. Escalate.

LMS/XMSS state-store — HEALTHY, shown first because it is misread constantly
  signer: fw-sign-01  persisted_leaf_index: 40961  last_signature_leaf_index: 40960
  -> NOT a finding. SP 800-208 8.1 mandates persisting before export, so the persisted
     index correctly runs one ahead of the last emitted signature.

LMS/XMSS state-store anomaly — ACTUAL one-time-key reuse
  2026-08-09T03:12Z  event: snapshot_restore  persisted_leaf_index: 40961 -> 40900   <-- rollback
  2026-08-09T03:14Z  signature emitted  keypair: fw-sign-01  leaf_index: 40900
                     digest: 9f2c...a10   (index 40900 previously signed digest 41bd...77e)
  -> Same (keypair, leaf_index) over two DIFFERENT digests. Definitive reuse.
     Signing halted, state store preserved. This is the realistic HBS failure mode.

ML-DSA signing configuration audit
  service: token-issuer  mode: deterministic  platform: shared_cloud_host
  -> RFC 9882 SHOULD NOT. Also the cheaper-to-protect option is the safer one.

Entropy health
  device: hsm-04  sp800-90b continuous health test failures: 3 in 1h
  noise_source_output: bias step-change at 02:41Z
  -> Security event, not a maintenance ticket.
```

---

### 16. Investigation Steps

1. **Classify the tier before anything else (§6).** Tier A is a patch-and-verify workflow; Tier B/C
   is a custody-and-blast-radius workflow. Misclassifying wastes the first hour of an incident.
2. **For a suspected Tier A defect, reproduce on the shipped artifact.** Verify the binary at the
   shipped optimization level; a clean source review or a clean `-O0` build proves nothing.
3. **Establish key scope immediately.** Which keys does this silicon hold, what do they sign or
   decapsulate, how long are they valid, how many relying parties trust them, and can they be
   revoked? Blast radius, not attack elegance, sets severity.
4. **For a device suspected of physical compromise: do not re-power it.** Preserve chain of custody,
   photograph in place, and treat the device key as disclosed until proven otherwise.
5. **Preserve before thermal handling.** Some radiation-induced fault effects are semi-permanent and
   anneal out — routine thermal handling can destroy the evidence of a physical attack.
6. **Reconcile the physical inventory.** Module vendor, part number, serial and firmware against the
   procurement record — reconcile against procurement, never against what the part reports about
   itself (§9.3).
7. **Determine whether the key could have been generated maliciously (§9.2).** If the device
   generated its own long-lived keypair and cannot regenerate it from a seed with independent
   software, that is an unfalsifiable trust dependency — record it as a finding regardless of the
   current incident's outcome.
8. **For HBS signers, reconstruct the state history.** Leaf-index sequence, every snapshot/clone/
   restore event, and whether any signature was emitted after a state-store write failure. One-time
   key reuse is a cryptographic break, not a hygiene issue.
9. **Pull the assurance evidence and read it against §11.** If the vendor's answer is "it is FIPS
   140-3 validated", that answer contains no side-channel information. Ask for the AVA_VAN.5 report
   and which §10 attack classes were in scope.
10. **Decide the rotation scope before remediation.** Per `PB-25`, treat every key reachable from the
    compromised boundary as exposed from the last verified-clean point, not from detection.

---

### 17. False Positive Considerations

- **Corrected-error counters rise for ordinary reasons** — aging, thermal stress, marginal DIMMs.
  Rowhammer detection requires the *activation pattern*, not the error count alone.
- **Legitimate memory-intensive workloads** (in-memory databases, HPC, compilers under load) produce
  high row-activation rates. Baseline per workload class.
- **Entropy health-test failures during boot or thermal transients** can be benign; sustained or
  repeated failure is not.
- **Constant-time tool findings on non-secret data** are noise; the finding must be on a
  secret-dependent operand, which is precisely what the patched-Valgrind approach establishes.
- **Deterministic signing is a legitimate choice** in some constrained or test contexts. Alert on it
  where physical exposure is uncontrolled, not universally.
- **Leaf-index gaps** can result from authorized key-rollover procedures; a *regression* cannot.
- **Vendor part-number changes** from second-sourcing and revisions are routine — reconcile against
  the procurement record before treating as counterfeit.
- **Physical tamper-evidence damage** occurs in shipping and handling. Investigate; do not assume.

---

### 18. Tuning Guidance

- **Prioritize by key scope and key lifetime, not by attack sophistication.** A device holding a
  ten-year firmware-signing key justifies Tier B/C controls; a TLS terminator with 90-day
  certificates does not.
- **Gate on the toolchain, not the source tree.** Re-run binary constant-time verification on every
  compiler, flag, or target change — that is the trigger condition for the entire §7.1 defect class.
- **Feed the `PB-14` Mosca margin into physical controls too.** Long-shelf-life keys on physically
  exposed devices are the intersection that deserves budget.
- **Baseline DRAM activation per workload class** before enabling hammer detection, or the queue
  fills with databases.
- **Keep the evidence grades (§3) in the tuning record.** A control justified by a `[sim]` result
  should be labeled as such, so a future reviewer can re-weigh it when hardware results land.
- **Re-check the §11 certification position periodically.** It is a snapshot: if CMVP populates
  Section 8 or Annex F, or the set of PQC AVA_VAN.5 certificates grows, the procurement ask changes
  and the playbook must change with it.
- **Provenance gate for outbound artifacts (document review, not incident response).** Block any
  artifact heading to a customer, a risk register or a public report if it contains: a
  "Planck-scale", "sub-Planck" or comparable claim; a process-node name used as a physical
  dimension; a `[sim]` result presented as demonstrated; a CVSS vector restated as an achieved
  experimental outcome; or a relayed figure presented as a first-party measurement. This is a
  checklist run at review time, not a detection — it has no runtime trigger and belongs to no queue.
- **Do not tune Tier B/C into the alert pipeline.** They generate no runtime telemetry; expressing
  them as detections creates false assurance.

---

### 19. Response Actions

**Immediate**

- For Tier A: identify every asset running the affected implementation, prioritize by exposure and
  key class, and treat network-reachable long-term-key holders as urgent.
- For a device suspected of physical compromise: do not re-power, preserve custody, and assume key
  disclosure.
- Halt signing on any HBS signer showing a **persisted-index rollback** or a `(keypair, leaf index)`
  pair reused over different digests, and preserve the state store before remediation. Do not halt
  on the persisted index leading the last emitted signature — that is the mandated ordering.
- Where entropy health tests are failing, stop generating keys on that device.

**Short-term**

- **Rotate on the assumption the attack succeeded.** Scope from the **last verified-clean point**,
  defined operationally as the most recent moment satisfying *all* of: (a) documented unbroken
  physical custody, or intact tamper evidence, from that moment forward; (b) module serial and
  firmware reconciled against the procurement record; and (c) no unexplained gap in the device's
  own audit or attestation record. Where none of those can be established — which is the normal
  case for a device returned from an unmonitored period — the verified-clean point is **the date of
  the last key ceremony or provisioning event**, and the exposure window is everything since. Say
  which definition you used; the window is the finding. `PB-25` governs the rewrap and rotation
  workflow.
- Patch and rebuild PQC implementations past the remediation floor, then **re-verify the binary** —
  a patched source built with the same toolchain is not evidence.
- Apply platform mitigations: refresh-interval override where exposed and supported (with the
  measured ~8.4% SPEC CPU2017 cost budgeted), RAPL restriction, microcode.
- Switch ML-DSA signers to hedged mode where deterministic mode is in use on exposed platforms,
  recording that this is partial mitigation.
- Revoke and reissue any certificate or firmware-signing key whose device cannot be shown to have
  remained in custody.

**Long-term**

- **Extend the CBOM (`PB-01`) to the silicon plane** — which module, which firmware, which entropy
  source, which physical security level, which keys are non-exportable, and whether keypairs are
  seed-regenerable.
- **Rewrite procurement language against §11.** FIPS validation for algorithmic correctness;
  AVA_VAN.5 under JIL plus explicit PQC-implementation evidence for physical resistance; SP 800-208
  §8.1 cited directly for LMS/XMSS.
- **Design for blast-radius reduction, because it is the only control that covers Tier B and C:**
  per-device keys, short validity, no global signing key resident on a fielded device, functioning
  revocation, attestation that fails closed.
- Require seed-based regeneration for any long-lived PQC keypair generated on a device (§9.2).
- Add optical modules, secure elements and HSMs to supply-chain assurance (`PB-27`) with serial and
  firmware reconciliation at install.
- **Specify verifier-side fault resistance in procurement (§12 A6)**, not just signer-side. The
  fleet contains orders of magnitude more verifiers than signers, and the WOTS+ checksum fault
  affects verification too.
- Where FN-DSA/Falcon is under consideration, weigh §10.3 — and note FIPS 206 is still in
  development, so a compliance claim is not available either way.

---

### 20. Escalation Criteria

Escalate to incident when **any** of the following are true:

- A PQC implementation with a known long-term-key-recovery defect is found on a network-reachable
  asset (the CVE-2024-37880 class).
- Binary constant-time verification finds a variable-time instruction on a secret operand in a
  shipped artifact.
- Hammer-pattern telemetry fires on a host performing PQC signing or holding a code-signing key.
- Any LMS/XMSS persisted-index rollback, or any `(keypair, leaf index)` pair observed signing two
  different digests.
- A signature was emitted after a state-store write failure.
- A device holding a long-lived private key returns from a period outside verified custody.
- Tamper evidence is broken on a module holding a code-signing, device-identity or root key.
- Entropy health tests fail persistently on a key-generating device.
- A module fails procurement reconciliation on **serial number**; or its firmware version was never
  released by the vendor for that part; or its firmware changed outside an authorized change record.
  (Routine vendor-released updates recorded in change management are not escalations — otherwise
  this criterion fires on every patch cycle and gets ignored.)
- A long-lived PQC keypair is found to be non-regenerable from a seed **and** the generating device
  or its supply chain is in question (§9.2).
*(The provenance gate for "Planck-scale" and comparable claims is deliberately **not** an escalation
criterion — by Appendix A.5's own measured base rate it would never fire, and a never-firing entry
trains on-call staff to skim the list. It belongs in §17 as a document-review gate.)*

---

### 21. Analyst Notes Template

```text
Incident ID:
Detection Rule / Tier (A | B | C):
Detected At / Detected By:
--- Asset ---
Device / Module / Serial:
Silicon (package type, bare-die flip-chip? Y/N):
Firmware version / matches procurement record? Y/N
Physical custody unbroken since: ____   Evidence: ____
--- Cryptography ---
Scheme(s):            ML-KEM | ML-DSA | SLH-DSA | FN-DSA | LMS/XMSS | ____
Parameter set:
Implementation / version / commit:
Compiler + version + optimization flags:
Binary constant-time verified? Y/N  tool: ____  at flags: ____  findings: ____
Signing mode (ML-DSA):        deterministic | hedged
HBS state ordering verified:  Y/N   persisted / last-emitted leaf index: ____ / ____
  (persisted SHOULD lead by one — flag rollback, or same index over differing digests)
Keypair seed-regenerable:     Y/N   independently verified: Y/N
Entropy source / SP 800-90B validated / health failures: ____ / Y/N / ____
--- Exposure ---
Key class:            session | long-term decapsulation | code signing | device identity | root
Key lifetime / relying parties / revocable? ____ / ____ / Y/N
Network exposure:     
Last verified-clean point:            Exposure window: ____
Blast radius (keys reachable):
--- Assurance ---
FIPS 140-3 validated? Y/N  <-- conveys NO side-channel assurance (§11)
IG 12.A vendor-claimed mitigation on file? Y/N  what was claimed: ____
CC AVA_VAN.5 / EAL6+? Y/N   certificate covers THIS algorithm+parameter set+product? Y/N
Verifier-side fault resistance stated by vendor (§12 A6)? Y/N
SP 800-208 §8.1 applicable / met (LMS/XMSS only): Y/N / Y/N
--- Evidence discipline ---
Every quoted figure graded [hw]/[sim]/[analysis]/[norm]/[adv]/[relayed]/[vendor]? Y/N
Any node-name used as a dimension? (must be N)
Any unverifiable-physics claim present? (must be N)
--- Handling ---
Device re-powered? (should be N)   Thermal handling avoided? Y/N
Evidence preserved before remediation: Y/N (list)
Keys rotated / scope (PB-25):
Containment actions:
Coverage gap identified:
Outstanding Risks:
Recommendations:
Analyst:
```

---

### 22. Summary

Post-quantum cryptography does not execute in the abstract. It executes in silicon, where a key is a
voltage, and where every published attack in this playbook breaks a *correct* implementation of a
*standardized* algorithm without touching the underlying mathematics.

The actionable center of gravity is not where intuition puts it. The exotic tiers yield **no runtime detection whatsoever**; their output is procurement language and
blast-radius design. Grade them precisely even in summary: optical probing, photonic emission and
focused ion beam are demonstrated on real hardware `[hw]`, as is the A2 analog fabrication-time
trojan; **dopant-level trojans remain `[sim]`** — layout-verified and simulated, never fabricated
(§9.1). Collapsing that distinction in a summary is how the overclaim §9.1 exists to prevent gets
shipped.
The deployable controls live almost entirely in the software-reachable tier: a compiler that
silently destroys constant-time guarantees, a DRAM defect that forges hash-based signatures with no
physical access, power and frequency interfaces that leak over a network, an entropy source that can
be locked, and a signing mode set by one line of configuration.

Three positions to carry into any engagement built on this playbook. **Verify the binary, not the
source** — CVE-2024-37880 is rated `AV:N` and recovers an ML-KEM-512 secret key in minutes because
constant-time source compiled to variable-time code. (State the rating as a rating: `AV:N` is the
CVSS vector NVD assigned, not a description of a demonstrated remote exploit.) **FIPS validation is not side-channel
assurance** — FIPS 140-3 created a non-invasive requirement area, CMVP never populated it, and the
Implementation Guidance's Section 8 and Annex F remain empty; require AVA_VAN.5 under JIL with
explicit PQC evidence, because JIL itself has no PQC content. And **for anything an adversary can
physically possess, assume the key is readable** — silicon light sensors cannot see the sub-bandgap
light used to probe them, memory encryption does not conceal optical emission, and the only
surviving control is that the key was small in scope, short in life, and revocable.

The physics floor is settled and closed (Appendix A): there is no Planck-scale attack surface, the
finest limit that actually binds an adversary — optical diffraction — is some twenty-eight orders of
magnitude coarser than the Planck length and entirely classical, and a claim to the contrary is a
provenance defect in the document making it.

---

## Appendix A — The Planck-scale investigation, and the physical floor

This appendix exists so the question is settled once, with numbers, and never re-argued. It was
produced as a genuine investigation into whether a "Planck-length intrusion" could constitute an
attack surface. It cannot. Here is why, and here is what actually bounds an adversary instead.

### A.1 The verdict

> **No Planck-scale attack surface has been demonstrated, and no coherent construction of one has
> been found across the searches recorded in A.5.** The
> Planck length, 1.616255(18) × 10⁻³⁵ m (CODATA 2022), is not a feature of any device; it is the
> scale at which the semiclassical description of spacetime is expected to fail. The strongest
> available device-independent argument — resting on causality, the uncertainty principle, and the
> hoop conjecture, the last of which is well supported by analytical and numerical work but remains
> **unproven** — indicates that no probe or target can be smaller than the Planck length, implying a
> Planck-size irreducible "minimum ball" of uncertainty in any position measurement, interferometers
> included. **That is a bound on measurement, not an accessible layer.** Probing it directly would
> require ~1.220890(14) × 10¹⁹ GeV, about 9 × 10¹⁴ times the LHC's 13.6 TeV proton–proton
> centre-of-mass energy, or ~1.8 × 10¹⁵ times its 6.8 TeV per-beam per-quantum energy — the
> highest energy achieved in a collider, though cosmic rays reach far higher single-particle
> energies without being steerable probes — and, on naive LHC-class bending-technology scaling, a
> ring of order 5 × 10¹⁹ m, roughly five thousand light-years. Every experimental program that
> reaches toward the scale does so indirectly, over cosmological baselines, and reports nulls with
> exclusion bounds. Information-theoretic bounds point the same way: holography limits the
> information content of adjacent spacetime regions to roughly 10⁶⁹ bits per square metre of
> bounding **area**, not to any addressable volumetric Planck substructure. Accordingly this
> playbook records "Planck-length intrusion" as a term with no referent in information security, and
> treats its appearance in any artifact as a provenance defect to be reviewed, not a threat to be
> modeled.

### A.2 The numbers

| Quantity | CODATA 2022 value | Relative uncertainty |
| --- | --- | --- |
| Planck length | 1.616255(18) × 10⁻³⁵ m | 1.1 × 10⁻⁵ |
| Planck time | 5.391247(60) × 10⁻⁴⁴ s | 1.1 × 10⁻⁵ |
| Planck mass | 2.176434(24) × 10⁻⁸ kg | 1.1 × 10⁻⁵ |
| Planck energy | 1.220890(14) × 10¹⁹ GeV | 1.1 × 10⁻⁵ |
| Planck temperature | 1.416784(16) × 10³² K | 1.1 × 10⁻⁵ |

Planck energy expressed in SI is ≈ 1.956 × 10⁹ J *per single quantum* — about 543 kWh, or roughly
0.47 tonnes of TNT equivalent. That is a unit conversion, not an independent measurement.

**The gap.** The LHC reached 13.6 TeV in Run 3 (6.8 TeV per beam, first delivered 5 July 2022). The
ratio to Planck energy is 8.977 × 10¹⁴ — and because resolvable length scales as *L* ~ ħ*c*/*E*, the
gap is identical in energy and in resolvable distance. Scaling the LHC's 26,659 m circumference
linearly at fixed dipole field to Planck energy per beam gives ≈ 4.79 × 10¹⁹ m, about 5,060
light-years. That is a scaling estimate to convey magnitude, not an engineering study.

### A.3 What the experiments actually found

Reported as nulls with exclusion bounds, per §3:

- **Fermi-LAT / GRB 090510** set 95% CL limits of *E*(QG,1) > 7.6 *E*(Planck)
  (linear) and *E*(QG,2) > 1.3 × 10¹¹ GeV (quadratic) — the most constraining limits in
  that paper's own 2013 four-GRB sample, for the **subluminal** case, **without** correction for
  intrinsic source-frame dispersion. Both qualifiers must travel with the number, and the linear
  limit has since been superseded by LHAASO below.
- **LHAASO / GRB 221009A** (2024) gives *E*(QG,1) > 10 *E*(Planck) and
  *E*(QG,2) > 6 × 10⁻⁸ *E*(Planck), both 95% CL. The correct statement is: *no
  linear energy-dependence of the vacuum speed of light has been observed; linear LIV is excluded up
  to 10× the Planck energy at 95% CL.* Not "no such effect exists."
- **The Fermilab Holometer** reached 2.1 × 10⁻²⁰ m/√Hz and, for signal *bandwidths* greater than
  11 kHz — an integration bandwidth, not a Fourier-frequency threshold — its strain/shear power
  spectral density passed below the Planck time. It found no correlated holographic noise, and
  Fermilab's own summary is that it ruled out the specific "pixelated universe" model it was built
  to test to high statistical significance.

The one proposal that sounds like a channel — a "Planck broadcast" at ~2 × 10⁴³ bits/s, the inverse
Planck time — is a speculative theoretical hypothesis whose single concrete observable prediction is
exactly the transverse position noise the Holometer searched for and did not find. It is not an
engineerable channel, and reading it as a covert channel is the "speculative-channel laundering"
failure mode named in §3.

A 2026 preprint proposes that a sufficiently large quantum computer could exceed the classical limit
of one operation per Planck volume-time, with 500 logical qubits sufficient to reject lab-confined
theories. It is **unrefereed**, its 2⁴⁹¹ figure matches the inverse Planck volume-time only to within
a factor of ~1.5, and — stated explicitly as this playbook's reading rather than the authors' — it
concerns Hilbert-space scaling, not Planck-regime access. It is included because omitting a real
preprint would be as dishonest as overstating it.

### A.4 The floors that actually bind an adversary

These are the limits an engineer meets. The finest length among them — the Abbe limit — is about
**28 orders of magnitude** coarser than the Planck length, and even the most extreme probe in
A.2–A.3, the LHC's resolvable scale of ~1.45 × 10⁻²⁰ m, is still ~15 orders of magnitude coarser.
Their job in this playbook is to let a reviewer say "that is physically impossible" and be right.

| Limit | Value | Why it matters here |
| --- | --- | --- |
| **Landauer** | *kT* ln 2 = 2.87 × 10⁻²¹ J per bit erased at 300 K | Experimentally confirmed with a single-particle one-bit memory. Real CMOS sits far above it — a first-principles analysis of CMOS switching, interconnect and leakage energy puts maximum CMOS efficiency at ~4.7 × 10¹⁵ FP4/J, roughly 200× above current microprocessors (Ho, Erdil & Besiroglu, arXiv:2312.08595 — **unrefereed preprint, a geometric-mean estimate, and the unit is four-bit floating point, not generic FLOP**), so **Landauer is not the binding constraint on real hardware** |
| **Margolus–Levitin** | "Adding one Joule of energy to a given computer can never increase its processing rate by more than about 3x10^33 operations per second" — **the authors' own stated figure**, quoted verbatim | Bounds brute-force claims. Note for reviewers: recomputing the orthogonal-state rate as 4*E*/*h* gives ~6 × 10³³ s⁻¹ J⁻¹, a factor of two above the authors' quoted number, because that expression counts orthogonal transitions rather than the authors' "operations". Cite the paper's figure with its wording, not a re-derivation |
| **Bekenstein** | *S*/*E* ≤ 2π*R*/(ħ*c*); ~2.58 × 10⁴³ bits for 1 kg within 1 m | Bounds storage claims |
| **Holographic** | ~10⁶⁹ bits per m² of bounding area | Information scales with area, not volume |
| **Diffraction (Abbe)** | *d* = λ/(2·NA); 177 nm at 514 nm with NA 1.45 — a **visible-light oil-immersion reference case**, not a probing figure | About **10²⁸ times the Planck length**. Applied instead to §8.4's ~1.3 µm backside infrared probing the limit is far coarser, which is why a solid immersion lens (raising effective NA through silicon's high index) is what buys resolution there |
| **Shot / radiation-pressure noise** | The binding quantum limits in real instruments | LIGO beats shot noise with frequency-dependent squeezing — 4.0 dB at Hanford, 5.8 dB at Livingston near 1 kHz, 15–18% range improvement — using 300 m filter cavities. Superresolution likewise shows the diffraction limit is not an absolute wall |

The last row is the honest counterweight: **these floors are engineering constraints, not
guarantees.** Squeezing beats shot noise; superresolution beats Abbe. When a control depends on an
adversary being stopped by a physical limit, state which limit, its value, and whether known
techniques already circumvent it.

### A.5 The reproducible negative

Two independent adversarial searches — one pairing Planck terminology with attack-surface,
threat-model and CVE vocabulary, one searching the exact strings "Planck-length intrusion",
"Planck scale attack" and "sub-Planck side channel" against the security corpus — returned **zero**
security-domain uses. Hits were either ordinary side-channel/QKD security literature with no Planck
content, or physics literature with no security content.

This is an absence-of-evidence result over accessible search, and is published as such with the
search strings recorded so the negative is reproducible. It is sufficient to support the §3
fabrication-indicator rule; it is not a proof of non-existence, and is not stated as one.

---

## Appendix B — Primary source ledger

Every substantive claim above traces to one of these. All were retrieved and verified during
authoring; each carries the evidence grade it supports. Re-verify status and availability before
using any of them in a compliance evidence package.

**Standards and government**
NIST FIPS 140-3; NIST SP 800-140F and its unfinalized Revision 1 draft; the FIPS 140-3
Implementation Guidance (last updated 16 April 2026); NIST FIPS 203, 204, 205; NIST SP 800-208;
NIST SP 800-227 (final, September 2025); NIST SP 800-90B; NIST IR 8547 (initial public draft);
ISO/IEC 17825:2024; ISO/IEC 20085-1:2019 and 20085-2:2020; ISO/IEC 19790:2025 and 24759:2025;
Common Criteria CC:2022 Part 3; JIL "Application of Attack Potential to Smartcards and Similar
Devices" v3.1 (June 2020) and v3.2.1 (February 2024); PSA Certified Attack Methods v1.3;
RFC 9334 (RATS Architecture); RFC 9882 (ML-DSA in CMS); `draft-ietf-pquip-hbs-state`;
IEEE 802.1AR-2018; NIST CODATA constants.

**Vulnerability records (all verified against NVD)**
CVE-2024-37880 (Clangover — compiler-emitted secret-dependent branch in the Kyber/ML-KEM reference
implementation; **distinct from KyberSlash**, which carries no CVE here); CVE-2025-6202 (Phoenix /
DDR5 Rowhammer);
CVE-2022-24436, CVE-2022-23823, CVE-2022-35888 (Hertzbleed — Intel, AMD, Ampere);
CVE-2020-8694, CVE-2020-8695 (PLATYPUS / RAPL); CVE-2019-11157 (Plundervolt).

**Peer-reviewed and preprint literature**
KyberSlash (TCHES 2025); single-trace NTT attacks (ePrint 2019/795); generic CCA side-channel
attacks on lattice KEMs (TCHES 2020(3)); FO re-encryption oracles (ePrint 2021/849); masked-Kyber
*k*-trace (ePrint 2021/956, simulation only); FO-skip fault attacks (TCHES 2021(2), ePrint 2021/840);
laser FI on seed pointers (ePrint 2025/2009); masked/shuffled Kyber breaks (ePrint 2022/1713,
2023/1587); message-encoding single-trace (ePrint 2020/992); two-step CPA + lattice reduction
(arXiv:2407.06942); ML-DSA rejection-sampling and intermediate-value attacks (ePrint 2025/214,
2023/050, 2026/056); deterministic and hedged ML-DSA fault attacks (ePrint 2018/355, 2024/138,
2024/238, 2025/904); EMFI on bit-sliced NTT (arXiv:2204.06153); masking cost studies (TCHES —
Masking Kyber; ePrint 2020/1038, 2022/1406, 2024/1817); Falcon Down (ePrint 2021/772); Crowhammer
(ePrint 2025/1042); SLasH-DSA (arXiv:2509.13048); SPHINCS+ and WOTS+ fault work (ePrint 2023/042,
2023/1572); DPA of XMSS and SPHINCS (ePrint 2018/673); BSI/Fraunhofer AISEC laser FI on XMSS;
optical fault induction (CHES 2002); simple photonic emission analysis (CHES 2012); photonic attacks
on RSA (ePrint 2017/108); optical contactless probing (CHES 2016, CCS 2017 / ePrint 2017/822);
EOFM/LLSI (USENIX Security 2021); electron-beam probing (ISTFA 2023); two-photon-absorption LFI
(TCHES 2022); dopant-level trojans (CHES 2013) and their detection (ePrint 2014/508); A2 analog
trojan (IEEE S&P 2016); counterfeit taxonomy and detection (Proc. IEEE 102(8)); LWE backdoor
(ePrint 2022/1381); hash-based signatures for UEFI Secure Boot (ePrint 2021/041); ISO 17825 critiques
(ePrint 2019/1013, 2022/229).

**Physics (Appendix A)**
Minimum length from first principles (Int. J. Mod. Phys. D14, 2195, 2005) and from QM + classical GR
(Phys. Rev. Lett. 93, 211101, 2004); Hossenfelder, *Living Reviews in Relativity* 16:2 (hoop
conjecture status); Fermi-LAT LIV constraints (Phys. Rev. D 87, 122001, 2013) and Nature 462, 331
(2009); LHAASO GRB 221009A (Phys. Rev. Lett. 133, 071501, 2024; JCAP 04 (2024) 060); Holometer
(Phys. Rev. Lett. 117, 111102, 2016; Class. Quantum Grav. 34, 165005, 2017); quantum-gravity
phenomenology review (Prog. Part. Nucl. Phys. 125, 103948, 2022); Landauer verification (J. Stat.
Mech. 2015, P06015); Margolus–Levitin (Physica D 120, 188, 1998); Bekenstein (Phys. Rev. D 23, 287,
1981); holographic principle (Rev. Mod. Phys. 74, 825, 2002); LIGO frequency-dependent squeezing
(Phys. Rev. X 13, 041021, 2023); CERN LHC parameters.

---

*GreyNOC — detection-engineering-first security operations. Reproducible or it didn't happen.*
