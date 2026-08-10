# GreyNOC Security Playbook

## TX-02 — Nanometer-Scale Optical Data Transmission, Reception & Intrusion Handling

---

### 1. Overview

Almost every byte the organization owns crosses a nanometer-wavelength carrier at some point. The
data-center fabric, the campus backbone, the metro and long-haul links, the subsea cable, the
inter-satellite crosslink — all of it is infrared light in glass or in vacuum, at wavelengths
between roughly 800 and 1600 nm. It is the highest-bandwidth, longest-lived, least-monitored
transmission medium in the estate, and in most organizations nobody in security has ever looked
at it.

This playbook covers how data is **created on** and **recovered from** an optical carrier, and how
to detect and respond to intrusions against that carrier.

**Why this is a post-quantum problem, not just a plumbing problem.** `PB-02` treats
harvest-now-decrypt-later as the dominant risk to long-lived confidentiality. A passive fiber tap
is the single best harvesting position that exists. It sits upstream of every application control,
it sees aggregate traffic rather than one session, it is silent, and — this is the part that
matters — the ciphertext it collects stays collected. An adversary who taps a link in 2026 and
stores the output is making a bet about 2036. The optical layer is where the HNDL adversary
actually stands.

**The two facts that structure everything below:**

1. **A tap costs light.** Extracting a copy of an optical signal removes optical power from the
   original. It is physics, and it cannot be engineered away — only made small. Modern taps can
   operate at a fraction of a dB, comfortably inside the margin most links run with. That is why
   detection depends on a *tight local baseline*, not on a published threshold.
2. **Optical-layer detection is a tripwire, not a control.** Assume a competent tap can be placed
   below your detection floor. The control that survives that assumption is cryptographic:
   encrypt before the photons, with hybrid post-quantum key establishment, so a successful tap
   yields ciphertext with a shelf life longer than the adversary's patience. §9 is where the real
   defense lives. §7 and §8 tell you when someone tried.

**Related:** `TX-01` (RF media — the other half of the physical layer), `PB-02` (HNDL — this is the
harvesting mechanism), `PB-03` (hybrid TLS/KEM downgrade — what the tapped traffic had better be
wrapped in), `PB-09` (PQ VPN/IPsec/SSH — the tunnel over the tapped link), `PB-25` (key management
— what to rotate when a tap is confirmed), `D&R-17` (exfiltration — optical is an alternate
medium), `D&R-19` (incident response).

---

### 2. Scope — the nanometer band

| Wavelength | Band / name | Typical use | Security relevance |
| --- | --- | --- | --- |
| ~380–750 nm | Visible | VLC / Li-Fi, status LEDs, displays | Covert channels; unintentional emission |
| ~780–860 nm | Short-wave IR | Multimode short-reach, some FSO, IR remotes | Short-reach DC fabric; sensor injection |
| ~1260–1360 nm | O-band (1310 nm nominal) | Single-mode short/medium reach, PON upstream | Campus and DC interconnect |
| ~1460–1530 nm | S-band | Some PON, pump/monitoring | Out-of-band monitoring channels |
| ~1530–1565 nm | **C-band (1550 nm nominal)** | **DWDM metro/long-haul, subsea, coherent** | **The highest-value tap target in the estate** |
| ~1565–1625 nm | L-band | DWDM capacity extension, OTDR monitoring | Monitoring channels; out-of-band tap surface |

DWDM channel plans follow the ITU-T G.694.1 grid (commonly 100 GHz or 50 GHz spacing, with
flexible-grid deployments in newer systems). **The grid is a security fact, not just an
engineering one:** a fiber carrying eighty channels can carry an eighty-first that nobody
provisioned, and if your monitoring only watches the channels in the service inventory you will
not see it.

Out of scope: X-ray and shorter (not a communications medium here), and the RF/microwave bands
covered by `TX-01`.

---

### 3. How data is created on an optical carrier

Detection requires knowing which measurement changes when something is wrong, which requires
knowing what the chain does. Transmit side:

1. **Framing and FEC.** Client data is framed (Ethernet, OTN) and forward error correction is
   added. FEC is the reason a link can degrade substantially before a single frame is lost — and
   therefore the reason **pre-FEC BER, not post-FEC error counts, is the sensitive early
   indicator**. Post-FEC errors mean the link is already failing; pre-FEC BER moves first.
2. **Electrical-to-optical conversion.** A laser (DFB or tunable) produces the carrier at an
   assigned wavelength. Direct modulation or an external modulator (Mach-Zehnder) imprints the
   data.
3. **Modulation format.** Short reach uses intensity modulation — NRZ/OOK, or PAM4 at higher
   rates — recovered by direct detection. Long reach uses coherent modulation (QPSK, 16QAM, and
   higher orders) encoding data in amplitude *and* phase across two polarizations, recovered by
   mixing with a local-oscillator laser. **Coherent links are materially harder to tap usefully**:
   the tapper needs to recover phase and polarization state, not merely detect power. Record the
   modulation format per link in the inventory — it changes the threat model.
4. **Multiplexing.** DWDM combines many wavelengths onto one fiber; ROADMs add, drop, and route
   individual wavelengths at intermediate sites. **The ROADM is the most under-appreciated security
   device in the network.** It can be configured to copy a wavelength to a monitor port. That is a
   legitimate operational feature and a perfect lawful-looking wiretap.
5. **Amplification.** EDFAs boost the aggregate signal without regeneration. They also add noise,
   which is why OSNR degrades along a path, and why an amplifier's gain-control behavior can mask
   a power loss introduced downstream — an important detection caveat in §7.
6. **Launch into the medium.** Single-mode fiber, multimode fiber, or free space (atmosphere or
   vacuum).

### 4. How data is recovered from an optical carrier

1. **Reception.** A photodiode (PIN or APD) for direct detection, or a coherent receiver front-end
   with a local oscillator and digital signal processing for phase-modulated formats.
2. **Recovered measurements** — this is the security telemetry, and the reason the receive side
   matters more to a detection engineer than the transmit side:
   - **Rx optical power (dBm)** — falls when power is removed. The primary tap indicator.
   - **OSNR (dB)** — optical signal-to-noise ratio. Falls with added noise or lost signal.
   - **Pre-FEC BER** — moves before anything else user-visible does.
   - **State of polarization (SOP) and polarization-dependent loss** — a physical disturbance to
     a fiber changes polarization state fast. **SOP transient monitoring is the most sensitive
     widely-available indicator of someone physically handling a cable**, and it is the closest
     thing the optical layer has to a burglar alarm.
   - **Chromatic dispersion and differential group delay** compensation values — these track the
     physical path. A step change means the path changed.
   - **Coherent DSP tap coefficients** on modern transponders — the equalizer's view of the
     channel. A discontinuity is a physical-path event.
3. **Path characterization telemetry** — not per-packet, but per-fiber:
   - **OTDR** — launches pulses and maps reflective and loss events by distance. **An OTDR trace is
     a fingerprint of the physical route.** Diffing today's trace against a stored reference is the
     single highest-value optical detection available, because it localizes an event to a distance
     along the cable.
   - **Distributed acoustic / vibration sensing (Φ-OTDR)** where deployed — detects digging,
     handling, and enclosure entry along the cable route.
   - **Optical spectrum analysis** — shows which wavelengths are actually present, versus which
     ones were provisioned.

---

### 5. MITRE ATT&CK Mapping

| Technique | ID | Matrix | Tactic |
|-----------|----|--------|--------|
| Hardware Additions | T1200 | Enterprise | Initial Access |
| Network Sniffing | T1040 | Enterprise | Credential Access, Discovery |
| Adversary-in-the-Middle | T1557 | Enterprise | Collection, Credential Access |
| Supply Chain Compromise: Compromise Hardware Supply Chain | T1195.003 | Enterprise | Initial Access |
| Exfiltration Over Other Network Medium | T1011 | Enterprise | Exfiltration |
| Exfiltration Over Physical Medium | T1052 | Enterprise | Exfiltration |
| Weaken Encryption | T1600 | Enterprise | Defense Impairment |
| Network Denial of Service | T1498 | Enterprise | Impact |
| Network Sniffing | T0842 | ICS | Discovery |
| Adversary-in-the-Middle | T0830 | ICS | Collection |

> **Mapping discipline (`CONVENTIONS §4`).** This table was verified against **ATT&CK v19.2**
> (Enterprise and ICS) on **2026-08-09**. **v19 retired the "Defense Evasion" tactic**, renaming
> TA0005 to **Stealth** and splitting out **TA0112 Defense Impairment**; `T1600` landed on the
> Defense Impairment side, as did its sub-technique `T1600.001 Reduce Key Space` cited in PB-09.
> The ICS rows previously left as "verify against your ATT&CK version" are now filled in from the
> same check — ICS tactic placement is a **separate tactic set** from Enterprise and still has to
> be re-verified on its own terms. Re-verify each row against the version your platform carries.

**Deliberately unmapped.** Per `CONVENTIONS §4`, these have no clean technique and are described
rather than tagged: **passive fiber tapping as a distinct technique** (`T1040` is the closest
analogue but describes network-layer capture, not physical-medium extraction), **rogue-wavelength
injection**, **ROADM monitor-port abuse**, **free-space optical beam interception**, and **optical
injection into sensors**. Tag these with the §6 class name.

---

### 6. Intrusion Classes

These are descriptive classes for this playbook. They are deliberately **not** given a
defect-class prefix under `CONVENTIONS §8.1` — that registry belongs to the bug-bounty catalogs,
and a prefix here would invite a triager to read a physical-medium event as an application defect.

#### 6.1 Passive tap — bend coupler

A clip-on coupler bends the fiber past its critical angle, causing a fraction of the light to
escape the core where a detector collects it. **Requires physical access to the cable but no cut,
no splice, and no service interruption** — it can be applied and removed in minutes, and it is the
reason "the link never went down" is not evidence that nothing happened.

Signature: a small step decrease in downstream Rx power; a rapid SOP transient at the moment of
application and removal (handling the fiber is unavoidable); often an OTDR loss event at the tap
distance. Magnitude depends entirely on the coupler and the operator's skill, and competent
application can land inside a link's normal margin. **This is why the baseline must be tight and
why SOP transients matter more than the steady-state power delta.**

#### 6.2 Passive tap — splice and splitter

The fiber is cut and a splitter inserted, sending a permanent copy to the adversary. More
reliable and higher-fidelity than a bend coupler, and permanent once installed.

Signature: an unavoidable service interruption at insertion (however brief — check for an
unexplained link flap or protection switch, then check what the change record says was happening);
a persistent step loss; a **new OTDR event at a fixed distance that was not in the reference
trace.** The OTDR event is the durable evidence — the outage is a moment, the splice is forever.

#### 6.3 ROADM / monitor-port abuse and optical-layer AiTM

No physical access required at all. An adversary with access to the optical management plane
configures a wavelength copy to a monitor port, or routes a channel through a path they control.
This is a **configuration** attack against a legitimate feature, and it produces almost no
physical signature — the light is copied by design, not by damage.

Signature: unauthorized change to cross-connect, monitor-port, or optical-channel configuration;
a wavelength appearing at a degree or port not in the service design; management-plane access
outside change control. **Detection here is control-plane detection, not physics detection.** Treat
the optical management system as a Tier-0 privileged system with the same rigor as the network
management plane — because that is what it is.

#### 6.4 Rogue wavelength / optical injection

An adversary adds an unprovisioned wavelength to a shared fiber, using the organization's own
infrastructure as an uncontrolled transport path — a covert channel that never touches a router.
On unlit or dark-fiber pairs this can run indefinitely with no service impact whatsoever.

Signature: optical spectrum analysis shows a channel present that is not in the service inventory
— the entire detection is *inventory versus reality*; unexplained EDFA gain-control activity as
total input power changes; interference on adjacent provisioned channels.

#### 6.5 Free-space optical and laser links

FSO, building-to-building laser links, and inter-satellite optical crosslinks trade the fiber's
physical containment for a beam that exists in open space.

- **Off-axis interception.** A tight beam is genuinely hard to intercept, but atmospheric
  scattering, beam divergence at long range, and pointing jitter all put recoverable energy
  outside the intended aperture. Interception is passive and **not detectable at the receiver**.
- **Blinding and denial.** A high-power source aimed at the receive aperture saturates or damages
  it. Signature: receive power spikes or saturates while BER collapses — the inverse of an
  atmospheric fade, which drops power and error rate together.
- **Transmitter spoofing and beam hijack.** An adversary positioned within the receive cone
  presents a stronger signal. Signature: a step change in received power with no corresponding
  change in reported pointing/tracking error; an alignment lock achieved at an unexpected angle.
- **Environmental confound.** Scintillation, fog, rain, and thermal-gradient beam wander degrade
  FSO constantly. Any FSO detection that is not correlated against environmental data will produce
  a false positive every foggy morning. For orbital links, add pointing-acquisition-tracking
  telemetry and ephemeris as the correlation source.

#### 6.6 Visible light, Li-Fi and IR

Short-range optical links in the visible and near-IR bands. The security property that matters:
**containment is optical, not cryptographic.** "It doesn't leave the room" fails at windows,
doorways, reflective surfaces, and glass partitions. Treat VLC/Li-Fi as a broadcast medium and
encrypt it accordingly.

#### 6.7 Optical air-gap covert channels

Both directions, both real, both demonstrated in published academic research:

- **Egress.** Data modulated onto a status LED, a display, a keyboard indicator, or an IR emitter,
  captured by a camera or photodiode with line of sight. This is `T1052`/`T1011` — an exfiltration
  path that never touches a network interface, and therefore never appears in any control in
  `D&R-17`.
- **Ingress.** Laser or modulated light injected into an optical sensor, camera, or scanner to
  inject commands or faults. Published research has demonstrated laser injection into MEMS
  microphones and optical sensors producing attacker-chosen input.

Detection is not primarily a telemetry problem here: it is line-of-sight control, physical siting,
covering or disabling non-essential emitters on high-consequence systems, and treating optical
sensors on those systems as untrusted input channels.

#### 6.8 Transceiver and hardware supply chain

An optical module is a computer. It has firmware, an I²C management interface, and physical access
to the signal before any host-side control sees it. A malicious or modified transceiver can copy
traffic, weaken the link, or provide a persistent implant that survives host rebuild — `T1195.003`
and `T1200`.

Signature: module vendor/serial/firmware that does not match the procurement record; DDM/DOM
telemetry inconsistent with the module's claimed type; unexpected firmware version or an
unexplained in-service firmware change; modules sourced outside the approved supply chain.
Reconcile module identity against procurement, not against what the module reports about itself —
a module that lies about its traffic will lie about its part number.

#### 6.9 Fiber cut and physical denial

The blunt instrument, and still the most common real-world optical incident. Signature: total loss
of signal, OTDR event at a specific distance, protection switch.

The security-relevant subtlety: **a cut can be cover.** A brief unexplained outage on a link is
the signature of splice-tap insertion (§6.2), and a cut that forces traffic onto a protection path
may be intended to move traffic onto a route the adversary *has* tapped. Investigate unexplained
optical outages as potential precursors, not just as availability events.

---

### 7. Detection Strategy

**Telemetry tiers — be explicit about which one you are on, because it determines what an absence
of alerts means.**

- **Tier 0 — transponder and platform telemetry you already have.** Rx/Tx optical power, OSNR,
  pre-FEC BER, and DDM/DOM per optical module, polled continuously and baselined. Plus
  optical-management-plane configuration and audit logs, which are what actually catch §6.3.
  Detects: gross taps, splice insertion, rogue-wavelength effects on provisioned channels, ROADM
  abuse, denial. Does **not** detect: a well-executed bend tap inside margin, or anything passive
  in free space.
- **Tier 1 — path characterization.** OTDR baselines with scheduled re-trace and automated diff;
  optical spectrum analysis against the provisioned channel plan; SOP monitoring where the
  transponder exposes it. This is where §6.1 and §6.4 become reliably detectable, and where events
  become *localizable to a distance* — which is what converts an alert into a dispatch.
- **Tier 2 — continuous physical-layer sensing.** Distributed acoustic sensing on critical routes,
  in-line optical intrusion detection systems, monitored and alarmed cable enclosures, and
  continuous SOP transient analysis. This is the tier that detects the fiber being *handled*,
  before and independently of any measurable loss.

**The four detection primitives:**

1. **Power and quality deviation from a tight local baseline.** Rx power, OSNR, and pre-FEC BER
   are baselined per link, per direction, with the normal diurnal and seasonal drift modeled. The
   detection is a **step change** — a discontinuity — not an absolute threshold. Slow drift is
   aging and temperature; a step is an event.
2. **Path-fingerprint diff.** Today's OTDR trace against the stored reference. A new event, or a
   changed loss at an existing event, is a physical change to the route. This is the strongest
   single optical detection because it carries a distance.
3. **Provisioned-versus-observed inventory.** Which wavelengths are lit, which ports are
   cross-connected, which modules are installed — reconciled against the service design and the
   procurement record. §6.3, §6.4, and §6.8 are all inventory-reconciliation detections.
4. **Disturbance transients.** SOP transients and DAS events indicate handling. **These fire
   during the intrusion, not after it** — they are the only optical primitive with a chance of
   catching the adversary while they are still at the cable.

**Two caveats that must appear in any report built on this playbook:**

- **Amplifier gain control can mask a loss.** An EDFA in automatic-gain or constant-output mode
  will partially compensate for power removed upstream, flattening the very step you are watching
  for. Baseline and alert on the **pre-amplifier** measurement where the platform exposes it, and
  record amplifier control mode per span in the inventory.
- **A sufficiently careful tap is below the detection floor of Tier 0 and often Tier 1.** State
  your floor. Do not report "no evidence of tapping" when the accurate statement is "no event
  above our detection floor of X dB on this link." The first is a fabrication under the house rule;
  the second is a finding.

---

### 8. Key Indicators

- Step decrease in Rx optical power on one direction of a link with no maintenance record.
- OSNR degradation without a matching change in span loss, weather, or amplifier state.
- Pre-FEC BER step increase while post-FEC traffic remains clean — **the earliest reliable
  indicator; treat a pre-FEC step as an event even when nothing user-visible has happened.**
- New or changed OTDR event versus the reference trace, especially at a distance that maps to an
  accessible location: a manhole, a riser, a patch panel, a building entrance, a cross-connect.
- SOP transient bursts on a link with no physical work scheduled — particularly outside working
  hours or in a location with no legitimate access.
- Brief unexplained link flap or protection switch followed by a persistent small loss increase —
  the splice-tap signature (§6.2).
- A wavelength present on the fiber that is not in the service inventory (§6.4).
- Optical cross-connect, monitor-port, or channel-routing change outside change control (§6.3).
- Transceiver vendor, serial, part number, or firmware inconsistent with the procurement record;
  unexplained in-service module firmware change (§6.8).
- Patch-panel, cross-connect enclosure, splice-closure, or manhole access without a work order.
- FSO: receive power spike with BER collapse (blinding); step power change with no pointing-error
  change (spoof); persistent degradation uncorrelated with weather.
- Unlit/dark fiber pairs showing optical activity.
- Any of the above on a link carrying long-shelf-life data — cross-reference the `PB-02` HNDL
  prioritization directly. **The same physical event on a link carrying decade-lived secrets and on
  a guest-network uplink are not the same severity.**

---

### 9. Design Controls — where the actual defense lives

Detection is a tripwire. These controls are what make a successful tap a non-event, and they
belong in the architecture before any of §7 is deployed.

- **Encrypt before the photons.** No plaintext on any optical span, including "internal" DCI, dark
  fiber between owned buildings, and anything a carrier calls a private circuit. Layer-2 MACsec
  (802.1AE), OTN-layer encryption, or Layer-3 IPsec — chosen per span and recorded per span.
- **Make it post-quantum, and specifically make the key establishment post-quantum.** A tapped
  span is harvested ciphertext (`PB-02`), so the relevant question is not whether it is encrypted
  today but whether it stays confidential for the data's full shelf life. Use hybrid key
  establishment — see `CONVENTIONS §1` for ML-KEM parameter selection and `CONVENTIONS §2` for
  hybrid named groups such as `X25519MLKEM768` (`0x11EC`). **Where a link encryptor's key
  agreement is classical-only, that is a finding, and it is the finding that matters most in this
  playbook** — the physics is a tripwire, this is the control. Record it as a CBOM gap under
  `PB-01` and prioritize it by Mosca margin under `PB-14`.
- **Prefer AES-256 on long-retention spans.** Grover halves symmetric strength; `CONVENTIONS §1`
  is the reference.
- **Never carry key material in-band on the span it protects**, and never derive the link key from
  something the tap can also see.
- **Govern the optical management plane as a Tier-0 privileged system.** §6.3 is a configuration
  attack; MFA, change control, and audit logging on the optical NMS/SDN controller are the control.
  Alert on cross-connect and monitor-port changes the same way you alert on domain-admin changes.
- **Physical protection proportional to consequence.** Alarmed and monitored enclosures, tamper-
  evident seals on patch panels and splice closures, conduit protection at building entrances, and
  documented route diversity so a cut cannot force traffic onto a single predictable path.
- **Procurement integrity for transceivers.** Approved-vendor sourcing, receiving inspection,
  serial reconciliation on install, and firmware version control. Treat an optical module as
  in-scope for supply-chain assurance (`PB-27`), not as a consumable.
- **On QKD, the GreyNOC position is explicit.** Quantum key distribution operates at this layer and
  is frequently proposed as the answer to optical tapping. It requires specialized hardware and
  trusted-node infrastructure, does not authenticate endpoints on its own, and multiple national
  authorities — NSA among them — do not recommend it for securing national security systems in
  place of standardized post-quantum cryptography. **PQC per `CONVENTIONS §1` remains the GreyNOC
  default.** Where a QKD deployment exists, treat it as an additional optical asset with its own
  attack surface, not as a replacement for the controls above.

---

### 10. Sample Detection Logic (JSON-style)

```json
{
  "rule_name": "Optical - Tap Signature by Step Loss and Quality Deviation",
  "description": "Detects the power/quality discontinuity characteristic of an inserted optical tap, distinguished from aging drift by requiring a step change.",
  "data_source": ["Transponder.OpticalPM", "Module.DDM", "NMS.ChangeRecord", "OpticalNMS.Amplifier"],
  "logic": {
    "window": "60m",
    "group_by": ["link_id", "direction"],
    "compute": {
      "rx_power_step_db": "step_change(rx_power_dbm, method='changepoint')",
      "osnr_step_db": "step_change(osnr_db, method='changepoint')",
      "prefec_ber_ratio": "prefec_ber / baseline_prefec_ber[link_id, direction]",
      "drift_rate_db_per_day": "linear_trend(rx_power_dbm, lookback='30d')"
    },
    "having": {
      "rx_power_step_db_lte": "-link_detection_floor_db",
      "step_duration_s_lte": 300,
      "is_step_not_drift": "abs(rx_power_step_db) > 5 * abs(drift_rate_db_per_day)"
    },
    "corroborate_any": [
      "osnr_step_db <= -link_osnr_floor_db",
      "prefec_ber_ratio >= link_prefec_multiplier",
      "sop_transient_count > baseline_p99 within 60m",
      "link_flap or protection_switch within preceding 24h"
    ],
    "suppress_if": [
      "NMS.ChangeRecord.active_maintenance(link_id) == true",
      "amplifier_control_mode in ['AGC','constant_output'] and pre_amp_measurement_unavailable == true"
    ]
  },
  "notes": [
    "link_detection_floor_db is derived per link from its own measured noise, NOT from a published constant. Record it; it is what bounds any 'no evidence of tapping' statement.",
    "The suppress_if amplifier clause is a KNOWN BLIND SPOT, not a clean result: AGC masks upstream loss. Route these links to the OTDR rule instead of silently dropping them."
  ],
  "severity": "high",
  "tags": ["T1040", "T1200", "optical_tap", "hndl_capture_point"]
}
```

```json
{
  "rule_name": "Optical - OTDR Path Fingerprint Divergence",
  "description": "Diffs the current OTDR trace against the stored reference to detect a physical change to the fiber route, localized to a distance.",
  "data_source": ["OTDR.Trace", "OTDR.ReferenceTrace", "Cable.RouteMap", "NMS.ChangeRecord"],
  "logic": {
    "schedule": "continuous_or_scheduled",
    "for_each": "fiber_span",
    "compute": {
      "new_events": "events(current) - events(reference)",
      "changed_events": "events where abs(loss_db_current - loss_db_reference) > event_tolerance_db",
      "event_location_m": "distance_along_span"
    },
    "trigger_any": [
      "count(new_events) > 0",
      "count(changed_events) > 0",
      "total_span_loss_db - reference_span_loss_db > span_tolerance_db"
    ],
    "enrich": {
      "physical_location": "RouteMap.lookup(event_location_m)",
      "accessibility": "RouteMap.access_class(event_location_m)"
    },
    "escalate_if_any": [
      "accessibility in ['manhole','riser','patch_panel','building_entrance','cross_connect','third_party_facility']",
      "no matching NMS.ChangeRecord within +/- 7d",
      "span carries data_class in PB02.hndl_priority_classes"
    ]
  },
  "notes": "The reference trace is the control. Re-baseline ONLY after authorized, documented work, and archive the superseded reference — a re-baseline performed on top of an intrusion permanently destroys the evidence.",
  "severity": "critical_when_escalated_else_high",
  "tags": ["T1200", "optical_path_change", "no_clean_attack_mapping"]
}
```

```json
{
  "rule_name": "Optical - Unprovisioned Wavelength and Cross-Connect Divergence",
  "description": "Reconciles observed optical spectrum and cross-connect state against the service inventory to detect rogue wavelengths and monitor-port abuse.",
  "data_source": ["OSA.ChannelScan", "OpticalNMS.CrossConnect", "OpticalNMS.AuditLog", "Service.Inventory"],
  "logic": {
    "window": "1h",
    "trigger_any": [
      "observed_channel not in Service.Inventory.provisioned_channels[fiber_id]",
      "observed_channel_power_dbm > noise_threshold on unlit_or_dark_pair",
      "cross_connect_state != Service.Inventory.designed_cross_connect",
      "monitor_port_active and not in Service.Inventory.approved_monitor_ports",
      "wavelength present at degree/port not in service design"
    ],
    "escalate_if_any": [
      "OpticalNMS.AuditLog shows config change outside approved change window",
      "config change by identity without optical-plane authorization",
      "no audit-log entry corresponds to the observed state change",
      "affected channel carries data_class in PB02.hndl_priority_classes"
    ],
    "action": "alert + preserve_config_snapshot + do_not_revert_before_capture"
  },
  "notes": "An unauthorized monitor port with NO corresponding audit entry is worse than one with a bad entry: it implies the management plane itself is compromised. Escalate to D&R-19 before touching the configuration.",
  "severity": "critical",
  "tags": ["T1557", "T1040", "roadm_monitor_abuse", "no_clean_attack_mapping"]
}
```

```json
{
  "rule_name": "Optical - FSO Beam Interference, Blinding or Spoof",
  "description": "Separates hostile optical events on free-space links from atmospheric degradation using the power/BER relationship and pointing telemetry.",
  "data_source": ["FSO.Terminal.PM", "FSO.PointingTelemetry", "Weather.Local", "Satellite.Ephemeris"],
  "logic": {
    "window": "15m",
    "for_each": "fso_link",
    "compute": {
      "rx_power_delta_db": "rx_power_dbm - baseline_rx_power_dbm[link_id, geometry]",
      "ber_delta": "prefec_ber / baseline_prefec_ber[link_id]",
      "pointing_error_delta": "tracking_error - baseline_tracking_error[link_id]"
    },
    "trigger_any": [
      "rx_power_delta_db > 0 and ber_delta > 1",
      "abs(rx_power_delta_db) > step_threshold_db and abs(pointing_error_delta) < pointing_tolerance",
      "alignment_lock_acquired_at_angle not in expected_geometry"
    ],
    "suppress_if": [
      "Weather.Local indicates fog/rain/scintillation consistent with observed fade",
      "Satellite.Ephemeris explains geometry change"
    ],
    "notes": "The discriminator: atmospheric fade drops received power AND raises BER together. Blinding RAISES received power while BER collapses. Spoofing changes received power with NO pointing-error change. Weather correlation is mandatory or this rule fires every foggy morning.",
    "severity": "high"
  },
  "tags": ["T1498", "T1557", "fso_interference", "no_clean_attack_mapping"]
}
```

---

### 11. Example Telemetry

IPv4 per RFC 5737; IPv6 per RFC 3849.

```
Transponder optical PM — bend-tap signature (link DCI-A-B, 1550.12 nm, C-band ch.34)
2026-08-09T02:10 rx=-8.42dBm osnr=21.7dB prefec_ber=2.1e-6   sop_transients=0
2026-08-09T02:15 rx=-8.44dBm osnr=21.7dB prefec_ber=2.2e-6   sop_transients=0
2026-08-09T02:41 rx=-8.43dBm osnr=21.6dB prefec_ber=2.1e-6   sop_transients=47   <- handling
2026-08-09T02:42 rx=-8.91dBm osnr=20.9dB prefec_ber=9.7e-6   sop_transients=112  <- step
2026-08-09T02:47 rx=-8.90dBm osnr=20.9dB prefec_ber=9.9e-6   sop_transients=3
2026-08-09T03:00 rx=-8.90dBm osnr=20.9dB prefec_ber=9.8e-6   sop_transients=0    <- new steady state
  -> 0.47 dB step in 60s. 30-day drift rate 0.004 dB/day: this is 117x the drift, i.e. a step.
     Post-FEC traffic clean throughout. No change record. link_detection_floor_db = 0.25.

OTDR trace diff — span MAN-04 (reference 2026-05-14)
  event  distance_m   type            loss_dB_ref   loss_dB_now   delta
  E1        0.0       connector          0.31          0.32       +0.01
  E2      412.6       splice             0.06          0.06        0.00
  E3     1187.3       connector          0.28          0.29       +0.01
  E4     2043.9       -- ABSENT --        --           0.44       NEW    <<<
  E5     3990.1       end                 --            --          --
  RouteMap.lookup(2043.9) = "Manhole MH-17, 3rd & Vine, access_class=street_manhole"
  ChangeRecord(+/-7d) = NONE

Optical spectrum analysis — fiber DARK-PAIR-07 (inventory: unlit)
  1529.55nm  -48.1 dBm   (noise)
  1550.92nm  -14.6 dBm   <<< channel present on a pair with no provisioned service
  1561.42nm  -47.9 dBm   (noise)

Optical NMS audit — monitor-port abuse
  2026-08-09T01:58Z  user=svc-optical-ro  action=cross_connect_add
    src=deg2/ch34  dst=mon-port-3  result=SUCCESS  change_ticket=<none>
  -> Read-only service account performed a write. No ticket. Monitor port not in approved list.

FSO terminal — blinding vs. fade (link ROOF-N to ROOF-S)
  baseline        rx=-31.2dBm prefec_ber=4e-7 tracking_err=0.8urad  weather=clear
  2026-08-09T11:02 rx=-38.7dBm prefec_ber=6e-5 tracking_err=0.9urad  weather=fog    <- fade (both worsen)
  2026-08-09T15:40 rx=-19.4dBm prefec_ber=3e-3 tracking_err=0.8urad  weather=clear  <- BLINDING
                                                                                       (power UP, BER UP)

Transceiver reconciliation
  port=Et1/49  reported: vendor=<V> pn=<P> sn=XXA1934  fw=3.2.1
  procurement:  vendor=<V> pn=<P> sn=XXA1934  fw=3.1.0 (shipped)
  -> In-service firmware change with no maintenance record. Module holds pre-encryption signal path.
```

---

### 12. Investigation Steps

1. **Do not re-baseline, do not revert, do not clean the connector.** The reference OTDR trace, the
   current optical PM history, and the current cross-connect configuration are the evidence. A
   re-baseline performed on top of an intrusion destroys it permanently and irreversibly. Snapshot
   everything before any remediation touches the link.
2. **Check the change record first.** Optical events have mundane causes at a high rate:
   maintenance, connector cleaning, re-patching, splice repair, module replacement, construction
   along the route. Pull work orders, carrier maintenance notices, and contractor schedules for the
   link and the window. This resolves most alerts and it resolves them fast.
3. **Confirm the step is a step.** Compare the magnitude against the link's own 30–90 day drift
   rate. Aging, temperature, and connector degradation produce gradual change; a tap produces a
   discontinuity. Compute the ratio and put it in the report — it is the difference between an
   event and a maintenance ticket.
4. **Localize with OTDR and map the distance to a physical place.** This is the decisive step. A
   distance becomes a manhole, a riser, a patch panel, a building entrance, a carrier
   cross-connect, a colocation cage. Record the access class of that location, because it
   determines both who could have done it and how urgent the dispatch is.
5. **Correlate with physical access.** Badge logs, camera footage, work orders, visitor records,
   and carrier or landlord access logs for that location and window. For third-party facilities,
   this means a formal request — start it immediately; it is the long pole.
6. **Check the direction and the position in the path.** Which direction lost power, and where
   the loss sits relative to amplifiers, tells you where in the span to look and whether AGC could
   have masked a larger upstream loss than you measured.
7. **Reconcile the optical inventory end to end.** Provisioned wavelengths versus observed
   spectrum; designed cross-connects versus running configuration; procurement records versus
   installed module serials and firmware. Rogue wavelengths, ROADM abuse, and malicious
   transceivers are all found here and nowhere else.
8. **For any management-plane involvement, pivot to a full intrusion investigation.** An
   unauthorized cross-connect means someone had access to the optical NMS. That is a compromised
   privileged system — hand off to `D&R-19` and treat the optical event as one symptom, not the
   incident.
9. **Determine exposure, and determine it cryptographically.** Enumerate every service, tunnel,
   and data class carried on the affected wavelength for the entire period since the last verified
   clean baseline — **not since detection.** Then answer the question that actually determines
   severity: *was the traffic on that span encrypted, with what key establishment, and does its
   confidentiality need to survive a cryptanalytically relevant quantum computer?* Ciphertext under
   hybrid PQ key establishment is a contained incident. Plaintext, or ciphertext under
   classical-only key exchange carrying decade-lived secrets, is an HNDL exposure — scope it under
   `PB-02` and escalate accordingly.
10. **Assume the exposure window is longer than the detection window.** A bend tap leaves nothing
    behind once removed. The defensible statement is bounded by your last verified clean
    measurement, and that is the window you must report.
11. **Preserve physical evidence properly.** If a device is found, photograph in place, document
    chain of custody, and hand to the physical-evidence process. Do not power it on outside a
    controlled environment.

---

### 13. False Positive Considerations

Most optical anomalies are maintenance and physics. Expect this to dominate the queue.

- **Scheduled and unscheduled maintenance** — splice repair, re-patching, module replacement,
  carrier work on leased spans. Carrier maintenance notices frequently arrive late or not at all;
  chase them rather than escalating.
- **Connector contamination and cleaning.** A dirty connector adds loss gradually; cleaning it
  removes loss suddenly. **A sudden loss *improvement* is a change record you are missing, not a
  clean result.**
- **Temperature and seasonal drift.** Aerial fiber, building risers, and outside plant all show
  diurnal and seasonal variation. Model it into the baseline or it will fire daily.
- **Component aging.** Laser output declines over life; receiver sensitivity degrades. Gradual,
  not step — which is exactly what the step-versus-drift test in §10 separates.
- **Amplifier gain transients** during channel add/drop operations, which are legitimate service
  activity.
- **Protection switching** moving traffic to a path with different loss characteristics. The new
  path has a different baseline; alerting against the old one is a false positive.
- **Construction and vibration near the route** producing SOP and DAS events with no tap. This is
  the main SOP false-positive source; correlate with known works.
- **FSO weather** — fog, rain, snow, scintillation, and thermal beam wander. Weather correlation is
  mandatory for any FSO rule.
- **Orbital-link geometry** — legitimate pointing and handover events on inter-satellite links.
  Correlate against ephemeris.

---

### 14. Tuning Guidance

- **The baseline is the detection.** Nothing in this playbook works without a per-link, per-
  direction, drift-modeled baseline of Rx power, OSNR, and pre-FEC BER, plus a stored OTDR
  reference trace per span. Build these before writing a single rule.
- **Record `link_detection_floor_db` per link and treat it as a first-class output**, not an
  internal parameter. It bounds every statement the program can make about tapping on that link,
  and it belongs in the analyst notes and in any assurance report.
- **Alert on steps, not thresholds.** Use changepoint detection with the drift-ratio test.
  Absolute-threshold alerting on optical power produces alarm fatigue and misses small taps.
- **Lead with pre-FEC BER.** It moves before post-FEC errors, before traffic impact, and often
  before a power step is unambiguous.
- **Prioritize by data class, not by link.** Use the `PB-02` HNDL prioritization to decide which
  spans get Tier-1 and Tier-2 sensing. Not every fiber warrants an OTDR program; the ones carrying
  decade-lived confidentiality do.
- **Re-baseline only after authorized documented work, and archive the superseded reference.**
  Never let an automated process silently re-baseline.
- **Treat AGC-masked links as an explicit coverage gap** with a named owner and a compensating
  control (OTDR or SOP), not as links that simply never alert.
- **Reconcile inventory on a schedule, not only on alert.** Rogue wavelengths and unauthorized
  cross-connects are found by periodic reconciliation; a rogue λ on a dark pair generates no
  service impact and will never alert on its own.

---

### 15. Response Actions

**Immediate**

- Preserve before you fix: snapshot optical PM history, current and reference OTDR traces, spectrum
  scan, cross-connect configuration, module inventory, and NMS audit logs. **Remediation destroys
  optical evidence — capture first, without exception.**
- Do not revert an unauthorized cross-connect before capturing it; the configuration is the
  evidence and reverting may tip the adversary.
- Determine what the affected wavelength carries and how it is protected. This determines
  everything downstream.
- Dispatch to the localized physical position; engage facilities, the carrier, or the colocation
  provider as the location requires.
- If safe and available, move critical traffic to a diverse path — but confirm the alternate path
  is not the one the adversary intended to force you onto (§6.9).
- For confirmed management-plane compromise, invoke `D&R-19` and treat the optical NMS as a
  compromised privileged system.

**Short-term**

- **Rotate keys on the assumption the tap succeeded.** Every link encryptor key, every session key
  negotiated over the affected span, and every long-lived secret that transited it since the last
  verified clean baseline. `PB-25` governs the rotation and rewrap workflow.
- Where key establishment on the affected span was classical-only, **treat all traffic carried
  since the last clean baseline as harvested** and scope it under `PB-02`. This is the HNDL case
  made concrete: the ciphertext is gone, and its confidentiality now depends entirely on the key
  exchange that protected it.
- Re-verify the physical path end to end, including patch panels, cross-connects, splice closures,
  and any third-party facility on the route.
- Reconcile every transceiver on the affected path against procurement; replace anything that does
  not reconcile.
- Sweep for the same signature across every other span — a tap found on one link is a reason to
  re-trace the rest, and organizations routinely find the second one this way.
- Notify the carrier or facility provider where the event localizes to their infrastructure, and
  preserve the right to inspect.

**Long-term**

- Close the encryption gap the incident exposed. **Any span found carrying plaintext or
  classical-only key establishment is the primary finding of the incident**, regardless of whether
  the tap is confirmed — the tap is the demonstration, the gap is the vulnerability. Migrate to
  hybrid PQ key establishment per `CONVENTIONS §1`/`§2`, and record it in the CBOM (`PB-01`) with a
  Mosca-margin-driven date (`PB-14`).
- Raise sensing tier on spans carrying HNDL-priority data: OTDR baselining with automated diff at
  minimum, DAS on critical routes where the consequence justifies it.
- Bring the optical management plane fully under privileged-access management with alerting on
  cross-connect and monitor-port changes.
- Harden the physical route: alarmed enclosures, tamper-evident seals, conduit protection, and
  documented, genuinely diverse routing.
- Add optical modules to supply-chain assurance (`PB-27`) with serial reconciliation at install.
- Add the optical plane to the CBOM as a first-class transport surface, so the next crypto
  inventory does not stop at the application layer.

---

### 16. Escalation Criteria

Escalate to incident when **any** of the following are true:

- An OTDR event appears that is absent from the reference trace with no corresponding change
  record — regardless of magnitude.
- A step power or OSNR loss is confirmed as a step (not drift) with no maintenance explanation.
- An unprovisioned wavelength is observed on any fiber, lit or dark.
- Any unauthorized optical cross-connect or monitor-port configuration is found — and treat it as
  **critical** where no corresponding audit-log entry exists, because that implies the management
  plane itself is compromised.
- A transceiver fails procurement reconciliation on serial or firmware.
- The affected span carried **plaintext**, or ciphertext under **classical-only key
  establishment**, and the data class has a shelf life extending past the organization's quantum
  risk horizon. This is an HNDL exposure under `PB-02` and escalates on its own merits, whether or
  not the tap is ever confirmed.
- SOP or DAS disturbance events occur at a location with no authorized access, particularly
  out-of-hours.
- FSO blinding or spoofing signature confirmed against weather and ephemeris.
- An optical event correlates with a physical-security event on the same route.
- An unexplained optical outage occurs on a link carrying high-consequence data — investigate as a
  possible splice-tap insertion or path-forcing precursor (§6.9), not as an availability ticket.

---

### 17. Analyst Notes Template

```text
Incident ID:
Detection Rule / Telemetry Tier (0|1|2):
Detected At / Detected By:
Link / Span ID / Direction:
Wavelength (nm) / DWDM Channel / Modulation Format:
Medium:                  SMF | MMF | FSO | ISL | VLC/IR
Intrusion Class:         bend-tap | splice-tap | ROADM/monitor | rogue-lambda | FSO |
                         air-gap-optical | transceiver-supply-chain | physical-denial
--- Measurements ---
Rx Power: baseline ____ dBm  observed ____ dBm  step ____ dB
OSNR:     baseline ____ dB   observed ____ dB
Pre-FEC BER: baseline ____   observed ____   ratio ____
30-90d drift rate ____ dB/day   step:drift ratio ____   (step confirmed? Y/N)
link_detection_floor_db: ____   <-- BOUNDS EVERY "no evidence" STATEMENT IN THIS REPORT
SOP transients / DAS events: ____
Amplifier control mode / AGC masking possible: ____ / Y/N
--- Localization ---
OTDR reference date / new or changed event / distance: ____ / ____ / ____ m
Physical location / access class: ____ / ____
Third-party facility involved: ____
Physical access correlation (badge/camera/work order/carrier): ____
Weather / ephemeris correlation (FSO & ISL only): ____
--- Inventory reconciliation ---
Provisioned vs observed wavelengths: ____
Cross-connect design vs running: ____
Monitor ports (approved vs active): ____
Transceiver serial/firmware vs procurement: ____
NMS audit entry present for observed change: Y/N   <-- N = management-plane compromise
--- Exposure ---
Services / data classes on affected wavelength: ____
Encryption in force on span: none | MACsec | OTN | IPsec | ____
Key establishment: classical-only | hybrid PQ (____)   <-- THE severity determinant
Data shelf life vs quantum risk horizon (PB-14 Mosca): ____
Last verified clean baseline: ____   Exposure window: ____
HNDL scoping required (PB-02): Y/N
--- Handling ---
Evidence preserved before remediation: Y/N (list)
Keys rotated / rewrap scope (PB-25): ____
Containment actions:
Coverage gap identified:
Outstanding Risks:
Recommendations:
Analyst:
```

---

### 18. Summary

Data is created at the nanometer scale by imprinting bits on a laser carrier — intensity-modulated
for short reach, coherent phase-and-polarization modulated for long reach — multiplexed onto a
DWDM grid, amplified, and routed through ROADMs. It is recovered by a photodiode or a coherent
receiver whose telemetry — Rx power, OSNR, pre-FEC BER, state of polarization — *is* the security
instrumentation for the medium.

Intrusion detection rests on four primitives: **step deviation** from a tight local baseline,
**OTDR path-fingerprint diff** (the only primitive that yields a distance, and therefore a
dispatch), **provisioned-versus-observed inventory reconciliation** (which is how rogue
wavelengths, ROADM monitor abuse, and malicious transceivers are found), and **disturbance
transients** (the only primitive that fires while the adversary is still at the cable). Alert on
steps rather than thresholds, lead with pre-FEC BER, and preserve the reference trace as evidence —
a re-baseline over an intrusion erases it permanently.

Two limits must be stated in every report. **Amplifier gain control can mask upstream loss** — such
links are a named coverage gap, not quiet links. And **a competent tap can sit below the detection
floor**, so the honest finding is "no event above our floor of X dB," never "no evidence of
tapping."

Which is why the response is cryptographic before it is physical. Assume the tap succeeded: rotate
keys, scope the exposure from the last verified clean baseline rather than from detection, and
treat any span running plaintext or classical-only key establishment as the primary finding.
Optical monitoring tells you someone was at the cable. **Hybrid post-quantum key establishment is
what makes it not matter.**

---

*GreyNOC — detection-engineering-first security operations.*
