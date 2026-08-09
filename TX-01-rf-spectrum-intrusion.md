# GreyNOC Security Playbook

## TX-01 — RF & Radio-Spectrum Intrusion Detection & Response

---

### 1. Overview

Every control in a modern security program assumes the adversary arrives over a wire. Radio does
not require one. An RF adversary needs proximity and an antenna — not a credential, not a port,
not an egress path through the proxy. The traffic never appears in NetFlow because it never
enters the network the SOC instruments.

This playbook covers detection and response for intrusions carried over radio-frequency media,
roughly 3 kHz to 300 GHz: Wi-Fi, Bluetooth/BLE, cellular, GNSS reception, sub-GHz ISM and LPWAN,
and microwave/satellite backhaul. It also scopes electromagnetic emanation (TEMPEST) honestly —
including the parts an ordinary enterprise cannot detect.

The organizing insight is the same one that drives `D&R-08 Malware Beaconing`: **detection runs on
geometry, not payload.** Most RF attack traffic is encrypted, proprietary, or deliberately
malformed. What gives it away is where it comes from, how strong it is, how it behaves over time,
and whether its claimed identity matches its physical position.

The second organizing insight is harder to accept: **passive reception is undetectable in
principle.** A receiver emits nothing. An adversary capturing your Wi-Fi, your BLE advertisements,
or your microwave backhaul leaves no signal to detect — ever, at any budget. Detection covers
*active* RF intrusion; passive interception is addressed by making the capture worthless, which is
a cryptographic control, not a detection one. Any RF playbook that claims otherwise is selling
something.

**Related:** `TX-02` (optical media, the other half of the physical layer), `D&R-17` (exfiltration —
RF is an alternate medium, not just an alternate protocol), `D&R-15` (persistence — an RF implant
is a persistence mechanism), `PB-02` (HNDL — passively captured RF is harvested ciphertext).

---

### 2. Scope and the RF-BOM

Detection begins with knowing what is *supposed* to be transmitting. The library already builds a
CBOM (`PB-01`) and an AI-BOM (`PB-21`); the RF equivalent is the same discipline applied to the
spectrum plane. Without it there is no baseline, and without a baseline every RF alert is
unfalsifiable.

Record, per emitter and per receiver:

- **Identity** — asset ID, owner, physical location (building/floor/room, and outdoor position for
  fixed links), business purpose.
- **Radio** — band(s), channel/ARFCN/EARFCN plan, modulation, protocol and version, transmit
  power, antenna type/gain/polarization/azimuth, duty cycle.
- **Addressing** — BSSID/MAC, BLE address type (public, random static, resolvable private), cell
  identity, LoRaWAN DevEUI/JoinEUI, device serial.
- **Security posture** — authentication and encryption in use (WPA2-PSK, WPA3-SAE, 802.1X, BLE
  pairing mode, LoRaWAN join method), management-frame protection status, firmware version,
  whether keys are per-device or shared.
- **Receive-only assets** — GNSS receivers, telemetry receivers, and anything that consumes radio
  it does not transmit on. These are the assets most often omitted from inventory and most easily
  attacked, because *nobody thinks of a receiver as an attack surface*.
- **Expected RF neighborhood** — the transmitters you do not own but always see. Adjacent-tenant
  APs, the coffee shop below, the operator macro cells. If this is not baselined, every one of
  them becomes an alert.

An RF-BOM entry with no baseline measurement attached is inventory, not telemetry. Pair each
fixed emitter with a recorded reference RSSI at each sensor position, and each receiver with its
normal signal-quality range.

---

### 3. MITRE ATT&CK Mapping

| Technique | ID | Matrix | Tactic |
|-----------|----|--------|--------|
| Hardware Additions | T1200 | Enterprise | Initial Access |
| Network Sniffing | T1040 | Enterprise | Credential Access, Discovery |
| Adversary-in-the-Middle | T1557 | Enterprise | Collection, Credential Access |
| Exfiltration Over Other Network Medium | T1011 | Enterprise | Exfiltration |
| Exfiltration Over Other Network Medium: Exfiltration Over Bluetooth | T1011.001 | Enterprise | Exfiltration |
| Exfiltration Over Physical Medium | T1052 | Enterprise | Exfiltration |
| Network Denial of Service | T1498 | Enterprise | Impact |
| Network Boundary Bridging | T1599 | Enterprise | Defense Impairment |
| Wireless Compromise | T0860 | ICS | Initial Access |
| Wireless Sniffing | T0887 | ICS | — verify against your ATT&CK version |
| Adversary-in-the-Middle | T0830 | ICS | — verify against your ATT&CK version |
| Denial of Service | T0814 | ICS | Inhibit Response Function |

> **Mapping discipline (`CONVENTIONS §4`).** ICS tactic placement differs from Enterprise and both
> IDs and tactic assignments move between ATT&CK versions. Re-verify every row against the version
> your platform carries before you tag a detection with it.

**Deliberately unmapped.** The following have no clean ATT&CK technique, and this playbook says so
rather than forcing a tag: **RF jamming as a distinct technique** (`T1498` describes network-layer
volumetric DoS, not physical-layer denial — the mapping is an analogy, use it with a note),
**GNSS spoofing**, **rogue cellular base station / IMSI catcher**, and **electromagnetic emanation
capture (TEMPEST)**. Tag these with the internal class from §5 and describe the behavior.

---

### 4. Detection Strategy — and what each tier can actually see

You cannot detect what you cannot receive. RF detection maturity is a function of hardware, and
being honest about the tier you are on is a precondition for trusting an absence of alerts.

**Tier 0 — infrastructure-derived. No new hardware.**
Telemetry from radios you already own: wireless LAN controller and AP logs, client association
history and RSSI, retry and PHY-error counters, channel-utilization stats, cellular modem
diagnostics on managed endpoints, GNSS receiver status sentences, LoRaWAN network-server join
logs. This detects: rogue APs on your own channels, evil twins, association anomalies, most
jamming, most GNSS spoofing, and cellular downgrade on *managed* devices.
It does **not** detect: transmitters on bands your infrastructure does not tune, RF implants using
proprietary sub-GHz protocols, or anything passive.

**Tier 1 — dedicated sensing.**
A WIPS overlay, receive-only SDR sensors, or spectrum analyzers at fixed positions. This adds:
wideband unauthorized-emitter discovery, spectral-occupancy baselining, RF implant detection, and
direction finding when three or more sensors see the same emitter.

**Tier 2 — RF baseline and anomaly program.**
Continuous spectral occupancy modeling per band, per position, per time-of-day, with drift
alerting. This is what turns "there is an unknown signal at 915 MHz" into "there is an unknown
signal at 915 MHz that was not here last Tuesday and is strongest near the server room."

**The five detectable behaviors.** Regardless of tier, active RF intrusion reduces to five shapes:

1. **Presence** — an emitter that should not exist. Detection: identity not in the RF-BOM.
2. **Impersonation** — an emitter claiming an identity that does exist. Detection: the claimed
   identity and the physical evidence disagree. A BSSID your RF-BOM places on floor 3 cannot
   legitimately appear at −40 dBm on a floor-8 sensor. **Physical position is the hardest property
   for an adversary to forge** and should carry the most weight in scoring.
3. **Denial** — energy that prevents reception. Detection: noise floor rises while signal quality
   falls. The distinguishing feature of jamming versus congestion is that jamming degrades SNR
   without a corresponding rise in *decodable* traffic.
4. **Injection / replay** — valid-looking frames the legitimate transmitter did not send.
   Detection: sequence-number discontinuities, duplicate counters, frames arriving with the right
   identity but the wrong RSSI or timing.
5. **Reception anomaly** — a receiver being fed a lie. Detection: physical implausibility in what
   the receiver reports (see §5.4 for the GNSS case, which is the canonical example).

---

### 5. Intrusion Classes and Their Indicators

#### 5.1 Wi-Fi (802.11)

- **Rogue AP on the corporate wire.** An unauthorized AP bridging RF to the internal LAN — the
  cleanest `T1599` Network Boundary Bridging case there is. Indicators: an SSID/BSSID absent from
  the RF-BOM whose wired-side MAC (or an adjacent MAC in the same OUI block) appears in switch CAM
  tables; an AP with a consumer OUI on an access port; DHCP leases from an unexpected server.
- **Evil twin.** A rogue transmitting a legitimate SSID. Indicators: correct SSID with a BSSID not
  in the RF-BOM; correct SSID *and* BSSID but implausible RSSI/position (BSSID spoofing);
  downgraded security posture (an open or WPA2-PSK twin of an 802.1X network); client roams to a
  new BSSID with no corresponding RSSI trend.
- **Deauthentication / disassociation flood.** Forced client disconnection, usually as a precursor
  to evil-twin capture or handshake collection. Indicators: burst of deauth/disassoc frames,
  mass simultaneous client loss across one AP, reason codes inconsistent with the AP's own logs.
  802.11w Protected Management Frames — mandatory under WPA3 — largely closes this; **an estate
  seeing deauth floods is telling you PMF is not enforced.**
- **Probe-response / known-beacon abuse.** A rogue answering client probe requests for any
  requested SSID, harvesting clients with stale preferred-network lists. Indicators: one BSSID
  beaconing or responding for an implausible number of distinct SSIDs.
- **Handshake capture for offline cracking.** Passive, therefore **not directly detectable** —
  detect the deauth that provokes the re-handshake, and defend with WPA3-SAE, which removes the
  offline-dictionary exposure that makes the capture worth doing.

#### 5.2 Bluetooth / BLE

- Unauthorized BLE peripherals advertising inside secure areas; devices whose address type is
  public/random-static (trackable) where policy requires resolvable private addresses.
- Peripherals paired to corporate endpoints that are absent from the RF-BOM — a BLE HID device is
  a keystroke injection surface (`T1200`).
- Exfiltration over Bluetooth (`T1011.001`): an endpoint with sustained BLE/BR-EDR throughput to
  an unenrolled peer, especially outside working hours.
- Tracker-class devices persisting with corporate assets or personnel.

#### 5.3 Cellular (LTE / 5G NR)

Detection here is almost entirely endpoint-side, from managed-device modem diagnostics.

- **Rogue base station / IMSI catcher.** Indicators: an unexpected downgrade to 2G/GSM or to a
  weaker cipher (including null encryption); serving-cell identity not present in the operator's
  published or previously observed cell database; a cell with abnormally high signal strength for
  its claimed location; forced reselection away from a stable serving cell; tracking-area updates
  at an implausible rate; identity requests for permanent identifiers.
- **5G note.** SUCI concealment removes the plain-IMSI exposure that made classic catchers easy,
  but a downgrade to LTE or 2G re-opens it. **Detect the downgrade, not the catcher.**
- Cellular-enabled rogue devices as an egress bypass: an internal host that also holds a cellular
  interface is an unmonitored egress path around every proxy control in `D&R-17`.

#### 5.4 GNSS reception — the canonical receiver attack

GNSS receivers accept unauthenticated broadcast from space, with received power low enough that a
local transmitter trivially overrides it. Time, not just position, is the target: a spoofed clock
breaks Kerberos, TOTP, certificate validity, log correlation, and financial timestamping.

Spoofing indicators:

- All tracked satellites reporting near-identical C/N₀, or C/N₀ abnormally high and uniform — real
  constellations produce a spread driven by elevation angle.
- Position or time discontinuity without corresponding motion; receiver clock steering at an
  implausible rate.
- Tracked PRN set inconsistent with the almanac for that time and location.
- Two or more independent receivers at known separation reporting the same position.
- Loss of RAIM/integrity consistency, or a sudden drop in reported dilution of precision that does
  not match sky visibility.

Defenses to record in the RF-BOM: multi-constellation and multi-frequency reception, RAIM,
antenna placement with sky-only view and terrain masking, a disciplined holdover oscillator sized
to survive the outage you plan for, and signal authentication where the constellation offers it —
Galileo OSNMA is available today; GPS signal-authentication work is still in development, so do
not plan a control around it as though it were deployed.

#### 5.5 Sub-GHz ISM and LPWAN (433 / 868 / 915 MHz, LoRa, Zigbee, Z-Wave)

This is where RF implants live, because the bands are lightly monitored, propagate well through
building structure, and support cheap long-range links.

- An emitter in the RF-BOM's "unknown" column with a periodic duty cycle — the RF equivalent of
  beaconing (`D&R-08`), and analyzed the same way: inter-burst interval regularity is the signal.
- LoRaWAN join anomalies: repeated join requests from a known DevEUI, join-request replay, or a
  DevEUI joining from an implausible gateway.
- Replay against building-automation, sensor, or access-control radios: identical payloads with
  stale rolling counters.

#### 5.6 Microwave and satellite backhaul

- Link-budget degradation inconsistent with weather (a jamming or interference signature versus
  rain fade — see §8).
- Received signal present with elevated bit-error rate and no corresponding fade: consistent with
  interference or an injection attempt.
- Any point-to-point link carrying unencrypted payload is a passive-capture target with a large
  standoff distance. Treat it as harvested (`PB-02`).

#### 5.7 Electromagnetic emanation (TEMPEST) — scoped honestly

Unintentional EM radiation from cables, displays, and processors can carry recoverable
information. This is a real phenomenon and a real research area.

**It is also, for the overwhelming majority of enterprises, not detectable.** The adversary is a
passive receiver. There is no emission to alert on, no log to correlate, and no commercially
routine control that verifies whether capture occurred. Treating TEMPEST as a *detection* problem
produces theater.

Handle it as an architecture and siting problem instead: zone placement, physical standoff
distance, shielding where the threat model genuinely warrants it, and — this being the part that
generalizes — **not putting the highest-consequence plaintext processing at the building
perimeter.** Escalate to a specialist program only where a documented threat model and a
regulatory or classification requirement justifies it. Do not file this under `PB-08 C10`, which
covers computational side channels.

---

### 6. Sample Detection Logic (JSON-style)

```json
{
  "rule_name": "RF - Evil Twin / SSID Impersonation by Position Implausibility",
  "description": "Detects a BSSID advertising a corporate SSID whose observed physical position or identity contradicts the RF-BOM baseline.",
  "data_source": ["WLC.AP.Neighbor", "WIPS.Sensor.Observation", "RFBOM.Emitter"],
  "logic": {
    "window": "15m",
    "for_each": "observed_emitter",
    "where": { "ssid": "in RFBOM.corporate_ssids" },
    "trigger_any": [
      "bssid not in RFBOM.emitter.bssid",
      "abs(observed.rssi_dbm - RFBOM.baseline_rssi_dbm[sensor_id]) > baseline_tolerance_db",
      "observed.security_profile weaker_than RFBOM.emitter.security_profile",
      "observed.bssid seen_at_sensor not_in RFBOM.emitter.expected_sensors"
    ],
    "escalate_if_any": [
      "observed.security_profile == 'open' or 'wpa2-psk' while baseline == '802.1x'",
      "client_count_migrated_to_observed_bssid >= 3 within 5m",
      "deauth_frame_rate[target_bssid] > baseline_p99 within preceding 10m"
    ]
  },
  "notes": "baseline_tolerance_db MUST be derived per sensor from a recorded local baseline. There is no portable absolute value; RF propagation is site-specific.",
  "severity": "high_when_escalated_else_medium",
  "tags": ["T1557", "T1599", "rf_impersonation"]
}
```

```json
{
  "rule_name": "RF - Physical-Layer Denial (Jamming) vs. Congestion",
  "description": "Separates jamming from ordinary congestion by requiring noise-floor rise WITHOUT a matching rise in decodable traffic.",
  "data_source": ["WLC.AP.RadioStats", "WIPS.Spectrum", "AP.ClientAssoc"],
  "logic": {
    "window": "5m",
    "group_by": ["ap_id", "band", "channel"],
    "compute": {
      "noise_delta_db": "noise_floor_dbm - baseline_noise_floor_dbm[ap_id, band, hour_of_day]",
      "snr_delta_db": "snr_db - baseline_snr_db[ap_id, band, hour_of_day]",
      "decodable_frame_rate_ratio": "frame_rate / baseline_frame_rate[ap_id, band, hour_of_day]",
      "retry_ratio": "retry_frames / total_frames"
    },
    "having": {
      "noise_delta_db_gte": "site_threshold_db",
      "snr_delta_db_lte": "-site_threshold_db",
      "decodable_frame_rate_ratio_lte": 1.1,
      "retry_ratio_gte": "site_retry_threshold"
    },
    "escalate_if_any": [
      "affected_ap_count >= 3 and shared_physical_zone == true",
      "concurrent mass_deassociation_event",
      "concurrent alarm on physical_security_system in same zone",
      "band in RFBOM.safety_or_ot_critical_bands"
    ]
  },
  "notes": "Congestion raises noise AND decodable traffic together. Jamming raises noise while decodable traffic stays flat or falls. That divergence is the detection.",
  "severity": "high",
  "tags": ["T1498", "T0814", "rf_denial"]
}
```

```json
{
  "rule_name": "RF - GNSS Spoofing by Physical Implausibility",
  "description": "Detects GNSS spoofing from internal inconsistency in receiver telemetry and disagreement between independent receivers.",
  "data_source": ["GNSS.Receiver.Status", "NTP.Peer.Stats", "Asset.Inventory"],
  "logic": {
    "window": "10m",
    "for_each": "gnss_receiver",
    "trigger_any": [
      "stddev(cn0_per_sv_dbhz) < uniformity_threshold and tracked_sv_count >= 6",
      "mean(cn0_per_sv_dbhz) > baseline_p99_cn0[receiver_id]",
      "abs(position_delta_m) > position_tolerance_m and asset.is_stationary == true",
      "abs(clock_offset_delta_s) > time_tolerance_s within window",
      "tracked_prn_set not_consistent_with almanac(time, location)",
      "disagreement_m(receiver_a, receiver_b) < known_separation_m * 0.5"
    ],
    "escalate_if_any": [
      "receiver feeds stratum-1 NTP or PTP grandmaster",
      "dependent_service in ['kerberos_kdc','pki_issuance','otp_validation','trading_timestamp','log_pipeline']",
      "two_or_more receivers affected concurrently"
    ],
    "action": "alert + fail_to_holdover_oscillator + freeze_time_dependent_issuance"
  },
  "notes": "Real constellations produce a C/N0 spread driven by elevation angle. A flat, uniformly strong C/N0 profile across all SVs is the classic single-transmitter signature.",
  "severity": "critical_when_escalated_else_high",
  "tags": ["gnss_spoofing", "no_clean_attack_mapping"]
}
```

---

### 7. Example Event Data

Documentation MAC addresses per RFC 7042 (`00-00-5E-00-53-xx`); IPv4 per RFC 5737.

```
WIPS sensor observation — evil twin
ts=2026-08-09T14:22:07Z sensor=SNS-08-N ssid="CORP-SECURE" bssid=00:00:5E:00:53:2F
  rssi=-38 channel=44 security=OPEN  rfbom_match=NONE
ts=2026-08-09T14:22:07Z sensor=SNS-08-N ssid="CORP-SECURE" bssid=00:00:5E:00:53:11
  rssi=-71 channel=44 security=WPA3-802.1X  rfbom_match=AP-0803 (baseline rssi -69 ±4)

  -> Legitimate AP-0803 observed at baseline. Unknown BSSID at +33 dB stronger, security downgraded
     to OPEN. Three clients migrated within 4m.

WLC radio stats — denial vs. congestion
ap=AP-0311 band=2.4 ch=6  noise=-92dBm  snr=31  frames/s=1840  retry=6%    <- baseline
ap=AP-0311 band=2.4 ch=6  noise=-61dBm  snr=4   frames/s=1795  retry=71%   <- noise +31 dB,
                                                                              traffic flat: denial
ap=AP-0312 band=2.4 ch=6  noise=-63dBm  snr=5   frames/s=1602  retry=68%   <- same zone
ap=AP-0313 band=2.4 ch=6  noise=-60dBm  snr=3   frames/s=1711  retry=74%   <- same zone

GNSS receiver status — spoofing
receiver=GNSS-DC1-A  fix=3D  sv_tracked=11
  cn0_dbhz=[51,51,52,51,51,52,51,51,51,52,51]   stddev=0.45   <- implausibly uniform
  pos_delta_m=0.4  clock_offset_delta_s=+41.7                 <- 41s time jump, no motion
receiver=GNSS-DC1-B  (separation 84 m)  reported_separation_m=3.1  <- both receivers pulled together

Cellular modem diagnostic — managed endpoint
imei=<redacted> rat=LTE  cell_id=0x1A2B3C  cipher=EEA2  ->
imei=<redacted> rat=GSM  cell_id=0x00FF01  cipher=A5/0  rxlev=-42
  -> Forced downgrade LTE->GSM with null encryption, serving cell not in observed-cell history,
     signal implausibly strong for claimed macro position.

Sub-GHz spectrum sensor — implant beacon
freq=915.4MHz  bw=125kHz  burst_len=87ms  interval=300.02s (cv=0.0007)  rfbom_match=NONE
  strongest_sensor=SNS-DC-02 (server room)  est_position=(rack row C)
```

---

### 8. Investigation Steps

1. **Do not transmit.** Investigation is receive-only. Transmitting to probe, deauthenticate, or
   "test" a suspected rogue is at best evidence contamination and at worst unlawful — see §10 for
   the legal constraint. Every step below is passive unless the engagement authorization says
   otherwise in writing.
2. **Confirm the observation is real before it is an incident.** Check the sensor itself:
   calibration date, firmware, antenna condition, and whether a neighbouring sensor corroborates.
   A single sensor reporting an anomaly no other sensor sees is a sensor fault until proven
   otherwise.
3. **Reconcile against the RF-BOM.** Is the emitter genuinely unknown, or is it a known asset that
   was moved, re-flashed, or re-channelized by a change nobody logged? Pull the change record.
   In practice this resolves the clear majority of "rogue emitter" alerts.
4. **Establish physical position.** With three or more sensors, trilaterate from RSSI; with a
   directional antenna, bearing-and-walk. Position is the property the adversary cannot forge and
   the one that converts an alert into an action. Record the method and the uncertainty.
5. **Determine wired-side reachability.** For a suspected rogue AP, search switch CAM tables and
   DHCP leases for the device MAC and its OUI neighbours. An RF rogue that also touches the wire is
   a `T1599` boundary bridge and escalates immediately.
6. **Characterize behavior over time.** Duty cycle, burst interval and its coefficient of
   variation, bandwidth, modulation family. Apply the `D&R-08` periodicity analysis unchanged — an
   RF implant beacons for the same reason an implant on a host does.
7. **Identify the affected receivers, not just the emitter.** For denial and spoofing, the
   consequence is at the receiver. Enumerate what depends on the affected link or timing source
   before deciding severity: a jammed guest SSID and a jammed OT safety radio are not the same
   incident.
8. **Scope the compromise reachable through the RF path.** If an evil twin or rogue AP was
   available, treat every credential and session that transited it as exposed and hand off to
   `D&R-01`/`D&R-04` for the identity workstream and `D&R-13` for lateral movement.
9. **Preserve evidence properly.** Timestamped I/Q captures where available, sensor observation
   logs, photographs and chain-of-custody for any recovered hardware, and the RF-BOM state at the
   time of detection. Physical devices go to the physical-evidence process — bag it, log it, do not
   power it on to "see what it is."
10. **Coordinate with physical security and facilities from the start.** RF incidents resolve in
    the physical world. Badge logs, camera footage, visitor records, and contractor schedules for
    the affected zone and time window are primary evidence here, not a nice-to-have.

---

### 9. False Positive Considerations

RF has the highest ambient false-positive rate of any medium in this library. Most of it is
physics, not adversaries.

- **The neighbours.** Adjacent tenants, nearby residences, and passing vehicles produce a constant
  churn of unknown emitters. Without a baselined RF neighborhood, this alone will bury the queue.
- **2.4 GHz is a junkyard.** Microwave ovens, video senders, cordless phones, wireless cameras, and
  Bluetooth all share it. A noise-floor spike at lunchtime near a break room is an oven.
- **Multipath and body attenuation.** RSSI swings of 10 dB or more from a door opening, a rack
  being moved, or a room filling with people are routine. Position estimates carry real
  uncertainty; treat trilateration as a region, not a point.
- **Legitimate device churn.** Personal hotspots, BYOD, contractor equipment, demo gear, and
  IoT devices arriving through procurement paths that never touch IT.
- **Weather on outdoor links.** Rain fade on microwave and satellite links looks like degradation.
  It is distinguishable: fade attenuates the *carrier* (received level drops with error rate
  rising in proportion), while interference and jamming raise the *noise* with received level
  steady. Correlate with local weather data before escalating.
- **GNSS ionospheric and multipath effects.** Solar activity, urban canyons, and reflective
  surfaces degrade fixes without an adversary. The uniform-C/N₀ and independent-receiver-agreement
  tests exist precisely because they separate natural degradation from a single spoofing
  transmitter.
- **Maintenance windows.** AP firmware upgrades, channel-plan changes, antenna work, and
  building-automation commissioning all generate exactly the signatures above.

---

### 10. Tuning Guidance

- **Baseline first, alert second.** No RF rule ships before its site has a recorded baseline per
  sensor, per band, per hour-of-day. Every threshold in §6 is written as a deviation from that
  baseline for this reason — RF propagation is site-specific and any portable absolute number is
  wrong somewhere.
- **Weight physical implausibility above identity mismatch.** Identity fields are cheap to forge;
  position, timing, and signal-quality geometry are not. Scoring that leads with position produces
  far fewer false positives than scoring that leads with an unknown MAC.
- **Suppress the neighborhood as a maintained layer, not an ingest filter.** Same rule as `D&R-08`:
  keep the observations, suppress the alerts, and re-evaluate suppressions on a schedule. An
  adversary parking in the neighbours' RF space is a known tactic.
- **Require corroboration for single-sensor detections** in dense environments, and prefer
  multi-sensor concurrence for anything that triggers containment.
- **Tune GNSS uniformity thresholds against your own sky view.** A rooftop antenna with a clean
  horizon and a receiver in an urban canyon produce very different natural C/N₀ spreads.
- **Re-baseline after every physical change** — new walls, new racks, new APs, new neighbours,
  seasonal foliage on outdoor links. A stale RF baseline generates false positives indefinitely.
- **Track detection coverage explicitly.** Maintain, per band and per zone, whether you have
  sensing at all. An empty alert queue for a band you do not receive is not a clean result, and it
  should not be reported as one.

---

### 11. Response Actions

> **Legal constraint, stated before the actions because it governs them.** Deliberate radio
> interference is unlawful in most jurisdictions — in the United States, 47 U.S.C. §333 prohibits
> willful interference with licensed radio communications, and the FCC prohibits the marketing,
> sale, and operation of jammers outright. Separately, the FCC has taken enforcement action against
> operators who used 802.11 deauthentication to block personal hotspots on their own premises.
> **"Jam the rogue" and "deauth it off the air" are not available responses.** They also destroy
> evidence and can disable safety-critical radio. Containment here is physical, wired, and
> policy-based. If your program believes it has an exception, get it in writing from counsel
> before an incident, not during one.

**Immediate**

- Preserve first: capture sensor observations, I/Q where available, and the current RF-BOM state
  before anything changes.
- Contain on the wire, not on the air. For a rogue AP with wired reachability, shut the switchport
  and quarantine the MAC — this is fully effective and entirely lawful.
- Move affected clients to a different band, channel, or SSID where the medium is contested.
- For GNSS spoofing: fail the affected receivers to holdover, and freeze time-dependent issuance
  (certificates, tokens, timestamps) until the time source is trusted again. **A wrong clock that
  is still being trusted does more damage than an outage.**
- Dispatch physical security to the estimated position. RF incidents are resolved by a person
  walking to a place.
- For OT/safety-critical denial, invoke the process-safety response path immediately and in
  parallel — do not serialize behind the security investigation.

**Short-term**

- Recover and forensically handle any physical device found; do not power it on outside a
  controlled environment.
- Rotate every credential and key that could have transited a compromised RF path, including PSKs
  for any network the rogue impersonated.
- Enforce 802.11w PMF and WPA3 where deauth abuse was observed — the attack is a configuration
  finding as much as an incident.
- Add the observed emitter characteristics to the RF-BOM as known-hostile, and hunt for the same
  signature across every other site.
- Review badge, camera, and visitor records for the zone and window; RF proximity implies physical
  presence.

**Long-term**

- Close the sensing gap the incident exposed. If the intrusion was found late or by accident, the
  finding is the coverage gap, not the emitter.
- Build and maintain the RF-BOM as a governed inventory with named owners, on the same footing as
  the CBOM (`PB-01`) and AI-BOM (`PB-21`).
- Eliminate unauthenticated and unencrypted radio from the estate on a dated plan: WPA3/802.1X for
  Wi-Fi, authenticated and encrypted LPWAN join, encryption on every point-to-point backhaul link.
- Architect on the assumption that RF is interceptable and jammable: **encrypt above the radio**,
  and ensure no safety-critical or availability-critical function depends on a single radio path
  with no wired or inertial fallback.
- Bring GNSS-derived time under the same discipline: multi-constellation, multi-frequency, signal
  authentication where available, disciplined holdover, and cross-checks against independent time
  sources.
- Include RF in physical-security zoning decisions — where the highest-consequence processing sits
  relative to the building perimeter is an RF control (§5.7).

---

### 12. Escalation Criteria

Escalate to incident when **any** of the following are true:

- A rogue emitter is confirmed to have wired-side reachability into the internal network
  (`T1599`) — this is a full intrusion, not an RF finding.
- An evil twin or rogue base station is confirmed **and** any client associated to it.
- GNSS spoofing is confirmed against a receiver feeding a time-dependent security service —
  KDC, PKI issuance, OTP validation, or the log pipeline that every other detection in this
  library depends on for correlation.
- Denial affects OT, safety, life-safety, or physical-security radio.
- An unauthorized emitter is localized inside a controlled or restricted zone — proximity implies
  physical access, which is its own incident regardless of what the radio was doing.
- Any RF implant is physically recovered, at any location.
- RF anomalies correlate in time with a physical-security event (forced door, unescorted visitor,
  after-hours badge) in the same zone.
- Sustained unexplained emission near a facility processing the organization's
  highest-consequence data.

---

### 13. Analyst Notes Template

```text
Incident ID:
Detection Rule / Tier (0|1|2):
Detected At / Detected By (sensor IDs):
Band / Frequency / Channel:
Protocol / Modulation (observed):
Claimed Identity (SSID/BSSID/CellID/DevEUI):
RF-BOM Match:            none | known-asset | known-neighbour | known-hostile
Observed RSSI vs Baseline (per sensor):
Estimated Position / Method / Uncertainty:
Duty Cycle / Burst Interval / CV:
Intrusion Class:         presence | impersonation | denial | injection | reception-anomaly
Wired-Side Reachability: Y/N  (switch/port/CAM evidence)
Affected Receivers / Dependent Services:
Clients or Sessions Exposed:
Physical Security Correlation (badge/camera/visitor):
Weather / Environmental Correlation (outdoor & GNSS only):
Evidence Preserved:      I/Q | sensor logs | photos | device (chain-of-custody ref)
Transmission Performed:  NONE  (record any exception + written authorization)
Containment Actions:     wired | physical | policy   (jamming/deauth NOT permitted — §11)
Credentials/Keys Rotated:
Coverage Gap Identified:
Outstanding Risks:
Recommendations:
Analyst:
```

---

### 14. Summary

Radio is the medium the SOC does not instrument, and an adversary on it bypasses every network
control by never entering the network. Detection is geometric: presence, impersonation, denial,
injection, and reception anomaly — scored with **physical position weighted above claimed
identity**, because position is the one property an adversary cannot forge. Every threshold is a
deviation from a locally recorded baseline; there are no portable absolute numbers in RF.

Two limits are structural and must be stated in any report built on this playbook. **Passive
interception is undetectable in principle** — it is answered by encrypting above the radio, not by
sensing. And **detection is bounded by the bands you actually receive** — an empty alert queue for
an uninstrumented band is a coverage gap, not a clean result. Say which tier you are on.

Containment is physical, wired, and policy-based. Jamming and deauthentication are unlawful in
most jurisdictions, destroy evidence, and can disable safety-critical radio. Shut the port, walk
to the position, and rotate what was exposed.

---

*GreyNOC — detection-engineering-first security operations.*
