# AP Capture Compatibility Matrix

Living record of which **capture methods** work against which **controller/firmware
flavor** and which **AP model family**. The tool supports several capture backends;
not all are available (or qualified) on every combination of controller, firmware,
form factor, and radio count. Update the cells as combinations are tested.

> **Why this exists:** the capture stack spans a documented REST API (model-agnostic)
> *and* rpcap-to-the-AP streaming (environment-sensitive). Behavior can vary by
> form factor (R/H/T), model series (300/500/600/700), and firmware (6.1.2 / 7.1.1 /
> Ruckus One). This matrix tracks the combos so we don't ship silent breakage.

## Legend

| Mark | Meaning |
|------|---------|
| ✅ | Qualified — tested end-to-end, captures real frames |
| 🟡 | Expected to work (same API/mechanism) but **not yet tested** on this combo |
| ❌ | Known not to work on this combo |
| — | Not applicable (mechanism doesn't exist for this platform) |

## Capture methods

| ID | Method | Mechanism | Model/firmware sensitivity |
|----|--------|-----------|----------------------------|
| **A** | **SZ API — file** | `apPacketCapture/startFileCapture` → `stop` → `download` (gzip tar of radiotap pcap) over HTTPS | **None.** Pure documented API; controller handles hardware. Works remotely (no AP↔tool path). Radio chosen by band enum (`RADIO24/50/60`). |
| **B** | **SZ API — stream → Wireshark** | `apPacketCapture/startStreaming(hostIp)` opens rpcapd on the AP; analyst points Wireshark at `rpcap://<ap>:2002/<monitor-iface>` | Needs AP↔Wireshark reachability + rpcap. Monitor iface **discovered at runtime** (the radiotap/DLT-127 iface), so no hardcoded names. |
| **C** | **SZ API — stream → in-app** | Same `startStreaming`; the tool's `RpcapReader` pulls the discovered monitor iface for live counters + pcap | Same as B, plus tool host must reach the AP. |
| **D** | **rkscli SSH + rpcap** | SSH `set capture <if> stream` + rpcap dial-back (DLT_PPI/192) | Needs SSH enabled + an AP CLI password. Used by Ruckus One (per-AP password via API). SZ APs typically have SSH disabled / no per-AP password API. |

**A is the universal default** (only API calls; survives NAT/remote; no per-model
qualification). **B/C are on-LAN only** and are the combos this matrix mostly tracks.

## Controller / firmware flavor → method availability

| Controller flavor | API ver | A (file) | B (WS stream) | C (in-app stream) | D (rkscli) | Notes |
|-------------------|---------|:--:|:--:|:--:|:--:|-------|
| **SmartZone 7.1.1** (vSZ-H 7.1.1.0.872) | v13_1 | ✅ | ✅ | ✅ | ❌ | Proven on R650. SSH disabled on SZ APs; no per-AP password API → D unavailable. |
| **SmartZone 6.1.2** | v11_x? | 🟡 | 🟡 | 🟡 | ❌ | API path expected but **untested**; confirm API version string + `apPacketCapture` shape. |
| **Ruckus One** (cloud) | R1 | — | — | — | ✅ | R1 has `getApPassword` (rotates ~daily) → rkscli+rpcap path. No SZ REST capture API. |

> SmartZone version → public-API version mapping must be confirmed per release
> (7.1.1 = **v13_1**). 6.1.2 uses an earlier `vX_Y`; the `apPacketCapture` request
> schema and `includedFrameTypes` behavior should be re-verified there.

## AP model qualification (SmartZone path)

Form factor: **R** = indoor, **H** = wall/hospitality, **T** = outdoor.
Radios: dual = 2.4+5 (`wifi0/wifi1` → `RADIO24/RADIO50`); tri = +6 GHz
(`wifi2` → `RADIO60`).

| Model | Family | Series | Radios | Firmware tested | A | B | C | Notes |
|-------|:--:|:--:|:--:|-----------------|:--:|:--:|:--:|-------|
| **R650** | R (indoor) | 600 | dual (2.4/5) | 7.1.1.0.5176 | ✅ | ✅ | ✅ | Reference AP. Monitor iface discovered = `wlan101` (RADIO50) / `wlan100` (RADIO24), radiotap/DLT-127. In-app pulled 217 frames live. |
| **T350SE** | T (outdoor) | 300 | dual (2.4/5) | 7.1.1.0.5176 | 🟡 | 🟡 | 🟡 | Present in fleet; **streaming not yet exercised** — verify rpcap reachability outdoors + monitor-iface discovery. |
| _R760 / R770-class_ | R (indoor) | 700 | **tri (+6 GHz)** | — | 🟡 | 🟡 | 🟡 | **RADIO60 path unexercised.** Confirm `wifi2`/6 GHz monitor iface appears + DFS/6E channel behavior. |
| _H-series_ | H (wall) | — | dual/tri | — | 🟡 | 🟡 | 🟡 | Untested form factor. |
| _R550 / 500-series_ | R (indoor) | 500 | dual | — | 🟡 | 🟡 | 🟡 | Untested. |

## Per-combo quirks to verify when qualifying a new model/firmware

1. **`startStreaming` opens rpcapd on :2002** and it's reachable from the tool/Wireshark host.
2. **Monitor interface presents as radiotap (DLT 127)** — discovery keys on this. If a family uses a different DLT, discovery must widen.
3. **`hostIp` authorization** — the streaming client must connect from the IP passed to `startStreaming` (confirm whether it's enforced or advisory).
4. **Radio count** — tri-radio adds `RADIO60`; dual-radio APs return an error/garbage for `wifi2`.
5. **`includedFrameTypes` semantics** — SZ 7.1.1 captures **nothing** if the list is omitted (must send `MANAGEMENT/CONTROL/DATA` explicitly). Re-verify on 6.1.2.
6. **File download format** — gzip tar of `<apMac>/capture0.pcap`, radiotap. Confirm unchanged across firmware.
7. **One capture per AP** — SZ `apPacketCapture` is single-instance per AP (rpcapd refuses a 2nd). Enforced in `add_assignment` (one radio per AP per session).

## How the tool populates this

Inventory import records each AP's **model** and (now) **firmware**; the controller
records **platform + API version**. As captures run, each (model, firmware, method)
outcome can be rolled up here. Longer term the tool can warn when a selected mode is
not-yet-qualified (🟡) or known-broken (❌) for the target's (model, firmware).

_Last updated from live fleet: vSZ-H 7.1.1.0.872 · R650 + T350SE @ 7.1.1.0.5176._
