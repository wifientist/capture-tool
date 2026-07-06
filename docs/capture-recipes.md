# M0 Capture Recipes — findings

Live-tested against one R1-managed AP on Chris's LAN, 2026-07-03.

## Test AP
- **Model:** Ruckus R510 (dual-band; `wifi0`=2.4 GHz, `wifi1`=5 GHz)
- **Firmware:** 6.2.4.103.262
- **Mgmt IP:** (Chris's lab AP) · serial 301602711622
- **SSH host key:** ecdsa-sha2-nistp384 fp=831e9b925508a4d98e80342bfe4b4de1

## SSH login flow  ✅ (non-obvious — matches Chris's warning)
1. SSH transport authenticates with **`none`** method (no SSH-layer password). paramiko: `auth_none(user)` returns `[]` = success. Do NOT send `auth_password` after — the embedded server errors ("unhandled type 3") and times out.
2. Then a **nested application login over the shell channel**:
   ```
   Please login:  -> send "admin"
   password :     -> send password   (note the SPACE before ':')
   rkscli:        -> shell prompt (colon, not '>')
   ```
3. Be prompt-aware: match on substrings `login` / `password`, not exact `endswith`.
Reusable client: `scratchpad/apcli.py` (seed of `engine/ssh.py`).

## Track B — native `set capture` (rkscli)  ✅ this is the orchestration path

```
set capture <interface> {idle | [stream|local][-no[b][c][m][d][p]] [restart] [showLDPC] [mac_addr] [limited_IP]}
get capture <wifi name> state
get capture <wifi name> copy {tftp|ftp|scp} <dest...>     # for local mode retrieval
```
- **interface:** `wifi0` (2.4) / `wifi1` (5). (Tri-band models add `wifi2`; confirm per model.)
- **mode:** `stream` = rpcapd server, streams live to `limited_IP` (our capture host) ·
  `local` = write to AP `/tmp`, pull via `copy scp/ftp/tftp` · `idle` = STOP.
- **filter flags (opt-out):** `-nob` nobeacon · `-noc` nocontrol · `-nom` nomgmt · `-nod` nodata ·
  `-nop` **no promiscuous**. Combine e.g. `-nobc`. DEFAULT (no flags) = promiscuous ON + all
  frame types ⇒ **other-BSS visible by default** (CWAP requirement met without extra config).
- `showLDPC`, `mac_addr` (single-MAC filter), `restart` (re-launch rpcapd if already running).
- Example: `set capture wifi1 stream-nob restart 192.168.0.5`  (5 GHz, drop beacons, stream to us)

### Transport = rpcapd (NOT ssh stdout) — engine impact
- AP runs **rpcapd** (remote pcap daemon, WinPcap/libpcap rpcap protocol, typically TCP 2002).
- Capture host attaches with `dumpcap -i rpcap://<ap-ip>/<iface>` (or tshark). Live counters for free.
- `get/set rpcapd bpf {enable|disable}` — band-pass filter; currently `Enabled` on test AP.
- => `engine/writer.py` connects to rpcap, it does NOT read an SSH stdout byte stream.
  SSH is used to *drive* `set capture` and read state/clock, not to carry frames.

### ⚠️ Radio needs an enabled BSS to be on-channel (answers open-Q #4)
`get capture wifi1 state` → `Err:Interface-Inactive, wifi1 must have an active wlan`.
Investigated for a WLAN-less monitor mode — NONE exists on this platform:
`spectrum` absent; `sensor` = orientation/temp hardware only; scan machinery
(`scand`/`chanbkgndscan`/`rescan`/dwell) is off-channel hopping tied to an operating radio.
**A Ruckus AP-mode radio's PHY comes up only with an enabled BSS. BSS enabled != serving clients.**

**Design model = dedicated capture-only APs (Chris's intent):**
- Deploy a throwaway WLAN (random PSK, no clients ever associate) purely as scaffolding to keep
  each radio up + on its pinned channel. Permanent on these APs; nothing to "interrupt."
- Promiscuous default still captures the WHOLE channel (all other BSSs/clients, mgmt+ctrl+data).
  Own inert BSS is the only self-noise; `-nob` filters its beacons from the pcap.
- **⚠ CORRECTION (2026-07-05): stream mode = ONE radio per AP at a time.** `set capture wifi1 stream`
  while wifi0 streams → rejected: "Stream capture is running on wifi0, please set it to idle mode."
  There is a single rpcapd. So you canNOT stream both 2.4 and 5 on one AP simultaneously — the
  engine now fails the 2nd radio's assignment with a clear error. Cover more channels with more APs.
  **LOCAL mode DOES support both radios** ("enabling the HCCD packet captures"; both show `local`,
  e.g. 20 MHz + 80 MHz at once) — a candidate dual-band-per-AP path.

### ⚠ LOCAL-mode retrieval is NOT viable on R510 (investigated 2026-07-05)
Built a TFTP receiver (works: api container is root, host-net → bind :69). Flow works:
`set capture wifiN local` → `set capture wifiN idle` → `get capture wifiN copy tftp <host> <file>`
→ AP pushes a pcap (valid PPI/802.11). BUT the retrieved file is a **fixed ~20 KB ring segment**
(`<file>.pcap0`) holding only the **last ~50 frames**, regardless of capture duration (12s→49 fr,
30s→56 fr). `copy` only grabs pcap0; no way via rkscli to pull the full ring. So local mode yields
only a tiny recent window — **not usable for real captures**. Conclusion: don't build Mode B on R510.
Simultaneous dual-radio full capture isn't achievable on this hardware; use 1 radio/AP (stream) +
more APs, or tri-radio/dual-5G hardware for a 2nd 5 GHz radio.
- Caveat: BSS up means the AP DOES transmit (beacons/probe-resp) on-channel — not 100% passive.
  Negligible + filterable for capture; truly-passive zero-TX would need a dedicated sensor NIC.
- **R510 = wifi0(2.4) + wifi1(5) only** → one 2.4ch + one 5ch per AP, NOT two 5 GHz channels.
  Two 5 GHz channels at once needs dual-5G hardware (tri-radio / R730/R760 dual-5G). No 6 GHz on R510.

### Radio must be UP (chain of preconditions) — confirmed error strings
- `set capture wifi1 stream…` with radio down → `Err:Interface-Down, wifi1 must be up`
- `get capture wifi1 state` with no WLAN → `Err:Interface-Inactive, wifi1 must have an active wlan`
- rpcapd (TCP **2002**) is NOT listening until a capture is active (started on demand).
- On test AP ALL WLANs are `down` (both radios) — nothing deployed from R1. So the precondition
  chain is: **R1 deploys/enables a WLAN → radio comes up → `set capture` allowed → rpcapd starts.**
- `set capture <if> idle` when nothing running → `rccd pkt mode file /tmp/rccd_pcap_status is not present` + OK (harmless).

### Local-mode verification path (no system Wireshark needed)
`dumpcap`/`tshark` absent on the host; only `tcpdump`. For M0 verification use `local` mode:
`set capture wifi1 local` → `get capture wifi1 copy scp <host> …` (or scp /tmp/*.pcap off) →
decode radiotap with **scapy** (installed in scratchpad venv): `RadioTap`/`Dot11` layers.
Product Track B still uses `stream`+rpcapd; system Wireshark goes in the api container.

### ✅ LIVE-VERIFIED (dummy WLAN "capture_the_flag" up on both radios)
Captured 120 frames off wifi0 (2.4 GHz ch1) and decoded with scapy:
- **PPI headers on 100% of frames** (DLT_PPI=192) → radio metadata (rate/channel/RSSI/flags) present.
- **All frame classes:** 85 mgmt / 25 control / 10 data. Control frames (CTS/ACK) present ⇒ true
  promiscuous on-channel monitor, not own-BSS-only.
- **Other-BSS visibility CONFIRMED:** 26 distinct TAs; neighbor SSIDs (Travis, legacycoffee,
  36hoursinGuyton, Recover.Me-*, HP DIRECT-*) alongside our own capture_the_flag (ec:8c:a2:1f:c6:38).
- 5 GHz ch36 was silent only because it's an empty channel (no neighbors + own TX not looped back).

### rpcap "stream" wire protocol (reverse-engineered; Ruckus rpcapd on :2002)
Standard product path should just use `dumpcap -i rpcap://<ap>/wifi0` (libpcap handles all this).
Hand-rolled client `scratchpad/rpcap_client.py` proves it and documents the quirks:
- Passive server on TCP **2002**. **Null auth** (rpcap_auth type=0).
- OPEN <iface> → reply linktype **192 (DLT_PPI)**.
- STARTCAP req = rpcap_startcapreq(12B: snaplen,read_timeout,flags,portdata) **+ filter block**
  {u16 type=1(BPF), u16 dummy, u32 nitems} + insns. Empty program REJECTED ("bogus instructions");
  must send accept-all `RET 0xffffffff` (code=0x0006). Missing filter block = no reply (silent hang).
- flags: PROMISC=1, **SERVEROPEN=4** (AP opens data conn back to client's advertised port).
- Data-channel packet messages are tagged type **0x07** (NOT 0x87), then rpcap_pkthdr(20B)+frame.
- "Connection established" printed by CLI is internal readiness; AP does NOT dial the client for the stream.

### ✅ 5 GHz + DFS verified (2026-07-05, R510 wifi1)
- **Channel pinning via CLI:** `set channel wifi1 <ch>` retunes (async ~4s) → mode
  "Manual Channel Select"; `get channel` confirms. No R1/controller round-trip needed.
  The engine sets + confirms the channel before capture (states: configuring → confirming_radio).
- **DFS has NO capture penalty (resolves open-Q #6):** time-to-first-frame was ~6s on
  ch36 (non-DFS), ch100 (DFS), and ch52 (DFS) — identical. CAC is a listen period, so
  passive capture flows during it; CAC only holds the AP's own beacon TX. ch52 yielded
  5205 frames in the window (real DFS traffic captured on the DFS channel).
- Non-DFS 5 GHz = UNII-1 36–48, UNII-3 149–165; DFS = 52–64, 100–144.

### Still UNVERIFIED (need dual-5G hardware / R1 creds)
- [ ] radiotap headers present? MCS/RSSI/retry/FCS flags? (open-Q #2)
- [ ] rpcapd exact port + auth (null-auth? does `limited_IP` gate it?)
- [ ] does `stream` mode take the radio off client-serving (monitor) → service impact?
- [ ] channel actually captured vs. radio's serving channel; width/HT/VHT/HE info in radiotap
- [ ] clock source precision for offset (open-Q #7): `date`/rkscli time cmd on AP

## Track A — R1 cloud native capture API  (simple, controller-mediated)
See `endpoints/ruckus-one.md`. Constraints confirmed from OpenAPI spec: interface + frameType +
mac filter only; **no channel/width/duration/ring-buffer**; poll GET for `fileUrl` (tar.gz→pcap).
Almost certainly wraps `set capture local` under the hood → same active-WLAN constraint likely applies.

## Capability-table update
```json
{ "R510": { "bands": {"2.4": "wifi0", "5": "wifi1"} } }
```
