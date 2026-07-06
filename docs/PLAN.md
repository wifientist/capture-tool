# Wi-Fi Capture Orchestrator — Implementation Plan

Status: pre-scaffold. R1-first (SZ deferred). Gathering endpoint + M0 info.
Reference: `endpoints/ruckus-one.md`.

## SCOPE DECISION — 2026-07-03 (post-M0)
M0 proved the direct SSH/rpcap capture works. Build decisions:
- **Capture = Track B (SSH + rpcapd) ONLY.** Track A (R1 native `…/packets` pcap API) is
  DEFERRED — "totally different workflow," revisit later. Schema stays in endpoints/ for reference.
- **R1 adapter shrinks to CONTROL-PLANE only:** inventory (venues/APs), ensure dummy WLAN up,
  pin channel/width via `PUT …/radioSettings`. NOT capture.
- Controller wiring can lag: dummy SSID + channel pinning may stay MANUAL in the R1 UI short-term
  (as done in M0). Engine must not hard-depend on the adapter to run a capture.

## Change from original handoff
- **R1 before SZ.** Chris tests on a few R1 devices first. SZ adapter slides to a later milestone;
  the `ControllerAdapter` Protocol is unchanged so SZ drops in later with no engine changes.
- **Two capture tracks** (both wanted):
  - **Track A — R1 native capture API** (beta `…/packets` PATCH/GET). Controller-mediated,
    manual start/stop, tar.gz→pcap download, no live counters. Fast first win for simple cases.
  - **Track B — SSH/CLI streaming engine** (original design). Live counters, multi-AP,
    time-aligned, CWAP-grade radiotap. The advanced orchestration path.

## Locked decisions (unchanged)
SSE for live status · Redis = pub/sub + ephemeral counters only · engine = in-process asyncio ·
app-generated UUID PKs, controller IDs in `external_id` · engine owns `confirming_radio` poll loop.

---

## Milestones (re-ordered)

### M1 — Skeleton + R1 adapter (inventory + radio)
- docker-compose (api/postgres/redis/web); wireshark-common baked into api image now.
- Models + Alembic (7 tables per handoff schema).
- `adapters/base.py` Protocol + DTOs; `adapters/ruckus_one.py`:
  - OAuth2 `POST /oauth2/token/{tenantId}` + token refresh in adapter.
  - `list_capture_scopes` → `GET /venues`; `list_aps` → `GET /venues/aps`;
    `get_ap_status` → `GET /venues/aps/{serial}`.
  - `set_radio` → `PUT /venues/aps/{serial}/radioSettings` (confirmed payload; `useVenueSettings:false`,
    `manualChannel`, `channelBandwidth`); poll `GET /activities/{requestId}` for apply-confirm.
  - Fixture mode (canned JSON) so UI + tests run with zero hardware.
- Routers: add controller, list scopes, sync inventory, list APs. Read-only AP list UI.
- **Acceptance:** with real R1 creds, UI lists venue APs with live radio state.

### M2 — Track A: R1 native capture (fast win)  ← NEW, small
- Wrap beta `…/packets`: start (PATCH), poll status (GET), download tar.gz, extract pcap,
  write sidecar, run capinfos, expose download. Reuses `sessions/assignments/artifacts` model
  with `capture.mode = "r1_native"`. No SSH.
- **Blocked on:** the attached beta packets JSON schema (body/response fields) → `endpoints/`.
- **Acceptance:** start a capture on one R1 AP from the UI, download the resulting pcap.

### M3 — Track B: SSH streaming engine, single AP
- `engine/statemachine.py` (pure, unit-tested first).
- `engine/ssh.py` — rkscli driver (none-auth + nested admin/password login per apcli.py);
  runs `set capture <if> stream[-flags] <limited_IP>` / `set capture <if> idle`, reads state + clock.
- `engine/writer.py` — **attaches to rpcapd via `dumpcap -i rpcap://<ap>/<iface>`** (NOT ssh stdout);
  writes pcapng, live byte/frame counters. `local` mode + `copy scp` as fallback (Mode B).
- `engine/capture.py` orchestration: set_radio→confirm→(ensure active WLAN)→set capture→rpcap writer,
  heartbeat, Redis counters, semaphore(8), finally-cleanup + `set capture idle`, startup reconciler.
- Sidecar + capinfos + SSE live status + download.
- **Buildable now via a fake rpcapd** (local rpcap source / fixture pcap). Real AP swaps in the host.
- **Acceptance:** full session lifecycle with fake source; real AP once live-capture verified.

### M4 — Multi-AP sessions + artifacts
Concurrent assignments, session start/stop, mergecap + clock-offset check, disk-quota warn, download UI.

### M5 — SmartZone adapter
OAuth/serviceTicket, SZ inventory + per-AP radio override, async-confirm. Engine unchanged.

### M6 — Polish
DFS/PSC-aware picker, capability table, ring buffers, filters, session templates.

---

## Blocked-on / needed from Chris
- [ ] **Beta packets JSON schema** (PATCH body + GET response) → gates M2. *(attach reaching us? see note)*
- [ ] R1 OAuth client_id/secret + tenantId + region base URL.
- [ ] Confirm `method` enum value to pin a manual channel in radioSettings.
- [ ] M0 SSH capture recipe (command, stream/file, radiotap, interfaces) → gates M3 real hardware.
