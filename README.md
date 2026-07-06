# Wi-Fi Capture Orchestrator

Local web tool that drives Ruckus APs into monitor-mode 802.11 packet captures over
SSH/rpcap and streams frames into pcaps on the capture host. Direct-CLI method (proven in
M0 — see [`docs/`](docs/)).

**Current stage:** direct SSH/rpcap capture engine with **sessions, persistence, merge, and
templates**, runnable as a **Docker + Postgres** stack. A *session* is a named plan of
*assignments* — each `(AP, radio, target channel)` — started/stopped/monitored as one unit,
mapping a set of channels to cover. State persists via async SQLAlchemy (SQLite for the venv
slice, Postgres in Docker via `CT_DATABASE_URL`; Alembic migrations). A startup reconciler
fails crash-orphaned captures and idles their APs. Completed sessions can be **time-aligned
merged** into one pcap (mergecap in Docker, pure-Python fallback in the venv — originals kept),
and any session can be **saved as a template** and re-instantiated. Next: the R1 control-plane
adapter (inventory + channel/WLAN pinning) and a React front end.

## How it works

```
Browser ──HTTP/SSE──► FastAPI (app/main.py)
                         └─ Engine (app/engine/orchestrator.py)   one asyncio task per capture
                              ├─ rkscli.py  ── SSH ─► AP: set capture <iface> stream <host>
                              └─ rpcap.py   ◄─ rpcapd:2002 ── frames ─► data/captures/<id>.pcap
```

- **rkscli.py** — Ruckus SSH driver: `none`-auth + nested `admin`/`password :` login, `set capture`.
- **rpcap.py** — reverse-engineered rpcap client (null auth, SERVEROPEN data, accept-all BPF,
  `0x07` packet msgs). Writes DLT_PPI pcap + live frame/byte counters.
- **orchestrator.py** — state machine `configuring → capturing → finalizing → done`, duration
  auto-stop, manual stop, always `set capture idle` on exit; multiple captures run concurrently.
- Each capture writes `<id>.pcap` + `<id>.json` sidecar (AP, radio/channel, timing, host-key fp).

## Run

### Docker + Postgres (persistent)
```bash
CT_AP_PASSWORD='...' docker compose up --build     # → http://localhost:8000
```
The `api` service uses **host networking** on purpose: the AP's rpcapd streams by dialing
*back* to the capture host, so the container must share the host's LAN identity (Linux-only,
matching the single-host LAN deployment). Migrations run automatically on start.

### Local venv (SQLite, no Docker)
```bash
cd backend
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
export CT_AP_PASSWORD='...'          # AP rkscli password (rotates)
.venv/bin/python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```
DB migrations (Postgres or SQLite): `CT_DATABASE_URL=... .venv/bin/alembic upgrade head`.

**Precondition:** the target radio must be up with an active WLAN (deploy a throwaway SSID via
the controller). See capture-recipes.md — a WLAN-less radio returns `Interface-Inactive`.

## API

| Method | Path | Purpose |
|---|---|---|
| POST | `/api/sessions` | create draft `{name, notes?}` |
| POST | `/api/sessions/{id}/assignments` | add `{ap_host, iface, target_channel?, flags?}` |
| DELETE | `/api/sessions/{id}/assignments/{aid}` | remove (draft only) |
| POST | `/api/sessions/{id}/start` | start all `{duration_s?}` |
| POST | `/api/sessions/{id}/stop` | stop all |
| GET | `/api/sessions` · `/{id}` | list / full status (live-overlaid) |
| GET | `/api/sessions/{id}/events` | SSE aggregate live status |
| DELETE | `/api/sessions/{id}` | delete (draft/done/failed) |
| POST | `/api/sessions/{id}/merge` | time-aligned merge `{assignment_ids?}` → artifact |
| GET | `/api/assignments/{aid}/download` · `/sidecar` | pcap · sidecar json |
| GET | `/api/artifacts/{aid}/download` | merged pcap |
| GET/POST/DELETE | `/api/controllers` | manage controllers (hold AP SSH creds centrally) |
| GET/POST/DELETE | `/api/targets` | manage capture-target APs |
| GET/POST | `/api/templates` · `/api/sessions/{id}/save-template` | list / save-from-session |
| POST | `/api/templates/{id}/instantiate` | new draft session from template |
| POST/GET | `/api/captures[...]` | ad-hoc single capture (not persisted) |

## Inventory & credentials

Register **controllers** (R1/SZ) and **targets** (APs) in the UI.

**Controller API auth is platform-specific:** Ruckus One uses an API key (`api_client_id` +
`api_client_secret`); SmartZone uses a session login (`base_url` + `api_username` +
`api_password` + `api_version` like `v13_0`). Validated on create.

**AP SSH login** lives on the **target** (unique per AP). Assignments reference a target (host
auto-filled) and creds resolve **target → `CT_AP_PASSWORD` fallback** at start time. Secrets are
stored in the DB (plaintext by design) and are **never returned** by the API.

**Import from R1** (`app/adapters/ruckus_one.py`): with an R1 controller (client_id + secret +
tenant_id + region), the **"Import AP from R1"** button opens a modal — pick a venue, pick the
APs, and they're pulled into targets auto-populated with name/IP/model/serial **and the per-AP
CLI password fetched from R1** (`GET /venues/{venueId}/aps/{serial}/passwords`, SSH user `admin`).
R1 rotates these passwords ~daily (the response carries an `expireTime`); **re-importing an AP
refreshes its stored password**. SmartZone import is not implemented yet.

## Known gaps (tracked in docs/PLAN.md)

- Channel/WLAN setup is manual (R1 control-plane adapter not wired) — `target_channel` is
  recorded as intent; the AP captures on whatever the radio currently serves.
- Controller API creds are stored but not yet used — inventory sync (auto-populate targets,
  push channel/WLAN) is the R1 adapter, still to build.
- Clock: relies on APs being NTP-synced for cross-AP merge alignment (sidecar `offset_ms`
  is a best-effort cross-check only, null when no rkscli clock source exists).
- `iface` trusted as given; per-model capability table + DFS/PSC channel picker come later.
- Front end is a single no-build HTML page; a React SPA comes later.
- Capture engine still runs in-process (no Redis/worker) — fine for one host; the reconciler
  covers crash recovery.
