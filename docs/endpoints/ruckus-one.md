# Ruckus One (R1) — API reference (gathered)

Base URL is region-specific: `https://api.ruckus.cloud` (NA). Others: `api.eu.ruckus.cloud`, `api.asia.ruckus.cloud`.
Source of confirmed endpoints below: official Postman collection
`commscope-ruckus/RUCKUS-One-Postman` → `RUCKUS One.postman_collection.json`.

---

## Auth — OAuth2 (JWT)

```
POST {baseUrl}/oauth2/token/{tenantId}
```
Client-credentials → bearer JWT. Token refresh handled inside the adapter, not callers.
(Exact client_id/secret grant body: confirm from collection auth block / Chris's tenant.)

## Async request pattern (IMPORTANT)

Config changes are asynchronous. Mutating calls return a `requestId`; poll:
```
GET {baseUrl}/activities/{requestId}
```
until complete. The **engine's `confirming_radio` state polls this AND/OR the AP radio state**
before starting capture. (Handoff open question #4 / #5.)

## Inventory

```
GET {baseUrl}/venues                              # list venues  == CaptureScope
GET {baseUrl}/venues/aps                           # list APs (all venues; filter by venueId)
GET {baseUrl}/venues/aps/{apSerialNumber}          # AP details == ApInfo / ApStatus
```
Note the AP path is `/venues/aps/{serial}` (serial-scoped), NOT `/venues/{venueId}/aps/{serial}`
— EXCEPT the packet-capture beta endpoint below, which DOES nest under venueId.

## Radio config == `set_radio`  ✅ confirmed payload

Per-AP override (what we want — pins a single AP):
```
PUT {baseUrl}/venues/aps/{apSerialNumber}/radioSettings
```
```json
{
  "enable24G": true, "enable50G": true, "enable6G": false,
  "apRadioParams50G": {
    "allowedChannels": ["149","153","157","161","165"],
    "channelBandwidth": "20MHz",        // 20MHz | 40MHz | 80MHz | 160MHz | AUTO
    "method": "BACKGROUND_SCANNING",     // -> set MANUAL + manualChannel to pin (VERIFY exact enum)
    "manualChannel": 0,                  // 0 = auto; set to target channel to pin
    "txPower": "-3"
  },
  "apRadioParams24G": { "...": "..." },
  "apRadioParamsDual5G": null,
  "apRadioParams6G": null,
  "useVenueSettings": false              // MUST be false to apply a per-AP override
}
```
- To pin: `useVenueSettings:false`, set the band's `manualChannel` + `channelBandwidth`,
  and `method` to manual (exact enum value TBD — verify against live/beta schema).
- `apRadioParams6G` present → 6 GHz supported; PSC/LPI handling lives in our channel picker.
- Venue-level equivalent (do NOT use for per-AP pinning): `PUT {baseUrl}/venues/{venueId}/radioSettings`.

---

## Packet capture — Track A (R1 cloud native)  ✅ schema confirmed

Source: `ruckus_one_spec/RUCKUS_One_Consolidated_API_07032026.json` (947 paths). TWO variants exist:

### Preferred: REST triad (serial-scoped)
```
POST   {baseUrl}/venues/aps/{serialNumber}/packets   startPacketCapture
GET    {baseUrl}/venues/aps/{serialNumber}/packets   getPacketCaptureState
DELETE {baseUrl}/venues/aps/{serialNumber}/packets   stopPacketCapture   body: {sessionId}
```
POST body (`ApPacketCaptureStartRequest`):
```json
{
  "captureInterface": "RADIO50",   // * required. enum: RADIO24 | RADIO50 |
                                    //   RADIO50UPPER | RADIO50LOWER | RADIO60 | ETH0..ETH7
  "frameTypeFilter": ["MANAGEMENT","CONTROL","DATA"],   // optional subset
  "macAddressFilter": "aa:bb:cc:dd:ee:ff"               // optional
}
```
- POST 200 → `{requestId, response:{...ACXApPacketCaptureStartResponse}}` (contains sessionId).
- GET 200 (`ACXApPacketCaptureStateResponse`) → `{status, sessionId, fileName, fileUrl, errorMsg}`.
  Poll `status`; when done, download `fileUrl` (tar.gz → pcap). 409 = duplicate sessionId.

### Variant Chris found via devtools: action-based (venue-scoped)
```
PATCH {baseUrl}/venues/{venueId}/aps/{serialNumber}/packets   body: ApPacketAction
GET   {baseUrl}/venues/{venueId}/aps/{serialNumber}/packets   -> ApPackets {state,sessionId,fileName,fileUrl,errorMsg}
```
PATCH body: `{action: "START"|"STOP", captureInterface, frameTypeFilter[], macAddressFilter, sessionId}`.
Functionally equivalent to the REST triad. **Use the REST triad** in the adapter; it's cleaner.

### Hard constraints (drive the two-track split)
- **No channel, no width, no duration, no ring-buffer** in the API. Capture runs on whatever
  channel the radio currently serves → channel/width MUST be pushed first via `…/radioSettings`.
- Single `captureInterface` per session. Likely wraps rkscli `set capture local` server-side
  ⇒ probably inherits the **active-WLAN-required** constraint (see capture-recipes.md).
- Radiotap/monitor-mode guarantees unverified from API alone.

### Two capture tracks
- **Track A (this API):** no SSH, no live counters (poll GET), tar.gz pulled post-capture. Fast win.
- **Track B (SSH `set capture` + rpcapd):** live counters, multi-AP, filter flags, the reason the
  project exists. See capture-recipes.md.
Both sit behind the engine; Track A ships first on R1.
