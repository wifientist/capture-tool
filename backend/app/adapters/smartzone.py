"""SmartZone (SZ) adapter — implements the same ControllerAdapter surface as R1.

Differences from Ruckus One:
  * Auth is a session serviceTicket (username/password -> ticket, passed as a
    query param on every call), not OAuth2.
  * Hierarchy is Zone -> AP Group -> AP (not Venues). We import at Zone -> AP.
  * There is NO per-AP CLI-password API — SZ AP admin passwords are static/shared,
    so get_ap_password() is unsupported; the target's password is entered manually
    (or supplied once at import and applied to all).

Base path: {base_url}/wsg/api/public/{version}  (version like 'v13_0').
SZ controllers typically use self-signed TLS on :8443, so cert verification is off.
"""
from __future__ import annotations

import httpx

from .base import ApInventory, ApPassword, Venue


class SZError(Exception):
    pass


class SmartZoneAdapter:
    def __init__(self, base_url: str, username: str, password: str, version: str):
        if not (base_url and username and password and version):
            raise SZError("SmartZone needs base_url, api_username, api_password, api_version")
        self.api = f"{base_url.rstrip('/')}/wsg/api/public/{version}"
        self.username = username
        self.password = password
        self._http = httpx.AsyncClient(timeout=25.0, verify=False)  # SZ self-signed TLS
        self._ticket: str | None = None

    async def aclose(self) -> None:
        await self._http.aclose()

    # -- auth (serviceTicket) -------------------------------------------------
    async def _login(self) -> str:
        r = await self._http.post(f"{self.api}/serviceTicket",
                                  json={"username": self.username, "password": self.password})
        if r.status_code != 200:
            raise SZError(f"serviceTicket failed HTTP {r.status_code}: {r.text[:160]}")
        tok = r.json().get("serviceTicket")
        if not tok:
            raise SZError("serviceTicket response had no ticket")
        self._ticket = tok
        return tok

    async def _ticket_param(self) -> dict:
        if not self._ticket:
            await self._login()
        return {"serviceTicket": self._ticket}

    async def _req(self, method: str, path: str, *, json=None, params=None) -> httpx.Response:
        params = {**(params or {}), **await self._ticket_param()}
        r = await self._http.request(method, f"{self.api}{path}", json=json, params=params)
        if r.status_code == 401:  # ticket expired -> re-login once
            self._ticket = None
            params = {**(params or {}), **await self._ticket_param()}
            r = await self._http.request(method, f"{self.api}{path}", json=json, params=params)
        if r.status_code >= 400:
            raise SZError(f"{method} {path} HTTP {r.status_code}: {r.text[:160]}")
        return r

    @staticmethod
    def _as_list(js) -> list:
        if isinstance(js, dict) and isinstance(js.get("list"), list):
            return js["list"]
        return js if isinstance(js, list) else []

    # -- inventory (Zone == "venue" in the shared interface) ------------------
    async def list_venues(self) -> list[Venue]:
        js = (await self._req("GET", "/rkszones", params={"listSize": 1000})).json()
        return [Venue(external_id=z.get("id"), name=z.get("name", "?")) for z in self._as_list(js)]

    def _ap(self, a: dict) -> ApInventory:
        return ApInventory(
            serial=a.get("serial") or a.get("serialNumber") or a.get("apMac"),
            name=a.get("deviceName") or a.get("name") or a.get("apMac", "?"),
            model=a.get("model"),
            mac=a.get("apMac") or a.get("mac"),
            ip=a.get("ip") or a.get("lanIp") or a.get("externalIp"),
            firmware=a.get("firmwareVersion") or a.get("firmware"),
            state=a.get("status") or a.get("connectionStatus") or a.get("configurationStatus"),
            venue_id=a.get("zoneId"))

    async def list_aps(self, venue_id: str) -> list[ApInventory]:
        # POST /query/ap filtered by zone; SZ returns {totalCount, list:[...]}
        # (page is 1-based; 'start' is not part of the v13_1 query schema)
        body = {"filters": [{"type": "ZONE", "value": venue_id}],
                "page": 1, "limit": 1000}
        js = (await self._req("POST", "/query/ap", json=body)).json()
        return [self._ap(a) for a in self._as_list(js)]

    async def get_ap(self, serial: str) -> ApInventory:
        # SZ keys APs by MAC; `serial` here is whatever list_aps returned as .serial
        js = (await self._req("GET", f"/aps/{serial}")).json()
        return self._ap(js)

    async def get_ap_password(self, venue_id: str, serial: str) -> ApPassword:
        raise SZError("SmartZone has no per-AP CLI password API — set it on the target")

    # -- Track A packet capture (controller-mediated; no AP SSH needed) --------
    async def start_file_capture(self, ap_mac: str, interface: str,
                                 frame_types: list[str] | None = None,
                                 mac_filter: str | None = None) -> dict:
        body: dict = {"captureInterface": interface}
        if frame_types:
            body["includedFrameTypes"] = frame_types
        if mac_filter:
            body["includedMac"] = mac_filter
        return (await self._req("POST", f"/aps/{ap_mac}/apPacketCapture/startFileCapture",
                                json=body)).json()

    async def start_streaming(self, ap_mac: str, interface: str, host_ip: str,
                              frame_types: list[str] | None = None,
                              mac_filter: str | None = None) -> dict:
        body: dict = {"captureInterface": interface, "hostIp": host_ip}
        if frame_types:
            body["includedFrameTypes"] = frame_types
        if mac_filter:
            body["includedMac"] = mac_filter
        return (await self._req("POST", f"/aps/{ap_mac}/apPacketCapture/startStreaming",
                                json=body)).json()

    async def capture_state(self, ap_mac: str) -> dict:
        return (await self._req("GET", f"/aps/{ap_mac}/apPacketCapture")).json()

    async def stop_capture(self, ap_mac: str) -> None:
        await self._req("POST", f"/aps/{ap_mac}/apPacketCapture/stop")

    async def download_capture(self, ap_mac: str) -> bytes:
        """Returns the raw download (gzipped tar containing <apMac>/capture0.pcap)."""
        r = await self._req("POST", f"/aps/{ap_mac}/apPacketCapture/download")
        return r.content
