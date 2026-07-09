"""Ruckus One adapter — OAuth2 client-credentials + inventory + per-AP CLI password.

Auth:  POST {base}/oauth2/token/{tenantId}  (form: grant_type=client_credentials,
       client_id, client_secret) -> {access_token, expires_in}. Token cached until
       expiry. Region selects the base host.
"""
from __future__ import annotations

import time

import httpx

from .base import ApInventory, ApPassword, ApSurvey, RadioSurvey, Venue, WlanInfo

REGION_HOSTS = {
    "na": "https://api.ruckus.cloud",
    "eu": "https://api.eu.ruckus.cloud",
    "asia": "https://api.asia.ruckus.cloud",
}


class R1Error(Exception):
    pass


class RuckusOneAdapter:
    def __init__(self, client_id: str, client_secret: str, tenant_id: str,
                 region: str | None = None, base_url: str | None = None):
        if not tenant_id:
            raise R1Error("Ruckus One requires a tenant_id")
        self.client_id = client_id
        self.client_secret = client_secret
        self.tenant_id = tenant_id
        self.base = (base_url or REGION_HOSTS.get((region or "na").lower(),
                                                  REGION_HOSTS["na"])).rstrip("/")
        self._http = httpx.AsyncClient(timeout=20.0)
        self._token: str | None = None
        self._token_exp: float = 0.0

    async def aclose(self) -> None:
        await self._http.aclose()

    # -- auth -----------------------------------------------------------------
    async def _bearer(self) -> str:
        if self._token and time.monotonic() < self._token_exp - 30:
            return self._token
        r = await self._http.post(
            f"{self.base}/oauth2/token/{self.tenant_id}",
            data={"grant_type": "client_credentials", "client_id": self.client_id,
                  "client_secret": self.client_secret},
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        if r.status_code != 200:
            raise R1Error(f"token failed HTTP {r.status_code}: {r.text[:160]}")
        js = r.json()
        self._token = js["access_token"]
        self._token_exp = time.monotonic() + float(js.get("expires_in", 3600))
        return self._token

    async def _get(self, path: str, **params) -> httpx.Response:
        tok = await self._bearer()
        r = await self._http.get(f"{self.base}{path}", params=params or None,
                                 headers={"Authorization": f"Bearer {tok}",
                                          "Accept": "application/json"})
        if r.status_code == 401:  # token expired mid-flight -> one retry
            self._token = None
            tok = await self._bearer()
            r = await self._http.get(f"{self.base}{path}", params=params or None,
                                     headers={"Authorization": f"Bearer {tok}"})
        if r.status_code >= 400:
            raise R1Error(f"GET {path} HTTP {r.status_code}: {r.text[:160]}")
        return r

    async def _post(self, path: str, body: dict) -> httpx.Response:
        tok = await self._bearer()
        hdr = {"Authorization": f"Bearer {tok}", "Content-Type": "application/json",
               "Accept": "application/json"}
        r = await self._http.post(f"{self.base}{path}", json=body, headers=hdr)
        if r.status_code == 401:
            self._token = None
            tok = await self._bearer()
            hdr["Authorization"] = f"Bearer {tok}"
            r = await self._http.post(f"{self.base}{path}", json=body, headers=hdr)
        if r.status_code >= 400:
            raise R1Error(f"POST {path} HTTP {r.status_code}: {r.text[:160]}")
        return r

    # -- inventory ------------------------------------------------------------
    @staticmethod
    def _as_list(js) -> list:
        if isinstance(js, list):
            return js
        if isinstance(js, dict):
            for k in ("data", "content", "list", "items"):
                if isinstance(js.get(k), list):
                    return js[k]
        return []

    async def list_venues(self) -> list[Venue]:
        js = (await self._get("/venues")).json()
        out = []
        for v in self._as_list(js):
            addr = v.get("address") or {}
            out.append(Venue(external_id=v.get("id"), name=v.get("name", "?"),
                             address=addr.get("addressLine") if isinstance(addr, dict) else None))
        return out

    def _ap(self, a: dict) -> ApInventory:
        return ApInventory(
            serial=a.get("serialNumber") or a.get("serial"),
            name=a.get("name") or a.get("serialNumber", "?"),
            model=a.get("model"), mac=a.get("mac") or a.get("macAddress"),
            ip=a.get("ip") or a.get("externalIp"), firmware=a.get("firmware"),
            state=a.get("state") or a.get("networkStatus") or a.get("subState"),
            venue_id=a.get("venueId"))

    async def list_aps(self, venue_id: str) -> list[ApInventory]:
        js = (await self._get("/venues/aps")).json()
        aps = [self._ap(a) for a in self._as_list(js)]
        return [a for a in aps if not venue_id or a.venue_id == venue_id]

    async def get_ap(self, serial: str) -> ApInventory:
        return self._ap((await self._get(f"/venues/aps/{serial}")).json())

    async def get_ap_password(self, venue_id: str, serial: str) -> ApPassword:
        js = (await self._get(f"/venues/{venue_id}/aps/{serial}/passwords")).json()
        return ApPassword(password=js.get("apPassword"),
                          expire_time=js.get("expireTime"),
                          updated_time=js.get("updatedTime"))

    # -- investigate (on-air survey) ------------------------------------------
    async def survey_aps(self, venue_id: str) -> list[ApSurvey]:
        """Per-AP radioStatuses (band/channel/width + SSIDs broadcast per radio)."""
        js = (await self._post("/venues/aps/query", {"page": 1, "pageSize": 1000})).json()
        out = []
        for a in self._as_list(js):
            if venue_id and a.get("venueId") != venue_id:
                continue
            radios = []
            for rs in (a.get("radioStatuses") or []):
                ch = rs.get("channel")
                try:
                    ch = int(ch) if ch not in (None, "", "N/A") else 0
                except (TypeError, ValueError):
                    ch = 0
                try:
                    width = int(rs.get("channelBandwidth")) if rs.get("channelBandwidth") else None
                except (TypeError, ValueError):
                    width = None
                nets = rs.get("wifiNetworks") or []
                ssids = [n.get("ssid") or n.get("name") for n in nets
                         if isinstance(n, dict)] if nets and isinstance(nets[0], dict) else \
                        [str(n) for n in nets]
                radios.append(RadioSurvey(
                    band=rs.get("band", "?"), channel=ch, width_mhz=width,
                    clients=rs.get("numClients") or rs.get("clientCount"),
                    ssids=[s for s in ssids if s] or None))
            out.append(ApSurvey(
                name=a.get("name") or a.get("serialNumber", "?"),
                mac=a.get("mac") or a.get("macAddress"), model=a.get("model"),
                ip=a.get("ip") or a.get("externalIp"),
                status=a.get("status") or a.get("networkStatus"), radios=radios))
        return out

    async def list_wlans(self, venue_id: str) -> list[WlanInfo]:
        """Actively-broadcast SSIDs, aggregated from each AP radio's wifiNetworks."""
        aps = await self.survey_aps(venue_id)
        seen: dict[str, WlanInfo] = {}
        for ap in aps:
            for r in (ap.radios or []):
                for ssid in (r.ssids or []):
                    if ssid not in seen:
                        seen[ssid] = WlanInfo(name=ssid, ssid=ssid, band=r.band)
        return list(seen.values())
