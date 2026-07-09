"""Controller adapter interface + DTOs. Inventory + per-AP CLI password only
(radio/WLAN push comes later). SmartZone will implement the same Protocol."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


@dataclass
class Venue:
    external_id: str
    name: str
    address: str | None = None


@dataclass
class ApInventory:
    serial: str
    name: str
    model: str | None = None
    mac: str | None = None
    ip: str | None = None
    firmware: str | None = None
    state: str | None = None
    venue_id: str | None = None


@dataclass
class ApPassword:
    password: str
    expire_time: str | None = None
    updated_time: str | None = None


# -- investigate / on-air survey ---------------------------------------------
@dataclass
class RadioSurvey:
    band: str                    # "2.4G" | "5G" | "6G"
    channel: int                 # 0 = radio off / disabled
    width_mhz: int | None = None
    clients: int | None = None
    ssids: list[str] | None = None   # SSIDs actively broadcast on this radio (if known)

    @property
    def active(self) -> bool:
        return self.channel > 0


@dataclass
class ApSurvey:
    name: str
    mac: str | None = None
    model: str | None = None
    ip: str | None = None
    status: str | None = None
    radios: list[RadioSurvey] | None = None


@dataclass
class WlanInfo:
    name: str
    ssid: str | None = None
    clients: int | None = None
    band: str | None = None


class ControllerAdapter(Protocol):
    async def list_venues(self) -> list[Venue]: ...
    async def list_aps(self, venue_id: str) -> list[ApInventory]: ...
    async def get_ap(self, serial: str) -> ApInventory: ...
    async def get_ap_password(self, venue_id: str, serial: str) -> ApPassword: ...
    # investigate (on-air survey)
    async def survey_aps(self, venue_id: str) -> list[ApSurvey]: ...
    async def list_wlans(self, venue_id: str) -> list[WlanInfo]: ...
    async def aclose(self) -> None: ...
