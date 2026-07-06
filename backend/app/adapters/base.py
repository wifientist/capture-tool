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


class ControllerAdapter(Protocol):
    async def list_venues(self) -> list[Venue]: ...
    async def list_aps(self, venue_id: str) -> list[ApInventory]: ...
    async def get_ap(self, serial: str) -> ApInventory: ...
    async def get_ap_password(self, venue_id: str, serial: str) -> ApPassword: ...
    async def aclose(self) -> None: ...
