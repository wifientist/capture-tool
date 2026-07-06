"""Synchronous rkscli driver for Ruckus APs.

Ruckus APs authenticate the SSH transport with the `none` method, then present a
nested application login over the shell channel (`Please login:` / `password :`).
This driver reproduces the exact M0 recipe. It is synchronous (paramiko); callers
in async contexts should wrap calls with ``asyncio.to_thread``.
"""
from __future__ import annotations

import re
import time

import paramiko

PROMPT = "rkscli:"


class RkscliError(Exception):
    pass


class RkscliClient:
    def __init__(self, host: str, password: str, username: str = "admin",
                 port: int = 22, connect_timeout: float = 8.0):
        self.host = host
        self.username = username
        self._password = password
        self.port = port
        self.connect_timeout = connect_timeout
        self._t: paramiko.Transport | None = None
        self._ch: paramiko.Channel | None = None
        self.host_key_fingerprint: str | None = None

    # -- connection lifecycle -------------------------------------------------
    def connect(self) -> None:
        t = paramiko.Transport((self.host, self.port))
        t.start_client(timeout=self.connect_timeout)
        key = t.get_remote_server_key()
        self.host_key_fingerprint = f"{key.get_name()}:{key.get_fingerprint().hex()}"
        t.auth_none(self.username)  # [] == success; real login is nested
        if not t.is_authenticated():
            t.close()
            raise RkscliError("SSH none-auth failed")
        ch = t.open_session()
        ch.get_pty(width=220, height=60)
        ch.invoke_shell()
        self._t, self._ch = t, ch
        self._nested_login()

    def _nested_login(self) -> None:
        assert self._ch is not None
        self._read_until(["login", "Please login"])
        self._ch.send(self.username + "\n")
        self._read_until(["password"])
        self._ch.send(self._password + "\n")
        out = self._read_until([PROMPT, "incorrect"], timeout=10)
        if "incorrect" in out.lower() or PROMPT not in out:
            self.close()
            raise RkscliError("rkscli login failed (check password)")

    def close(self) -> None:
        try:
            if self._ch is not None:
                self._ch.close()
        finally:
            if self._t is not None:
                self._t.close()
            self._t = self._ch = None

    def __enter__(self) -> "RkscliClient":
        self.connect()
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # -- low-level I/O --------------------------------------------------------
    def _read_until(self, marks: list[str], timeout: float = 8.0) -> str:
        assert self._ch is not None
        buf = ""
        end = time.time() + timeout
        while time.time() < end:
            if self._ch.recv_ready():
                buf += self._ch.recv(65535).decode(errors="replace")
                if any(m in buf for m in marks):
                    time.sleep(0.15)
                    while self._ch.recv_ready():
                        buf += self._ch.recv(65535).decode(errors="replace")
                    return buf
            else:
                time.sleep(0.15)
        return buf

    def run(self, cmd: str, timeout: float = 12.0) -> str:
        """Run one rkscli command, return output with echo/prompt stripped."""
        if self._ch is None:
            raise RkscliError("not connected")
        self._ch.send(cmd + "\n")
        raw = self._read_until([PROMPT], timeout)
        lines = [ln for ln in raw.splitlines()
                 if ln.strip() and cmd not in ln and PROMPT not in ln and "[J" not in ln]
        return "\n".join(lines).strip()

    # -- capture control ------------------------------------------------------
    def set_capture(self, iface: str, mode: str, remote_ip: str | None = None,
                    flags: str = "") -> str:
        """mode: 'stream' | 'local' | 'idle'. flags e.g. '-nob'. remote_ip for stream."""
        token = mode + flags if mode in ("stream", "local") else mode
        parts = ["set", "capture", iface, token]
        if mode == "stream" and remote_ip:
            parts.append(remote_ip)
        return self.run(" ".join(parts))

    def capture_state(self, iface: str) -> str:
        return self.run(f"get capture {iface} state")

    def get_channel(self, iface: str) -> int | None:
        out = self.run(f"get channel {iface}")
        m = re.search(r"Channel:\s*(\d+)", out)
        return int(m.group(1)) if m else None

    def set_channel(self, iface: str, channel: int | str) -> str:
        """Pin a manual channel (or 'auto'). Retune is async — poll get_channel."""
        return self.run(f"set channel {iface} {channel}")

    def confirm_channel(self, iface: str, channel: int, timeout: float = 30.0,
                        interval: float = 1.5) -> int | None:
        """Poll until the radio reports the requested channel; return actual."""
        end = time.time() + timeout
        cur = self.get_channel(iface)
        while cur != channel and time.time() < end:
            time.sleep(interval)
            cur = self.get_channel(iface)
        return cur

    # channel width via `set/get cwmode`: 0=20 2=40 3=10 4=80 5=160 6=80+80
    _WIDTH_CODE = {20: 0, 40: 2, 80: 4, 160: 5}

    def set_width(self, iface: str, mhz: int) -> str:
        code = self._WIDTH_CODE.get(mhz)
        if code is None:
            raise RkscliError(f"unsupported channel width {mhz} MHz (use 20/40/80/160)")
        return self.run(f"set cwmode {iface} {code}")

    def get_width(self, iface: str) -> int | None:
        out = self.run(f"get cwmode {iface}")
        m = re.search(r"Width Mode:\s*(\d+)\s*MHz", out)
        return int(m.group(1)) if m else None

    def ap_epoch_ms(self) -> int | None:
        """Best-effort AP wall-clock in ms for merge alignment; None if unavailable."""
        for cmd in ("get rpmkey deviceTime", "get clock", "get time"):
            out = self.run(cmd)
            m = re.search(r"(\d{10,13})", out)
            if m:
                v = int(m.group(1))
                return v if v > 10**12 else v * 1000
        return None
