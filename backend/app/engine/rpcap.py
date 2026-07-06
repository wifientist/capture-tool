"""Minimal rpcap client for Ruckus AP `set capture ... stream` mode.

Reverse-engineered in M0 (see docs/capture-recipes.md). The AP's rpcapd on TCP
2002 speaks a dialect with three quirks vs. stock libpcap:
  * STARTCAP must carry a filter block; an empty BPF program is rejected, so we
    send an accept-all `RET 0xffffffff`.
  * SERVEROPEN: the AP opens the *data* connection back to a port we advertise.
  * data-channel packet messages are tagged 0x07 (not 0x87).

Writes a classic pcap file with the AP's link-type (192 = DLT_PPI) and updates a
shared :class:`CaptureStats` for live counters / heartbeat.
"""
from __future__ import annotations

import socket
import struct
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

# rpcap message types
_AUTH_REQ, _OPEN_REQ, _STARTCAP_REQ = 8, 3, 4
_ERROR = 1
_PKT_TYPES = (0x07, 0x87)  # this rpcapd tags data packets 0x07


def _reply(t: int) -> int:
    return 0x80 | t


# STARTCAP flags
_FLAG_PROMISC = 1
_FLAG_SERVEROPEN = 4


@dataclass
class CaptureStats:
    frames: int = 0
    bytes: int = 0
    linktype: int | None = None
    first_ts: float | None = None
    last_ts: float | None = None
    last_data_monotonic: float | None = None
    host_key_note: str = ""
    error: str | None = None
    capped: bool = False   # stopped at the max-bytes safety cap
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)


class RpcapError(Exception):
    pass


class RpcapReader:
    def __init__(self, ap_host: str, iface: str, out_path: Path, *,
                 port: int = 2002, snaplen: int = 65535, max_bytes: int = 0):
        self.ap_host = ap_host
        self.iface = iface
        self.out_path = Path(out_path)
        self.port = port
        self.snaplen = snaplen
        self.max_bytes = max_bytes   # 0 = unlimited
        self.stats = CaptureStats()

    # -- protocol helpers -----------------------------------------------------
    @staticmethod
    def _hdr(mtype: int, value: int = 0, plen: int = 0) -> bytes:
        return struct.pack("!BBHI", 0, mtype, value, plen)

    @staticmethod
    def _recvn(sock: socket.socket, n: int) -> bytes:
        buf = b""
        while len(buf) < n:
            c = sock.recv(n - len(buf))
            if not c:
                raise RpcapError(f"peer closed ({len(buf)}/{n})")
            buf += c
        return buf

    def _read_msg(self, sock: socket.socket) -> tuple[int, int, bytes]:
        _ver, mtype, value, plen = struct.unpack("!BBHI", self._recvn(sock, 8))
        body = self._recvn(sock, plen) if plen else b""
        return mtype, value, body

    def _expect(self, sock: socket.socket, want: int) -> bytes:
        mtype, value, body = self._read_msg(sock)
        if mtype == _ERROR:
            raise RpcapError(f"rpcapd error {value}: {body.decode(errors='replace')}")
        if mtype != want:
            raise RpcapError(f"expected 0x{want:02x} got 0x{mtype:02x}")
        return body

    # -- capture loop ---------------------------------------------------------
    def run(self, stop: threading.Event) -> None:
        """Blocking. Runs until *stop* is set, the AP closes, or an error occurs."""
        ctrl = data = listener = None
        f = None
        try:
            ctrl = socket.create_connection((self.ap_host, self.port), timeout=8)
            ctrl.settimeout(8)

            # 1) null auth
            ctrl.sendall(self._hdr(_AUTH_REQ, 0, 8) + struct.pack("!HHHH", 0, 0, 0, 0))
            self._expect(ctrl, _reply(_AUTH_REQ))

            # 2) open interface -> link-type
            ctrl.sendall(self._hdr(_OPEN_REQ, 0, len(self.iface)) + self.iface.encode())
            body = self._expect(ctrl, _reply(_OPEN_REQ))
            linktype = struct.unpack("!i", body[:4])[0]
            with self.stats._lock:
                self.stats.linktype = linktype

            # 3) startcap (SERVEROPEN) + accept-all BPF filter
            listener = socket.socket()
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind(("0.0.0.0", 0))
            listener.listen(1)
            myport = listener.getsockname()[1]
            req = struct.pack("!IIHH", self.snaplen, 1000,
                              _FLAG_PROMISC | _FLAG_SERVEROPEN, myport)
            req += struct.pack("!HHI", 1, 0, 1)               # rpcap_filter: BPF, nitems=1
            req += struct.pack("!HBBI", 0x0006, 0, 0, 0xFFFFFFFF)  # RET 0xffffffff
            ctrl.sendall(self._hdr(_STARTCAP_REQ, 0, len(req)) + req)

            # data conn (from AP) + control reply may arrive in either order
            listener.settimeout(1.0)
            data = None
            got_reply = False
            deadline = time.time() + 15
            ctrl.setblocking(False)
            while (data is None or not got_reply) and time.time() < deadline:
                if not stop.is_set():
                    try:
                        data, _ = listener.accept()
                    except socket.timeout:
                        pass
                    except BlockingIOError:
                        pass
                if not got_reply:
                    try:
                        ctrl.setblocking(True)
                        ctrl.settimeout(0.5)
                        self._expect(ctrl, _reply(_STARTCAP_REQ))
                        got_reply = True
                    except (socket.timeout, RpcapError):
                        pass
                if stop.is_set():
                    break
            if data is None:
                raise RpcapError("AP never opened the data connection")

            # 4) write pcap + stream frames
            f = open(self.out_path, "wb")
            f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, self.snaplen, linktype))
            f.flush()
            data.settimeout(1.0)
            self.stats.last_data_monotonic = time.monotonic()
            while not stop.is_set():
                try:
                    mtype, _value, body = self._read_msg(data)
                except socket.timeout:
                    continue
                if mtype not in _PKT_TYPES:
                    continue
                ts_sec, ts_usec, caplen, orig, _npkt = struct.unpack("!IIIII", body[:20])
                pkt = body[20:20 + caplen]
                f.write(struct.pack("<IIII", ts_sec, ts_usec, caplen, orig) + pkt)
                ts = ts_sec + ts_usec / 1e6
                with self.stats._lock:
                    st = self.stats
                    st.frames += 1
                    st.bytes += caplen
                    st.first_ts = st.first_ts or ts
                    st.last_ts = ts
                    st.last_data_monotonic = time.monotonic()
                if self.max_bytes and self.stats.bytes >= self.max_bytes:
                    self.stats.capped = True   # hit disk safety cap -> finalize
                    break
        except Exception as exc:  # keep partial capture; record why we stopped
            with self.stats._lock:
                self.stats.error = f"{type(exc).__name__}: {exc}"
        finally:
            if f is not None:
                f.flush()
                f.close()
            for s in (data, listener, ctrl):
                try:
                    if s is not None:
                        s.close()
                except OSError:
                    pass
