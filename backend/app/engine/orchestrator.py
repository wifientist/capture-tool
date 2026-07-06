"""Capture engine: one asyncio task per capture wiring rkscli + rpcap together.

State machine (per capture):
    configuring -> capturing -> finalizing -> done
    failed/cancelled reachable from any active state.

Blocking work (paramiko SSH, rpcap socket loop) runs in worker threads via
``asyncio.to_thread``; the async layer owns lifecycle, duration and cleanup.
The engine never hard-depends on channel/WLAN config succeeding — it captures on
whatever the radio is currently serving (control-plane setup is out of scope here).
"""
from __future__ import annotations

import asyncio
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from ..config import Settings
from ..models import CaptureSpec, CaptureState, CaptureStatus
from . import sidecar
from .rkscli import RkscliClient, RkscliError
from .rpcap import RpcapReader


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()


# Channel-pin note: rkscli `set channel <if> <ch>` retunes the radio (async, ~4s) and
# reports mode "Manual Channel Select"; confirmed via get_channel before capturing.
# 5 GHz DFS verified 2026-07-05: first frame at ~6s on ch 36/100/52 alike — CAC does
# not delay passive capture (it only gates the AP's own beacon TX).


@dataclass
class CaptureJob:
    id: str
    ap_host: str
    iface: str
    name: str | None = None
    flags: str = ""
    duration_s: int | None = None
    target_channel: int | None = None
    width_mhz: int | None = None
    ssh_username: str | None = None
    ssh_password: str | None = None
    state: CaptureState = CaptureState.pending
    error: str | None = None
    channel: int | None = None
    host_key_fingerprint: str | None = None
    ap_epoch_ms_at_start: int | None = None
    server_epoch_ms_at_start: int | None = None
    started_at: str | None = None
    ended_at: str | None = None
    file_path: Path | None = None
    reader: RpcapReader | None = None
    stop_event: threading.Event = field(default_factory=threading.Event)
    _task: asyncio.Task | None = None
    _t0: float | None = None

    def status(self) -> CaptureStatus:
        st = self.reader.stats if self.reader else None
        elapsed = (time.monotonic() - self._t0) if self._t0 else 0.0
        since = None
        if st and st.last_data_monotonic:
            since = round(time.monotonic() - st.last_data_monotonic)
        return CaptureStatus(
            id=self.id, name=self.name, state=self.state, ap_host=self.ap_host,
            iface=self.iface, channel=self.channel,
            linktype=st.linktype if st else None,
            frames=st.frames if st else 0, bytes=st.bytes if st else 0,
            elapsed_s=round(elapsed), seconds_since_last_frame=since,
            duration_s=self.duration_s, started_at=self.started_at,
            ended_at=self.ended_at, error=self.error,
            has_file=bool(self.file_path and self.file_path.exists()),
        )


class Engine:
    def __init__(self, settings: Settings):
        self.settings = settings
        self._jobs: dict[str, CaptureJob] = {}

    # -- public API -----------------------------------------------------------
    def list_jobs(self) -> list[CaptureJob]:
        return list(self._jobs.values())

    def get(self, cid: str) -> CaptureJob | None:
        return self._jobs.get(cid)

    def start(self, spec: CaptureSpec, job_id: str | None = None) -> CaptureJob:
        cid = job_id or uuid.uuid4().hex[:12]
        job = CaptureJob(id=cid, ap_host=spec.ap_host, iface=spec.iface,
                         name=spec.name, flags=spec.flags, duration_s=spec.duration_s,
                         target_channel=spec.target_channel, width_mhz=spec.width_mhz,
                         ssh_username=spec.ssh_username, ssh_password=spec.ssh_password)
        out = self.settings.capture_dir / f"{cid}.pcap"
        job.reader = RpcapReader(spec.ap_host, spec.iface, out,
                                 port=self.settings.rpcap_port, snaplen=self.settings.snaplen,
                                 max_bytes=self.settings.max_capture_bytes)
        job.file_path = out
        self._jobs[cid] = job
        job._task = asyncio.create_task(self._run(job))
        return job

    async def stop(self, cid: str) -> bool:
        job = self._jobs.get(cid)
        if not job or job.state in (CaptureState.done, CaptureState.failed,
                                    CaptureState.cancelled):
            return False
        job.stop_event.set()
        return True

    async def shutdown(self) -> None:
        for job in self._jobs.values():
            job.stop_event.set()
        tasks = [j._task for j in self._jobs.values() if j._task]
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    # -- lifecycle ------------------------------------------------------------
    async def _run(self, job: CaptureJob) -> None:
        try:
            job.state = CaptureState.configuring
            await asyncio.to_thread(self._configure, job)

            job.state = CaptureState.capturing
            job._t0 = time.monotonic()
            job.started_at = _iso(time.time())
            reader_task = asyncio.create_task(
                asyncio.to_thread(job.reader.run, job.stop_event))

            if job.duration_s:
                try:
                    await asyncio.wait_for(asyncio.shield(reader_task), job.duration_s)
                except asyncio.TimeoutError:
                    job.stop_event.set()
                    await reader_task
            else:
                await reader_task

            job.state = CaptureState.finalizing
            await asyncio.to_thread(self._finalize_ap, job)
            job.ended_at = _iso(time.time())
            st = job.reader.stats
            if st.frames == 0 and st.error:
                job.error = st.error
                job.state = CaptureState.failed
            else:
                job.state = CaptureState.done
        except Exception as exc:  # configure/other failure
            job.error = f"{type(exc).__name__}: {exc}"
            job.state = CaptureState.failed
            job.stop_event.set()
            job.ended_at = _iso(time.time())
            await asyncio.to_thread(self._finalize_ap, job)
        finally:
            self._write_sidecar(job)

    # -- blocking steps (run in threads) --------------------------------------
    def _creds(self, job: CaptureJob) -> tuple[str, str]:
        return (job.ssh_username or self.settings.ap_username,
                job.ssh_password or self.settings.ap_password)

    def _configure(self, job: CaptureJob) -> None:
        host_ip = self.settings.local_ip_for(job.ap_host)
        username, password = self._creds(job)
        cli = RkscliClient(job.ap_host, password, username=username)
        cli.connect()
        try:
            job.host_key_fingerprint = cli.host_key_fingerprint
            # Pin the requested channel over the CLI (no controller round-trip) and
            # confirm the radio actually retuned before capturing.
            if job.target_channel:
                job.state = CaptureState.confirming_radio
                cli.set_channel(job.iface, job.target_channel)
                # DFS channels confirm/capture as fast as non-DFS (~4-6s, verified) —
                # CAC only holds the AP's own beacon, not passive RX, so no special timeout.
                actual = cli.confirm_channel(job.iface, job.target_channel)
                if actual != job.target_channel:
                    raise RkscliError(
                        f"{job.iface} did not tune to channel {job.target_channel} "
                        f"(still {actual}); check width/DFS/regulatory limits")
            # Channel width (synchronous): set then verify it took.
            if job.width_mhz:
                cli.set_width(job.iface, job.width_mhz)
                aw = cli.get_width(job.iface)
                if aw != job.width_mhz:
                    raise RkscliError(
                        f"{job.iface} did not set width {job.width_mhz} MHz (still {aw}); "
                        f"the channel may not support it in this band")
            job.channel = cli.get_channel(job.iface)
            job.ap_epoch_ms_at_start = cli.ap_epoch_ms()
            job.server_epoch_ms_at_start = int(time.time() * 1000)
            state = cli.capture_state(job.iface)
            if "Inactive" in state or "must be up" in state or "must have an active" in state:
                raise RkscliError(
                    f"{job.iface} not ready to capture (need an active WLAN / radio up): {state}")
            out = cli.set_capture(job.iface, "stream", remote_ip=host_ip, flags=job.flags)
            low = out.lower()
            if "running on" in low or "please set it to idle" in low:
                # An AP streams only ONE radio at a time (single rpcapd). Surface it.
                raise RkscliError(
                    "AP can stream only one radio at a time — another radio on this AP "
                    f"is already capturing: {out.strip().splitlines()[0][:80]}")
        finally:
            cli.close()

    def _finalize_ap(self, job: CaptureJob) -> None:
        try:
            username, password = self._creds(job)
            cli = RkscliClient(job.ap_host, password, username=username)
            cli.connect()
            try:
                cli.set_capture(job.iface, "idle")
            finally:
                cli.close()
        except Exception:  # best-effort; capture file is already flushed
            pass

    def _write_sidecar(self, job: CaptureJob) -> None:
        if not job.file_path:
            return
        try:
            sidecar.write_sidecar(job, job.file_path.with_suffix(".json"))
        except Exception:
            pass
