"""SessionService — bridges the DB (sessions/assignments) and the in-memory
capture Engine. Owns start/stop, a per-session status-sync loop, and a startup
reconciler that fails assignments orphaned by a crash/restart."""
from __future__ import annotations

import asyncio
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import select

from .db import Database
from .engine import merge as merge_mod
from .engine.orchestrator import Engine
from .models import CaptureSpec
from .models_db import (Artifact, Assignment, CaptureSession, Controller, Target,
                        Template)
from .schemas import (ApInventoryOut, ArtifactOut, AssignmentCreate, AssignmentOut,
                      ControllerCreate, ControllerOut, SessionCreate, SessionOut,
                      SessionTotals, TargetCreate, TargetOut, TemplateCreate,
                      TemplateOut, VenueOut, validate_controller_auth)

TERMINAL = {"done", "failed", "cancelled"}
ACTIVE = {"pending", "configuring", "confirming_radio", "capturing", "finalizing", "stopping"}


def _now_iso() -> str:
    return datetime.now(tz=timezone.utc).isoformat()


class SessionService:
    def __init__(self, db: Database, engine: Engine):
        self.db = db
        self.engine = engine
        self._tasks: dict[str, asyncio.Task] = {}

    # -- CRUD -----------------------------------------------------------------
    async def create_session(self, spec: SessionCreate) -> str:
        sid = uuid.uuid4().hex[:12]
        async with self.db.sessionmaker() as s:
            s.add(CaptureSession(id=sid, name=spec.name, notes=spec.notes, status="draft"))
            await s.commit()
        return sid

    async def add_assignment(self, sid: str, spec: AssignmentCreate) -> str:
        async with self.db.sessionmaker() as s:
            sess = await s.get(CaptureSession, sid)
            if not sess:
                raise KeyError("unknown session")
            if sess.status != "draft":
                raise ValueError(f"cannot add to a {sess.status} session")
            target = await s.get(Target, spec.target_id)
            if not target:
                raise ValueError("unknown target")
            # Stream capture is one-radio-per-AP (single rpcapd; concurrent radios race).
            if any(a.ap_host == target.host for a in sess.assignments):
                raise ValueError(
                    f"{target.host} already has a radio in this session — stream capture "
                    "runs one radio per AP. Put the other band/channel on a different AP.")
            aid = uuid.uuid4().hex[:12]
            s.add(Assignment(id=aid, session_id=sid, target_id=target.id, ap_host=target.host,
                             iface=spec.iface, target_channel=spec.target_channel,
                             width_mhz=spec.width_mhz, flags=spec.flags))
            await s.commit()
        return aid

    async def delete_assignment(self, sid: str, aid: str) -> None:
        async with self.db.sessionmaker() as s:
            sess = await s.get(CaptureSession, sid)
            if not sess or sess.status != "draft":
                raise ValueError("can only edit a draft session")
            a = await s.get(Assignment, aid)
            if a and a.session_id == sid:
                await s.delete(a)
                await s.commit()

    def _session_files(self, sess: CaptureSession, artifacts) -> list[Path]:
        """All on-disk files for a session: assignment pcaps + sidecars + artifacts."""
        files: list[Path] = []
        for a in sess.assignments:
            if a.file_path:
                p = Path(a.file_path)
                files += [p, p.with_suffix(".json")]
        files += [Path(a.file_path) for a in artifacts if a.file_path]
        return files

    @staticmethod
    def _unlink(files: list[Path]) -> int:
        n = 0
        for p in files:
            try:
                if p.exists():
                    p.unlink()
                    n += 1
            except OSError:
                pass
        return n

    async def delete_session(self, sid: str) -> int:
        """Delete a finished/draft session AND its pcaps/sidecars/artifacts. Returns files removed."""
        async with self.db.sessionmaker() as s:
            sess = await s.get(CaptureSession, sid)
            if not sess or sess.status not in ("draft", "done", "failed", "cancelled"):
                return 0
            artifacts = await self._artifacts_for(s, sid)
            removed = self._unlink(self._session_files(sess, artifacts))
            await s.delete(sess)
            await s.commit()
        return removed

    async def _referenced_files(self) -> set[str]:
        """Names of capture-dir files still referenced by the DB or an active job."""
        names: set[str] = set()
        async with self.db.sessionmaker() as s:
            for a in (await s.execute(select(Assignment))).scalars().all():
                if a.file_path:
                    names.add(Path(a.file_path).name)
                    names.add(Path(a.file_path).with_suffix(".json").name)
            for art in (await s.execute(select(Artifact))).scalars().all():
                if art.file_path:
                    names.add(Path(art.file_path).name)
        # protect files owned by in-flight captures (rows may not be written yet)
        for job in self.engine.list_jobs():
            if job.state.value in ACTIVE and job.file_path:
                names.add(job.file_path.name)
                names.add(job.file_path.with_suffix(".json").name)
        return names

    async def sweep_orphans(self) -> tuple[int, int]:
        """Delete capture-dir files not referenced by any session/artifact/active job."""
        keep = await self._referenced_files()
        removed = freed = 0
        for p in self.engine.settings.capture_dir.glob("*"):
            if p.is_file() and p.name not in keep:
                try:
                    freed += p.stat().st_size
                    p.unlink()
                    removed += 1
                except OSError:
                    pass
        return removed, freed

    async def purge_completed(self) -> dict:
        """Bulk purge: delete done/failed/cancelled sessions + their files, then
        sweep any orphaned capture files left behind (deleted sessions, ad-hoc runs)."""
        async with self.db.sessionmaker() as s:
            rows = (await s.execute(select(CaptureSession).where(
                CaptureSession.status.in_(["done", "failed", "cancelled"])))).scalars().all()
            files = 0
            sessions = 0
            for sess in rows:
                artifacts = await self._artifacts_for(s, sess.id)
                files += self._unlink(self._session_files(sess, artifacts))
                await s.delete(sess)
                sessions += 1
            await s.commit()
        orphans, freed = await self.sweep_orphans()
        return {"sessions_deleted": sessions, "files_removed": files,
                "orphans_removed": orphans, "orphan_bytes": freed}

    def disk_usage(self) -> dict:
        d = self.engine.settings.capture_dir
        total = 0
        count = 0
        for p in d.glob("*"):
            if p.is_file():
                try:
                    total += p.stat().st_size
                    count += 1
                except OSError:
                    pass
        return {"capture_dir": str(d), "bytes": total, "files": count}

    # -- lifecycle ------------------------------------------------------------
    async def start_session(self, sid: str, duration_s: int | None) -> None:
        async with self.db.sessionmaker() as s:
            sess = await s.get(CaptureSession, sid)
            if not sess:
                raise KeyError("unknown session")
            if sess.status != "draft":
                raise ValueError(f"session is {sess.status}, not draft")
            if not sess.assignments:
                raise ValueError("session has no assignments")
            if duration_s is None:   # cap open-ended sessions
                duration_s = self.engine.settings.default_max_duration_s
            sess.status = "running"
            sess.started_at = _now_iso()
            specs = []
            adapters: dict = {}   # controller_id -> adapter (reuse token across its APs)
            try:
                for a in sess.assignments:
                    a.status = "pending"
                    a.error = a.started_at = a.ended_at = None
                    a.frames = a.bytes = 0
                    target = await s.get(Target, a.target_id) if a.target_id else None
                    if target:
                        await self._refresh_target_password(s, target, adapters)
                    user, pw = self._resolve_ssh(target)
                    specs.append((a.id, CaptureSpec(ap_host=a.ap_host, iface=a.iface,
                                                    flags=a.flags, duration_s=duration_s,
                                                    target_channel=a.target_channel,
                                                    width_mhz=a.width_mhz,
                                                    ssh_username=user, ssh_password=pw)))
            finally:
                for ad in adapters.values():
                    await ad.aclose()
            await s.commit()

        for aid, spec in specs:
            self.engine.start(spec, job_id=aid)
        self._tasks[sid] = asyncio.create_task(self._sync_loop(sid, [a for a, _ in specs]))

    async def stop_session(self, sid: str) -> None:
        async with self.db.sessionmaker() as s:
            sess = await s.get(CaptureSession, sid)
            if not sess:
                raise KeyError("unknown session")
            if sess.status not in ("running", "stopping"):
                raise ValueError(f"session is {sess.status}")
            sess.status = "stopping"
            aids = [a.id for a in sess.assignments]
            await s.commit()
        for aid in aids:
            await self.engine.stop(aid)

    async def _sync_loop(self, sid: str, aids: list[str]) -> None:
        while True:
            await asyncio.sleep(1.5)
            all_terminal = True
            async with self.db.sessionmaker() as s:
                sess = await s.get(CaptureSession, sid)
                if not sess:
                    return
                for a in sess.assignments:
                    job = self.engine.get(a.id)
                    if job is None:
                        if a.status not in TERMINAL:
                            all_terminal = False
                        continue
                    st = job.status()
                    a.status = st.state.value
                    a.frames, a.bytes = st.frames, st.bytes
                    a.channel = st.channel if st.channel is not None else a.channel
                    a.linktype = st.linktype if st.linktype is not None else a.linktype
                    a.error = st.error
                    a.started_at = a.started_at or st.started_at
                    if st.state.value in TERMINAL:
                        a.ended_at = st.ended_at
                        a.host_key_fingerprint = job.host_key_fingerprint
                        if job.file_path:
                            a.file_path = str(job.file_path)
                            sc = job.file_path.with_suffix(".json")
                            if sc.exists():
                                a.sidecar = json.loads(sc.read_text())
                    else:
                        all_terminal = False
                if all_terminal:
                    sess.status = "failed" if any(a.status == "failed"
                                                  for a in sess.assignments) else "done"
                    sess.ended_at = _now_iso()
                await s.commit()
            if all_terminal:
                self._tasks.pop(sid, None)
                return

    async def reconcile_startup(self) -> int:
        """Crash recovery: in-memory jobs are gone after a restart, so any row left
        in an active state is orphaned — mark it failed and best-effort idle the AP
        (an orphaned rkscli 'stream' would otherwise leave rpcapd running)."""
        async with self.db.sessionmaker() as s:
            rows = (await s.execute(
                select(Assignment).where(Assignment.status.in_(ACTIVE)))).scalars().all()
            orphans = []
            for a in rows:
                target = await s.get(Target, a.target_id) if a.target_id else None
                user, pw = self._resolve_ssh(target)
                orphans.append((a.ap_host, a.iface, user, pw))
            for a in rows:
                a.status = "failed"
                a.error = a.error or "orphaned by server restart"
                a.ended_at = a.ended_at or _now_iso()
            sessions = (await s.execute(select(CaptureSession).where(
                CaptureSession.status.in_(["running", "stopping"])))).scalars().all()
            for sess in sessions:
                sess.status = "failed"
                sess.ended_at = sess.ended_at or _now_iso()
            await s.commit()
        for host, iface, user, pw in set(orphans):
            await asyncio.to_thread(self._idle_ap, host, iface, user, pw)
        return len(rows)

    def _idle_ap(self, host: str, iface: str, user: str | None, pw: str | None) -> None:
        from .engine.rkscli import RkscliClient
        try:
            cli = RkscliClient(host, pw or self.engine.settings.ap_password,
                               username=user or self.engine.settings.ap_username)
            cli.connect()
            try:
                cli.set_capture(iface, "idle")
            finally:
                cli.close()
        except Exception:
            pass

    async def shutdown(self) -> None:
        for t in list(self._tasks.values()):
            t.cancel()

    # -- read models ----------------------------------------------------------
    def _assignment_out(self, a: Assignment) -> AssignmentOut:
        job = self.engine.get(a.id)
        status, frames, byts = a.status, a.frames, a.bytes
        channel, linktype, error = a.channel, a.linktype, a.error
        elapsed = since = None
        has_file = bool(a.file_path and Path(a.file_path).exists())
        if job is not None:
            st = job.status()
            status, frames, byts = st.state.value, st.frames, st.bytes
            channel = st.channel if st.channel is not None else channel
            linktype = st.linktype if st.linktype is not None else linktype
            error, elapsed, since = st.error, st.elapsed_s, st.seconds_since_last_frame
            if job.file_path and job.file_path.exists():
                has_file = True
        return AssignmentOut(
            id=a.id, ap_host=a.ap_host, target_id=a.target_id, iface=a.iface,
            target_channel=a.target_channel, width_mhz=a.width_mhz,
            flags=a.flags, status=status, channel=channel, linktype=linktype,
            frames=frames, bytes=byts, has_file=has_file, error=error,
            started_at=a.started_at, ended_at=a.ended_at,
            elapsed_s=elapsed, seconds_since_last_frame=since)

    def _session_out(self, sess: CaptureSession, artifacts: list[Artifact] = ()) -> SessionOut:
        outs = [self._assignment_out(a) for a in sess.assignments]
        totals = SessionTotals(
            assignments=len(outs),
            active=sum(o.status in ACTIVE for o in outs),
            done=sum(o.status == "done" for o in outs),
            failed=sum(o.status == "failed" for o in outs),
            frames=sum(o.frames for o in outs),
            bytes=sum(o.bytes for o in outs))
        arts = [ArtifactOut(id=a.id, kind=a.kind, size_bytes=a.size_bytes,
                            sha256=a.sha256, created_at=a.created_at, meta=a.meta)
                for a in artifacts]
        return SessionOut(
            id=sess.id, name=sess.name, status=sess.status, notes=sess.notes,
            created_at=sess.created_at, started_at=sess.started_at,
            ended_at=sess.ended_at, totals=totals, assignments=outs, artifacts=arts)

    async def _artifacts_for(self, s, sid: str) -> list[Artifact]:
        return (await s.execute(select(Artifact).where(Artifact.session_id == sid)
                                .order_by(Artifact.created_at))).scalars().all()

    async def get_session(self, sid: str) -> SessionOut | None:
        async with self.db.sessionmaker() as s:
            sess = await s.get(CaptureSession, sid)
            if not sess:
                return None
            return self._session_out(sess, await self._artifacts_for(s, sid))

    async def list_sessions(self) -> list[SessionOut]:
        async with self.db.sessionmaker() as s:
            rows = (await s.execute(
                select(CaptureSession).order_by(CaptureSession.created_at.desc()))
            ).scalars().all()
            return [self._session_out(sess, await self._artifacts_for(s, sess.id))
                    for sess in rows]

    async def merge_session(self, sid: str, assignment_ids: list[str] | None) -> ArtifactOut:
        async with self.db.sessionmaker() as s:
            sess = await s.get(CaptureSession, sid)
            if not sess:
                raise KeyError("unknown session")
            wanted = set(assignment_ids) if assignment_ids else None
            inputs = [a.file_path for a in sess.assignments
                      if a.file_path and (wanted is None or a.id in wanted)]
            inputs = [p for p in inputs if p and Path(p).exists()]
            if len(inputs) < 2:
                raise ValueError("need at least 2 assignment pcaps with data to merge")
            out = self.engine.settings.capture_dir / f"{sid}_merged.pcap"
        meta = await asyncio.to_thread(merge_mod.merge_pcaps, [Path(p) for p in inputs], out)
        aid = uuid.uuid4().hex[:12]
        async with self.db.sessionmaker() as s:
            art = Artifact(id=aid, session_id=sid, kind="merged_pcap", file_path=str(out),
                           size_bytes=meta["size_bytes"], sha256=meta["sha256"], meta=meta)
            s.add(art)
            await s.commit()
            return ArtifactOut(id=aid, kind="merged_pcap", size_bytes=meta["size_bytes"],
                               sha256=meta["sha256"], created_at=art.created_at, meta=meta)

    async def artifact_file(self, art_id: str) -> Path | None:
        async with self.db.sessionmaker() as s:
            art = await s.get(Artifact, art_id)
            if art and Path(art.file_path).exists():
                return Path(art.file_path)
        return None

    # -- templates ------------------------------------------------------------
    @staticmethod
    def _template_out(t: Template) -> TemplateOut:
        return TemplateOut(id=t.id, name=t.name, description=t.description,
                           assignments=[AssignmentCreate(**a) for a in t.assignments],
                           created_at=t.created_at)

    async def create_template(self, spec: TemplateCreate) -> TemplateOut:
        tid = uuid.uuid4().hex[:12]
        async with self.db.sessionmaker() as s:
            t = Template(id=tid, name=spec.name, description=spec.description,
                         assignments=[a.model_dump() for a in spec.assignments])
            s.add(t)
            await s.commit()
            return self._template_out(t)

    async def save_template_from_session(self, sid: str, name: str | None,
                                         description: str | None) -> TemplateOut:
        async with self.db.sessionmaker() as s:
            sess = await s.get(CaptureSession, sid)
            if not sess:
                raise KeyError("unknown session")
            if not sess.assignments:
                raise ValueError("session has no assignments to save")
            assigns = [AssignmentCreate(target_id=a.target_id, iface=a.iface,
                                        target_channel=a.target_channel,
                                        width_mhz=a.width_mhz, flags=a.flags)
                       for a in sess.assignments if a.target_id]
        return await self.create_template(TemplateCreate(
            name=name or f"{sess.name} (template)", description=description,
            assignments=assigns))

    async def list_templates(self) -> list[TemplateOut]:
        async with self.db.sessionmaker() as s:
            rows = (await s.execute(
                select(Template).order_by(Template.created_at.desc()))).scalars().all()
            return [self._template_out(t) for t in rows]

    async def delete_template(self, tid: str) -> None:
        async with self.db.sessionmaker() as s:
            t = await s.get(Template, tid)
            if t:
                await s.delete(t)
                await s.commit()

    # -- inventory: controllers & targets -------------------------------------
    async def _refresh_target_password(self, s, target: Target, adapters: dict) -> None:
        """Best-effort: for an R1 target, pull the current CLI password from the
        controller right before capture (they rotate ~daily) and persist it."""
        if not (target.controller_id and target.serial and target.venue_id):
            return
        try:
            ad = adapters.get(target.controller_id)
            if ad is None:
                ctrl = await s.get(Controller, target.controller_id)
                if not ctrl or ctrl.platform != "r1":
                    return
                ad = self._adapter_for(ctrl)
                adapters[target.controller_id] = ad
            pw = await ad.get_ap_password(target.venue_id, target.serial)
            if pw.password:
                target.ssh_password = pw.password
        except Exception:
            pass  # fall back to the stored password

    def _resolve_ssh(self, target: Target | None) -> tuple[str | None, str | None]:
        """AP SSH creds come from the target (unique per AP; later auto-pulled from the
        controller's API). Returns (None, None) -> engine falls back to CT_AP_* env."""
        if target is None:
            return None, None
        return target.ssh_username, target.ssh_password

    async def create_controller(self, spec: ControllerCreate) -> ControllerOut:
        cid = uuid.uuid4().hex[:12]
        async with self.db.sessionmaker() as s:
            c = Controller(id=cid, **spec.model_dump())
            s.add(c)
            await s.commit()
            return self._controller_out(c, 0)

    async def update_controller(self, cid: str, patch: dict) -> ControllerOut:
        async with self.db.sessionmaker() as s:
            c = await s.get(Controller, cid)
            if not c:
                raise KeyError("unknown controller")
            for k in ("name", "base_url", "region", "tenant_id", "api_client_id",
                      "api_username", "api_version"):
                if k in patch:
                    setattr(c, k, patch[k])
            for k in ("api_client_secret", "api_password"):   # secrets: only if non-empty
                if patch.get(k):
                    setattr(c, k, patch[k])
            validate_controller_auth(c.platform, c.base_url, c.api_client_id,
                                     c.api_client_secret, c.api_username,
                                     c.api_password, c.api_version, c.tenant_id)
            await s.commit()
            count = len((await s.execute(
                select(Target).where(Target.controller_id == cid))).scalars().all())
            return self._controller_out(c, count)

    def _controller_out(self, c: Controller, target_count: int) -> ControllerOut:
        if c.platform == "sz":
            has_api = bool(c.base_url and c.api_username and c.api_password and c.api_version)
        else:
            has_api = bool(c.api_client_id and c.api_client_secret)
        return ControllerOut(
            id=c.id, platform=c.platform, name=c.name, base_url=c.base_url,
            region=c.region, tenant_id=c.tenant_id, api_client_id=c.api_client_id,
            api_username=c.api_username, api_version=c.api_version,
            has_api_creds=has_api, target_count=target_count, created_at=c.created_at)

    async def list_controllers(self) -> list[ControllerOut]:
        async with self.db.sessionmaker() as s:
            rows = (await s.execute(select(Controller)
                    .order_by(Controller.created_at.desc()))).scalars().all()
            return [self._controller_out(c, len(c.targets)) for c in rows]

    async def delete_controller(self, cid: str) -> None:
        async with self.db.sessionmaker() as s:
            c = await s.get(Controller, cid)
            if c:
                await s.delete(c)
                await s.commit()

    async def create_target(self, spec: TargetCreate) -> TargetOut:
        tid = uuid.uuid4().hex[:12]
        async with self.db.sessionmaker() as s:
            t = Target(id=tid, **spec.model_dump())
            s.add(t)
            await s.commit()
            ctrl = await s.get(Controller, t.controller_id) if t.controller_id else None
            return self._target_out(t, ctrl)

    def _target_out(self, t: Target, ctrl: Controller | None) -> TargetOut:
        effective = t.ssh_username or self.engine.settings.ap_username
        return TargetOut(
            id=t.id, name=t.name, host=t.host, model=t.model, serial=t.serial,
            controller_id=t.controller_id, controller_name=ctrl.name if ctrl else None,
            ssh_username=t.ssh_username, ssh_username_effective=effective,
            has_stored_password=bool(t.ssh_password),
            notes=t.notes, created_at=t.created_at)

    async def update_target(self, tid: str, patch: dict) -> TargetOut:
        async with self.db.sessionmaker() as s:
            t = await s.get(Target, tid)
            if not t:
                raise KeyError("unknown target")
            if "controller_id" in patch and patch["controller_id"]:
                if not await s.get(Controller, patch["controller_id"]):
                    raise ValueError("unknown controller")
            for k in ("name", "host", "model", "serial", "controller_id",
                      "ssh_username", "notes"):
                if k in patch:
                    setattr(t, k, patch[k])
            if patch.get("ssh_password"):   # secret: only if non-empty
                t.ssh_password = patch["ssh_password"]
            await s.commit()
            ctrl = await s.get(Controller, t.controller_id) if t.controller_id else None
            return self._target_out(t, ctrl)

    async def list_targets(self) -> list[TargetOut]:
        async with self.db.sessionmaker() as s:
            rows = (await s.execute(select(Target)
                    .order_by(Target.created_at.desc()))).scalars().all()
            cmap = {c.id: c for c in
                    (await s.execute(select(Controller))).scalars().all()}
            return [self._target_out(t, cmap.get(t.controller_id)) for t in rows]

    async def delete_target(self, tid: str) -> None:
        async with self.db.sessionmaker() as s:
            t = await s.get(Target, tid)
            if t:
                await s.delete(t)
                await s.commit()

    # -- controller inventory sync (R1) ---------------------------------------
    def _adapter_for(self, c: Controller):
        if c.platform == "r1":
            from .adapters.ruckus_one import RuckusOneAdapter
            return RuckusOneAdapter(c.api_client_id, c.api_client_secret, c.tenant_id,
                                    region=c.region, base_url=c.base_url)
        if c.platform == "sz":
            from .adapters.smartzone import SmartZoneAdapter
            return SmartZoneAdapter(c.base_url, c.api_username, c.api_password, c.api_version)
        raise ValueError(f"{c.platform.upper()} inventory not supported")

    async def _load_controller(self, cid: str) -> Controller:
        async with self.db.sessionmaker() as s:
            c = await s.get(Controller, cid)
            if not c:
                raise KeyError("unknown controller")
            return c

    async def list_controller_venues(self, cid: str) -> list[VenueOut]:
        c = await self._load_controller(cid)
        ad = self._adapter_for(c)
        try:
            venues = await ad.list_venues()
        finally:
            await ad.aclose()
        return [VenueOut(external_id=v.external_id, name=v.name, address=v.address)
                for v in venues]

    async def list_controller_venue_aps(self, cid: str, venue_id: str) -> list[ApInventoryOut]:
        c = await self._load_controller(cid)
        async with self.db.sessionmaker() as s:
            have = {t.serial for t in (await s.execute(
                select(Target).where(Target.controller_id == cid))).scalars().all() if t.serial}
        ad = self._adapter_for(c)
        try:
            aps = await ad.list_aps(venue_id)
        finally:
            await ad.aclose()
        return [ApInventoryOut(serial=a.serial, name=a.name, model=a.model, mac=a.mac,
                               ip=a.ip, firmware=a.firmware, state=a.state,
                               venue_id=a.venue_id, already_target=a.serial in have)
                for a in aps]

    async def import_targets(self, cid: str, venue_id: str, serials: list[str],
                             ssh_password: str | None = None) -> list[TargetOut]:
        """Pull AP details from the controller and upsert as targets (SSH user
        'admin'). R1: per-AP CLI password fetched from the API. SZ: no password
        API — use the supplied static/shared password (or leave for manual entry)."""
        c = await self._load_controller(cid)
        ad = self._adapter_for(c)
        fetched = []
        try:
            by_serial = {a.serial: a for a in await ad.list_aps(venue_id)}
            for serial in serials:
                ap = by_serial.get(serial)
                if not ap:
                    continue
                pw = None
                try:
                    pw = (await ad.get_ap_password(venue_id, serial)).password
                except Exception:
                    pw = None   # no per-AP password API (SZ) or fetch failed
                fetched.append((ap, pw or ssh_password))
        finally:
            await ad.aclose()

        out_ids = []
        async with self.db.sessionmaker() as s:
            for ap, pw in fetched:
                t = (await s.execute(select(Target).where(
                    Target.controller_id == cid, Target.serial == ap.serial))).scalars().first()
                if not t:
                    t = Target(id=uuid.uuid4().hex[:12], controller_id=cid, serial=ap.serial)
                    s.add(t)
                t.name = ap.name or ap.serial
                t.host = ap.ip or t.host or ""
                t.model = ap.model
                t.venue_id = ap.venue_id or venue_id   # for later password refresh
                t.ssh_username = "admin"
                if pw:
                    t.ssh_password = pw
                out_ids.append(t.id)
            await s.commit()
            results = []
            for tid in out_ids:
                t = await s.get(Target, tid)
                results.append(self._target_out(t, c))
            return results

    async def instantiate_template(self, tid: str, name: str | None) -> str:
        async with self.db.sessionmaker() as s:
            t = await s.get(Template, tid)
            if not t:
                raise KeyError("unknown template")
            sid = uuid.uuid4().hex[:12]
            sess = CaptureSession(id=sid, name=name or t.name, status="draft")
            s.add(sess)
            for a in t.assignments:
                target = await s.get(Target, a["target_id"]) if a.get("target_id") else None
                s.add(Assignment(id=uuid.uuid4().hex[:12], session_id=sid,
                                 target_id=a.get("target_id"),
                                 ap_host=target.host if target else a.get("ap_host", ""),
                                 iface=a["iface"], target_channel=a.get("target_channel"),
                                 width_mhz=a.get("width_mhz"), flags=a.get("flags", "")))
            await s.commit()
        return sid

    async def assignment_file(self, aid: str) -> tuple[Path, dict | None] | None:
        job = self.engine.get(aid)
        if job and job.file_path and job.file_path.exists():
            sc = job.file_path.with_suffix(".json")
            return job.file_path, (json.loads(sc.read_text()) if sc.exists() else None)
        async with self.db.sessionmaker() as s:
            a = await s.get(Assignment, aid)
            if a and a.file_path and Path(a.file_path).exists():
                return Path(a.file_path), a.sidecar
        return None
