"""
PHP2Scanner — FastAPI application.

Routes
------
GET  /                       -> the dashboard (static/index.html)
GET  /api/health             -> liveness probe
POST /api/scan               -> start a scan, returns {scan_id}
GET  /api/scan/{id}          -> full snapshot (polling fallback)
GET  /api/scan/{id}/stream   -> Server-Sent Events: live log / result / progress
POST /api/scan/{id}/stop     -> cancel a running scan
GET  /api/scan/{id}/report.json -> JSON report download
GET  /api/scan/{id}/report.csv  -> CSV report download

State is held in memory only (no database, per spec). Restarting the process
clears past scans.
"""

from __future__ import annotations
import asyncio
import csv
import io
import json
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import (
    FileResponse,
    JSONResponse,
    PlainTextResponse,
    Response,
    StreamingResponse,
)
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from scanner import scan_one, summarize, normalize_url, host_of
from signatures import SIGNATURES, SIGNATURE_IDS

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"

MAX_TARGETS = 1000
HARD_CONCURRENCY_CAP = 50

app = FastAPI(title="PHP2Scanner", version="1.0.0")


def _ts() -> str:
    return datetime.now(timezone.utc).strftime("%H:%M:%S")


def _iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# --------------------------------------------------------------------------- #
# Request models
# --------------------------------------------------------------------------- #

class ScanConfig(BaseModel):
    profile: str = "Standard"
    concurrency: int = Field(12, ge=1, le=HARD_CONCURRENCY_CAP)
    timeout: int = Field(10, ge=2, le=60)
    follow_redirects: bool = True
    verify_tls: bool = False


class ScanRequest(BaseModel):
    targets: List[str] = Field(default_factory=list)
    config: ScanConfig = Field(default_factory=ScanConfig)


# --------------------------------------------------------------------------- #
# Scan state
# --------------------------------------------------------------------------- #

class Scan:
    def __init__(self, scan_id: str, targets: List[str], config: ScanConfig):
        self.id = scan_id
        self.targets = targets
        self.config = config
        self.status = "running"              # running | done | cancelled
        self.started_at = _iso()
        self.finished_at: Optional[str] = None
        self.results: List[Dict] = []
        self.summary = summarize([], len(targets))
        self.events: List[Dict] = []         # replay history for new subscribers
        self.subscribers: set[asyncio.Queue] = set()
        self.cancel = asyncio.Event()
        self.task: Optional[asyncio.Task] = None

    def emit(self, event: Dict) -> None:
        self.events.append(event)
        for q in list(self.subscribers):
            try:
                q.put_nowait(event)
            except Exception:
                pass

    def snapshot(self) -> Dict:
        return {
            "scan_id": self.id,
            "status": self.status,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "config": self.config.model_dump(),
            "summary": self.summary,
            "results": self.results,
        }


SCANS: Dict[str, Scan] = {}


# --------------------------------------------------------------------------- #
# Scan runner
# --------------------------------------------------------------------------- #

async def run_scan(scan: Scan) -> None:
    cfg = scan.config
    total = len(scan.targets)
    scan.emit({"type": "log", "ts": _ts(), "level": "info",
               "msg": f"→ queue loaded · {total} target(s) · profile {cfg.profile}"})

    sem = asyncio.Semaphore(cfg.concurrency)
    limits = httpx.Limits(max_connections=cfg.concurrency + 5)
    headers = {"User-Agent": "php2scanner/1.0 (+exposure-check)"}

    async with httpx.AsyncClient(verify=cfg.verify_tls, limits=limits,
                                 headers=headers) as client:

        async def worker(raw: str) -> None:
            if scan.cancel.is_set():
                return
            async with sem:
                if scan.cancel.is_set():
                    return
                host = host_of(normalize_url(raw))
                scan.emit({"type": "log", "ts": _ts(), "level": "req",
                           "msg": f"GET {host} …"})
                result = await scan_one(client, raw, cfg.model_dump())
                scan.results.append(result)
                scan.summary = summarize(scan.results, total)

                # human-readable log line for this target
                if result["state"] == "vuln":
                    for cid in SIGNATURE_IDS:
                        if result["findings"][cid] == "vulnerable":
                            scan.emit({"type": "log", "ts": _ts(), "level": "crit",
                                       "msg": f"⚠ {cid} CONFIRMED · {result['host']}"})
                elif result["state"] == "fail":
                    scan.emit({"type": "log", "ts": _ts(), "level": "warn",
                               "msg": f"✗ {result['host']} · unreachable"})
                else:
                    scan.emit({"type": "log", "ts": _ts(), "level": "ok",
                               "msg": f"✓ {result['host']} · no exposure"})

                scan.emit({"type": "result", "result": result})
                scan.emit({"type": "progress", "summary": scan.summary})

        await asyncio.gather(*(worker(t) for t in scan.targets))

    scan.status = "cancelled" if scan.cancel.is_set() else "done"
    scan.finished_at = _iso()
    scan.summary = summarize(scan.results, total)
    scan.emit({"type": "log", "ts": _ts(), "level": "info",
               "msg": f"■ scan {scan.status} · {scan.summary['vulnerable']} at risk"})
    scan.emit({"type": "done", "status": scan.status, "summary": scan.summary})


# --------------------------------------------------------------------------- #
# API routes
# --------------------------------------------------------------------------- #

@app.get("/api/health")
async def health():
    return {"status": "ok", "scans": len(SCANS), "time": _iso()}


@app.get("/api/signatures")
async def signatures():
    return {"signatures": [
        {k: s[k] for k in ("id", "title", "severity", "cvss", "vector", "fixed")}
        for s in SIGNATURES
    ]}


@app.post("/api/scan")
async def start_scan(req: ScanRequest):
    targets = []
    seen = set()
    for t in req.targets:
        t = (t or "").strip()
        if not t or t in seen:
            continue
        seen.add(t)
        targets.append(t)
    if not targets:
        raise HTTPException(status_code=400, detail="No targets provided.")
    if len(targets) > MAX_TARGETS:
        raise HTTPException(status_code=400, detail=f"Too many targets (max {MAX_TARGETS}).")

    scan_id = uuid.uuid4().hex[:12]
    scan = Scan(scan_id, targets, req.config)
    SCANS[scan_id] = scan
    scan.task = asyncio.create_task(run_scan(scan))
    return {"scan_id": scan_id, "total": len(targets)}


def _get(scan_id: str) -> Scan:
    scan = SCANS.get(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found.")
    return scan


@app.get("/api/scan/{scan_id}")
async def scan_snapshot(scan_id: str):
    return _get(scan_id).snapshot()


@app.post("/api/scan/{scan_id}/stop")
async def stop_scan(scan_id: str):
    scan = _get(scan_id)
    scan.cancel.set()
    return {"scan_id": scan_id, "status": "stopping"}


@app.get("/api/scan/{scan_id}/stream")
async def stream(scan_id: str, request: Request):
    scan = _get(scan_id)
    queue: asyncio.Queue = asyncio.Queue()
    scan.subscribers.add(queue)

    async def gen():
        try:
            # replay everything so far, then live updates
            for ev in list(scan.events):
                yield f"data: {json.dumps(ev)}\n\n"
            if scan.status != "running":
                return
            while True:
                if await request.is_disconnected():
                    break
                try:
                    ev = await asyncio.wait_for(queue.get(), timeout=15)
                    yield f"data: {json.dumps(ev)}\n\n"
                    if ev.get("type") == "done":
                        break
                except asyncio.TimeoutError:
                    yield ": keep-alive\n\n"  # comment frame to hold the connection
        finally:
            scan.subscribers.discard(queue)

    return StreamingResponse(gen(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache",
                                      "X-Accel-Buffering": "no"})


@app.get("/api/scan/{scan_id}/report.json")
async def report_json(scan_id: str):
    scan = _get(scan_id)
    payload = {
        "tool": "PHP2Scanner",
        "generated_at": _iso(),
        **scan.snapshot(),
    }
    data = json.dumps(payload, indent=2)
    return Response(
        content=data,
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="php2scanner-{scan_id}.json"'},
    )


@app.get("/api/scan/{scan_id}/report.csv")
async def report_csv(scan_id: str):
    scan = _get(scan_id)
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["url", "status", "php_version", "state", "severity", "cvss",
                *SIGNATURE_IDS, "error"])
    for r in scan.results:
        w.writerow([
            r["url"], r["status"], r["php"], r["state"], r["severity"], r["cvss"],
            *[r["findings"].get(cid, "") for cid in SIGNATURE_IDS],
            r.get("error", ""),
        ])
    return Response(
        content=buf.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="php2scanner-{scan_id}.csv"'},
    )


# --------------------------------------------------------------------------- #
# Static front-end (mounted last so /api/* wins)
# --------------------------------------------------------------------------- #

@app.get("/")
async def index():
    return FileResponse(STATIC_DIR / "index.html")


app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
