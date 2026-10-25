# PHP2Scanner

A PHP CVE **exposure scanner** with a live security-console dashboard. It
fingerprints the PHP version a web target advertises and flags whether that
version falls inside the affected range for the tracked CVEs
(`CVE-2026-109618`, `CVE-2026-109619`). Detection is passive — it reads
response headers and compares versions. **No exploit traffic is ever sent.**

> 🛡 **Authorized use only.** Scan systems you own or are explicitly permitted
> to test. Unauthorized scanning may be illegal in your jurisdiction.

---

## Stack

- **Backend:** Python + FastAPI, `httpx` + `asyncio` for concurrent scanning
- **Live progress:** Server-Sent Events (SSE)
- **Frontend:** HTML + CSS + vanilla JavaScript (20 switchable themes, command
  palette, sortable findings, tabbed views)
- **Reports:** JSON and CSV download
- **State:** in-memory (no database)
- No Docker, no React, no authentication

> The UI ships as the custom-themed design that was approved during the preview
> stage (hand-written CSS rather than Tailwind) so the look matches exactly.

---

## Run locally

```bash
pip install -r requirements.txt
uvicorn app:app --reload --port 8000
```

Open <http://localhost:8000>.

Enter a single domain (Single mode) or a list / uploaded `.txt` (Bulk mode),
adjust the scan config, and press **Start Scan**. Results stream in live.

---

## Project layout

```
php2scanner/
├── app.py            FastAPI app: routes, SSE, reports, static serving
├── scanner.py        async httpx scan engine (fingerprint + evaluate)
├── signatures.py     CVE registry + version-range matching  ← EDIT THIS
├── requirements.txt
├── render.yaml       Render.com deployment config
└── static/
    ├── index.html    dashboard markup + themes
    └── app.js        front-end controller (API + live updates)
```

---

## ⚠ Configure the CVE ranges before relying on results

The affected-version ranges in `signatures.py` are **placeholders**. Open the
file and replace each signature's `affected` list with the real ranges from the
official advisory. Example:

```python
"affected": [
    [">=8.1.0", "<=8.1.6"],   # a version is affected if it satisfies ALL specs in a row
    [">=8.0.0", "<=8.0.28"],  # ...or any other row
],
"fixed": "8.1.7",
```

Supported operators: `>=`, `<=`, `>`, `<`, `==`, `!=`.

Run the built-in self-test after editing:

```bash
python signatures.py
```

---

## API

| Method | Path | Purpose |
|--------|------|---------|
| GET  | `/api/health` | liveness probe |
| GET  | `/api/signatures` | list tracked CVEs |
| POST | `/api/scan` | start a scan → `{scan_id}` |
| GET  | `/api/scan/{id}` | full snapshot (polling fallback) |
| GET  | `/api/scan/{id}/stream` | SSE: live `log` / `result` / `progress` / `done` |
| POST | `/api/scan/{id}/stop` | cancel a running scan |
| GET  | `/api/scan/{id}/report.json` | JSON report download |
| GET  | `/api/scan/{id}/report.csv` | CSV report download |

`POST /api/scan` body:

```json
{
  "targets": ["https://example.com", "api.example.net"],
  "config": {
    "profile": "Standard",
    "concurrency": 12,
    "timeout": 10,
    "follow_redirects": true,
    "verify_tls": false
  }
}
```

---

## Deploy to Render

The repo includes `render.yaml`, so it deploys as a Blueprint:

1. Push this folder to a GitHub repo.
2. In Render: **New → Blueprint**, point it at the repo.
3. Render reads `render.yaml` and provisions a free web service with:
   - Build: `pip install -r requirements.txt`
   - Start: `uvicorn app:app --host 0.0.0.0 --port $PORT`

Or configure a Web Service manually with those two commands (Python runtime,
no Docker).

---

## Notes & limits

- State is in memory, so a restart clears past scans. Fine for a single-instance
  free deployment; add a store if you need history.
- Risk score is a heuristic aggregate (worst CVSS dominates, extra findings add
  a little), meant for at-a-glance triage, not formal scoring.
- The scanner makes one request per target to whatever host you supply; it does
  not restrict internal/private addresses, since authorized internal scanning is
  a legitimate use. Keep that in mind when exposing the service.
