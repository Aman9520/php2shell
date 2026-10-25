"""
PHP2Scanner — async scan engine.

Fingerprints each target with a single non-destructive HTTP request (httpx),
extracts the advertised PHP version, and evaluates it against the CVE
signatures. No exploit traffic is ever sent.
"""

from __future__ import annotations
import re
import time
from typing import Optional, Dict, List

import httpx

from signatures import evaluate, SIGNATURE_IDS

_PHP_RE = re.compile(r"PHP/(\d+\.\d+(?:\.\d+)?)", re.IGNORECASE)
# PHPSESSID is PHP's default session cookie; its presence confirms a PHP runtime
# even when the version is hidden. Also match a couple of common framework names.
_PHP_COOKIE_RE = re.compile(r"(?:^|[;,\s])(PHPSESSID|PHPSESSION|CAKEPHP|symfony)=", re.IGNORECASE)


def normalize_url(raw: str) -> str:
    raw = (raw or "").strip()
    if not raw:
        return raw
    if not re.match(r"^https?://", raw, re.IGNORECASE):
        raw = "https://" + raw
    return raw


def host_of(url: str) -> str:
    return re.sub(r"^https?://", "", url, flags=re.IGNORECASE).split("/")[0]


def _extract_php(*sources: str) -> Optional[str]:
    for s in sources:
        if not s:
            continue
        m = _PHP_RE.search(s)
        if m:
            return m.group(1)
    return None


def _php_session_cookie(set_cookie: str) -> Optional[str]:
    """Return the matched PHP session cookie name, or None."""
    if not set_cookie:
        return None
    m = _PHP_COOKIE_RE.search(set_cookie)
    return m.group(1) if m else None


def _http_class(status) -> str:
    if not isinstance(status, int):
        return "http-x"
    return f"http-{status // 100}"


async def scan_one(client: httpx.AsyncClient, raw_url: str, cfg: Dict) -> Dict:
    """Scan a single target. Always returns a result dict (never raises)."""
    url = normalize_url(raw_url)
    started = time.time()
    base = {
        "url": url,
        "host": host_of(url),
        "https": url.lower().startswith("https://"),
    }

    try:
        resp = await client.get(
            url,
            timeout=cfg.get("timeout", 10),
            follow_redirects=cfg.get("follow_redirects", True),
        )
    except Exception as exc:  # noqa: BLE001 — any network error -> failed target
        return {
            **base,
            "status": "ERR",
            "status_class": "http-x",
            "php": "—",
            "state": "fail",
            "severity": "None",
            "cvss": 0,
            "error": type(exc).__name__,
            "findings": {cid: "unknown" for cid in SIGNATURE_IDS},
            "detail": {cid: None for cid in SIGNATURE_IDS},
            "evidence": {"error": f"{type(exc).__name__}: {exc}"},
            "elapsed_ms": int((time.time() - started) * 1000),
        }

    server = resp.headers.get("server", "")
    powered = resp.headers.get("x-powered-by", "")
    set_cookie = ", ".join(resp.headers.get_list("set-cookie")) or resp.headers.get("set-cookie", "")

    php = _extract_php(powered, server, set_cookie)
    session_cookie = _php_session_cookie(set_cookie)
    # PHP runtime is "confirmed" if we found a version OR a PHP session cookie
    # OR the string 'php' appears in the Server / X-Powered-By headers.
    php_confirmed = bool(php) or bool(session_cookie) or ("php" in (powered + " " + server).lower())

    detail = evaluate(php, php_confirmed=php_confirmed)
    findings = {cid: detail[cid]["status"] for cid in SIGNATURE_IDS}

    vulns = [detail[cid] for cid in SIGNATURE_IDS if findings[cid] == "vulnerable"]
    potentials = [detail[cid] for cid in SIGNATURE_IDS if findings[cid] == "potential"]
    if vulns:
        worst = max(vulns, key=lambda d: d["cvss"])
        state, severity, cvss = "vuln", worst["severity"], worst["cvss"]
    elif potentials:
        worst = max(potentials, key=lambda d: d["cvss"])
        state, severity, cvss = "potential", "Potential", worst["cvss"]
    else:
        state, severity, cvss = "safe", "None", 0

    how = ("X-Powered-By" if _extract_php(powered) else
           "Server header" if _extract_php(server) else
           f"{session_cookie} cookie" if session_cookie else
           "not confirmed")
    evidence = {
        "final_url": str(resp.url),
        "status": resp.status_code,
        "server": server or "(not disclosed)",
        "x_powered_by": powered or "(not disclosed)",
        "php_detected": php or "(version hidden)",
        "php_session_cookie": session_cookie or "(none)",
        "runtime_confirmed_via": how,
    }

    return {
        **base,
        "status": resp.status_code,
        "status_class": _http_class(resp.status_code),
        "php": php or "—",
        "state": state,
        "severity": severity,
        "cvss": cvss,
        "findings": findings,
        "detail": detail,
        "evidence": evidence,
        "elapsed_ms": int((time.time() - started) * 1000),
    }


def summarize(results: List[Dict], total: int) -> Dict:
    scanned = len(results)
    vuln = sum(1 for r in results if r["state"] == "vuln")
    potential = sum(1 for r in results if r["state"] == "potential")
    safe = sum(1 for r in results if r["state"] == "safe")
    fail = sum(1 for r in results if r["state"] == "fail")
    max_cvss = max((r["cvss"] for r in results if r["state"] == "vuln"), default=0)
    # Heuristic aggregate risk score (0-100): a confirmed finding dominates;
    # 'potential' raises a moderate alert; extra findings add a little.
    score = 0
    if vuln:
        score = min(100, round(max_cvss * 10 + max(0, vuln - 1) * 5))
    elif potential:
        score = min(55, 25 + (potential - 1) * 5)
    return {
        "total": total,
        "scanned": scanned,
        "pending": max(0, total - scanned),
        "vulnerable": vuln,
        "potential": potential,
        "safe": safe,
        "failed": fail,
        "max_cvss": max_cvss,
        "risk_score": score,
    }
