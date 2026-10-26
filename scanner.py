"""
PHP2Scanner — async scan engine.

Fingerprints each target with non-destructive HTTP requests (httpx), extracts
the advertised PHP version through several read-only techniques, and evaluates it
against the CVE signatures. No exploit traffic is ever sent.

Detection techniques (all passive / read-only)
-----------------------------------------------
1. Response-header fingerprint  — X-Powered-By, Server, Set-Cookie
2. PHP session cookie           — PHPSESSID / framework cookies confirm a PHP runtime
3. HTML body + meta generator   — version strings and CMS generator tags in the page
4. CMS fingerprint              — WordPress / Drupal / Joomla (demonstrated PHP2Shell targets)
5. phpinfo() exposure probe     — (Deep) common info pages that leak the exact version
6. Error-page version leak      — (Deep) a 404 response that still discloses the version
7. Extra path probe             — (Deep) /index.php and site root when the version is hidden
"""

from __future__ import annotations
import re
import time
from typing import Optional, Dict, List, Tuple

import httpx

from signatures import evaluate, SIGNATURE_IDS

_PHP_RE = re.compile(r"PHP/(\d+\.\d+(?:\.\d+)?)", re.IGNORECASE)
# PHPSESSID is PHP's default session cookie; its presence confirms a PHP runtime
# even when the version is hidden. Also match a couple of common framework names.
_PHP_COOKIE_RE = re.compile(r"(?:^|[;,\s])(PHPSESSID|PHPSESSION|CAKEPHP|symfony|laravel_session)=", re.IGNORECASE)
# A healthy PHPSESSID value: ~22-40 chars of PHP's session id alphabet (0-9a-v, comma, dash).
_PHPSESSID_VAL_RE = re.compile(r"PHPSESSID=([^;,\s]+)", re.IGNORECASE)
_HEALTHY_SID_RE = re.compile(r"^[A-Za-z0-9,\-]{16,48}$")
_META_GEN_RE = re.compile(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']', re.IGNORECASE)
_PHPINFO_RE = re.compile(r"phpinfo\(\)|PHP Version\s*</td>|<title>phpinfo\(\)", re.IGNORECASE)

# CMS fingerprints: name -> list of regexes checked against headers + body.
_CMS_SIGNS = {
    "WordPress": [re.compile(r"/wp-content/", re.I), re.compile(r"/wp-includes/", re.I),
                  re.compile(r'name=["\']generator["\'][^>]*WordPress', re.I)],
    "Drupal": [re.compile(r"Drupal", re.I), re.compile(r"/sites/default/files", re.I),
               re.compile(r"X-Generator:\s*Drupal", re.I)],
    "Joomla": [re.compile(r"Joomla", re.I), re.compile(r"/media/jui/", re.I),
               re.compile(r"/templates/.*?joomla", re.I)],
}
# Common paths that may expose phpinfo() output (checked only in Deep profile).
_PHPINFO_PATHS = ("/phpinfo.php", "/info.php", "/php_info.php", "/test.php", "/i.php")

_BODY_CAP = 200_000  # only scan the first ~200 KB of any response body


def normalize_url(raw: str) -> str:
    raw = (raw or "").strip()
    if not raw:
        return raw
    if not re.match(r"^https?://", raw, re.IGNORECASE):
        raw = "https://" + raw
    return raw


def host_of(url: str) -> str:
    return re.sub(r"^https?://", "", url, flags=re.IGNORECASE).split("/")[0]


def origin_of(url: str) -> str:
    m = re.match(r"^(https?://[^/]+)", url)
    return m.group(1) if m else url.rstrip("/")


def _extract_php(*sources: str) -> Optional[str]:
    for s in sources:
        if not s:
            continue
        m = _PHP_RE.search(s)
        if m:
            return m.group(1)
    return None


def _php_session_cookie(set_cookie: str) -> Optional[str]:
    if not set_cookie:
        return None
    m = _PHP_COOKIE_RE.search(set_cookie)
    return m.group(1) if m else None


def _sid_anomaly(set_cookie: str) -> Optional[str]:
    """
    PHP2Shell's memory-disclosure bug leaks reclaimed heap bytes into a
    URL-encoded PHPSESSID *response* cookie (Wiz advisory). A healthy PHPSESSID
    is ~26 chars of a fixed alphabet; an oversized or %-encoded one is an
    anomaly worth manual review. Returns a reason string, or None.
    (Read-only: inspects a cookie the server already sent.)
    """
    if not set_cookie:
        return None
    m = _PHPSESSID_VAL_RE.search(set_cookie)
    if not m:
        return None
    val = m.group(1)
    if "%" in val:
        return "URL-encoded bytes in PHPSESSID"
    if len(val) > 64:
        return f"oversized PHPSESSID ({len(val)} chars)"
    if not _HEALTHY_SID_RE.match(val):
        return "malformed PHPSESSID charset"
    return None


def _confidence(state: str, methods: List[str], cms: Optional[str],
                versions_seen: set, sid_anomaly: Optional[str]) -> str:
    """How reliable the vulnerable/not verdict is: High / Medium / Low."""
    authoritative = any(m in methods for m in
                        ("X-Powered-By", "Server header", "exposed phpinfo()", "error-page leak"))
    conflict = len({v for v in versions_seen if v}) > 1
    if state == "vuln":
        if conflict:
            return "Medium"                 # sources disagree — proxy may hide origin
        return "High" if authoritative else "Medium"  # body/meta only = cacheable, Medium
    if state == "potential":
        if sid_anomaly:
            return "Medium"                 # behavioural indicator present
        return "Medium" if cms else "Low"
    return "—"


def _body_text(resp: httpx.Response) -> str:
    try:
        ctype = resp.headers.get("content-type", "")
        if ctype and not any(t in ctype.lower() for t in ("html", "text", "xml", "json", "")):
            return ""
        return resp.text[:_BODY_CAP]
    except Exception:  # noqa: BLE001
        return ""


def _detect_cms(headers_blob: str, body: str) -> Optional[str]:
    blob = headers_blob + "\n" + body
    for name, signs in _CMS_SIGNS.items():
        if any(rx.search(blob) for rx in signs):
            return name
    return None


def _meta_generator(body: str) -> Optional[str]:
    m = _META_GEN_RE.search(body or "")
    return m.group(1).strip() if m else None


def _http_class(status) -> str:
    if not isinstance(status, int):
        return "http-x"
    return f"http-{status // 100}"


async def scan_one(client: httpx.AsyncClient, raw_url: str, cfg: Dict) -> Dict:
    """Scan a single target. Always returns a result dict (never raises)."""
    url = normalize_url(raw_url)
    started = time.time()
    deep = cfg.get("profile") == "Deep"
    timeout = cfg.get("timeout", 10)
    follow = cfg.get("follow_redirects", True)
    base = {"url": url, "host": host_of(url), "https": url.lower().startswith("https://")}
    methods: List[str] = []   # which detection techniques fired

    try:
        resp = await client.get(url, timeout=timeout, follow_redirects=follow)
    except Exception as exc:  # noqa: BLE001 — any network error -> failed target
        return {
            **base, "status": "ERR", "status_class": "http-x", "php": "—",
            "state": "fail", "severity": "None", "cvss": 0, "confidence": "—",
            "sid_anomaly": False, "error": type(exc).__name__,
            "findings": {cid: "unknown" for cid in SIGNATURE_IDS},
            "detail": {cid: None for cid in SIGNATURE_IDS},
            "evidence": {"error": f"{type(exc).__name__}: {exc}", "detection_methods": [], "confidence": "—"},
            "elapsed_ms": int((time.time() - started) * 1000),
        }

    server = resp.headers.get("server", "")
    powered = resp.headers.get("x-powered-by", "")
    set_cookie = ", ".join(resp.headers.get_list("set-cookie")) or resp.headers.get("set-cookie", "")
    headers_blob = "\n".join(f"{k}: {v}" for k, v in resp.headers.items())
    body = _body_text(resp)

    # 1 + 2. Header / cookie fingerprint
    php = _extract_php(powered, server, set_cookie)
    if php:
        methods.append("X-Powered-By" if _extract_php(powered) else "Server header")
    session_cookie = _php_session_cookie(set_cookie)
    if session_cookie:
        methods.append(f"{session_cookie} cookie")

    # 3. HTML body + meta generator
    meta_gen = _meta_generator(body)
    if not php:
        php_body = _extract_php(body)
        if php_body:
            php = php_body
            methods.append("HTML body")
    if meta_gen and _extract_php(meta_gen) and not php:
        php = _extract_php(meta_gen)
        methods.append("meta generator")

    # 4. CMS fingerprint (context — these are the demonstrated PHP2Shell targets)
    cms = _detect_cms(headers_blob, body)
    if cms:
        methods.append(f"{cms} detected")

    phpinfo_url = None
    error_leak = None

    if deep:
        # 5. phpinfo() exposure probe — a few common info pages
        for path in _PHPINFO_PATHS:
            cand = origin_of(str(resp.url)) + path
            try:
                ri = await client.get(cand, timeout=timeout, follow_redirects=follow)
            except Exception:  # noqa: BLE001
                continue
            if ri.status_code == 200:
                bi = _body_text(ri)
                if _PHPINFO_RE.search(bi):
                    phpinfo_url = cand
                    methods.append("exposed phpinfo()")
                    pv = _extract_php(bi) or _extract_php(ri.headers.get("x-powered-by", ""))
                    if pv:
                        php = pv
                    break

        # 6. Error-page version leak — request a path that should 404
        if not php:
            cand = origin_of(str(resp.url)) + "/php2scanner-probe-" + str(int(started))
            try:
                re404 = await client.get(cand, timeout=timeout, follow_redirects=follow)
                pv = _extract_php(re404.headers.get("x-powered-by", ""), re404.headers.get("server", ""), _body_text(re404))
                if pv:
                    php = pv
                    error_leak = re404.status_code
                    methods.append("error-page leak")
                if not session_cookie:
                    session_cookie = _php_session_cookie(", ".join(re404.headers.get_list("set-cookie")))
            except Exception:  # noqa: BLE001
                pass

        # 7. Extra path probe — /index.php and root when still hidden
        if not php:
            for extra in ("/index.php", "/"):
                cand = origin_of(str(resp.url)) + extra
                if cand == str(resp.url):
                    continue
                try:
                    r2 = await client.get(cand, timeout=timeout, follow_redirects=follow)
                except Exception:  # noqa: BLE001
                    continue
                sc2 = ", ".join(r2.headers.get_list("set-cookie"))
                pv = _extract_php(r2.headers.get("x-powered-by", ""), r2.headers.get("server", ""), sc2, _body_text(r2))
                if not session_cookie:
                    session_cookie = _php_session_cookie(sc2)
                if pv:
                    php = pv
                    methods.append(f"path probe ({extra})")
                    break

    # PHP runtime confirmed by any strong signal
    php_confirmed = bool(php) or bool(session_cookie) or ("php" in (powered + " " + server).lower()) or bool(cms)

    # Behavioural indicator: anomalous PHPSESSID response cookie (advisory-backed)
    sid_anomaly = _sid_anomaly(set_cookie)
    if sid_anomaly:
        methods.append("PHPSESSID anomaly")

    # All distinct versions seen across sources — disagreement lowers confidence
    versions_seen = set(filter(None, [
        _extract_php(powered), _extract_php(server), _extract_php(set_cookie),
        _extract_php(body), _extract_php(meta_gen or ""),
    ]))

    detail = evaluate(php, php_confirmed=php_confirmed)
    findings = {cid: detail[cid]["status"] for cid in SIGNATURE_IDS}

    # Server / OS hint — used to judge conditional CVEs (e.g. CVE-2024-4577 = Windows+CGI)
    srv_l = (server + " " + powered).lower()
    if any(w in srv_l for w in ("win", "iis")):
        os_hint = "windows"
    elif any(w in srv_l for w in ("ubuntu", "debian", "centos", "unix", "nginx")):
        os_hint = "unix-like"
    else:
        os_hint = None

    def _cond_met(d: Dict) -> str:
        if not d.get("conditional"):
            return "n/a"
        if d.get("condition_hint") == "windows":
            return "likely" if os_hint == "windows" else "unlikely" if os_hint == "unix-like" else "unverified"
        return "unverified"

    # Collect every CVE whose version range matches, with condition assessment
    matched_cves: List[Dict] = []
    for cid in SIGNATURE_IDS:
        if findings[cid] == "vulnerable":
            d = detail[cid]
            matched_cves.append({
                "id": d["id"], "title": d["title"], "cvss": d["cvss"], "severity": d["severity"],
                "conditional": d.get("conditional", False), "condition": d.get("condition"),
                "condition_met": _cond_met(d),
            })

    potentials = [detail[cid] for cid in SIGNATURE_IDS if findings[cid] == "potential"]
    unconditional = [m for m in matched_cves if not m["conditional"]]
    cond_likely = [m for m in matched_cves if m["conditional"] and m["condition_met"] == "likely"]

    headline = None
    if unconditional:
        headline = max(unconditional, key=lambda m: m["cvss"])
    elif cond_likely:
        headline = max(cond_likely, key=lambda m: m["cvss"])
    elif matched_cves:
        headline = max(matched_cves, key=lambda m: m["cvss"])

    if headline:
        state, severity, cvss = "vuln", headline["severity"], headline["cvss"]
    elif potentials:
        worst = max(potentials, key=lambda d: d["cvss"])
        state, severity, cvss = "potential", "Potential", worst["cvss"]
    else:
        state, severity, cvss = "safe", "None", 0

    confidence = _confidence(state, methods, cms, versions_seen, sid_anomaly)
    # A conditional headline (e.g. Windows-only CVE) that isn't corroborated is less certain
    if state == "vuln" and headline and headline["conditional"] and headline["condition_met"] != "likely":
        confidence = "Low" if headline["condition_met"] == "unlikely" else "Medium"

    how = methods[0] if methods else "not confirmed"
    evidence = {
        "final_url": str(resp.url),
        "status": resp.status_code,
        "server": server or "(not disclosed)",
        "x_powered_by": powered or "(not disclosed)",
        "php_detected": php or "(version hidden)",
        "php_session_cookie": session_cookie or "(none)",
        "sid_anomaly": sid_anomaly or "(none)",
        "versions_seen": sorted(versions_seen) or ["(none)"],
        "version_conflict": len({v for v in versions_seen if v}) > 1,
        "cms": cms or "(none detected)",
        "os_hint": os_hint or "(unknown)",
        "meta_generator": meta_gen or "(none)",
        "phpinfo_exposed": phpinfo_url or "(not found)",
        "confidence": confidence,
        "matched_cves": matched_cves,
        "runtime_confirmed_via": how,
        "detection_methods": methods,
        "profile": cfg.get("profile", "Standard"),
    }

    return {
        **base,
        "status": resp.status_code,
        "status_class": _http_class(resp.status_code),
        "php": php or "—",
        "cms": cms,
        "state": state,
        "severity": severity,
        "cvss": cvss,
        "confidence": confidence,
        "sid_anomaly": bool(sid_anomaly),
        "matched_cves": matched_cves,
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
    score = 0
    if vuln:
        score = min(100, round(max_cvss * 10 + max(0, vuln - 1) * 5))
    elif potential:
        score = min(55, 25 + (potential - 1) * 5)
    return {
        "total": total, "scanned": scanned, "pending": max(0, total - scanned),
        "vulnerable": vuln, "potential": potential, "safe": safe, "failed": fail,
        "max_cvss": max_cvss, "risk_score": score,
    }
