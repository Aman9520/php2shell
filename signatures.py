"""
PHP2Scanner — CVE signature registry and version-range matching.

Detection philosophy
---------------------
This scanner is a *passive exposure* checker. It fingerprints the PHP version a
target advertises (response headers, cookies) and compares it against the
affected-version ranges declared below. It does NOT send exploit payloads or
attempt to trigger the vulnerabilities — the same approach version-check
templates use in tools like Nuclei.

The signatures below cover "PHP2Shell" (CVE-2026-109618 and CVE-2026-109619),
the critical PHP core memory-safety flaws disclosed by Wiz Research on
21 October 2026. Both are unauthenticated and rated CVSS 9.2 (v4.0). They affect
essentially every PHP release going back to ~2004. The PHP team shipped fixes on
21 October 2026 in 8.5.12, 8.4.27, 8.3.36 and 8.2.35; PHP 8.1 and older are
end-of-life and will not be patched, so they remain permanently vulnerable.

If PHP ships further patch releases, add the new branch's fixed version to the
affected ranges below.
"""

from __future__ import annotations
import re
from typing import Optional, List, Dict

# --------------------------------------------------------------------------- #
# Version helpers
# --------------------------------------------------------------------------- #

_VER_RE = re.compile(r"\d+")
_SPEC_RE = re.compile(r"\s*(>=|<=|==|!=|>|<)\s*(.+)\s*$")


def parse_version(v: Optional[str]) -> tuple:
    """'8.3.36' -> (8, 3, 36). Non-numeric / empty -> (0,)."""
    if not v:
        return (0,)
    nums = _VER_RE.findall(v)
    return tuple(int(n) for n in nums[:4]) or (0,)


def _cmp(a: tuple, b: tuple) -> int:
    L = max(len(a), len(b))
    a = a + (0,) * (L - len(a))
    b = b + (0,) * (L - len(b))
    return (a > b) - (a < b)


def satisfies(version: str, spec: str) -> bool:
    """Does `version` satisfy a single spec like '>=8.2.0'?"""
    m = _SPEC_RE.match(spec)
    if not m:
        return False
    op, target = m.group(1), m.group(2)
    c = _cmp(parse_version(version), parse_version(target))
    return {
        ">=": c >= 0, "<=": c <= 0, ">": c > 0,
        "<": c < 0, "==": c == 0, "!=": c != 0,
    }[op]


def is_affected(version: Optional[str], ranges: List[List[str]]) -> Optional[bool]:
    """
    True  -> version falls inside at least one affected range
    False -> version known and outside every range
    None  -> version unknown (cannot decide)
    """
    if not version:
        return None
    for rng in ranges:
        if all(satisfies(version, spec) for spec in rng):
            return True
    return False


# --------------------------------------------------------------------------- #
# Signature registry — PHP2Shell (21 Oct 2026)
# --------------------------------------------------------------------------- #

# Shared affected set: every PHP version below its branch's patched release, plus
# every end-of-life branch (anything below 8.2) which never receives a fix.
_PHP2SHELL_AFFECTED: List[List[str]] = [
    [">=8.5.0", "<8.5.12"],
    [">=8.4.0", "<8.4.27"],
    [">=8.3.0", "<8.3.36"],
    [">=8.2.0", "<8.2.35"],
    [">=4.0.0", "<8.2.0"],   # 8.1.x and older — end-of-life, not patched
]
_PHP2SHELL_FIXED = "8.5.12 / 8.4.27 / 8.3.36 / 8.2.35 (per branch)"
_PHP2SHELL_REFS = [
    {"label": "Wiz — PHP2Shell", "url": "https://www.wiz.io/blog/php2shell"},
    {"label": "PHP release (21 Oct 2026)", "url": "https://www.php.net/archive/2026.php"},
]

SIGNATURES: List[Dict] = [
    {
        "id": "CVE-2026-109618",
        "title": "Upload-progress unserializer UAF — unauth RCE & memory disclosure",
        "severity": "Critical",
        "cvss": 9.2,
        "vector": "Network / Unauthenticated (CVSS v4.0)",
        "condition": None,          # applies to any PHP deployment in range
        "conditional": False,
        "affected": _PHP2SHELL_AFFECTED,
        "fixed": _PHP2SHELL_FIXED,
        "remediation": [
            "Upgrade PHP to the patched release for your branch: 8.5.12, 8.4.27, 8.3.36 or 8.2.35.",
            "PHP 8.1 and older are end-of-life and will NOT be patched — migrate to a supported, patched branch.",
            "Restart PHP-FPM and all long-running PHP workers (queues, Octane, Horizon) so they load the new build.",
            "Watch for oversized or malformed PHPSESSID response cookies and unexplained memory-limit / HTTP 500 errors as exploitation signs.",
        ],
        "references": _PHP2SHELL_REFS + [
            {"label": "NVD Entry", "url": "https://nvd.nist.gov/vuln/detail/CVE-2026-109618"},
        ],
    },
    {
        "id": "CVE-2026-109619",
        "title": "Fatal-error backtrace UAF / OPcache type confusion — unauth RCE",
        "severity": "Critical",
        "cvss": 9.2,
        "vector": "Network / Unauthenticated (CVSS v4.0)",
        "condition": None,
        "conditional": False,
        "affected": _PHP2SHELL_AFFECTED,
        "fixed": _PHP2SHELL_FIXED,
        "remediation": [
            "Upgrade PHP to the patched release for your branch: 8.5.12, 8.4.27, 8.3.36 or 8.2.35.",
            "PHP 8.1 and older are end-of-life and will NOT be patched — migrate to a supported, patched branch.",
            "Restart PHP-FPM and all long-running PHP workers so OPcache and the engine reload cleanly.",
            "Review access logs for repeated HTTP 500s and PHP worker churn that can accompany exploitation attempts.",
        ],
        "references": _PHP2SHELL_REFS + [
            {"label": "NVD Entry", "url": "https://nvd.nist.gov/vuln/detail/CVE-2026-109619"},
        ],
    },
]

SIGNATURE_IDS = [s["id"] for s in SIGNATURES]


def evaluate(php_version: Optional[str], php_confirmed: bool = False) -> Dict[str, Dict]:
    """
    Run every signature against a detected PHP version.
    Returns { cve_id: {status, severity, cvss, ...} }.

    status is one of:
      'vulnerable'  — version known and inside an affected range
      'not_exposed' — version known and outside every range
      'potential'   — version unknown BUT PHP runtime was confirmed another way
                      (e.g. a PHPSESSID cookie); may be affected, verify manually
      'unknown'     — version unknown and PHP not confirmed at all
    """
    out: Dict[str, Dict] = {}
    for sig in SIGNATURES:
        aff = is_affected(php_version, sig["affected"])
        if aff is True:
            status = "vulnerable"
        elif aff is False:
            status = "not_exposed"
        else:
            status = "potential" if php_confirmed else "unknown"
        out[sig["id"]] = {
            "id": sig["id"],
            "title": sig["title"],
            "severity": sig["severity"],
            "cvss": sig["cvss"],
            "vector": sig["vector"],
            "fixed": sig["fixed"],
            "condition": sig.get("condition"),
            "conditional": sig.get("conditional", False),
            "condition_hint": sig.get("condition_hint"),
            "status": status,
            "remediation": sig["remediation"],
            "references": sig["references"],
        }
    return out


# --------------------------------------------------------------------------- #
# Self-test
# --------------------------------------------------------------------------- #

if __name__ == "__main__":
    cases = [
        ("8.3.35", "CVE-2026-109618", "vulnerable"),   # below branch fix
        ("8.3.36", "CVE-2026-109618", "not_exposed"),  # patched
        ("8.2.35", "CVE-2026-109619", "not_exposed"),  # patched
        ("8.2.11", "CVE-2026-109618", "vulnerable"),
        ("8.5.11", "CVE-2026-109619", "vulnerable"),
        ("8.5.12", "CVE-2026-109618", "not_exposed"),  # patched
        ("7.4.33", "CVE-2026-109619", "vulnerable"),   # EOL branch
        ("5.6.40", "CVE-2026-109618", "vulnerable"),   # EOL branch
        (None,     "CVE-2026-109618", "unknown"),
    ]
    ok = True
    for ver, cve, expected in cases:
        got = evaluate(ver)[cve]["status"]
        flag = "ok" if got == expected else "FAIL"
        if got != expected:
            ok = False
        print(f"[{flag}] php={ver!s:>8}  {cve} -> {got} (expected {expected})")
    print("\nAll signature checks passed." if ok else "\nSOME CHECKS FAILED.")
