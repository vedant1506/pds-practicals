"""Shared SQL-Injection payload-variant taxonomy for PDS Practicals.

Sub-classifies the `sqli` label into the actual payload family
(UNION-based, tautology, RCE/passthru, RFI, scanner probe, ...).

Same architecture as `bot_taxonomy.py`: ordered signatures, first match wins.
Only applied to rows already labeled `sqli` — everything else gets "-".

Used by: backend/app.py (upload pipeline), scripts/practical_4.py.
"""

import re

# (variant_id, human_label, regex, severity_emoji)
# Order matters: specific/dangerous families first, generic probes last.
SQLI_SIGNATURES = [
    ("rce_exec", "RCE / Command Exec", r"passthru|shell_exec|eval\s*\(|base64_decode|system\s*\(|popen|proc_open|xp_cmdshell", "🔴"),
    ("rfi_lfi", "RFI / File Include", r"rfiinc|https?://[^\s'\"]+\?|/etc/passwd|boot\.ini", "🔴"),
    ("union_based", "UNION-based", r"union(\s|\+|%20)+.*select|select.*from", "🔴"),
    ("stacked", "Stacked / Destructive", r";\s*(drop|delete|insert|update|shutdown)\b|drop\s+table|xp_", "🔴"),
    ("tautology", "Tautology (OR 1=1)", r"or\s+1\s*=\s*1|'='|\"\s*=\s*\"|\bor\b.{0,10}=\s*", "🟠"),
    ("comment_evasion", "Comment Evasion", r"--(\s|$)|/\*|\%23|%60", "🟡"),
    ("scanner_probe", "Scanner Probe", r"\.nasl\b|acunetix|netsparker|md5|hellothinkphp|nvdxgzs", "🟡"),
    ("quote_probe", "Quote Probe", r"'|%27|%22", "🟢"),
]

_COMPILED = [(vid, label, re.compile(pat, re.IGNORECASE), sev) for vid, label, pat, sev in SQLI_SIGNATURES]

#: variant_id -> (human_label, severity_emoji)
SQLI_VARIANT_INFO = {vid: (label, sev) for vid, label, _, sev in SQLI_SIGNATURES}

#: Bar-chart colors per variant for the dashboard.
SQLI_VARIANT_COLORS = {
    "rce_exec": "#dc2626",
    "rfi_lfi": "#ef4444",
    "union_based": "#f97316",
    "stacked": "#b91c1c",
    "tautology": "#eab308",
    "comment_evasion": "#84cc16",
    "scanner_probe": "#38bdf8",
    "quote_probe": "#64748b",
}


def classify_sqli(url) -> str:
    """Return the SQLi payload-variant id for a request URL/path.

    Returns "-" for non-SQLi input (caller should only pass sqli rows,
    but the function is safe either way).
    """
    text = str(url or "")
    if not text or text.strip() in ("", "/", "nan", "None"):
        return "-"
    for vid, _label, pattern, _sev in _COMPILED:
        if pattern.search(text):
            return vid
    return "other_sqli"


SQLI_VARIANT_INFO["other_sqli"] = ("Other SQLi", "⚪")
SQLI_VARIANT_COLORS["other_sqli"] = "#475569"
SQLI_VARIANT_INFO["-"] = ("N/A", "⚪")


def variant_label(variant_id: str) -> str:
    """Human-readable label for a variant id."""
    return SQLI_VARIANT_INFO.get(variant_id, ("Unknown", "⚪"))[0]
