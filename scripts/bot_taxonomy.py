"""Shared bot/tool taxonomy for PDS Practicals.

Single source of truth for sub-classifying the `brute_force` label into
the actual attacking tool (sqlmap, Nikto, Gobuster, ...), plus generic
buckets for ordinary browsers, search crawlers and unknown agents.

Used by: backend/app.py (upload pipeline), scripts/practical_4.py,
scripts/practical_5.py. Keeps viva answers consistent everywhere.
"""

import re

# (family_id, human_label, regex, severity_emoji)
# Order matters: first match wins (specific tools before generic buckets).
# NOTE: scanner UAs often masquerade as browsers ("Mozilla/5.0 zgrab/0.x"),
# so every known scanner must appear BEFORE the browser bucket.
BOT_SIGNATURES = [
    ("sqlmap", "SQLMap", r"sqlmap", "🔴"),
    ("nikto", "Nikto", r"nikto", "🟠"),
    ("gobuster", "Gobuster", r"gobuster", "🟠"),
    ("dirbuster", "DirBuster", r"dirbuster", "🟠"),
    ("hydra", "Hydra", r"hydra", "🟠"),
    ("nmap", "Nmap", r"nmap", "🟠"),
    ("zgrab", "Zgrab", r"zgrab", "🟠"),
    ("masscan", "Masscan", r"masscan", "🟠"),
    ("nessus", "Nessus", r"nessus", "🟠"),
    ("burp", "Burp Suite", r"burp", "🟠"),
    ("acunetix", "Acunetix", r"acunetix", "🔴"),
    ("netsparker", "Netsparker", r"netsparker", "🔴"),
    ("wpscan", "WPScan", r"wpscan|joomscan", "🟠"),
    ("shodan", "Shodan", r"shodan", "🟡"),
    ("censys", "Censys", r"censys", "🟡"),
    ("metasploit", "Metasploit", r"metasploit", "🔴"),
    ("python-urllib", "Python-urllib", r"python-urllib|python/requests|urllib", "🟡"),
    ("curl", "cURL", r"\bcurl\b", "🟡"),
    ("wget", "Wget", r"\bwget\b", "🟡"),
    ("search_crawler", "Search Crawler", r"googlebot|bingbot|slurp|duckduckbot|baiduspider|yandexbot", "🟢"),
    ("browser", "Web Browser", r"mozilla|chrome|safari|firefox|edge|opera|msie|trident", "🟢"),
    ("other_bot", "Other Bot", r"bot|crawler|spider|scraper|wget|masscan|nessus|burp|acunetix|netsparker|wpscan|joomscan|metasploit", "🟡"),
]

_COMPILED = [(fam, label, re.compile(pat, re.IGNORECASE), sev) for fam, label, pat, sev in BOT_SIGNATURES]

#: family_id -> (human_label, severity_emoji)
BOT_FAMILY_INFO = {fam: (label, sev) for fam, label, _, sev in BOT_SIGNATURES}
BOT_FAMILY_INFO["unknown"] = ("Unknown", "⚪")

#: Bar-chart colors per family for the dashboard.
BOT_FAMILY_COLORS = {
    "sqlmap": "#ef4444",
    "nikto": "#f97316",
    "gobuster": "#a855f7",
    "dirbuster": "#8b5cf6",
    "hydra": "#f59e0b",
    "nmap": "#fb7185",
    "zgrab": "#f43f5e",
    "masscan": "#ec4899",
    "nessus": "#d946ef",
    "burp": "#c026d3",
    "acunetix": "#dc2626",
    "netsparker": "#b91c1c",
    "wpscan": "#f97316",
    "shodan": "#eab308",
    "censys": "#a3e635",
    "metasploit": "#ef4444",
    "python-urllib": "#eab308",
    "curl": "#84cc16",
    "wget": "#65a30d",
    "search_crawler": "#10b981",
    "browser": "#3b82f6",
    "other_bot": "#64748b",
    "unknown": "#475569",
}

#: Shared heuristic for the `brute_force` LABEL (Practical 4 rule).
#: Single source of truth — backend upload parser and practical_4.py both use this,
#: so the label and the bot_family attribution can never disagree.
#: Browsers and search crawlers are deliberately EXCLUDED (they stay benign).
BOT_LABEL_PATTERN = (
    r"(?:sqlmap|nikto|gobuster|dirbuster|hydra|nmap|zgrab|masscan|nessus|burp|"
    r"acunetix|netsparker|wpscan|joomscan|shodan|censys|metasploit|"
    r"python-urllib|python/requests|urllib|\bcurl\b|\bwget\b)"
)


def classify_bot(user_agent) -> str:
    """Return the bot family id for a User-Agent string."""
    ua = str(user_agent or "")
    if not ua or ua.strip().lower() in ("unknown", "-", "none"):
        return "unknown"
    for fam, _label, pattern, _sev in _COMPILED:
        if pattern.search(ua):
            return fam
    return "unknown"


def family_label(family_id: str) -> str:
    """Human-readable label for a family id."""
    return BOT_FAMILY_INFO.get(family_id, ("Unknown", "⚪"))[0]
