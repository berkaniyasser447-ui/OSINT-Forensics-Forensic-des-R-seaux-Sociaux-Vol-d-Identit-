"""
report_generator.py
Generates a structured evidence report from correlation results.
Outputs both a human-readable .txt and a machine-readable .json file.
"""

import json
from datetime import datetime
from pathlib import Path


RISK_COLORS = {
    "HIGH":    "\033[91m",   # red
    "MEDIUM":  "\033[93m",   # yellow
    "LOW":     "\033[94m",   # blue
    "MINIMAL": "\033[92m",   # green
}
RESET = "\033[0m"


def generate_report(correlation: dict, output_dir: str = "results/reports") -> str:
    """
    Writes .txt and .json reports. Returns the path to the .txt report.
    """
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    username = correlation.get("username", "unknown")
    base = Path(output_dir) / f"{username}_{ts}"

    txt_path = str(base) + ".txt"
    json_path = str(base) + ".json"

    # --- JSON report ---
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(correlation, f, indent=2, default=str)

    # --- Text report ---
    lines = _build_text_report(correlation)
    with open(txt_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    return txt_path


def print_report(correlation: dict):
    """Prints a colored summary to stdout."""
    lines = _build_text_report(correlation)
    risk = correlation.get("risk_level", "MINIMAL")
    color = RISK_COLORS.get(risk, "")

    for line in lines:
        if "CONFIDENCE" in line or "RISK" in line:
            print(f"{color}{line}{RESET}")
        else:
            print(line)


def _build_text_report(c: dict) -> list:
    sep = "=" * 60
    lines = [
        sep,
        "  OSINT FORENSICS - IDENTITY CORRELATION REPORT",
        sep,
        f"  Target          : {c.get('username')}",
        f"  Generated       : {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC",
        f"  Confidence      : {c.get('confidence_score', 0)}/100",
        f"  Risk Level      : {c.get('risk_level', 'MINIMAL')}",
        sep, "",
        "[ ACCOUNTS FOUND ]",
    ]
    for site, url in c.get("accounts_found", {}).items():
        lines.append(f"  [*] {site:<22} {url}")

    lines += ["", "[ EVIDENCE ]",]
    for ev in c.get("evidence", []):
        lines.append(f"  [{ev.get('severity','?')}] {ev.get('type')}: {ev.get('detail')}")
        if ev.get("maps_url"):
            lines.append(f"        Maps: {ev['maps_url']}")

    lines += ["", "[ SIGNALS ]",]
    for sig in c.get("signals", []):
        lines.append(f"  [+] {sig}")
    if not c.get("signals"):
        lines.append("  No strong signals detected.")

    lines += ["", "[ WAYBACK TIMELINE ]",]
    for t in c.get("timeline", []):
        lines.append(f"  {t.get('site','?'):<20} first={t.get('first_seen','?')}  last={t.get('last_seen','?')}  snaps={t.get('total_snaps',0)}")
    if not c.get("timeline"):
        lines.append("  No archive history found.")

    exif = c.get("exif", {})
    if exif and exif.get("gps"):
        lines += ["", "[ EXIF ]",
            f"  GPS       : {exif['gps']['lat']}, {exif['gps']['lon']}",
            f"  Maps      : {exif.get('gps_maps_url', '')}",
        ]
        if exif.get("capture_time"):
            lines.append(f"  Captured  : {exif['capture_time']}")
        if exif.get("camera_model"):
            lines.append(f"  Camera    : {exif.get('camera_make','')} {exif['camera_model']}")

    lines += ["", sep]
    return lines
