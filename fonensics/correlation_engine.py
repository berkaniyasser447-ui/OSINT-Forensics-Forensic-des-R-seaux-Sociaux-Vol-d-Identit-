"""
correlation_engine.py
Correlates real OSINT evidence:
  - Wayback Machine account creation dates
  - EXIF GPS coordinates + capture timestamps
  - Profile image hash matching (same photo = same person)
  - Language consistency across profiles
  - Account activity timeline overlap
"""

from collections import Counter
from datetime import datetime
import re

WEIGHTS = {
    "account_count":        5,   # per account beyond 1, max 20
    "same_image_hash":     35,   # same profile picture = very strong signal
    "exif_gps":            25,   # GPS in uploaded image
    "exif_timestamp":      10,   # capture time in uploaded image
    "wayback_exists":       5,   # per account with wayback history, max 15
    "same_creation_year":  15,   # accounts created same year
    "same_language":       10,   # same HTML language across profiles
    "activity_overlap":    15,   # active in same years across platforms
}


def correlate(sherlock_result: dict, profile_analyses: list, wayback_timelines: list,
              exif_data: dict = None) -> dict:
    """
    Args:
        sherlock_result    : from sherlock_module.run_sherlock()
        profile_analyses   : list of dicts from metadata_module.analyze_profile_page()
        wayback_timelines  : list of dicts from metadata_module.get_wayback_timeline()
        exif_data          : optional dict from metadata_module.extract_exif()
    """
    signals = []
    evidence = []
    score   = 0

    accounts      = sherlock_result.get("accounts", {})
    account_count = len(accounts)

    # ── Account count ─────────────────────────────────────────────────────────
    if account_count > 1:
        pts = min((account_count - 1) * WEIGHTS["account_count"], 20)
        score += pts
        signals.append(f"{account_count} accounts found across platforms (+{pts}pts)")

    # ── Same profile image hash ────────────────────────────────────────────────
    hashes = [p.get("profile_image_hash") for p in profile_analyses if p.get("profile_image_hash")]
    if len(hashes) >= 2:
        hash_counts = Counter(hashes)
        top_hash, freq = hash_counts.most_common(1)[0]
        if freq >= 2:
            score += WEIGHTS["same_image_hash"]
            signals.append(f"Identical profile picture detected on {freq} accounts (+{WEIGHTS['same_image_hash']}pts)")
            evidence.append({
                "type": "SAME_PROFILE_IMAGE",
                "detail": f"MD5 {top_hash[:12]}... matched on {freq} profiles",
                "severity": "HIGH"
            })

    # ── EXIF GPS ───────────────────────────────────────────────────────────────
    if exif_data and exif_data.get("gps"):
        score += WEIGHTS["exif_gps"]
        gps = exif_data["gps"]
        maps_url = exif_data.get("gps_maps_url", "")
        signals.append(f"EXIF GPS found in uploaded image: {gps['lat']}, {gps['lon']} (+{WEIGHTS['exif_gps']}pts)")
        evidence.append({
            "type": "EXIF_GPS",
            "detail": f"Lat: {gps['lat']}, Lon: {gps['lon']}",
            "maps_url": maps_url,
            "severity": "HIGH"
        })

    # ── EXIF capture timestamp ─────────────────────────────────────────────────
    if exif_data and exif_data.get("capture_time"):
        score += WEIGHTS["exif_timestamp"]
        signals.append(f"EXIF capture time: {exif_data['capture_time']} (+{WEIGHTS['exif_timestamp']}pts)")
        evidence.append({
            "type": "EXIF_TIMESTAMP",
            "detail": exif_data["capture_time"],
            "severity": "MEDIUM"
        })

    # ── Wayback Machine history ────────────────────────────────────────────────
    wb_with_history = [w for w in wayback_timelines if w.get("total_snaps", 0) > 0]
    if wb_with_history:
        pts = min(len(wb_with_history) * WEIGHTS["wayback_exists"], 15)
        score += pts
        signals.append(f"Wayback Machine history found for {len(wb_with_history)} account(s) (+{pts}pts)")

    # ── Same account creation year ─────────────────────────────────────────────
    creation_years = []
    for w in wb_with_history:
        if w.get("first_seen"):
            try:
                yr = int(w["first_seen"][:4])
                creation_years.append(yr)
            except Exception:
                pass

    if len(creation_years) >= 2:
        yr_counts = Counter(creation_years)
        top_yr, yr_freq = yr_counts.most_common(1)[0]
        if yr_freq >= 2:
            score += WEIGHTS["same_creation_year"]
            signals.append(f"Accounts first archived in same year ({top_yr}) on {yr_freq} platforms (+{WEIGHTS['same_creation_year']}pts)")
            evidence.append({
                "type": "SAME_CREATION_YEAR",
                "detail": f"Year {top_yr} — {yr_freq} accounts",
                "severity": "MEDIUM"
            })

    # ── Activity timeline overlap ──────────────────────────────────────────────
    all_year_sets = [set(w.get("years_active", [])) for w in wb_with_history if w.get("years_active")]
    if len(all_year_sets) >= 2:
        common_years = set.intersection(*all_year_sets)
        if common_years:
            score += WEIGHTS["activity_overlap"]
            yrs = ", ".join(str(y) for y in sorted(common_years))
            signals.append(f"Active on multiple platforms in same years: {yrs} (+{WEIGHTS['activity_overlap']}pts)")
            evidence.append({
                "type": "ACTIVITY_OVERLAP",
                "detail": f"Overlapping years: {yrs}",
                "severity": "MEDIUM"
            })

    # ── Language consistency ───────────────────────────────────────────────────
    languages = [p.get("language") for p in profile_analyses if p.get("language")]
    if len(languages) >= 2:
        lang_counts = Counter(languages)
        top_lang, lang_freq = lang_counts.most_common(1)[0]
        if lang_freq >= 2:
            score += WEIGHTS["same_language"]
            signals.append(f"Same profile language '{top_lang}' on {lang_freq} accounts (+{WEIGHTS['same_language']}pts)")
            evidence.append({
                "type": "SAME_LANGUAGE",
                "detail": f"Language: {top_lang} on {lang_freq} profiles",
                "severity": "LOW"
            })

    score = min(score, 100)

    # ── Build Wayback timeline summary ────────────────────────────────────────
    timeline = []
    for w in sorted(wb_with_history, key=lambda x: x.get("first_seen") or ""):
        timeline.append({
            "site": w.get("url", "").split("/")[2] if w.get("url") else "unknown",
            "url": w.get("url"),
            "first_seen": w.get("first_seen"),
            "last_seen": w.get("last_seen"),
            "total_snaps": w.get("total_snaps"),
            "years_active": w.get("years_active"),
            "snapshots": w.get("snapshots", [])[:5],
        })

    return {
        "username":         sherlock_result.get("username"),
        "accounts_found":   accounts,
        "variations_searched": sherlock_result.get("variations_searched", []),
        "signals":          signals,
        "evidence":         evidence,
        "confidence_score": score,
        "risk_level":       _risk_level(score),
        "timeline":         timeline,
        "exif":             exif_data or {},
        "profile_images":   [
            {"url": p.get("url"), "image": p.get("profile_image_url"), "hash": p.get("profile_image_hash")}
            for p in profile_analyses if p.get("profile_image_url")
        ],
    }


def _risk_level(score: int) -> str:
    if score >= 75: return "HIGH"
    if score >= 45: return "MEDIUM"
    if score >= 20: return "LOW"
    return "MINIMAL"
