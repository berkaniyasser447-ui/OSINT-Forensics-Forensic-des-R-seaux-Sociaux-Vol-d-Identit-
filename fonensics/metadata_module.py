"""
metadata_module.py
Real evidence collection:
  - Wayback Machine CDX API  -> account creation date + activity timeline
  - EXIF extraction           -> GPS coordinates + camera timestamps
  - HTML language detection   -> profile language
"""

import re
import hashlib
import requests
from datetime import datetime
from pathlib import Path
from bs4 import BeautifulSoup

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    )
}

LANGUAGE_PATTERN = re.compile(r'<html[^>]+lang=["\']([a-zA-Z-]{2,5})["\']', re.I)


# ── Wayback Machine ────────────────────────────────────────────────────────────

def get_wayback_timeline(url: str) -> dict:
    """
    Queries Wayback CDX API for full snapshot history of a URL.
    Returns:
      first_seen   : earliest snapshot datetime
      last_seen    : most recent snapshot datetime
      total_snaps  : total number of snapshots
      snapshots    : list of {timestamp, url, status}
      years_active : list of years with activity
    """
    result = {
        "url": url,
        "first_seen": None,
        "last_seen": None,
        "total_snaps": 0,
        "snapshots": [],
        "years_active": [],
    }
    try:
        cdx = (
            f"http://web.archive.org/cdx/search/cdx"
            f"?url={url}&output=json&fl=timestamp,statuscode"
            f"&filter=statuscode:200&collapse=timestamp:6&limit=100"
        )
        resp = requests.get(cdx, timeout=15)
        rows = resp.json()
        if len(rows) <= 1:
            return result

        snaps = []
        for row in rows[1:]:
            ts = row[0]  # e.g. 20190315142301
            try:
                dt = datetime.strptime(ts[:14], "%Y%m%d%H%M%S")
                snaps.append(dt)
            except Exception:
                pass

        if not snaps:
            return result

        snaps.sort()
        result["first_seen"]   = snaps[0].strftime("%Y-%m-%d %H:%M:%S")
        result["last_seen"]    = snaps[-1].strftime("%Y-%m-%d %H:%M:%S")
        result["total_snaps"]  = len(snaps)
        result["years_active"] = sorted(set(d.year for d in snaps))
        result["snapshots"]    = [
            {"timestamp": d.strftime("%Y-%m-%d"), "wayback_url": f"https://web.archive.org/web/{d.strftime('%Y%m%d%H%M%S')}/{url}"}
            for d in snaps[:10]
        ]

    except Exception:
        pass

    return result


# ── EXIF Extraction ────────────────────────────────────────────────────────────

def extract_exif(image_path: str) -> dict:
    """
    Extracts EXIF from a local image file.
    Returns GPS coords, capture datetime, camera make/model.
    """
    result = {}
    try:
        from PIL import Image
        from PIL.ExifTags import TAGS, GPSTAGS

        img = Image.open(image_path)
        raw = img._getexif()
        if not raw:
            return {"note": "No EXIF data found in image."}

        for tag_id, value in raw.items():
            tag = TAGS.get(tag_id, tag_id)
            if tag == "GPSInfo":
                gps = {GPSTAGS.get(k, k): v for k, v in value.items()}
                coords = _parse_gps(gps)
                if coords:
                    result["gps"] = coords
                    result["gps_maps_url"] = (
                        f"https://www.google.com/maps?q={coords['lat']},{coords['lon']}"
                    )
            elif tag in ("DateTime", "DateTimeOriginal"):
                result["capture_time"] = str(value)
            elif tag == "Make":
                result["camera_make"] = str(value)
            elif tag == "Model":
                result["camera_model"] = str(value)
            elif tag == "Software":
                result["software"] = str(value)

    except Exception as e:
        result["exif_error"] = str(e)

    return result


def _parse_gps(gps_data: dict) -> dict:
    def to_decimal(values, ref):
        try:
            d = float(values[0])
            m = float(values[1])
            s = float(values[2])
        except Exception:
            # Handle IFDRational objects
            d = float(values[0].numerator) / float(values[0].denominator)
            m = float(values[1].numerator) / float(values[1].denominator)
            s = float(values[2].numerator) / float(values[2].denominator)
        dec = d + m / 60 + s / 3600
        if ref in ("S", "W"):
            dec = -dec
        return round(dec, 6)

    try:
        lat = to_decimal(gps_data["GPSLatitude"], gps_data["GPSLatitudeRef"])
        lon = to_decimal(gps_data["GPSLongitude"], gps_data["GPSLongitudeRef"])
        return {"lat": lat, "lon": lon}
    except Exception:
        return {}


# ── Profile HTML analysis ──────────────────────────────────────────────────────

def analyze_profile_page(url: str) -> dict:
    """
    Fetches a profile page and extracts:
      - HTML language attribute
      - Profile image URL + hash (for cross-account comparison)
      - Any visible location text
      - Page title
    """
    result = {
        "url": url,
        "language": None,
        "profile_image_url": None,
        "profile_image_hash": None,
        "location_text": None,
        "page_title": None,
    }
    try:
        resp = requests.get(url, headers=HEADERS, timeout=10)
        soup = BeautifulSoup(resp.text, "html.parser")

        # Language
        lang_match = LANGUAGE_PATTERN.search(resp.text)
        if lang_match:
            result["language"] = lang_match.group(1).lower()

        # Page title
        title = soup.find("title")
        if title:
            result["page_title"] = title.get_text().strip()

        # Profile image — look for og:image meta tag (works on most platforms)
        og_img = soup.find("meta", property="og:image")
        if og_img and og_img.get("content"):
            img_url = og_img["content"]
            result["profile_image_url"] = img_url
            result["profile_image_hash"] = _hash_image(img_url)

        # Location — look for og:description or common location patterns
        og_desc = soup.find("meta", property="og:description")
        if og_desc and og_desc.get("content"):
            loc_match = re.search(
                r'\b([A-Z][a-z]+(?:,\s*[A-Z][a-z]+)*)\b', og_desc["content"]
            )
            if loc_match:
                result["location_text"] = loc_match.group(1)

    except Exception as e:
        result["error"] = str(e)

    return result


def _hash_image(img_url: str) -> str:
    """Downloads an image and returns its MD5 hash for cross-account comparison."""
    try:
        r = requests.get(img_url, headers=HEADERS, timeout=8)
        if r.status_code == 200:
            return hashlib.md5(r.content).hexdigest()
    except Exception:
        pass
    return None
