# OSINT Forensics — Forensic des Réseaux Sociaux & Vol d'Identité

## Objective

Link anonymous or unknown social media accounts to real identities using OSINT techniques:
- Username enumeration across 444+ platforms (Sherlock)
- Metadata extraction from images (EXIF — GPS, timestamps, camera)
- Historical account analysis via Wayback Machine
- Cross-platform correlation to build an identity confidence score

---

## Project Structure

```
/fonensics
│
├── app.py                  # Flask web server — entry point
├── sherlock_module.py      # Phase 1 — username search across platforms
├── metadata_module.py      # Phase 2 — Wayback Machine + EXIF + profile analysis
├── correlation_engine.py   # Phase 2 — evidence correlation + confidence score
├── report_generator.py     # Saves .txt and .json reports to disk
├── requirements.txt        # Python dependencies
│
├── templates/
│   └── index.html          # Single-page web UI (two-phase interface)
│
└── results/
    ├── reports/            # Generated .txt and .json reports per search
    └── uploads/            # Uploaded images for EXIF analysis
```

---

## How to Run

```bash
# Install dependencies
pip install -r requirements.txt

# Start the web app
py app.py

# Open in browser
http://localhost:5000
```

---

## Pipeline — How It Works

The system works in two phases. The user drives both phases from the web interface.

```
INPUT: Full name (e.g. "John Doe")
         │
         ▼
┌─────────────────────────────────────────────┐
│  PHASE 1 — Account Discovery (Sherlock)     │
│                                             │
│  Generate username variations:              │
│    johndoe, john_doe, john.doe,             │
│    jdoe, johnd, doejohn, doe_john ...       │
│                                             │
│  For each variation:                        │
│    Check 444 sites in parallel              │
│    Validate with error message / 404 check  │
│    Stream [FOUND] results live to browser   │
└─────────────────────────────────────────────┘
         │
         ▼
  User selects which accounts to analyze
  User optionally uploads a profile image
         │
         ▼
┌─────────────────────────────────────────────┐
│  PHASE 2 — Deep Analysis                    │
│                                             │
│  For each selected account:                 │
│    [Wayback] Query CDX API                  │
│      → first seen date                      │
│      → last seen date                       │
│      → total snapshots                      │
│      → years of activity                    │
│                                             │
│    [Profile] Fetch profile page             │
│      → HTML language attribute              │
│      → og:image URL + MD5 hash              │
│      → page title                           │
│                                             │
│  If image uploaded:                         │
│    [EXIF] Extract metadata                  │
│      → GPS coordinates (lat/lon)            │
│      → Capture timestamp                    │
│      → Camera make/model                    │
│      → Software used                        │
└─────────────────────────────────────────────┘
         │
         ▼
┌─────────────────────────────────────────────┐
│  CORRELATION ENGINE                         │
│                                             │
│  Score each signal:                         │
│    Same profile image hash    → +35 pts     │
│    EXIF GPS found             → +25 pts     │
│    Same account creation year → +15 pts     │
│    Activity timeline overlap  → +15 pts     │
│    Same language across sites → +10 pts     │
│    EXIF capture timestamp     → +10 pts     │
│    Wayback history exists     → +5 pts each │
│    Account count bonus        → +5 pts each │
│                                             │
│  Final score: 0–100                         │
│  Risk level: MINIMAL / LOW / MEDIUM / HIGH  │
└─────────────────────────────────────────────┘
         │
         ▼
OUTPUT:
  - Confidence score (0–100)
  - Risk level
  - Evidence cards (GPS map link, image hashes, dates)
  - Wayback timeline table with snapshot links
  - EXIF data panel
  - Saved .txt + .json report in results/reports/
```

---

## File-by-File Explanation

### `app.py`
The Flask web server. Handles all HTTP routes:

| Route | Method | Purpose |
|---|---|---|
| `/` | GET | Serves the web UI |
| `/sites` | GET | Returns list of all 444 Sherlock sites for the filter UI |
| `/search` | POST | Starts Phase 1 — launches Sherlock in a background thread |
| `/stop/<id>` | POST | Sets a stop flag to abort an ongoing search |
| `/stream/<id>` | GET | SSE endpoint — streams log lines and results live to the browser |
| `/analyze` | POST | Starts Phase 2 — accepts selected accounts + optional image upload |

Each search runs in its own thread. Results are pushed to a `queue.Queue` and streamed to the browser via Server-Sent Events (SSE) so the user sees accounts appear in real time.

---

### `sherlock_module.py`
Handles Phase 1 — username discovery.

**`generate_variations(full_name)`**
Takes a full name like `"John Doe"` and generates username patterns:
```
johndoe, john_doe, john.doe, jdoe, johnd, doejohn, doe_john, johndoe, doejoh
```

**`run_sherlock(full_name, log_fn, stop_flag, site_filter)`**
- Loads 444 site definitions from `sherlock_project`
- For each username variation, checks all sites in parallel (15 threads)
- Before checking a site, validates the username against the site's `regexCheck` pattern to skip invalid formats
- Calls `_check_site()` for each site
- Emits `[FOUND] SiteName: URL` immediately when a match is found (live streaming)
- Respects `stop_flag` to abort mid-search

**`_check_site(session, site_name, info, username, url)`**
The core validation logic. Uses three strategies depending on the site's `errorType`:
- `status_code` — account exists if URL returns 200 but a known-bad URL does not
- `message` — account exists if the page does NOT contain the site's error message string
- `response_url` — account exists if the final URL after redirects does not match the error URL

This double-check (real URL vs bad URL) eliminates false positives from sites that return 200 for everything.

---

### `metadata_module.py`
Handles Phase 2 data collection. Three independent functions:

**`get_wayback_timeline(url)`**
Queries the Wayback Machine CDX API:
```
http://web.archive.org/cdx/search/cdx?url=<url>&output=json&fl=timestamp,statuscode&filter=statuscode:200
```
Returns:
- `first_seen` — earliest archive date (when the account was first captured)
- `last_seen` — most recent archive date
- `total_snaps` — how many times it was archived
- `years_active` — list of years with activity
- `snapshots` — first 10 snapshot links (clickable in the UI)

**`extract_exif(image_path)`**
Uses Pillow to read raw EXIF tags from a JPEG/PNG:
- `GPSInfo` → converts DMS fractions to decimal lat/lon → builds Google Maps URL
- `DateTimeOriginal` → exact capture timestamp
- `Make` / `Model` → camera hardware
- `Software` → editing software (reveals if image was processed)

**`analyze_profile_page(url)`**
Fetches the profile page HTML and extracts:
- `lang=` attribute from `<html>` tag → profile language
- `og:image` meta tag → profile picture URL → downloads it and computes MD5 hash
- `og:description` → tries to extract location text
- `<title>` → page title

The MD5 hash of the profile image is the key signal — if two accounts on different platforms have the same hash, it is the same person.

---

### `correlation_engine.py`
Takes all collected evidence and computes a confidence score.

**Signals and weights:**

| Signal | Points | How detected |
|---|---|---|
| Same profile image hash | +35 | MD5 of og:image matches across 2+ accounts |
| EXIF GPS coordinates | +25 | GPS found in uploaded image |
| Same account creation year | +15 | Wayback first_seen year matches across accounts |
| Activity timeline overlap | +15 | Same years active on multiple platforms |
| Same HTML language | +10 | lang= attribute matches across profiles |
| EXIF capture timestamp | +10 | DateTime found in uploaded image |
| Wayback history per account | +5 each (max 15) | Account has archive snapshots |
| Account count bonus | +5 each (max 20) | Multiple accounts found |

Each signal also produces an `evidence` card with severity (HIGH / MEDIUM / LOW) shown in the UI.

---

### `report_generator.py`
Saves two files per analysis to `results/reports/`:
- `<name>_<timestamp>.txt` — human-readable report with all sections
- `<name>_<timestamp>.json` — full machine-readable data for further processing

---

### `templates/index.html`
Single-page app with two phases:

**Phase 1 tab — Search Accounts**
- Input field for full name or username
- Site filter panel — 444 checkboxes, searchable, select all/clear
- Stop button — aborts search mid-way
- Live account list — each found account appears instantly as a clickable row with a checkbox
- Image upload area — drag or click to upload a profile image for EXIF analysis

**Phase 2 tab — Deep Analysis**
- Automatically switches when user clicks "Analyze Selected Accounts"
- Live log terminal showing Wayback queries, profile fetches, EXIF extraction
- Results rendered in sections:
  - Confidence score circle (color-coded by risk)
  - Evidence cards
  - Correlation signals
  - Wayback timeline table with clickable snapshot links
  - EXIF panel with GPS map link
  - Profile image comparison grid

Communication between browser and server uses **Server-Sent Events (SSE)** — the server pushes data line by line as it's produced, so the UI updates in real time without polling.

---

## Real Scenario Example

**Target:** You have a username `shadow_x` posting suspicious content. You want to know who this person is.

**Step 1 — Search**
Enter `shadow x` in the search box. The system generates:
`shadowx, shadow_x, shadow.x, sx, shadowx, xshadow, x_shadow ...`

Sherlock finds:
- `GitHub: https://github.com/shadow_x`
- `Reddit: https://reddit.com/user/shadow_x`
- `DeviantArt: https://deviantart.com/shadow_x`

**Step 2 — Select & Analyze**
Check all three accounts. Optionally upload a profile picture you found on one of them.

**Step 3 — Evidence collected**
- Wayback shows GitHub account first archived in 2019, Reddit in 2019 → same creation year → +15pts
- Both accounts active in 2019, 2020, 2021 → activity overlap → +15pts
- og:image hash on GitHub and Reddit match → same profile photo → +35pts
- Uploaded image EXIF contains GPS: 48.8566, 2.3522 (Paris, France) → +25pts
- Both profiles have `lang="fr"` → +10pts

**Result:** Confidence score 85/100 — HIGH risk. Evidence points to a French-speaking person in Paris who created accounts on multiple platforms in 2019 using the same profile photo.

---

## Limitations

- **Truly random usernames** — if the anonymous account has no connection to a real name (e.g. `xk7r29z`), Sherlock won't find it. You need a starting point.
- **Modern social media scraping** — Twitter/Instagram/TikTok block scrapers, so og:image and language extraction may fail on those. Wayback Machine still works.
- **EXIF stripping** — most platforms (Facebook, Twitter) strip EXIF before storing images. EXIF analysis works best on images downloaded directly from less-processed sources (GitHub, personal sites, forums).
