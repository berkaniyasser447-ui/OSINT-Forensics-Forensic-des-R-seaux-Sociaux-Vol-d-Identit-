"""
app.py - OSINT Forensics Web App
Run: py app.py  -> http://localhost:5000
"""

import sys
_SITE_PKGS = r"C:\Users\mirou\AppData\Local\Programs\Python\Python313\Lib\site-packages"
if _SITE_PKGS not in sys.path:
    sys.path.insert(0, _SITE_PKGS)

import json
import queue
import threading
from datetime import datetime
from pathlib import Path

from flask import Flask, Response, render_template, request, stream_with_context

from sherlock_module import run_sherlock, get_all_sites
from metadata_module import analyze_profile_page, get_wayback_timeline, extract_exif
from correlation_engine import correlate
from report_generator import generate_report

app = Flask(__name__)
UPLOAD_DIR = Path("results/uploads")
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

_queues:    dict[str, queue.Queue] = {}
_stopflags: dict[str, list]        = {}


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/sites")
def sites():
    return {"sites": get_all_sites()}


# ── Phase 1: Username search ───────────────────────────────────────────────────

@app.route("/search", methods=["POST"])
def search():
    full_name   = request.form.get("full_name", "").strip()
    site_filter = request.form.getlist("sites")
    if not full_name:
        return {"error": "Name is required"}, 400

    search_id             = datetime.utcnow().strftime("%Y%m%d%H%M%S%f")
    q                     = queue.Queue()
    stop_flag             = [False]
    _queues[search_id]    = q
    _stopflags[search_id] = stop_flag

    threading.Thread(
        target=_run_sherlock_phase,
        args=(search_id, full_name, q, stop_flag, site_filter or None),
        daemon=True
    ).start()
    return {"search_id": search_id}


@app.route("/stop/<search_id>", methods=["POST"])
def stop(search_id):
    flag = _stopflags.get(search_id)
    if flag:
        flag[0] = True
    return {"ok": True}


@app.route("/stream/<search_id>")
def stream(search_id):
    def event_stream():
        q = _queues.get(search_id)
        if not q:
            yield _sse({"type": "error", "msg": "Invalid search ID"})
            return
        while True:
            try:
                msg = q.get(timeout=180)
                yield _sse(msg)
                if msg.get("type") in ("done", "error"):
                    break
            except queue.Empty:
                yield _sse({"type": "error", "msg": "Timed out"})
                break

    return Response(
        stream_with_context(event_stream()),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


# ── Phase 2: Deep analysis ─────────────────────────────────────────────────────

@app.route("/analyze", methods=["POST"])
def analyze():
    """
    Accepts:
      - selected_accounts: JSON string of {site: url} chosen by user
      - username: the original search name
      - image: optional uploaded image file
    Runs: Wayback timelines + profile analysis + EXIF + correlation
    """
    username  = request.form.get("username", "unknown")
    accounts_json = request.form.get("selected_accounts", "{}")
    accounts  = json.loads(accounts_json)

    # Save uploaded image if provided
    exif_data = {}
    img_file  = request.files.get("image")
    if img_file and img_file.filename:
        img_path = UPLOAD_DIR / img_file.filename
        img_file.save(str(img_path))
        exif_data = extract_exif(str(img_path))

    analyze_id            = datetime.utcnow().strftime("%Y%m%d%H%M%S%f")
    q                     = queue.Queue()
    _queues[analyze_id]   = q

    threading.Thread(
        target=_run_analysis_phase,
        args=(analyze_id, username, accounts, exif_data, q),
        daemon=True
    ).start()
    return {"analyze_id": analyze_id}


def _run_sherlock_phase(search_id, full_name, q, stop_flag, site_filter):
    def log(msg):
        q.put({"type": "log", "msg": msg})
    try:
        result = run_sherlock(full_name, log_fn=log, stop_flag=stop_flag, site_filter=site_filter)
        q.put({"type": "done", "accounts": result["accounts"],
               "variations": result.get("variations_searched", []),
               "username": full_name})
    except Exception as e:
        q.put({"type": "error", "msg": str(e)})


def _run_analysis_phase(analyze_id, username, accounts, exif_data, q):
    def log(msg):
        q.put({"type": "log", "msg": msg})

    try:
        profile_analyses  = []
        wayback_timelines = []

        for site, url in accounts.items():
            log(f"[WAYBACK] Querying archive history: {site}")
            wb = get_wayback_timeline(url)
            wb["site"] = site
            wayback_timelines.append(wb)
            snaps = wb.get("total_snaps", 0)
            if snaps:
                log(f"[WAYBACK] {site}: {snaps} snapshots, first seen {wb.get('first_seen', '?')}")
            else:
                log(f"[WAYBACK] {site}: no archive history found")

            log(f"[PROFILE] Analyzing profile page: {site}")
            profile = analyze_profile_page(url)
            profile["site"] = site
            profile_analyses.append(profile)
            if profile.get("profile_image_hash"):
                log(f"[PROFILE] {site}: profile image hash {profile['profile_image_hash'][:12]}...")
            if profile.get("language"):
                log(f"[PROFILE] {site}: language = {profile['language']}")

        if exif_data.get("gps"):
            log(f"[EXIF] GPS found: {exif_data['gps']['lat']}, {exif_data['gps']['lon']}")
        if exif_data.get("capture_time"):
            log(f"[EXIF] Capture time: {exif_data['capture_time']}")
        if exif_data.get("camera_model"):
            log(f"[EXIF] Camera: {exif_data.get('camera_make','')} {exif_data['camera_model']}")

        log("[CORRELATE] Running correlation engine...")
        sherlock_stub = {"username": username, "accounts": accounts, "variations_searched": []}
        result = correlate(sherlock_stub, profile_analyses, wayback_timelines, exif_data)

        Path("results/reports").mkdir(parents=True, exist_ok=True)
        generate_report(result, output_dir="results/reports")
        log(f"[DONE] Confidence score: {result['confidence_score']}/100 — {result['risk_level']}")

        q.put({"type": "done", "result": result})

    except Exception as e:
        q.put({"type": "error", "msg": str(e)})


def _sse(data: dict) -> str:
    return f"data: {json.dumps(data)}\n\n"


if __name__ == "__main__":
    Path("results/reports").mkdir(parents=True, exist_ok=True)
    app.run(debug=False, threaded=True, port=5000)
