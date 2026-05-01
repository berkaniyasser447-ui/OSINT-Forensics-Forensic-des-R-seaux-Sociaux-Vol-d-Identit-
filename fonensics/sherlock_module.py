"""
sherlock_module.py
Checks each site individually so results stream live to the browser.
"""

import sys
import re
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

_SITE_PKGS = r"C:\Users\mirou\AppData\Local\Programs\Python\Python313\Lib\site-packages"
if _SITE_PKGS not in sys.path:
    sys.path.insert(0, _SITE_PKGS)

_SITE_DATA = None


def get_all_sites() -> list:
    """Returns sorted list of all site names sherlock knows about."""
    return sorted(_load_site_data().keys())


def _load_site_data() -> dict:
    global _SITE_DATA
    if _SITE_DATA is None:
        from sherlock_project.sites import SitesInformation
        _SITE_DATA = {site.name: site.information for site in SitesInformation()}
    return _SITE_DATA


def generate_variations(full_name: str) -> list:
    parts = full_name.lower().strip().split()
    if len(parts) == 1:
        return [parts[0]]
    first, last = parts[0], parts[-1]
    middle = parts[1:-1]
    variations = [
        full_name.lower().replace(" ", ""),
        f"{first}_{last}",
        f"{first}.{last}",
        f"{first[0]}{last}",
        f"{first}{last[0]}",
        f"{last}{first}",
        f"{last}_{first}",
        f"{first}{last[:3]}",
        f"{last}{first[:3]}",
    ]
    for m in middle:
        variations.append(f"{first}{m[0]}{last}")
    seen, unique = set(), []
    for v in variations:
        if v not in seen:
            seen.add(v)
            unique.append(v)
    return unique


def run_sherlock(full_name: str, log_fn=None, stop_flag=None, site_filter: list = None) -> dict:
    """
    Checks each site in parallel (10 workers) so results stream live.
    stop_flag: list used as mutable bool — set stop_flag[0]=True to abort.
    site_filter: list of site names to check; None = all sites.
    """
    variations   = generate_variations(full_name)
    site_data    = _load_site_data()
    sites_to_check = {k: v for k, v in site_data.items()
                      if site_filter is None or k in site_filter}

    result = {"username": full_name, "variations_searched": variations, "accounts": {}}
    _log(log_fn, f"Searching {len(variations)} variation(s) across {len(sites_to_check)} site(s)...")

    session = requests.Session()
    session.headers.update({
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/120.0.0.0 Safari/537.36"
        )
    })

    for variant in variations:
        if stop_flag and stop_flag[0]:
            _log(log_fn, "[STOPPED] Search stopped by user.")
            break

        _log(log_fn, f"[VAR] Checking variant: {variant}")

        # Build task list — skip sites where username fails regex or already found
        tasks = []
        for site_name, info in sites_to_check.items():
            if site_name in result["accounts"]:
                continue
            regex = info.get("regexCheck")
            if regex and not re.fullmatch(regex, variant):
                continue  # username format invalid for this site
            url = info.get("url", "").replace("{}", variant)
            if url:
                tasks.append((site_name, info, variant, url))

        # Check sites in parallel
        with ThreadPoolExecutor(max_workers=15) as pool:
            futures = {
                pool.submit(_check_site, session, sn, info, var, url): (sn, url)
                for sn, info, var, url in tasks
            }
            for future in as_completed(futures):
                if stop_flag and stop_flag[0]:
                    break
                site_name, url = futures[future]
                try:
                    if future.result() and site_name not in result["accounts"]:
                        result["accounts"][site_name] = url
                        _log(log_fn, f"[FOUND] {site_name}: {url}")
                except Exception:
                    pass

    _log(log_fn, f"[DONE] {len(result['accounts'])} account(s) found.")
    return result


def _check_site(session, site_name: str, info: dict, username: str, url: str) -> bool:
    """Returns True only if the username genuinely exists on this site."""
    error_type = info.get("errorType", "")
    # First verify the claimed username works (sanity check the site is reachable)
    claimed    = info.get("username_claimed", "")
    timeout    = 10

    try:
        r = session.get(url, timeout=timeout, allow_redirects=True)

        if r.status_code == 404:
            return False

        # Many sites return 200 for everything — verify with a known-bad username
        bad_url = info.get("url", "").replace("{}", "thisisaveryrandomuserthatdoesnotexist99999")
        r_bad   = session.get(bad_url, timeout=timeout, allow_redirects=True)

        if error_type == "status_code":
            # Account exists if our URL returns 200 but bad URL does not
            return r.status_code == 200 and r_bad.status_code != 200

        elif error_type == "message":
            error_msgs = info.get("errorMsg", [])
            if isinstance(error_msgs, str):
                error_msgs = [error_msgs]
            # Page must not contain error messages
            if any(e in r.text for e in error_msgs):
                return False
            # Bad username page must contain at least one error message
            bad_has_error = any(e in r_bad.text for e in error_msgs)
            return r.status_code == 200 and bad_has_error

        elif error_type == "response_url":
            error_url = info.get("errorUrl", "")
            # Our URL must not redirect to the error URL
            return r.status_code == 200 and error_url not in r.url

    except Exception:
        pass

    return False


def _log(log_fn, msg: str):
    if log_fn:
        log_fn(msg)
    else:
        print(msg)
