# [PARAMS]
# target_user;String;*;User to collect from (username or "*" for all users)
# browser_filter;String;*;Browser: "*" for all, "chrome", "edge", "firefox"
# mode;String;history;Mode: "history" for browsing history, "downloads" for download history, "both" for both
# start_date;String;*;Start time: YYYY-MM-DD, YYYY-MM-DD HH:MM:SS, HH:MM, epoch ms, or "*" for no limit
# end_date;String;*;End time: YYYY-MM-DD, YYYY-MM-DD HH:MM:SS, HH:MM, epoch ms, or "*" for no limit
# url_filter;String;*;URL/domain to search for (contains match). "*" for all URLs
# max_results;String;0;Max results to return (0 = unlimited)
# [/PARAMS]

import sqlite3
import shutil
import os
import sys
import glob
import json
import re
from datetime import datetime, timedelta, timezone

CHROME_EPOCH_OFFSET = 11644473600 * 1000000

TRANSITION_TYPES = {
    0: "Link", 1: "Typed", 2: "Bookmark", 3: "Auto Subframe",
    4: "Manual Subframe", 5: "Generated", 6: "Auto Toplevel",
    7: "Form Submit", 8: "Reload", 9: "Keyword", 10: "Keyword Generated"
}

FF_VISIT_TYPES = {
    1: "Link", 2: "Typed", 3: "Bookmark", 4: "Embed",
    5: "Redirect Permanent", 6: "Redirect Temporary",
    7: "Download", 8: "Framed Link", 9: "Reload"
}

DOWNLOAD_STATES = {
    0: "In Progress", 1: "Complete", 2: "Cancelled",
    3: "Interrupted", 4: "Interrupted"
}

DANGER_TYPES = {
    0: "Safe", 1: "Dangerous File", 2: "Dangerous URL",
    3: "Dangerous Content", 4: "Uncommon Content", 5: "Uncommon Content",
    6: "User Validated", 7: "Dangerous Host", 8: "Potentially Unwanted",
    9: "Whitelisted by Policy", 10: "Pending Scan",
    11: "Blocked - Password Protected", 12: "Blocked - Too Large",
    13: "Sensitive Content Warning", 14: "Blocked - Sensitive Content",
    15: "Deep Scanned - Safe", 16: "Deep Scanned - Dangerous",
    17: "Prompt for Scanning", 18: "Account Compromise Risk"
}

BYTES_TO_MB = 1024 * 1024

# Detect endpoint local timezone
try:
    LOCAL_UTC_OFFSET = datetime.now(timezone.utc).astimezone().utcoffset()
    LOCAL_TZ_NAME = datetime.now().astimezone().strftime("%Z")
except Exception:
    LOCAL_UTC_OFFSET = timedelta(hours=2)
    LOCAL_TZ_NAME = "UTC+2"


def _format_utc_offset(offset: timedelta) -> str:
    """Format a timedelta as a UTC offset string like ``3:00:00`` or ``-5:00:00``.

    Python's ``str(timedelta)`` produces ``-1 day, 19:00:00`` for negative
    offsets, which breaks the ``Endpoint TZ`` header regex.  This helper
    always produces the ``<sign><H>:<MM>:<SS>`` form.
    """
    total_seconds = int(offset.total_seconds())
    sign = "-" if total_seconds < 0 else ""
    abs_seconds = abs(total_seconds)
    h, remainder = divmod(abs_seconds, 3600)
    m, s = divmod(remainder, 60)
    return "{}{}:{:02d}:{:02d}".format(sign, h, m, s)


def chrome_time_to_local_str(chrome_time):
    if not chrome_time:
        return ""
    try:
        epoch_us = int(chrome_time) - CHROME_EPOCH_OFFSET
        utc_dt = datetime(1970, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=epoch_us)
        local_dt = utc_dt + LOCAL_UTC_OFFSET
        return local_dt.strftime("%Y-%m-%d %H:%M:%S")
    except (ValueError, OverflowError, OSError):
        return ""


def firefox_time_to_local_str(ff_time):
    if not ff_time:
        return ""
    try:
        utc_dt = datetime(1970, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=int(ff_time))
        local_dt = utc_dt + LOCAL_UTC_OFFSET
        return local_dt.strftime("%Y-%m-%d %H:%M:%S")
    except (ValueError, OverflowError, OSError):
        return ""


def firefox_time_ms_to_local_str(ff_time_ms):
    if not ff_time_ms:
        return ""
    try:
        utc_dt = datetime(1970, 1, 1, tzinfo=timezone.utc) + timedelta(milliseconds=int(ff_time_ms))
        local_dt = utc_dt + LOCAL_UTC_OFFSET
        return local_dt.strftime("%Y-%m-%d %H:%M:%S")
    except (ValueError, OverflowError, OSError):
        return ""


def decode_transition(transition):
    if transition is None:
        return "Unknown"
    return TRANSITION_TYPES.get(int(transition) & 0xFF, "Other")


def detect_browser(cursor):
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
    tables = [r[0] for r in cursor.fetchall()]
    if "moz_places" in tables:
        return "Firefox"
    if "urls" in tables:
        try:
            cursor.execute("SELECT url FROM urls WHERE url LIKE 'edge://%' LIMIT 1")
            if cursor.fetchone():
                return "Edge"
        except Exception:
            pass
        return "Chrome"
    return "Unknown"


def parse_local_datetime(date_str, is_end=False):
    """Parse date string as LOCAL time, or epoch milliseconds as UTC."""
    if not date_str:
        return None
    if date_str.isdigit() and len(date_str) >= 13:
        try:
            return datetime.fromtimestamp(int(date_str) / 1000.0, tz=timezone.utc)
        except (ValueError, OverflowError, OSError):
            print("WARNING: Could not parse epoch ms '{}'".format(date_str))
            return None
    time_only_formats = ["%H:%M:%S", "%H:%M"]
    for fmt in time_only_formats:
        try:
            parsed_time = datetime.strptime(date_str, fmt)
            today = datetime.now()
            local_dt = today.replace(hour=parsed_time.hour, minute=parsed_time.minute,
                                     second=parsed_time.second, microsecond=0)
            utc_dt = local_dt - LOCAL_UTC_OFFSET
            return utc_dt.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    formats = ["%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%d",
               "%d/%m/%Y %H:%M:%S", "%d/%m/%Y %H:%M", "%d/%m/%Y"]
    local_dt = None
    for fmt in formats:
        try:
            local_dt = datetime.strptime(date_str, fmt)
            if is_end and "%H" not in fmt:
                local_dt = local_dt.replace(hour=23, minute=59, second=59)
            break
        except ValueError:
            continue
    if local_dt is None:
        print("WARNING: Could not parse '{}'".format(date_str))
        return None
    utc_dt = local_dt - LOCAL_UTC_OFFSET
    return utc_dt.replace(tzinfo=timezone.utc)


def utc_to_chrome_ts(utc_dt):
    if utc_dt is None:
        return None
    return int(utc_dt.timestamp() * 1000000 + CHROME_EPOCH_OFFSET)


def utc_to_firefox_ts(utc_dt):
    if utc_dt is None:
        return None
    return int(utc_dt.timestamp() * 1000000)


def find_history_files(target_user, browser_filter):
    found = []
    users_dir = "C:\\Users"
    if not os.path.isdir(users_dir):
        return found
    for user_folder in os.listdir(users_dir):
        if user_folder.lower() in ("public", "default", "default user", "all users"):
            continue
        user_path = os.path.join(users_dir, user_folder)
        if not os.path.isdir(user_path):
            continue
        if target_user.lower() != "all" and user_folder.lower() != target_user.lower():
            continue
        for bname, bpath in [("Chrome", "AppData\\Local\\Google\\Chrome\\User Data"),
                              ("Edge", "AppData\\Local\\Microsoft\\Edge\\User Data")]:
            if browser_filter != "all" and bname.lower() != browser_filter:
                continue
            base = os.path.join(user_path, bpath)
            if not os.path.isdir(base):
                continue
            for pdir in glob.glob(os.path.join(base, "*")):
                dn = os.path.basename(pdir)
                if dn.lower() == "default" or dn.lower().startswith("profile "):
                    hf = os.path.join(pdir, "History")
                    if os.path.isfile(hf):
                        found.append((hf, user_folder, bname, dn, os.path.getsize(hf)))
        if browser_filter in ("all", "firefox"):
            ff_base = os.path.join(user_path, "AppData\\Roaming\\Mozilla\\Firefox\\Profiles")
            if os.path.isdir(ff_base):
                for pdir in glob.glob(os.path.join(ff_base, "*")):
                    pf = os.path.join(pdir, "places.sqlite")
                    if os.path.isfile(pf):
                        found.append((pf, user_folder, "Firefox", os.path.basename(pdir), os.path.getsize(pf)))
    found.sort(key=lambda x: x[4], reverse=True)
    return [(f[0], f[1], f[2], f[3]) for f in found]


# ============== DOWNLOAD COLLECTION ==============

def collect_chrome_edge_downloads(cursor, browser, chrome_start, chrome_end, url_filter, hostname, username, profile_name):
    """Collect download history from Chrome/Edge History database."""
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='downloads'")
    if not cursor.fetchone():
        return []

    conditions = []
    if chrome_start is not None:
        conditions.append("start_time > {}".format(chrome_start))
    if chrome_end is not None:
        conditions.append("start_time < {}".format(chrome_end))
    if url_filter:
        conditions.append("(tab_url LIKE '%{0}%' OR site_url LIKE '%{0}%' OR target_path LIKE '%{0}%')".format(
            url_filter.replace("'", "''")))
    where = "WHERE " + " AND ".join(conditions) if conditions else ""

    cursor.execute("""
        SELECT target_path, tab_url, referrer, site_url, start_time, end_time,
               received_bytes, total_bytes, state, danger_type, opened, mime_type
        FROM downloads
        {} ORDER BY start_time DESC
    """.format(where))

    results = []
    for row in cursor.fetchall():
        target_path, tab_url, referrer, site_url, start_time, end_time, \
            received_bytes, total_bytes, state, danger_type, opened, mime_type = row
        if not start_time:
            continue

        size_mb = ""
        if total_bytes and int(total_bytes) > 0:
            size_mb = "{:.2f}".format(int(total_bytes) / BYTES_TO_MB)

        results.append({
            "Timestamp": chrome_time_to_local_str(start_time),
            "EndTime": chrome_time_to_local_str(end_time),
            "User": username,
            "Browser": browser,
            "Profile": profile_name,
            "FilePath": target_path or "",
            "SourceURL": tab_url or site_url or "",
            "Referrer": referrer or "",
            "SizeMB": size_mb,
            "State": DOWNLOAD_STATES.get(int(state) if state is not None else -1, "Unknown"),
            "DangerType": DANGER_TYPES.get(int(danger_type) if danger_type is not None else -1, "Unknown"),
            "Opened": "Yes" if opened and int(opened) == 1 else "No",
            "MimeType": mime_type or "",
            "Hostname": hostname,
        })
    return results


def collect_firefox_downloads(cursor, ff_start, ff_end, url_filter, hostname, username, profile_name):
    """Collect download history from Firefox places.sqlite using moz_annos."""
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='moz_annos'")
    if not cursor.fetchone():
        return []
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='moz_anno_attributes'")
    if not cursor.fetchone():
        return []

    conditions = []
    if ff_start is not None:
        conditions.append("a.dateAdded > {}".format(ff_start))
    if ff_end is not None:
        conditions.append("a.dateAdded < {}".format(ff_end))
    if url_filter:
        conditions.append("p.url LIKE '%{}%'".format(url_filter.replace("'", "''")))
    extra_where = " AND " + " AND ".join(conditions) if conditions else ""

    cursor.execute("""
        SELECT p.id, p.url, p.title, aa.name, a.content, a.dateAdded, a.lastModified
        FROM moz_annos a
        JOIN moz_places p ON a.place_id = p.id
        JOIN moz_anno_attributes aa ON a.anno_attribute_id = aa.id
        WHERE aa.name IN ('downloads/destinationFileURI', 'downloads/metaData')
        {} ORDER BY p.id, aa.name
    """.format(extra_where))
    rows = cursor.fetchall()
    if not rows:
        return []

    downloads = {}
    for row in rows:
        place_id, source_url, title, anno_name, content, date_added, last_modified = row
        if place_id not in downloads:
            downloads[place_id] = {
                "source_url": source_url, "title": title,
                "date_added": date_added, "last_modified": last_modified
            }
        if anno_name == "downloads/destinationFileURI":
            path = content
            if path and path.startswith("file:///"):
                path = path[8:]
                path = re.sub(r'%([0-9A-Fa-f]{2})', lambda m: chr(int(m.group(1), 16)), path)
            downloads[place_id]["destination"] = path
        elif anno_name == "downloads/metaData":
            try:
                meta = json.loads(content)
                downloads[place_id]["file_size"] = meta.get("fileSize")
                downloads[place_id]["state"] = meta.get("state")
                downloads[place_id]["end_time"] = meta.get("endTime")
            except (json.JSONDecodeError, TypeError):
                pass

    results = []
    for dl in downloads.values():
        size_mb = ""
        if dl.get("file_size") and int(dl["file_size"]) > 0:
            size_mb = "{:.2f}".format(int(dl["file_size"]) / BYTES_TO_MB)

        ff_dl_states = {0: "In Progress", 1: "Complete", 2: "Failed",
                        3: "Cancelled", 4: "Paused", 5: "Queued"}

        results.append({
            "Timestamp": firefox_time_to_local_str(dl.get("date_added")),
            "EndTime": firefox_time_ms_to_local_str(dl.get("end_time")),
            "User": username,
            "Browser": "Firefox",
            "Profile": profile_name,
            "FilePath": dl.get("destination", ""),
            "SourceURL": dl.get("source_url", ""),
            "Referrer": "",
            "SizeMB": size_mb,
            "State": ff_dl_states.get(dl.get("state", -1), "Unknown"),
            "DangerType": "",
            "Opened": "",
            "MimeType": "",
            "Hostname": hostname,
        })

    results.sort(key=lambda x: x["Timestamp"], reverse=True)
    return results


# ============== MAIN ENTRY POINT ==============

def run(target_user="*", browser_filter="*", mode="history", start_date="*", end_date="*", url_filter="*", max_results="0"):
    """Entry point for XDR Agent Script Library"""

    target_user = target_user.strip()
    browser_filter = browser_filter.strip().lower()
    mode = mode.strip().lower()
    start_date = start_date.strip()
    end_date = end_date.strip()
    url_filter = url_filter.strip()
    max_results = int(max_results)

    if target_user in ("*", "all", ""):
        target_user = "all"
    if browser_filter in ("*", "all", ""):
        browser_filter = "all"
    if mode not in ("history", "downloads", "both"):
        mode = "history"
    if start_date == "*":
        start_date = ""
    if end_date == "*":
        end_date = ""
    if url_filter in ("*", ""):
        url_filter = ""

    hostname = os.environ.get("COMPUTERNAME", "UNKNOWN")
    collect_history = mode in ("history", "both")
    collect_downloads = mode in ("downloads", "both")

    start_utc = parse_local_datetime(start_date, is_end=False)
    end_utc = parse_local_datetime(end_date, is_end=True)
    chrome_start = utc_to_chrome_ts(start_utc)
    chrome_end = utc_to_chrome_ts(end_utc)
    ff_start = utc_to_firefox_ts(start_utc)
    ff_end = utc_to_firefox_ts(end_utc)

    print("=" * 80)
    print("Browser History Collector for XDR")
    print("=" * 80)
    print("Hostname:       {}".format(hostname))
    print("Endpoint TZ:    {} (UTC{})".format(LOCAL_TZ_NAME, _format_utc_offset(LOCAL_UTC_OFFSET)))
    print("User filter:    {}".format(target_user))
    print("Browser:        {}".format(browser_filter))
    print("Mode:           {}".format(mode))
    print("Max results:    {}".format("unlimited" if max_results == 0 else max_results))
    print("URL filter:     {}".format(url_filter if url_filter else "none (all URLs)"))
    if start_utc or end_utc:
        start_display = (start_utc + LOCAL_UTC_OFFSET).strftime("%Y-%m-%d %H:%M:%S") if start_utc else "beginning"
        end_display = (end_utc + LOCAL_UTC_OFFSET).strftime("%Y-%m-%d %H:%M:%S") if end_utc else "now"
        print("Search range:   {} to {} (local time)".format(start_display, end_display))
    else:
        print("Search range:   ALL history (no date filter)")
    print("")

    history_files = find_history_files(target_user, browser_filter)
    print("Found {} history file(s):".format(len(history_files)))
    for hf in history_files:
        print("  {} / {} / {}".format(hf[1], hf[2], hf[3]))
    print("")

    if not history_files:
        print("NO DATA: No browser history files found on {}".format(hostname))
        return {"hostname": hostname, "timezone": "{} (UTC{})".format(LOCAL_TZ_NAME, _format_utc_offset(LOCAL_UTC_OFFSET)),
                "total_entries": 0, "entries": [], "total_downloads": 0, "downloads": []}

    history_results = []
    download_results = []

    for hist_path, username, browser_hint, profile_name in history_files:
        print("Processing: {} / {} / {}".format(username, browser_hint, profile_name))

        temp_copy = os.path.join(os.environ.get("TEMP", "C:\\Temp"),
                                 "xdr_hist_{}_{}_{}.db".format(username, browser_hint, profile_name.replace(" ", "_")))
        try:
            shutil.copy2(hist_path, temp_copy)
        except Exception:
            # If copy fails (file locked by browser), try reading raw bytes
            try:
                with open(hist_path, "rb") as src_f:
                    data = src_f.read()
                with open(temp_copy, "wb") as dst_f:
                    dst_f.write(data)
            except Exception:
                pass

        if not os.path.isfile(temp_copy):
            print("  SKIP: Could not copy (file locked)")
            continue

        try:
            conn = sqlite3.connect(temp_copy, timeout=5)
            cursor = conn.cursor()
            browser = detect_browser(cursor)

            # ── Browsing history ──
            if collect_history:
                h_before = len(history_results)
                if browser == "Firefox":
                    conditions = []
                    if ff_start is not None:
                        conditions.append("moz_historyvisits.visit_date > {}".format(ff_start))
                    if ff_end is not None:
                        conditions.append("moz_historyvisits.visit_date < {}".format(ff_end))
                    if url_filter:
                        conditions.append("moz_places.url LIKE '%{}%'".format(url_filter.replace("'", "''")))
                    where = "WHERE " + " AND ".join(conditions) if conditions else ""
                    cursor.execute("""
                        SELECT moz_places.url, moz_places.title, moz_historyvisits.visit_date,
                               moz_historyvisits.visit_type, moz_places.visit_count, ref_places.url
                        FROM moz_places
                        LEFT JOIN moz_historyvisits ON moz_places.id = moz_historyvisits.place_id
                        LEFT JOIN moz_historyvisits AS ref_v ON moz_historyvisits.from_visit = ref_v.id
                        LEFT JOIN moz_places AS ref_places ON ref_v.place_id = ref_places.id
                        {} ORDER BY moz_historyvisits.visit_date DESC
                    """.format(where))
                    for row in cursor.fetchall():
                        url, title, visit_date, visit_type, visit_count, referrer = row
                        if not visit_date:
                            continue
                        history_results.append({
                            "Timestamp": firefox_time_to_local_str(visit_date),
                            "User": username, "Browser": "Firefox", "Profile": profile_name,
                            "URL": url or "", "Title": title or "",
                            "VisitType": FF_VISIT_TYPES.get(int(visit_type) if visit_type else 0, "Unknown"),
                            "ReferrerURL": referrer or "", "VisitCount": visit_count or 0,
                            "Hostname": hostname})
                else:
                    conditions = []
                    if chrome_start is not None:
                        conditions.append("visits.visit_time > {}".format(chrome_start))
                    if chrome_end is not None:
                        conditions.append("visits.visit_time < {}".format(chrome_end))
                    if url_filter:
                        conditions.append("urls.url LIKE '%{}%'".format(url_filter.replace("'", "''")))
                    where = "WHERE " + " AND ".join(conditions) if conditions else ""
                    cursor.execute("""
                        SELECT urls.url, urls.title, visits.visit_time, visits.visit_duration,
                               visits.transition, urls.visit_count, urls.typed_count, ref_urls.url
                        FROM urls
                        LEFT JOIN visits ON urls.id = visits.url
                        LEFT JOIN visits AS ref_v ON visits.from_visit = ref_v.id
                        LEFT JOIN urls AS ref_urls ON ref_v.url = ref_urls.id
                        {} ORDER BY visits.visit_time DESC
                    """.format(where))
                    for row in cursor.fetchall():
                        url, title, vtime, vdur, trans, vcount, tcount, referrer = row
                        if not vtime:
                            continue
                        history_results.append({
                            "Timestamp": chrome_time_to_local_str(vtime),
                            "User": username, "Browser": browser, "Profile": profile_name,
                            "URL": url or "", "Title": title or "",
                            "VisitType": decode_transition(trans),
                            "ReferrerURL": referrer or "", "VisitCount": vcount or 0,
                            "Hostname": hostname})
                print("  History: {} entries".format(len(history_results) - h_before))

            # ── Download history ──
            if collect_downloads:
                d_before = len(download_results)
                if browser == "Firefox":
                    download_results.extend(
                        collect_firefox_downloads(cursor, ff_start, ff_end, url_filter, hostname, username, profile_name))
                else:
                    download_results.extend(
                        collect_chrome_edge_downloads(cursor, browser, chrome_start, chrome_end, url_filter, hostname, username, profile_name))
                print("  Downloads: {} entries".format(len(download_results) - d_before))

            conn.close()
        except Exception as e:
            print("  ERROR: {}".format(e))
        finally:
            try:
                if 'conn' in dir():
                    conn.close()
            except Exception:
                pass
            try:
                os.remove(temp_copy)
            except Exception:
                pass

    # Apply max_results
    if max_results > 0:
        if len(history_results) > max_results:
            history_results = history_results[:max_results]
        if len(download_results) > max_results:
            download_results = download_results[:max_results]

    # Print browsing history
    if collect_history:
        if history_results:
            print("\n" + "=" * 80)
            print("BROWSING HISTORY: {} entries".format(len(history_results)))
            print("=" * 80)
            print("Timestamp | User | Browser | VisitType | URL | ReferrerURL")
            print("-" * 80)
            for r in history_results:
                print("[{}] | {} | {} | {} | {} | {}".format(
                    r["Timestamp"], r["User"], r["Browser"],
                    r["VisitType"], r["URL"], r["ReferrerURL"]))
        else:
            print("\nNO BROWSING HISTORY found")

    # Print download history
    if collect_downloads:
        if download_results:
            print("\n" + "=" * 80)
            print("DOWNLOAD HISTORY: {} entries".format(len(download_results)))
            print("=" * 80)
            print("Timestamp | User | Browser | State | DangerType | SizeMB | Opened | MimeType | FilePath | SourceURL | Referrer")
            print("-" * 80)
            for d in download_results:
                print("[{}] | {} | {} | {} | {} | {} | {} | {} | {} | {} | {}".format(
                    d["Timestamp"], d["User"], d["Browser"],
                    d["State"], d["DangerType"], d["SizeMB"],
                    d["Opened"], d["MimeType"],
                    d["FilePath"], d["SourceURL"], d["Referrer"]))
        else:
            print("\nNO DOWNLOADS found")

    total = len(history_results) + len(download_results)
    print("\n" + "=" * 80)
    print("TOTAL: {} entries from {} | TZ: {} (UTC{})".format(
        total, hostname, LOCAL_TZ_NAME, _format_utc_offset(LOCAL_UTC_OFFSET)))
    print("=" * 80)

    return {
        "hostname": hostname,
        "timezone": "{} (UTC{})".format(LOCAL_TZ_NAME, _format_utc_offset(LOCAL_UTC_OFFSET)),
        "total_entries": len(history_results),
        "entries": history_results,
        "total_downloads": len(download_results),
        "downloads": download_results,
    }
