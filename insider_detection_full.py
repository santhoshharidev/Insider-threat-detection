# insider_detection_full.py
"""
Full timeline-based insider detection implementing 5 scenarios.
- Works chunked for large CSVs
- Primary date format: "%d/%m/%Y %H:%M:%S" (day/month/year hour:min:sec)
- Outputs:
    - scored_users.csv  (User, SuspicionScore, MatchedScenarios, SuspiciousEventsCount, feature columns...)
    - suspicious_activities.csv (detail records that triggered scenario bits)
    - top70.csv (top 70 candidates)
Optional:
    - labels.csv (User,IsInsider) to enable supervised calibration (LogisticRegression).
"""

import os
import re
import math
import numpy as np
import pandas as pd
from collections import defaultdict, Counter
from datetime import datetime, time, timedelta

# Optional supervised calibration
try:
    from sklearn.linear_model import LogisticRegression
    SKLEARN_AVAILABLE = True
except Exception:
    SKLEARN_AVAILABLE = False

# ---------------------------
# CONFIG - change file paths
# ---------------------------
EMAIL_FILE = "email.csv"
HTTP_FILE  = "http.csv"
FILE_FILE  = "file.csv"
LOGON_FILE = "logon.csv"
DEVICES_FILE = "devices.csv"
PSYCHO_FILE = "psychometric.csv"
LABELS_FILE = "labels.csv"   # optional: for supervised calibration

CHUNK = 200000  # chunk size for pd.read_csv
PERSONAL_DOMAINS = ["gmail.com","yahoo.com","hotmail.com","outlook.com"]
JOB_PATTERNS = ["monster.com", "indeed.com", "naukri.com", "linkedin.com/jobs", "glassdoor.com"]
AFTER_HOURS_START = time(20,0,0)  # 8 PM onward
AFTER_HOURS_END   = time(6,0,0)   # until 6 AM
# thresholds (tunable)
MASS_EMAIL_RECIPIENTS_THRESH = 50
USB_SPIKE_MULTIPLIER = 3.0
LEAVE_WINDOW_DAYS = 14  # scenario 1
SCEN3_LEAVE_DAYS = 7    # scenario 3

# ---------------------------
# Helpers
# ---------------------------
def try_parse_datetime(s):
    """Primary format D/M/Y H:M:S, with fallbacks. Returns pd.Timestamp or pd.NaT."""
    if pd.isna(s):
        return pd.NaT
    s = str(s).strip()
    fmts = [
        "%d/%m/%Y %H:%M:%S",
        "%d/%m/%Y %H:%M",
        "%Y-%m-%d %H:%M:%S",
        "%Y/%m/%d %H:%M:%S",
        "%m/%d/%Y %H:%M:%S",
        "%d-%m-%Y %H:%M:%S",
        "%Y-%m-%d",
        "%d/%m/%Y"
    ]
    for f in fmts:
        try:
            return pd.to_datetime(datetime.strptime(s, f))
        except Exception:
            pass
    # last resort:
    try:
        return pd.to_datetime(s, dayfirst=True, errors="coerce")
    except Exception:
        return pd.NaT

def is_after_hours(dt):
    if pd.isna(dt):
        return False
    t = dt.time()
    return (t >= AFTER_HOURS_START) or (t <= AFTER_HOURS_END)

def recipients_count_field(s):
    if pd.isna(s):
        return 0
    parts = re.split(r"[;,]+", str(s))
    return sum(1 for p in parts if p.strip())

def contains_personal_addr(s):
    if pd.isna(s):
        return False
    txt = str(s).lower()
    return any(dom in txt for dom in PERSONAL_DOMAINS)

def contains_any_pattern(text, patterns):
    if pd.isna(text):
        return False
    t = str(text).lower()
    return any(p.lower() in t for p in patterns)

def month_label(dt):
    if pd.isna(dt):
        return "unknown"
    return dt.strftime("%Y-%m")

# ---------------------------
# Build PC -> owner map
# ---------------------------
def build_pc_owner_map(logon_path):
    pc_counts = defaultdict(Counter)
    if not os.path.exists(logon_path):
        return {}
    # read in chunks to limit memory
    try:
        header_cols = pd.read_csv(logon_path, nrows=0).columns.tolist()
    except Exception:
        header_cols = []
    usecols = [c for c in ["ID","Date","User","PC","Activity"] if c in header_cols]
    if not usecols:
        return {}
    for chunk in pd.read_csv(logon_path, usecols=usecols, chunksize=CHUNK):
        for _, r in chunk.iterrows():
            pc = str(r.get("PC","")).strip()
            user = str(r.get("User","")).strip()
            if pc and user:
                pc_counts[pc][user] += 1
    pc_owner = {}
    for pc, cnt in pc_counts.items():
        owner, _ = cnt.most_common(1)[0]
        pc_owner[pc] = owner
    print(f"[pc_owner_map] {len(pc_owner)} PCs mapped to owners.")
    return pc_owner

# ---------------------------
# Stream all files and build per-user timeline (list of events)
# We'll create a dict: user -> list of events (Date, EventType, Details, PC, raw_row_info)
# ---------------------------
def stream_and_build_user_events(paths):
    user_events = defaultdict(list)
    def append_event(user, dt, etype, details, pc=None, raw=None):
        if pd.isna(dt):
            return
        user_events[str(user)].append({
            "Date": dt, "EventType": etype, "Details": str(details) if details is not None else "", "PC": str(pc) if pc is not None else "", "Raw": raw
        })

    # HTTP
    if os.path.exists(paths["http"]):
        try:
            cols = pd.read_csv(paths["http"], nrows=0).columns.tolist()
        except Exception:
            cols = []
        usecols = [c for c in ["ID","Date","User","PC","URL","Content"] if c in cols]
        if usecols:
            for chunk in pd.read_csv(paths["http"], usecols=usecols, chunksize=CHUNK):
                for _, r in chunk.iterrows():
                    dt = try_parse_datetime(r.get("Date"))
                    user = r.get("User", "")
                    pc = r.get("PC", "")
                    url = str(r.get("URL","") or "")
                    content = str(r.get("Content","") or "")
                    details = (url + " " + content).strip()
                    append_event(user, dt, "http", details, pc, raw={"id": r.get("ID")})
    # FILE
    if os.path.exists(paths["file"]):
        try:
            cols = pd.read_csv(paths["file"], nrows=0).columns.tolist()
        except Exception:
            cols = []
        usecols = [c for c in ["ID","Date","User","PC","File Name","Content"] if c in cols]
        if usecols:
            for chunk in pd.read_csv(paths["file"], usecols=usecols, chunksize=CHUNK):
                for _, r in chunk.iterrows():
                    dt = try_parse_datetime(r.get("Date"))
                    user = r.get("User","")
                    pc = r.get("PC","")
                    fname = str(r.get("File Name","") or "")
                    content = str(r.get("Content","") or "")
                    details = (fname + " " + content).strip()
                    append_event(user, dt, "file", details, pc, raw={"id": r.get("ID")})
    # EMAIL
    if os.path.exists(paths["email"]):
        try:
            cols = pd.read_csv(paths["email"], nrows=0).columns.tolist()
        except Exception:
            cols = []
        usecols = [c for c in ["ID","Date","User","PC","To","CC","BCC","From","Size","Attachment","Content"] if c in cols]
        if usecols:
            for chunk in pd.read_csv(paths["email"], usecols=usecols, chunksize=CHUNK):
                for _, r in chunk.iterrows():
                    dt = try_parse_datetime(r.get("Date"))
                    user = r.get("User","")
                    pc = r.get("PC","")
                    to = str(r.get("To","") or "")
                    cc = str(r.get("CC","") or "")
                    bcc = str(r.get("BCC","") or "")
                    content = str(r.get("Content","") or "")
                    details = "TO:"+to + " CC:"+cc + " BCC:"+bcc + " " + content
                    append_event(user, dt, "email", details, pc, raw={"id": r.get("ID"), "size": r.get("Size"), "attachment": r.get("Attachment")})
    # DEVICES
    if os.path.exists(paths["device"]):
        try:
            cols = pd.read_csv(paths["device"], nrows=0).columns.tolist()
        except Exception:
            cols = []
        usecols = [c for c in ["ID","Date","User","PC","Activity"] if c in cols]
        if usecols:
            for chunk in pd.read_csv(paths["device"], usecols=usecols, chunksize=CHUNK):
                for _, r in chunk.iterrows():
                    dt = try_parse_datetime(r.get("Date"))
                    user = r.get("User","")
                    pc = r.get("PC","")
                    act = str(r.get("Activity","") or "")
                    append_event(user, dt, "device", act, pc, raw={"id": r.get("ID")})
    # LOGON
    if os.path.exists(paths["logon"]):
        try:
            cols = pd.read_csv(paths["logon"], nrows=0).columns.tolist()
        except Exception:
            cols = []
        usecols = [c for c in ["ID","Date","User","PC","Activity"] if c in cols]
        if usecols:
            for chunk in pd.read_csv(paths["logon"], usecols=usecols, chunksize=CHUNK):
                for _, r in chunk.iterrows():
                    dt = try_parse_datetime(r.get("Date"))
                    user = r.get("User","")
                    pc = r.get("PC","")
                    act = str(r.get("Activity","") or "")
                    append_event(user, dt, "logon", act, pc, raw={"id": r.get("ID")})
    print(f"[stream] Built events for {len(user_events)} users (events not yet sorted).")
    # sort each user's events by date
    for u, evs in user_events.items():
        evs.sort(key=lambda x: x["Date"])
    return user_events

# ---------------------------
# Extract features & match scenarios per user
# ---------------------------
def extract_features_and_match(user_events, pc_owner_map, psych_df):
    user_feats = defaultdict(lambda: defaultdict(float))
    suspense_records = []   # list of dicts for suspicious events (User, Scenario, Date, Description)
    all_users = sorted(user_events.keys())

    for user in all_users:
        events = user_events[user]
        if not events:
            continue
        # convert to simple list for fast scanning
        n = len(events)
        split_idx = max(1, int(n * 0.6))  # baseline first 60%, recent last 40%
        before = events[:split_idx]
        after = events[split_idx:]

        # Basic counts
        usb_before = sum(1 for e in before if re.search(r"usb|thumb|remov|flash", e["Details"], re.I))
        usb_after  = sum(1 for e in after  if re.search(r"usb|thumb|remov|flash", e["Details"], re.I))
        user_feats[user]["usb_before"] = usb_before
        user_feats[user]["usb_after"]  = usb_after

        # after-hours logons
        ah_before = sum(1 for e in before if e["EventType"]=="logon" and is_after_hours(e["Date"]))
        ah_after  = sum(1 for e in after  if e["EventType"]=="logon" and is_after_hours(e["Date"]))
        user_feats[user]["after_hours_before"] = ah_before
        user_feats[user]["after_hours_after"]  = ah_after

        # http-based indicators in 'after'
        after_http = [e for e in after if e["EventType"]=="http"]
        wikileaks_after = sum(1 for e in after_http if "wikileaks" in e["Details"])
        dropbox_after   = sum(1 for e in after_http if "dropbox" in e["Details"])
        job_after       = sum(1 for e in after_http if any(p in e["Details"] for p in JOB_PATTERNS))
        keylogger_http_after = sum(1 for e in after_http if re.search(r"keylogger|key log|key_log", e["Details"], re.I))
        user_feats[user]["wikileaks_after"] = wikileaks_after
        user_feats[user]["dropbox_after"]   = dropbox_after
        user_feats[user]["job_sites_after"] = job_after
        user_feats[user]["keylogger_http_after"] = keylogger_http_after

        # files in 'after'
        after_files = [e for e in after if e["EventType"]=="file"]
        keylogger_file_after = sum(1 for e in after_files if re.search(r"keylogger|key log|key_log", e["Details"], re.I))
        sensitive_files_after = sum(1 for e in after_files if re.search(r"sensitive|confidential|classified|salary|student-record|financial", e["Details"], re.I))
        user_feats[user]["keylogger_file_after"] = keylogger_file_after
        user_feats[user]["sensitive_files_after"] = sensitive_files_after

        # email in 'after'
        after_email = [e for e in after if e["EventType"]=="email"]
        sent_personal_after = 0
        mass_email_after = 0
        sent_from_other_pc_after = 0
        for e in after_email:
            # personal recipients
            if contains_personal_addr(e["Details"]):
                sent_personal_after += 1
            # mass email heuristic: count '@' occurrences in details
            if e["Details"].count("@") >= MASS_EMAIL_RECIPIENTS_THRESH:
                mass_email_after += 1
            # sent from other PC: if pc owner exists and owner != user
            pc = e.get("PC","")
            owner = pc_owner_map.get(pc)
            if owner and owner != user:
                sent_from_other_pc_after += 1
        user_feats[user]["sent_personal_after"] = sent_personal_after
        user_feats[user]["mass_email_after"] = mass_email_after
        user_feats[user]["sent_from_other_pc_after"] = sent_from_other_pc_after

        # logon-other-machine: total and monthly trend
        logon_events = [e for e in (before + after) if e["EventType"]=="logon"]
        login_other_total = 0
        month_counts = defaultdict(int)
        for e in logon_events:
            pc = e.get("PC","")
            owner = pc_owner_map.get(pc)
            if owner and owner != user:
                login_other_total += 1
                month_counts[month_label(e["Date"])] += 1
        user_feats[user]["login_other_total"] = login_other_total
        if len(month_counts) >= 2:
            items = sorted(month_counts.items())
            ys = np.array([c for _,c in items], dtype=float)
            xs = np.arange(len(ys), dtype=float)
            slope = np.polyfit(xs, ys, 1)[0]
            mean = ys.mean() if ys.mean() != 0 else 1.0
            user_feats[user]["login_other_trend"] = slope / mean
        else:
            user_feats[user]["login_other_trend"] = 0.0

        # total events counts
        user_feats[user]["total_events"] = n
        user_feats[user]["events_after"] = len(after)

        # Last activity date
        last_activity_date = events[-1]["Date"]

        #
        # SCENARIO MATCHING (sequence + window checks)
        #
        # Scenario 1:
        scen1 = False
        if usb_before == 0 and usb_after > 0 and ah_after > ah_before and wikileaks_after > 0:
            # find last suspicious event date in 'after'
            last_susp = None
            for e in reversed(after):
                if re.search(r"wikileaks|usb|dropbox|keylogger", e["Details"], re.I):
                    last_susp = e["Date"]; break
            if last_susp is not None:
                if (last_activity_date - last_susp).days <= LEAVE_WINDOW_DAYS:
                    scen1 = True
                    suspense_records.append({"User":user, "Scenario":1, "Date": last_susp, "Desc":"USB spike + after-hours + wikileaks + left soon"})
        user_feats[user]["scen1"] = 1 if scen1 else 0

        # Scenario 2:
        scen2 = False
        # job_site in after period + usb spike relative to before
        usb_spike_cond = False
        if usb_before == 0:
            usb_spike_cond = (usb_after >= 2)
        else:
            usb_spike_cond = (usb_after >= max(1, int(usb_before * USB_SPIKE_MULTIPLIER)))
        if job_after > 0 and usb_spike_cond:
            # check if last suspicious event near leaving (optional)
            # last job or usb event date
            last_susp = None
            for e in reversed(after):
                if any(j in e["Details"].lower() for j in JOB_PATTERNS) or re.search(r"usb|thumb|remov|flash", e["Details"], re.I):
                    last_susp = e["Date"]; break
            if last_susp is not None:
                if (last_activity_date - last_susp).days <= LEAVE_WINDOW_DAYS:
                    scen2 = True
                    suspense_records.append({"User":user, "Scenario":2, "Date": last_susp, "Desc":"Job-site visits + USB spike + left soon"})
            else:
                # partial match (no clear leave)
                scen2 = True
                suspense_records.append({"User":user, "Scenario":2, "Date": after[0]["Date"] if after else last_activity_date, "Desc":"Job-site visits + USB spike (no leave)"} )
        user_feats[user]["scen2"] = 1 if scen2 else 0

        # Scenario 3:
        scen3 = False
        # keylogger download (http/file), usb transfer to supervisor's machine, then login as supervisor and mass email next day
        # Step 1: keylogger event date
        key_events = [e for e in after if re.search(r"keylogger|key log|key_log", e["Details"], re.I)]
        if key_events:
            # earliest keylogger event
            key_date = key_events[0]["Date"]
            # Step 2: usb transfer (device event mentioning 'usb' within 0-3 days after key_date)
            usb_transfers = [e for e in after if e["EventType"]=="device" and re.search(r"usb|write|copy|remove", e["Details"], re.I) and (0 <= (e["Date"] - key_date).days <= 3)]
            if usb_transfers:
                # Step 3: login as supervisor -- we look for a logon event where this user logs into a PC whose owner is someone else (and that owner might be their supervisor)
                login_super = [e for e in after if e["EventType"]=="logon" and pc_owner_map.get(e.get("PC","")) not in (None, user) and (0 <= (e["Date"] - usb_transfers[0]["Date"]).days <= 2)]
                if login_super:
                    # Step 4: mass email after login_super within 1 day
                    login_date = login_super[0]["Date"]
                    mass_email_after_login = [e for e in after if e["EventType"]=="email" and (e["Date"] >= login_date) and e["Details"].count("@") >= MASS_EMAIL_RECIPIENTS_THRESH and (0 <= (e["Date"] - login_date).days <= 2)]
                    if mass_email_after_login:
                        # check leave soon
                        last_susp_date = max(key_date, usb_transfers[0]["Date"], login_date, mass_email_after_login[0]["Date"])
                        if (last_activity_date - last_susp_date).days <= SCEN3_LEAVE_DAYS:
                            scen3 = True
                            suspense_records.append({"User":user, "Scenario":3, "Date": last_susp_date, "Desc":"Keylogger download -> USB transfer -> login as supervisor -> mass email -> left quickly"})
        user_feats[user]["scen3"] = 1 if scen3 else 0

        # Scenario 4:
        scen4 = False
        # Check frequent logins to other machines AND sending to personal email AND rising trend over 3 months
        login_other_events = [e for e in (before + after) if e["EventType"]=="logon" and pc_owner_map.get(e.get("PC","")) not in (None, user)]
        # monthly counts in last 3 months from last_activity_date (require >=3 months of data)
        if login_other_events:
            # compute month buckets for last 6 months and look at last 3 months trend
            month_counts = defaultdict(int)
            for e in login_other_events:
                m = month_label(e["Date"])
                month_counts[m] += 1
            # convert to sorted months and compute slope
            months_sorted = sorted(month_counts.items())
            if len(months_sorted) >= 3:
                ys = np.array([c for _,c in months_sorted], dtype=float)
                xs = np.arange(len(ys))
                slope = np.polyfit(xs, ys, 1)[0]
                mean = ys.mean() if ys.mean()!=0 else 1.0
                trend = slope / mean
            else:
                trend = 0.0
        else:
            trend = 0.0
        # personal emails in after
        personal_after = user_feats[user]["sent_personal_after"]
        if (user_feats[user]["login_other_total"] >= 3 and personal_after >= 1 and trend > 0.2) or (trend > 0.5 and personal_after >= 1):
            scen4 = True
            suspense_records.append({"User":user, "Scenario":4, "Date": after[0]["Date"] if after else last_activity_date, "Desc":"Login-other machines + sending to personal email + rising trend"})
        user_feats[user]["scen4"] = 1 if scen4 else 0

        # Scenario 5:
        scen5 = False
        drop_before = sum(1 for e in before if e["EventType"]=="http" and "dropbox" in e["Details"])
        drop_after  = user_feats[user]["dropbox_after"]
        if drop_after > 0 and (drop_before == 0 or drop_after >= max(2, drop_before * 5)):
            scen5 = True
            suspense_records.append({"User":user, "Scenario":5, "Date": after[0]["Date"] if after else last_activity_date, "Desc":"Dropbox uploads spike after baseline"})
        user_feats[user]["scen5"] = 1 if scen5 else 0

    # psychometric flags
    if os.path.exists(PSYCHO_FILE):
        try:
            p = pd.read_csv(PSYCHO_FILE)
            # ensure numeric
            for col in ["O","C","E","A","N"]:
                if col in p.columns:
                    p[col] = pd.to_numeric(p[col], errors="coerce").fillna(0.0)
            for _, r in p.iterrows():
                uid = str(r.get("UserID") or r.get("Employee")).strip()
                if not uid:
                    continue
                flag = 0.0
                if r.get("O",0) > 0.8:
                    flag += 0.5
                if r.get("N",0) > 0.7:
                    flag += 0.7
                if r.get("C",1) < 0.3:
                    flag += 0.8
                user_feats[uid]["psych_flag"] = flag
        except Exception:
            pass

    return user_feats, suspense_records

# ---------------------------
# Scoring & normalization
# ---------------------------
def pct_clip_scale(arr, low=1, high=99):
    if len(arr)==0:
        return arr
    p_low = np.percentile(arr, low)
    p_high = np.percentile(arr, high)
    if p_high <= p_low:
        return np.zeros_like(arr, dtype=float)
    clipped = np.clip(arr, p_low, p_high)
    return (clipped - p_low) / (p_high - p_low)

def normalize_and_score(user_feats, suspense_records, labels_path=None):
    # Build DataFrame from user_feats
    users = sorted(user_feats.keys())
    # collect possible feature names
    feats = set()
    for u in users:
        feats.update(user_feats[u].keys())
    feat_list = sorted(feats)
    # create df
    rows = []
    for u in users:
        row = {"User":u}
        for f in feat_list:
            row[f] = float(user_feats[u].get(f, 0.0))
        rows.append(row)
    df = pd.DataFrame(rows).fillna(0.0)

    # derived features
    if "usb_after" in df.columns and "usb_before" in df.columns:
        df["usb_spike_ratio"] = df.apply(lambda r: (r["usb_after"] / (r["usb_before"] + 1.0)), axis=1)
    else:
        df["usb_spike_ratio"] = 0.0

    # choose features for scoring (scenario flags + strong indicators)
    feature_for_norm = []
    # scenario flags
    for s in ["scen1","scen2","scen3","scen4","scen5"]:
        if s in df.columns:
            feature_for_norm.append(s)
    # other numerical signals
    for f in ["wikileaks_after","dropbox_after","job_sites_after","keylogger_http_after","keylogger_file_after",
              "usb_spike_ratio","sent_personal_after","sent_from_other_pc_after","mass_email_after",
              "sensitive_files_after","login_other_total","login_other_trend","psych_flag"]:
        if f in df.columns:
            feature_for_norm.append(f)

    # normalize each feature to 0-1 via pct-clip
    norm_vals = {}
    for f in feature_for_norm:
        norm_vals[f] = pct_clip_scale(df[f].values, 1, 99)

    # Default heuristic weights (tunable). Emphasize scenario flags.
    weights = {
        "scen1": 0.20, "scen2": 0.16, "scen3": 0.20, "scen4": 0.14, "scen5": 0.10,
        "wikileaks_after": 0.03, "keylogger_http_after": 0.03, "keylogger_file_after": 0.03,
        "usb_spike_ratio": 0.02, "sent_personal_after": 0.02, "sent_from_other_pc_after": 0.01,
        "mass_email_after": 0.01, "login_other_trend": 0.01, "sensitive_files_after": 0.01, "psych_flag": 0.01
    }
    # Filter weights to available features
    weights = {k:v for k,v in weights.items() if k in norm_vals}
    # normalize weights
    total_w = sum(weights.values()) if weights else 1.0
    weights = {k:v/total_w for k,v in weights.items()}

    # combine weighted normalized scores
    combined = np.zeros(len(df), dtype=float)
    for f,w in weights.items():
        vals = norm_vals.get(f, np.zeros(len(df)))
        combined += vals * w

    # supervised calibration if labels.csv present and sklearn available
    used_supervised = False
    if labels_path and os.path.exists(labels_path) and SKLEARN_AVAILABLE:
        try:
            labels = pd.read_csv(labels_path)
            labels["User"] = labels["User"].astype(str)
            merged = df.merge(labels[["User","IsInsider"]], on="User", how="left")
            train = merged[merged["IsInsider"].notna()].copy()
            if len(train) >= 10:
                # Build X matrix using normalized features in same order as weights keys
                X_all = np.vstack([norm_vals[f] for f in weights.keys()]).T
                train_idx = merged[merged["IsInsider"].notna()].index.values
                X_train = X_all[train_idx]
                y_train = merged.loc[train_idx, "IsInsider"].astype(int).values
                clf = LogisticRegression(class_weight="balanced", max_iter=1000)
                clf.fit(X_train, y_train)
                probs = clf.predict_proba(X_all)[:,1]
                combined = probs  # override combined with supervised probabilities
                used_supervised = True
                print(f"[supervised] Trained logistic regression on {len(train)} labeled rows.")
            else:
                print("[supervised] labels.csv found but too few labeled examples (<10). Skipping supervised step.")
        except Exception as e:
            print("[supervised] error during supervised calibration:", e)
            print("[supervised] continuing with heuristic combined score.")

    # final scaling to 0-100
    if combined.max() - combined.min() < 1e-9:
        scores = np.zeros_like(combined)
    else:
        scores = (combined - combined.min()) / (combined.max() - combined.min())
    scores = (scores * 100).round(2)
    df["SuspicionScore"] = scores

    # matched scenarios string & SuspiciousEventsCount (approx)
    scen_cols = [c for c in ["scen1","scen2","scen3","scen4","scen5"] if c in df.columns]
    df["MatchedScenarios"] = df.apply(lambda r: ",".join([str(i+1) for i,c in enumerate(scen_cols) if r.get(c,0)==1]), axis=1)
    if scen_cols:
        df["SuspiciousEventsCount"] = df[scen_cols].sum(axis=1).astype(int)
    else:
        df["SuspiciousEventsCount"] = 0

    # attach additional helpful feature columns for inspection (subset)
    info_cols = ["User","SuspicionScore","MatchedScenarios","SuspiciousEventsCount"]
    other_cols = [c for c in ["usb_before","usb_after","usb_spike_ratio","wikileaks_after","dropbox_after",
                  "job_sites_after","keylogger_http_after","keylogger_file_after",
                  "sent_personal_after","sent_from_other_pc_after","mass_email_after",
                  "login_other_total","login_other_trend","sensitive_files_after","psych_flag"] if c in df.columns]
    final_cols = info_cols + other_cols
    out_df = df[final_cols].copy()

    # sort descending by score
    out_df = out_df.sort_values("SuspicionScore", ascending=False).reset_index(drop=True)

    # prepare suspense_records DataFrame
    susp_df = pd.DataFrame(suspense_records) if suspense_records else pd.DataFrame(columns=["User","Scenario","Date","Desc"])
    return out_df, susp_df, used_supervised

# ---------------------------
# MAIN pipeline
# ---------------------------
def main():
    print("=== INSIDER DETECTION RUN START ===")
    paths = {"http": HTTP_FILE, "file": FILE_FILE, "email": EMAIL_FILE, "device": DEVICES_FILE, "logon": LOGON_FILE}
    print("1) Building PC owner map from logon.csv ...")
    pc_owner_map = build_pc_owner_map(LOGON_FILE)

    print("2) Streaming and building user event timelines (chunked reads) ...")
    user_events = stream_and_build_user_events(paths)

    print("3) Extracting features and matching scenarios ...")
    user_feats, suspense_records = extract_features_and_match(user_events, pc_owner_map, PSYCHO_FILE)

    print("4) Normalizing and scoring (supervised calibration if labels.csv present) ...")
    use_labels = os.path.exists(LABELS_FILE)
    scored_df, susp_df, used_supervised = normalize_and_score(user_feats, suspense_records, labels_path=LABELS_FILE if use_labels else None)

    # Save outputs
    scored_df.to_csv("scored_users.csv", index=False)
    susp_df.to_csv("suspicious_activities.csv", index=False)
    # Save top 70
    top70 = scored_df.head(70).copy()
    top70.to_csv("top70.csv", index=False)

    print(f"[OUTPUT] scored_users.csv ({len(scored_df)} users), suspicious_activities.csv ({len(susp_df)} records), top70.csv")
    if used_supervised:
        print("[NOTE] Supervised calibration applied (labels.csv used). Scores are model probabilities scaled to 0-100.")
    else:
        print("[NOTE] Heuristic scoring used (no / insufficient labels or sklearn missing). You can provide labels.csv and install scikit-learn to calibrate.")

    # If user provided labels, show simple metrics (if sklearn used)
    if use_labels and SKLEARN_AVAILABLE and used_supervised:
        try:
            labels = pd.read_csv(LABELS_FILE)
            labels["User"] = labels["User"].astype(str)
            merged = scored_df.merge(labels[["User","IsInsider"]], on="User", how="left")
            known = merged[merged["IsInsider"].notna()]
            if len(known):
                thr = 50.0
                preds = (known["SuspicionScore"] >= thr).astype(int)
                actual = known["IsInsider"].astype(int)
                tp = int(((preds==1) & (actual==1)).sum())
                fp = int(((preds==1) & (actual==0)).sum())
                fn = int(((preds==0) & (actual==1)).sum())
                tn = int(((preds==0) & (actual==0)).sum())
                print(f"[CALIBRATION] On labeled subset (n={len(known)}), threshold={thr}: TP={tp}, FP={fp}, FN={fn}, TN={tn}")
        except Exception:
            pass

    # Print top 20 for quick inspection
    print("\nTop 20 suspects:")
    print(scored_df.head(20).to_string(index=False))
    print("=== RUN COMPLETE ===")

if __name__ == "__main__":
    main()
