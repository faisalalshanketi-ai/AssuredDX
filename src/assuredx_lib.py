"""
AssureDx experiments - shared library, stages 0-3 (CICIoT2023).

Every stage is resumable: outputs are written atomically and a stage (or a
seed / file inside a stage) is skipped when its output already exists.
Delete an output file to force that piece to be recomputed.

Stages
  0  data      sample CSVs, clean, split 60/20/20, manifest
  1  detect    XGBoost binary detector (5 seeds), 8- and 34-class XGBoost, RF
  2  taxonomy  immutable / mutable / derived features, ranges, scales, strata
  3  explain   TreeSHAP for detected alerts, frozen top-k diagnosers,
               decoy groups G_c, eligible-alert sets for the attack stages
"""
CODE_VERSION = "2026-10-23c"
import os, json, glob, time, hashlib, platform, warnings
import numpy as np
import pandas as pd

warnings.filterwarnings("ignore", category=UserWarning)

# --------------------------------------------------------------------------
# configuration
# --------------------------------------------------------------------------
DEFAULT_CFG = {
    "dataset": "CICIoT2023",
    "data_dir": None,                 # folder holding the CICIoT2023 CSV files
    "out_dir": None,                  # results folder (on Google Drive in Colab)
    "seed": 42,
    "max_files": None,                # None = use every CSV; e.g. 60 for a faster run
    # per-family sampling fraction applied while reading each CSV
    "family_frac": {"DDoS": 0.01, "DoS": 0.03, "Mirai": 0.08, "Benign": 0.25,
                    "Recon": 1.0, "Spoofing": 1.0, "Web": 1.0, "BruteForce": 1.0},
    "cap_per_family": 200_000,        # final cap after all files are read
    "cap_per_label": 40_000,          # cap per label (34 labels) before the family cap
    "max_rows_per_file": 30_000,      # per-class layout: rows sampled from each source file
    "min_files_for_file_split": 3,    # labels with fewer files are split row by row
    "edge_rows_attack_file": 60_000, "edge_rows_normal_file": 25_000,   # Edge-IIoTset sampling
    "benign_rows_per_file": 100_000,  # benign has few files, so read more rows from each
    "drop_features": [],              # e.g. ["IAT"] after inspecting stage-3 report
    "detector_seeds": [0, 1, 2, 3, 4],
    "xgb_params": {"n_estimators": 2000, "max_depth": 8, "learning_rate": 0.1,
                   "subsample": 0.9, "colsample_bytree": 0.9,
                   "early_stopping_rounds": 50, "tree_method": "hist"},
    "rf_trees": 100, "rf_leaf_grid": [1, 5, 20], "rf_train_max": 300_000,
    "k_values": [3, 5, 10],
    "diag_penalties": [0.01, 0.1, 1, 10, 100],
    "expl_train_max": 150_000,        # detected training alerts explained (diagnoser + G_c)
    "decoy_group_size": 5,
    "split_mode": "file",             # "row" reproduces the random row split of published work
    "stage0_from": None, "cache_from": None,
}

LABEL = "label"
FAMILY = "family"
WEIGHT = "nat_weight"                 # inverse sampling rate -> natural-distribution metrics
GROUP = "source_file"                 # source CSV: a contiguous chunk of one capture (per-class layout)

# CICIoT2023 34 labels -> 8 classes (7 attack families + Benign)
# Edge-IIoTset attack types -> families (Ferrag et al. 2022 grouping)
EDGE_FAMILY = {"Normal": "Benign",
               "DDoS_UDP": "DDoS", "DDoS_ICMP": "DDoS", "DDoS_TCP": "DDoS", "DDoS_HTTP": "DDoS",
               "SQL_injection": "Injection", "XSS": "Injection", "Uploading": "Injection",
               "Backdoor": "Malware", "Password": "Malware", "Ransomware": "Malware",
               "Port_Scanning": "Scanning", "Vulnerability_scanner": "Scanning",
               "Fingerprinting": "Scanning", "OS_Fingerprinting": "Scanning",
               "MITM": "MITM"}

def family_of(label: str) -> str:
    l = str(label)
    u = l.upper()                      # merged CICIoT2023 release uses upper-case labels
    if u.startswith("DDOS"): return "DDoS"
    if u.startswith("DOS"): return "DoS"
    if u.startswith("MIRAI"): return "Mirai"
    if u.startswith("RECON") or u == "VULNERABILITYSCAN": return "Recon"
    if u in ("DNS_SPOOFING", "MITM-ARPSPOOFING"): return "Spoofing"
    if u in ("SQLINJECTION", "XSS", "COMMANDINJECTION", "BACKDOOR_MALWARE",
             "UPLOADING_ATTACK", "BROWSERHIJACKING"): return "Web"
    if u == "DICTIONARYBRUTEFORCE": return "BruteForce"
    if u.startswith("BENIGN"): return "Benign"
    return EDGE_FAMILY.get(l, "Unknown")      # Edge-IIoTset names not used by CICIoT2023

# feature roles for CICIoT2023 (column names as released)
PROTOCOL_INDICATORS = ["HTTP", "HTTPS", "DNS", "Telnet", "SMTP", "SSH", "IRC", "TCP",
                       "UDP", "DHCP", "ARP", "ICMP", "IGMP", "IPv", "LLC"]
FLAG_FEATURES = ["fin_flag_number", "syn_flag_number", "rst_flag_number",
                 "psh_flag_number", "ack_flag_number", "ece_flag_number",
                 "cwr_flag_number"]
IMMUTABLE = ["Protocol Type"] + PROTOCOL_INDICATORS + FLAG_FEATURES
COUNTS = ["ack_count", "syn_count", "fin_count", "urg_count", "rst_count"]
SIZE_STATS = ["Tot sum", "Min", "Max", "AVG", "Std", "Tot size", "Magnitue",
              "Radius", "Covariance", "Variance", "Weight", "Number"]
TIMING_RATE = ["flow_duration", "Header_Length", "Duration", "Time_To_Live", "Rate", "Srate",
               "Drate", "IAT"]
# derived fields are never edited directly. Identities verified on the per-class CSVs
# (exact to floating point): Tot sum = AVG * Number, Tot size = AVG, Variance = Std^2.
# Stage 2 re-verifies them on the training split and project() recomputes the ones that hold;
# derived fields without a verified identity are held at their source value.
DERIVED = ["Tot sum", "Tot size", "Variance", "Magnitue", "Radius", "Covariance", "Weight"]
IDENTITIES = {"Tot sum": lambda X: X["AVG"] * X["Number"],
              "Tot size": lambda X: X["AVG"],
              "Variance": lambda X: X["Std"] ** 2}
ORDER_CONSTRAINTS = [("Min", "AVG"), ("AVG", "Max")]       # a <= b


def make_cfg(**over):
    cfg = json.loads(json.dumps(DEFAULT_CFG))
    for k, v in over.items():
        if isinstance(v, dict) and isinstance(cfg.get(k), dict):
            cfg[k].update(v)
        else:
            cfg[k] = v
    if not cfg["data_dir"] or not cfg["out_dir"]:
        raise ValueError("set data_dir and out_dir")
    os.makedirs(cfg["out_dir"], exist_ok=True)
    p = os.path.join(cfg["out_dir"], "config.json")
    if os.path.exists(p):           # a run keeps its first configuration
        saved = json.load(open(p))
        changed = {k for k in cfg if k in saved and saved[k] != cfg[k]
                   and k not in ("data_dir", "out_dir")}
        if changed:
            print(f"[config] keeping saved values for {sorted(changed)} "
                  f"(delete config.json to start a new run)")
        saved.update({"data_dir": cfg["data_dir"], "out_dir": cfg["out_dir"]})
        added = [k for k in cfg if k not in saved]
        for k in added:                 # settings introduced after this run started
            saved[k] = cfg[k]
        if added:
            _atomic_json(p, saved)
        cfg = saved
    else:
        _atomic_json(p, cfg)
    return cfg


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------
def P(cfg, *parts):
    path = os.path.join(cfg["out_dir"], *parts)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    return path

def _atomic_json(path, obj):
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(obj, f, indent=2, default=_np_default)
    os.replace(tmp, path)

def _np_default(o):
    if isinstance(o, (np.integer,)): return int(o)
    if isinstance(o, (np.floating,)): return float(o)
    if isinstance(o, np.ndarray): return o.tolist()
    return str(o)

def _atomic_parquet(df, path):
    tmp = path + ".tmp"
    df.to_parquet(tmp, index=False)
    os.replace(tmp, path)

def _atomic_npy(arr, path):
    tmp = path + ".tmp.npy"
    np.save(tmp, arr)
    os.replace(tmp, path)

def log(msg):
    print(time.strftime("%H:%M:%S"), msg, flush=True)

def gpu_available():
    try:
        import subprocess
        return subprocess.run(["nvidia-smi"], capture_output=True).returncode == 0
    except Exception:
        return False

def load_split(cfg, name):
    src = cfg.get("stage0_from")
    if src:                                 # reuse the splits of an earlier run
        return pd.read_parquet(os.path.join(src, "stage0", f"{name}.parquet"))
    return pd.read_parquet(P(cfg, "stage0", f"{name}.parquet"))

def feature_cols(cfg, df):
    drop = {LABEL, FAMILY, WEIGHT, GROUP} | set(cfg.get("drop_features", []))
    return [c for c in df.columns if c not in drop]


# --------------------------------------------------------------------------
# STAGE 0 - data
# --------------------------------------------------------------------------
def _list_csvs(data_dir):
    """Return [(path, folder_label_or_None)].
    Merged layout : data_dir/*.csv                (label column inside each file)
    Per-class     : data_dir/<LabelFolder>/*.csv  (one folder per label, one file per capture)"""
    flat = sorted(glob.glob(os.path.join(data_dir, "*.csv")))
    nested = sorted(glob.glob(os.path.join(data_dir, "*", "**", "*.csv"), recursive=True))
    out = [(f, None) for f in flat]
    for f in nested:
        out.append((f, os.path.basename(os.path.dirname(f))))   # label = immediate parent folder
    return out

# per-class folder names that differ from the official 34-class label strings
FOLDER_LABEL_FIX = {"DDoS-PSHACK_FLOOD": "DDoS-PSHACK_Flood", "DDoS-RSTFINFLOOD": "DDoS-RSTFINFlood"}

def folder_to_label(folder):
    if folder is None: return None
    if folder.lower().startswith("benign"): return "BenignTraffic"
    return FOLDER_LABEL_FIX.get(folder, folder)

def _cache_key(data_dir, f):
    rel = os.path.relpath(f, data_dir)
    # "v2" keeps samples cached by earlier code versions from being reused
    return "v2_" + hashlib.md5(rel.encode()).hexdigest()[:10] + "_" + os.path.splitext(os.path.basename(f))[0][:40]

def _grouped_split(df, seed, min_groups=3):
    """60/20/20 split. Labels with >= min_groups source files are split by whole file
    (each file is a contiguous chunk of the label's capture, so train and test come from
    different time segments); labels with fewer files fall back to a row-level split."""
    rng = np.random.default_rng(seed)
    assign = pd.Series(index=df.index, dtype=object)
    mode = {}
    for lab, g in df.groupby(LABEL):
        groups = g[GROUP].unique()
        if len(groups) >= min_groups:
            rng.shuffle(groups)
            sizes = g.groupby(GROUP).size().loc[groups].values
            cum = np.cumsum(sizes) / sizes.sum()
            part = np.where(cum <= 0.6, "train", np.where(cum <= 0.8, "val", "test"))
            # guarantee at least one file in each part
            part[0], part[-1] = "train", "test"
            if "val" not in part: part[-2] = "val"
            assign.loc[g.index] = g[GROUP].map(dict(zip(groups, part))).values
            mode[lab] = f"file-level ({len(groups)} files)"
        else:
            idx = rng.permutation(g.index.values)
            n = len(idx); a, b = int(0.6 * n), int(0.8 * n)
            assign.loc[idx[:a]], assign.loc[idx[a:b]], assign.loc[idx[b:]] = "train", "val", "test"
            mode[lab] = f"row-level ({len(groups)} file{'s' if len(groups) != 1 else ''})"
    return assign, mode

def stage0_data(cfg):
    if cfg.get("stage0_from"):
        log(f"stage 0 reused from {cfg['stage0_from']}"); return
    if cfg.get("dataset") == "EdgeIIoTset":
        return stage0_edgeiiot(cfg)
    final = P(cfg, "stage0", "test.parquet")
    if os.path.exists(final):
        log("stage 0 already complete"); return
    files = _list_csvs(cfg["data_dir"])
    if not files:
        raise FileNotFoundError(f"no CSV files in {cfg['data_dir']} or its subfolders")
    per_class = any(lbl is not None for _, lbl in files)
    if cfg["max_files"] and not per_class:
        rng = np.random.default_rng(cfg["seed"])
        pick = sorted(rng.choice(len(files), size=min(cfg["max_files"], len(files)), replace=False))
        files = [files[i] for i in pick]
    log(f"assuredx_lib {CODE_VERSION}")
    log(f"stage 0: {len(files)} CSV files, layout = {'per-class folders' if per_class else 'merged'}")
    cache = (os.path.join(cfg["cache_from"], "stage0", "cache") if cfg.get("cache_from")
             else P(cfg, "stage0", "cache", "x")[:-1])
    for i, (f, folder) in enumerate(files):
        key = _cache_key(cfg["data_dir"], f)
        out, cnt = os.path.join(cache, key + ".parquet"), os.path.join(cache, key + ".counts.json")
        if os.path.exists(out) and os.path.exists(cnt):
            continue
        df = pd.read_csv(f, low_memory=False)
        df.columns = [c.strip() for c in df.columns]
        if LABEL not in df.columns and "Label" in df.columns:
            df = df.rename(columns={"Label": LABEL})
        if LABEL not in df.columns:
            if folder is None:
                raise KeyError(f"{f} has no '{LABEL}' column and is not inside a label folder")
            df[LABEL] = folder_to_label(folder)
        df[FAMILY] = df[LABEL].map(family_of)
        counts = df[LABEL].value_counts().to_dict()
        seed = (cfg["seed"] * 1000003 + int(hashlib.md5(key.encode()).hexdigest()[:6], 16)) % 2**31
        if per_class:
            cap_f = cfg["benign_rows_per_file"] if family_of(folder_to_label(folder)) == "Benign" \
                    else cfg["max_rows_per_file"]
            s = df if len(df) <= cap_f else df.sample(n=cap_f, random_state=seed)
        else:
            parts = []
            for fam, g in df.groupby(FAMILY):
                frac = cfg["family_frac"].get(fam, 1.0)
                parts.append(g if frac >= 1 else g.sample(frac=frac, random_state=seed))
            s = pd.concat(parts)
        num = [c for c in s.columns if c not in (LABEL, FAMILY)]
        s = s.copy()
        s[num] = s[num].apply(pd.to_numeric, errors="coerce").astype("float32")
        s[GROUP] = os.path.relpath(f, cfg["data_dir"])
        _atomic_parquet(s, out)
        _atomic_json(cnt, {"file": os.path.relpath(f, cfg["data_dir"]), "bytes": os.path.getsize(f),
                           "label_counts": counts})
        log(f"  [{i+1}/{len(files)}] {os.path.relpath(f, cfg['data_dir'])}: kept {len(s):,} of {len(df):,}")
        del df, s

    log("stage 0: combining cached samples")
    keys = [_cache_key(cfg["data_dir"], f) for f, _ in files]
    df = pd.concat([pd.read_parquet(os.path.join(cache, k + ".parquet")) for k in keys], ignore_index=True)
    src_label = {}
    for k in keys:
        for lab, v in json.load(open(os.path.join(cache, k + ".counts.json")))["label_counts"].items():
            src_label[lab] = src_label.get(lab, 0) + v
    n0 = len(df)
    unknown = sorted(df.loc[df[FAMILY] == "Unknown", LABEL].unique())
    if unknown:
        print(f"[stage 0] rows with unrecognised labels removed: {unknown}")
    df = df[df[FAMILY] != "Unknown"]
    if df.empty:
        raise RuntimeError("no rows with a recognised CICIoT2023 label; check the class folder names")
    num = [c for c in df.columns if c not in (LABEL, FAMILY, GROUP)]
    df[num] = df[num].replace([np.inf, -np.inf], np.nan)
    df = df.dropna(subset=num)
    log(f"  removed {n0 - len(df):,} rows (unknown label / NaN / inf)")
    # caps: per label first (keeps the 34 labels balanced inside a family), then per family
    # benign is a single label, so it is limited only by the family cap
    keep_idx = [g.sample(n=min(len(g), cfg["cap_per_family"] if family_of(lab) == "Benign"
                               else cfg["cap_per_label"]), random_state=cfg["seed"]).index
                for lab, g in df.groupby(LABEL)]
    df = df.loc[np.concatenate(keep_idx)]
    keep_idx = [g.sample(n=min(len(g), cfg["cap_per_family"]), random_state=cfg["seed"]).index
                for _, g in df.groupby(FAMILY)]
    df = df.loc[np.concatenate(keep_idx)]
    kept_label = df[LABEL].value_counts().to_dict()
    df[WEIGHT] = df[LABEL].map({k: src_label.get(k, 0) / v for k, v in kept_label.items()}).astype("float32")

    if per_class and cfg.get("split_mode", "file") == "file":
        assign, mode = _grouped_split(df, cfg["seed"], cfg["min_files_for_file_split"])
        tr, va, te = (df[assign == s] for s in ("train", "val", "test"))
    else:
        from sklearn.model_selection import train_test_split
        strat = df[LABEL].where(df[LABEL].map(df[LABEL].value_counts()) >= 10, df[FAMILY])
        strat = strat.where(strat.map(strat.value_counts()) >= 10, "rare")
        tr, rest = train_test_split(df, test_size=0.4, random_state=cfg["seed"], stratify=strat)
        va, te = train_test_split(rest, test_size=0.5, random_state=cfg["seed"], stratify=strat.loc[rest.index])
        why = "requested row-level split" if per_class else "merged CSV, no capture identifiers"
        mode = {lab: f"row-level ({why})" for lab in df[LABEL].unique()}
    for name, part in (("train", tr), ("val", va), ("test", te)):
        _atomic_parquet(part.reset_index(drop=True), P(cfg, "stage0", f"{name}.parquet"))

    files_per_label = df.groupby(LABEL)[GROUP].nunique().to_dict()
    manifest = {
        "dataset": cfg["dataset"], "layout": "per-class" if per_class else "merged",
        "split_mode": cfg.get("split_mode", "file"), "dropped_features": cfg.get("drop_features", []),
        "n_files": len(files),
        "files": [{"name": os.path.relpath(f, cfg["data_dir"]), "bytes": os.path.getsize(f)} for f, _ in files],
        "source_label_counts": src_label, "kept_label_counts": kept_label,
        "kept_family_counts": df[FAMILY].value_counts().to_dict(),
        "files_per_label": files_per_label, "split_mode_per_label": mode,
        "split_sizes": {"train": len(tr), "val": len(va), "test": len(te)},
        "split_family_counts": {n: p[FAMILY].value_counts().to_dict()
                                for n, p in (("train", tr), ("val", va), ("test", te))},
        "split_label_counts": {n: p[LABEL].value_counts().to_dict()
                               for n, p in (("train", tr), ("val", va), ("test", te))},
        "seed": cfg["seed"], "max_rows_per_file": cfg["max_rows_per_file"],
        "cap_per_label": cfg["cap_per_label"], "cap_per_family": cfg["cap_per_family"],
        "natural_weight_note": "weights restore the label mix of the files read; they match the "
                               "full-dataset mix only if every file of every label was downloaded",
        "versions": {"python": platform.python_version(), "pandas": pd.__version__,
                     "numpy": np.__version__},
    }
    _atomic_json(P(cfg, "stage0", "manifest.json"), manifest)
    log(f"stage 0 done: train {len(tr):,}  val {len(va):,}  test {len(te):,}")
    summary = pd.DataFrame({"files": pd.Series(files_per_label), "kept rows": pd.Series(kept_label),
                            "split": pd.Series(mode)})
    print(summary.to_string())
    missing = [s for s in ("train", "val", "test")
               if set(df[LABEL].unique()) - set({"train": tr, "val": va, "test": te}[s][LABEL].unique())]
    if missing:
        print("[stage 0] some labels are absent from:", missing)



# --------------------------------------------------------------------------
# Edge-IIoTset (raw per-attack and per-sensor CSV files)
# --------------------------------------------------------------------------
# Numeric packet fields kept as features. Identifiers and capture artefacts are excluded:
# timestamps, IP addresses, checksums, sequence/ack numbers, stream and frame indices,
# Modbus transaction ids, source ports, and every free-text payload field.
EDGE_NUMERIC = ["arp.opcode", "arp.hw.size", "http.content_length", "http.response",
                "http.tls_port", "tcp.connection.fin", "tcp.connection.rst", "tcp.connection.syn",
                "tcp.connection.synack", "tcp.dstport", "tcp.flags", "tcp.flags.ack", "tcp.len",
                "udp.port", "udp.time_delta", "dns.qry.name.len", "dns.qry.qu", "dns.qry.type",
                "dns.retransmission", "dns.retransmit_request", "mqtt.conflag.cleansess",
                "mqtt.conflags", "mqtt.hdrflags", "mqtt.len", "mqtt.msg_decoded_as", "mqtt.msgtype",
                "mqtt.proto_len", "mqtt.topic_len", "mqtt.ver", "mbtcp.len", "mbtcp.unit_id"]
EDGE_ENGINEERED = ["Protocol Type", "http_GET", "http_POST", "http_other_method",
                   "http_v10", "http_v11", "mqtt_proto", "tcp_opt_len"]
EDGE_MUTABLE = ["tcp.len", "http.content_length", "udp.time_delta", "dns.qry.name.len",
                "dns.retransmission", "dns.retransmit_request", "mqtt.len", "mqtt.proto_len",
                "mqtt.topic_len", "mbtcp.len", "tcp_opt_len"]
EDGE_IMMUTABLE = [f for f in EDGE_NUMERIC + EDGE_ENGINEERED if f not in EDGE_MUTABLE]
PLACEHOLDERS = {"0", "0.0", "", "nan"}
_TIME_RE = r"^\s*(?:[A-Za-z]{3}\s+\d{1,2},)?\s*\d{4}\s+\d{2}:\d{2}:\d{2}\.\d+\s*$"

def _edge_features(c):
    """c: chunk read with dtype=str. Returns (features DataFrame, valid mask, time-of-day seconds).
    Both placeholder spellings ('0' and '0.0') map to 0, which removes the provenance artefact."""
    ft = c["frame.time"].fillna("").astype(str)
    valid = np.array(ft.str.match(_TIME_RE).values, dtype=bool, copy=True)
    tod = pd.to_timedelta(ft.str.extract(r"(\d{2}:\d{2}:\d{2}\.\d+)\s*$")[0], errors="coerce").dt.total_seconds()
    out = {}
    for col in EDGE_NUMERIC:
        v = c[col].fillna("0").astype(str).str.strip()
        v = v.where(~v.isin(PLACEHOLDERS), "0")
        num = pd.to_numeric(v, errors="coerce")
        hx = num.isna() & v.str.fullmatch(r"0[xX][0-9a-fA-F]+")     # e.g. tcp.flags = 0x00000018
        if hx.any():
            num[hx] = v[hx].map(lambda t: float(int(t, 16)))
        valid &= num.notna().values
        out[col] = num.fillna(0).values
    meth = c["http.request.method"].fillna("0").astype(str).str.strip()
    ver = c["http.request.version"].fillna("0").astype(str).str.strip()
    real_m = ~meth.isin(PLACEHOLDERS)
    out["http_GET"] = (meth == "GET").astype(float).values
    out["http_POST"] = (meth == "POST").astype(float).values
    out["http_other_method"] = (real_m & ~meth.isin(["GET", "POST"])).astype(float).values
    out["http_v10"] = (ver == "HTTP/1.0").astype(float).values
    out["http_v11"] = (ver == "HTTP/1.1").astype(float).values
    out["mqtt_proto"] = (c["mqtt.protoname"].fillna("").astype(str).str.strip() == "MQTT").astype(float).values
    opt = c["tcp.options"].fillna("0").astype(str).str.strip()
    hexopt = opt.str.fullmatch(r"[0-9a-fA-F]+") & ~opt.isin(PLACEHOLDERS) & (opt.str.len() % 2 == 0)
    out["tcp_opt_len"] = np.where(hexopt, opt.str.len() / 2, 0.0)
    X = pd.DataFrame(out)
    icmp = ~c["icmp.checksum"].fillna("0").astype(str).str.strip().isin(PLACEHOLDERS)
    tcp = (X["tcp.dstport"] > 0) | (X["tcp.flags"] > 0) | (X["tcp.len"] > 0)
    udp = X["udp.port"] > 0
    X["Protocol Type"] = np.select([tcp.values, udp.values, icmp.values], [6.0, 17.0, 1.0], 0.0)
    return X[EDGE_NUMERIC + EDGE_ENGINEERED].astype("float32"), valid, tod.values

def _count_rows(path):
    n = 0
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 24), b""):
            n += block.count(b"\n")
    return max(n - 1, 0)

def stage0_edgeiiot(cfg):
    final = P(cfg, "stage0", "test.parquet")
    if os.path.exists(final):
        log("stage 0 already complete"); return
    root = cfg["data_dir"]
    files = sorted([f for f in glob.glob(os.path.join(root, "**", "*.csv"), recursive=True)
                    if "Selected dataset" not in f])
    if not files:
        raise FileNotFoundError(f"no Edge-IIoTset CSV files under {root}")
    log(f"assuredx_lib {CODE_VERSION}")
    log(f"stage 0 (Edge-IIoTset): {len(files)} raw CSV files")
    cache = P(cfg, "stage0", "cache", "x")[:-1]
    for i, f in enumerate(files):
        key = _cache_key(root, f)
        out, cnt = os.path.join(cache, key + ".parquet"), os.path.join(cache, key + ".counts.json")
        if os.path.exists(out) and os.path.exists(cnt):
            continue
        t0 = time.time()
        total = _count_rows(f)
        normal = "Normal traffic" in f
        cap = cfg["edge_rows_normal_file"] if normal else cfg["edge_rows_attack_file"]
        frac = min(1.0, cap / max(total, 1) * 1.15)
        rng = np.random.default_rng((cfg["seed"] * 1000003 + int(hashlib.md5(key.encode()).hexdigest()[:6], 16)) % 2**31)
        parts, labels, n_valid, start = [], {}, 0, 0
        for c in pd.read_csv(f, dtype=str, chunksize=200_000, low_memory=False):
            c.columns = [x.strip() for x in c.columns]
            X, valid, tod = _edge_features(c)
            lab = c["Attack_type"].fillna("Unknown").astype(str).str.strip().values
            idx = np.arange(start, start + len(c)); start += len(c)
            n_valid += int(valid.sum())
            for l in np.unique(lab[valid]): labels[l] = labels.get(l, 0) + int((lab[valid] == l).sum())
            keep = valid & (rng.random(len(c)) < frac)
            if keep.any():
                Xk = X[keep].copy()
                Xk[LABEL] = lab[keep]; Xk["_row"] = idx[keep]; Xk["_tod"] = tod[keep]
                parts.append(Xk)
        s = pd.concat(parts, ignore_index=True) if parts else pd.DataFrame(columns=EDGE_NUMERIC + EDGE_ENGINEERED + [LABEL, "_row", "_tod"])
        if len(s) > cap: s = s.sample(n=cap, random_state=int(rng.integers(1 << 30)))
        s["_pos"] = s["_row"] / max(start, 1)
        s[GROUP] = os.path.relpath(f, root)
        _atomic_parquet(s, out)
        _atomic_json(cnt, {"file": os.path.relpath(f, root), "rows": start, "valid_rows": n_valid,
                           "valid_fraction": n_valid / max(start, 1), "label_counts": labels})
        log(f"  [{i+1}/{len(files)}] {os.path.relpath(f, root)}: {start:,} rows, "
            f"{n_valid/max(start,1):.1%} aligned, kept {len(s):,} ({time.time()-t0:.0f}s)")

    log("stage 0: combining")
    keys = [_cache_key(root, f) for f in files]
    df = pd.concat([pd.read_parquet(os.path.join(cache, k + ".parquet")) for k in keys], ignore_index=True)
    info = [json.load(open(os.path.join(cache, k + ".counts.json"))) for k in keys]
    src_label = {}
    for d in info:
        for l, v in d["label_counts"].items(): src_label[l] = src_label.get(l, 0) + v
    df[FAMILY] = df[LABEL].map(lambda l: EDGE_FAMILY.get(l, "Unknown"))
    df = df[df[FAMILY] != "Unknown"]
    # each label is capped, then each family
    keep = [g.sample(n=min(len(g), cfg["cap_per_family"] if EDGE_FAMILY.get(l) == "Benign" else cfg["cap_per_label"]),
                     random_state=cfg["seed"]).index for l, g in df.groupby(LABEL)]
    df = df.loc[np.concatenate(keep)]
    keep = [g.sample(n=min(len(g), cfg["cap_per_family"]), random_state=cfg["seed"]).index
            for _, g in df.groupby(FAMILY)]
    df = df.loc[np.concatenate(keep)]
    kept = df[LABEL].value_counts().to_dict()
    df[WEIGHT] = df[LABEL].map({k: src_label.get(k, 0) / v for k, v in kept.items()}).astype("float32")

    # split: labels with >= 3 source files -> whole files; single-file labels -> temporal
    # blocks inside the capture (first 60% train, next 20% validation, last 20% test)
    rng = np.random.default_rng(cfg["seed"]); assign = pd.Series(index=df.index, dtype=object); mode = {}
    for lab, g in df.groupby(LABEL):
        files_l = g[GROUP].unique()
        if len(files_l) >= cfg["min_files_for_file_split"]:
            rng.shuffle(files_l)
            sizes = g.groupby(GROUP).size().loc[files_l].values
            cum = np.cumsum(sizes) / sizes.sum()
            part = np.where(cum <= 0.6, "train", np.where(cum <= 0.8, "val", "test"))
            part[0], part[-1] = "train", "test"
            if "val" not in part: part[-2] = "val"
            assign.loc[g.index] = g[GROUP].map(dict(zip(files_l, part))).values
            mode[lab] = f"file-level ({len(files_l)} files)"
        else:
            p = g["_pos"].values
            assign.loc[g.index] = np.where(p < 0.6, "train", np.where(p < 0.8, "val", "test"))
            mode[lab] = "temporal within capture (60/20/20 by packet order)"
            # bootstrap clusters: 20 contiguous time blocks per capture
            df.loc[g.index, GROUP] = g[GROUP] + "#b" + (np.minimum(p * 20, 19).astype(int)).astype(str)
    tr, va, te = (df[assign == s] for s in ("train", "val", "test"))
    drop = ["_row", "_tod", "_pos"]
    for name, part in (("train", tr), ("val", va), ("test", te)):
        _atomic_parquet(part.drop(columns=drop).reset_index(drop=True), P(cfg, "stage0", f"{name}.parquet"))
    manifest = {"dataset": "EdgeIIoTset", "layout": "raw per-attack / per-sensor CSV",
                "n_files": len(files), "files": info, "source_label_counts": src_label,
                "kept_label_counts": kept, "kept_family_counts": df[FAMILY].value_counts().to_dict(),
                "split_mode_per_label": mode,
                "split_sizes": {"train": len(tr), "val": len(va), "test": len(te)},
                "split_family_counts": {n: p[FAMILY].value_counts().to_dict()
                                        for n, p in (("train", tr), ("val", va), ("test", te))},
                "features": EDGE_NUMERIC + EDGE_ENGINEERED,
                "artefact_handling": "placeholder spellings '0' and '0.0' mapped to 0; identifiers, "
                                     "timestamps, checksums, sequence numbers, stream indices and "
                                     "free-text fields excluded; rows with misaligned columns dropped",
                "seed": cfg["seed"], "versions": {"python": platform.python_version(),
                                                  "pandas": pd.__version__, "numpy": np.__version__}}
    _atomic_json(P(cfg, "stage0", "manifest.json"), manifest)
    log(f"stage 0 done: train {len(tr):,}  val {len(va):,}  test {len(te):,}")
    print(pd.DataFrame({"kept": pd.Series(kept), "split": pd.Series(mode)}).to_string())
    bad = [d["file"] for d in info if d["valid_fraction"] < 0.5]
    if bad: print("[stage 0] files with mostly misaligned columns (excluded in practice):", bad)


# --------------------------------------------------------------------------
# STAGE 1 - detectors
# --------------------------------------------------------------------------
def _xgb(cfg, objective, num_class=None, seed=0):
    import xgboost as xgb
    p = dict(cfg["xgb_params"])
    p.update(random_state=seed, objective=objective, n_jobs=-1,
             device="cuda" if gpu_available() else "cpu")
    if num_class:
        p["num_class"] = num_class
        p["eval_metric"] = "mlogloss"
    else:
        p["eval_metric"] = "logloss"
    return xgb.XGBClassifier(**p)

def _binary_metrics(y, score, thr, w=None):
    from sklearn.metrics import (precision_score, recall_score, f1_score,
                                 accuracy_score, roc_auc_score, confusion_matrix)
    pred = (score >= thr).astype(int)
    tn, fp, fn, tp = confusion_matrix(y, pred, labels=[0, 1], sample_weight=w).ravel()
    return {"accuracy": accuracy_score(y, pred, sample_weight=w),
            "precision": precision_score(y, pred, sample_weight=w, zero_division=0),
            "attack_recall": recall_score(y, pred, sample_weight=w, zero_division=0),
            "fpr": fp / max(fp + tn, 1e-12),
            "macro_f1": f1_score(y, pred, average="macro", sample_weight=w),
            "auc": roc_auc_score(y, score, sample_weight=w)}

def _pick_threshold(y, score):
    from sklearn.metrics import f1_score
    grid = np.unique(np.quantile(score, np.linspace(0.001, 0.999, 999)))
    best = max(grid, key=lambda t: f1_score(y, (score >= t).astype(int), average="macro"))
    return float(best)

def stage1_detectors(cfg):
    import joblib
    from sklearn.metrics import accuracy_score, f1_score, classification_report
    tr, va, te = (load_split(cfg, s) for s in ("train", "val", "test"))
    feats = feature_cols(cfg, tr)
    Xtr, Xva, Xte = (d[feats].values for d in (tr, va, te))
    ytr, yva, yte = ((d[FAMILY] != "Benign").astype(int).values for d in (tr, va, te))
    log(f"stage 1: {len(feats)} features, device={'cuda' if gpu_available() else 'cpu'}")

    rows_path = P(cfg, "stage1", "binary_metrics.csv")
    rows = pd.read_csv(rows_path).to_dict("records") if os.path.exists(rows_path) else []
    done = {(r["model"], r["seed"]) for r in rows}
    for s in cfg["detector_seeds"]:
        if ("xgb", s) in done: continue
        t0 = time.time()
        m = _xgb(cfg, "binary:logistic", seed=s)
        m.fit(Xtr, ytr, eval_set=[(Xva, yva)], verbose=False)
        m.save_model(P(cfg, "stage1", f"xgb_bin_seed{s}.json"))
        thr = _pick_threshold(yva, m.predict_proba(Xva)[:, 1])
        sc = m.predict_proba(Xte)[:, 1]
        for view, w in (("sampled", None), ("natural", te[WEIGHT].values)):
            r = {"model": "xgb", "seed": s, "view": view, "threshold": thr,
                 "best_iteration": int(m.best_iteration), "train_sec": time.time() - t0}
            r.update(_binary_metrics(yte, sc, thr, w)); rows.append(r)
        pd.DataFrame(rows).to_csv(rows_path + ".tmp", index=False); os.replace(rows_path + ".tmp", rows_path)
        log(f"  xgb seed {s}: macro-F1 {rows[-2]['macro_f1']:.4f}  thr {thr:.4f}")

    if ("rf", 0) not in done:
        from sklearn.ensemble import RandomForestClassifier
        rng = np.random.default_rng(cfg["seed"])
        idx = rng.choice(len(Xtr), size=min(cfg["rf_train_max"], len(Xtr)), replace=False)
        best = None
        for leaf in cfg["rf_leaf_grid"]:
            rf = RandomForestClassifier(cfg["rf_trees"], min_samples_leaf=leaf, n_jobs=-1,
                                        random_state=0).fit(Xtr[idx], ytr[idx])
            f1 = f1_score(yva, rf.predict(Xva), average="macro")
            log(f"  rf leaf={leaf}: val macro-F1 {f1:.4f}")
            if best is None or f1 > best[0]: best = (f1, leaf, rf)
        _, leaf, rf = best
        joblib.dump(rf, P(cfg, "stage1", "rf_bin_seed0.joblib"), compress=3)
        thr = _pick_threshold(yva, rf.predict_proba(Xva)[:, 1])
        sc = rf.predict_proba(Xte)[:, 1]
        for view, w in (("sampled", None), ("natural", te[WEIGHT].values)):
            r = {"model": "rf", "seed": 0, "view": view, "threshold": thr,
                 "min_samples_leaf": leaf}
            r.update(_binary_metrics(yte, sc, thr, w)); rows.append(r)
        pd.DataFrame(rows).to_csv(rows_path, index=False)

    # multiclass detectors for comparison with published CICIoT2023 results
    mc_path = P(cfg, "stage1", "multiclass_metrics.csv")
    mrows = pd.read_csv(mc_path).to_dict("records") if os.path.exists(mc_path) else []
    for task, col in (("8class", FAMILY), ("34class", LABEL)):
        if any(r["task"] == task for r in mrows): continue
        classes = sorted(tr[col].unique())
        enc = {c: i for i, c in enumerate(classes)}
        keep_va, keep_te = va[col].isin(enc).values, te[col].isin(enc).values
        m = _xgb(cfg, "multi:softprob", num_class=len(classes), seed=0)
        m.fit(Xtr, tr[col].map(enc).values,
              eval_set=[(Xva[keep_va], va[col][keep_va].map(enc).values)], verbose=False)
        m.save_model(P(cfg, "stage1", f"xgb_{task}_seed0.json"))
        yt = te[col][keep_te].map(enc).values
        pr = m.predict(Xte[keep_te])
        for view, w in (("sampled", None), ("natural", te[WEIGHT].values[keep_te])):
            mrows.append({"task": task, "view": view, "n_classes": len(classes),
                          "accuracy": accuracy_score(yt, pr, sample_weight=w),
                          "macro_f1": f1_score(yt, pr, average="macro", sample_weight=w),
                          "weighted_f1": f1_score(yt, pr, average="weighted", sample_weight=w)})
        rep = classification_report(yt, pr, labels=list(range(len(classes))), target_names=classes, output_dict=True, zero_division=0)
        _atomic_json(P(cfg, "stage1", f"report_{task}.json"), rep)
        pd.DataFrame(mrows).to_csv(mc_path, index=False)
        log(f"  {task}: macro-F1 {mrows[-2]['macro_f1']:.4f}")

    summ = pd.read_csv(rows_path).groupby(["model", "view"]).agg(["mean", "std"])
    summ = summ[[c for c in summ.columns if c[0] in ("accuracy", "precision", "attack_recall", "fpr", "macro_f1", "auc")]]
    summ.to_csv(P(cfg, "stage1", "binary_summary.csv"))
    log("stage 1 done")
    print(summ.round(4).to_string())
    print(pd.read_csv(mc_path).round(4).to_string())


# --------------------------------------------------------------------------
# STAGE 2 - feature taxonomy, ranges, scales, strata
# --------------------------------------------------------------------------
def stratum_of(protocol_type):
    """Protocol stratum from the (window-averaged) IP protocol number."""
    pt = np.asarray(protocol_type, dtype=float)
    out = np.full(pt.shape, "other", dtype=object)
    out[np.abs(pt - 1) < 0.5] = "icmp"
    out[np.abs(pt - 6) < 0.5] = "tcp"
    out[np.abs(pt - 17) < 0.5] = "udp"
    return out

def stage2_taxonomy(cfg):
    path = P(cfg, "stage2", "taxonomy.json")
    if os.path.exists(path):
        log("stage 2 already complete"); return json.load(open(path))
    tr = load_split(cfg, "train")
    feats = feature_cols(cfg, tr)
    roles, unknown = {}, []
    edge = cfg.get("dataset") == "EdgeIIoTset"
    for f in feats:
        if edge:
            if f in EDGE_IMMUTABLE: roles[f] = "immutable"
            elif f in EDGE_MUTABLE: roles[f] = "mutable"
            else: roles[f] = "immutable"; unknown.append(f)   # conservative default
            continue
        if f in IMMUTABLE: roles[f] = "immutable"
        elif f in DERIVED: roles[f] = "derived"
        elif f in COUNTS or f in SIZE_STATS or f in TIMING_RATE: roles[f] = "mutable"
        else: roles[f] = "mutable"; unknown.append(f)
    if unknown:
        print("[stage 2] columns not in the CICIoT2023 schema, treated as mutable:", unknown)
    X = tr[feats].astype("float64")

    # verify the derived-field identities and order constraints on the training split
    identities = {}
    for f, fn in IDENTITIES.items():
        try:
            pred = fn(X)
        except KeyError:
            continue
        if f not in X: continue
        rel = (np.abs(X[f] - pred) / (np.abs(X[f]) + 1.0))
        ok = float((rel < 1e-4).mean())
        identities[f] = {"holds_fraction": ok, "max_rel_err": float(rel.max()), "used": ok >= 0.999}
    orders = []
    for lo_f, hi_f in ORDER_CONSTRAINTS:
        if lo_f in X and hi_f in X:
            frac = float((X[lo_f] <= X[hi_f] + 1e-6).mean())
            orders.append({"lo": lo_f, "hi": hi_f, "holds_fraction": frac, "used": frac >= 0.999})

    lo = X.quantile(0.001).to_dict(); hi = X.quantile(0.999).to_dict()
    for f in feats:                                 # non-negative physical quantities
        if X[f].min() >= 0: lo[f] = max(lo[f], 0.0)
    mutable = [f for f in feats if roles[f] == "mutable"]
    std = X[mutable].std().replace(0, np.nan).fillna(1.0)
    scale = {f: float(1.0 / std[f]) for f in mutable}   # W diagonal (inverse scale)
    strata = pd.Series(stratum_of(tr["Protocol Type"].values) if "Protocol Type" in tr else "all")
    tax = {"features": feats, "roles": roles, "mutable": mutable,
           "immutable": [f for f in feats if roles[f] == "immutable"],
           "derived": [f for f in feats if roles[f] == "derived"],
           "identities": identities, "order_constraints": orders,
           "lo": lo, "hi": hi, "W": scale,
           "strata_counts": strata.value_counts().to_dict(),
           "stratum_rule": "Protocol Type rounded to ICMP(1)/TCP(6)/UDP(17)/other"}
    _atomic_json(path, tax)
    tab = pd.DataFrame({"role": roles, "lo": lo, "hi": hi}).loc[feats]
    tab.to_csv(P(cfg, "stage2", "feature_roles.csv"))
    log(f"stage 2 done: {len(mutable)} mutable, {len(tax['immutable'])} immutable, "
        f"{len(tax['derived'])} derived; strata {tax['strata_counts']}")
    print("derived-field identities:", json.dumps(identities, indent=1))
    print("order constraints:", orders)
    return tax

def project(X, X_orig, tax):
    """Numerical-feasibility projection used by the attack stages (V_num).
    Immutable fields are restored, mutable fields clipped to training ranges, verified order
    constraints enforced, and derived fields recomputed from their verified identities
    (or held at the source value when no identity was verified)."""
    X = X.copy()
    for f in tax["immutable"] + tax["derived"]:
        if f in X: X[f] = X_orig[f].values
    for f in tax["mutable"]:
        X[f] = X[f].clip(tax["lo"][f], tax["hi"][f])
    for c in tax.get("order_constraints", []):
        if c["used"]:
            a, b = X[c["lo"]].values, X[c["hi"]].values
            X[c["lo"]], X[c["hi"]] = np.minimum(a, b), np.maximum(a, b)
    if "Std" in X: X["Std"] = X["Std"].clip(lower=0)
    for f, info in tax.get("identities", {}).items():
        if info["used"] and f in X:
            X[f] = IDENTITIES[f](X).values
    return X


# --------------------------------------------------------------------------
# STAGE 3 - explanations, diagnosers, decoy groups, eligible sets
# --------------------------------------------------------------------------
def load_primary_detector(cfg):
    import xgboost as xgb
    b = xgb.Booster(); b.load_model(P(cfg, "stage1", "xgb_bin_seed0.json"))
    m = pd.read_csv(P(cfg, "stage1", "binary_metrics.csv"))
    thr = float(m[(m.model == "xgb") & (m.seed == 0)].threshold.iloc[0])
    return b, thr

def tree_shap(booster, X, batch=50_000):
    """Exact path-dependent TreeSHAP on the margin; returns (n, d) without bias."""
    import xgboost as xgb
    out = []
    for i in range(0, len(X), batch):
        dm = xgb.DMatrix(X[i:i + batch])
        out.append(booster.predict(dm, pred_contribs=True)[:, :-1].astype("float32"))
    return np.vstack(out) if out else np.zeros((0, X.shape[1]), "float32")

def detector_score(booster, X):
    import xgboost as xgb
    return booster.predict(xgb.DMatrix(X))

def topk_membership(S, k):
    idx = np.argsort(-np.abs(S), axis=1, kind="stable")[:, :k]  # stable = fixed tie rule
    M = np.zeros(S.shape, dtype=np.uint8)
    np.put_along_axis(M, idx, 1, axis=1)
    return M

def rich_repr(S):
    return S / (np.abs(S).sum(1, keepdims=True) + 1e-12)

def _fit_diagnoser(cfg, Xtr, ytr, Xva, yva):
    from sklearn.linear_model import LogisticRegression
    from sklearn.metrics import f1_score
    best = None
    for lam in cfg["diag_penalties"]:
        clf = LogisticRegression(C=1.0 / lam, max_iter=3000).fit(Xtr, ytr)
        f1 = f1_score(yva, clf.predict(Xva), average="macro")
        if best is None or f1 > best[0]: best = (f1, lam, clf)
    return best

def stage3_explain(cfg):
    import joblib
    from sklearn.metrics import accuracy_score, f1_score, confusion_matrix
    done_flag = P(cfg, "stage3", "DONE")
    if os.path.exists(done_flag):
        log("stage 3 already complete"); return
    booster, thr = load_primary_detector(cfg)
    feats = json.load(open(P(cfg, "stage2", "taxonomy.json")))["features"]
    rng = np.random.default_rng(cfg["seed"])

    # explain detected attack alerts in each split
    for split in ("train", "val", "test"):
        sp = P(cfg, "stage3", f"shap_{split}.npy")
        if os.path.exists(sp): continue
        d = load_split(cfg, split)
        att = np.where(d[FAMILY].values != "Benign")[0]
        sc = detector_score(booster, d[feats].values[att])
        det = att[sc >= thr]
        if split == "train" and len(det) > cfg["expl_train_max"]:
            det = np.sort(rng.choice(det, cfg["expl_train_max"], replace=False))
        t0 = time.time()
        S = tree_shap(booster, d[feats].values[det])
        log(f"  {split}: {len(det):,} detected alerts explained in {time.time()-t0:.1f}s "
            f"({1000*(time.time()-t0)/max(len(det),1):.3f} ms/alert)")
        _atomic_npy(det, P(cfg, "stage3", f"rows_{split}.npy"))
        _atomic_npy(S, sp)

    load = lambda s: (np.load(P(cfg, "stage3", f"rows_{s}.npy")), np.load(P(cfg, "stage3", f"shap_{s}.npy")))
    (rtr, Str), (rva, Sva), (rte, Ste) = load("train"), load("val"), load("test")
    fam = {s: load_split(cfg, s)[FAMILY].values for s in ("train", "val", "test")}
    ytr, yva, yte = fam["train"][rtr], fam["val"][rva], fam["test"][rte]
    families = sorted(set(ytr))

    # global importance and dominance check
    imp = pd.Series(np.abs(Str).mean(0), index=feats).sort_values(ascending=False)
    imp.to_csv(P(cfg, "stage3", "global_importance.csv"), header=["mean_abs_shap"])
    share = imp.iloc[0] / imp.sum()
    if share > 0.5:
        print(f"[stage 3] WARNING: '{imp.index[0]}' carries {share:.0%} of total |SHAP|. "
              f"Inspect it for collection artefacts before running the attack stages.")

    # decoy groups G_c (training detections only, fixed tie rule)
    #   magnitude: top-m features by mean |SHAP| in family c (all features)
    #   contrast : top-m attacker-mutable features by mean |SHAP| in c minus the mean over
    #              the other families; this is the group used by the attack stages
    m = cfg["decoy_group_size"]
    tax = json.load(open(P(cfg, "stage2", "taxonomy.json")))
    mut = np.array([f in tax["mutable"] for f in feats])
    fam_mean = {f: np.abs(Str[ytr == f]).mean(0) for f in families}
    G_mag, G = {}, {}
    for f in families:
        order = np.lexsort((np.arange(len(feats)), -fam_mean[f]))
        G_mag[f] = [feats[i] for i in order[:m]]
        others = np.mean([fam_mean[o] for o in families if o != f], axis=0)
        score = np.where(mut, fam_mean[f] - others, -np.inf)
        order = np.lexsort((np.arange(len(feats)), -score))
        G[f] = [feats[i] for i in order[:m]]
    def _jac(groups):
        j = pd.DataFrame(index=families, columns=families, dtype=float)
        for a in families:
            for b in families:
                A, B = set(groups[a]), set(groups[b]); j.loc[a, b] = len(A & B) / len(A | B)
        return j
    jac, jac_mag = _jac(G), _jac(G_mag)
    _atomic_json(P(cfg, "stage3", "decoy_groups.json"), G)
    _atomic_json(P(cfg, "stage3", "decoy_groups_magnitude.json"), G_mag)
    jac.to_csv(P(cfg, "stage3", "decoy_group_jaccard.csv"))
    jac_mag.to_csv(P(cfg, "stage3", "decoy_group_jaccard_magnitude.csv"))

    # frozen diagnosers: set-only (per k) and rich representation
    rows, eligible = [], {}
    reps = [(f"set_k{k}", lambda S, k=k: topk_membership(S, k)) for k in cfg["k_values"]
            if k < len(feats)]
    reps.append(("rich", rich_repr))
    for name, fn in reps:
        f1v, lam, clf = _fit_diagnoser(cfg, fn(Str), ytr, fn(Sva), yva)
        joblib.dump(clf, P(cfg, "stage3", f"diagnoser_{name}.joblib"))
        pr = clf.predict(fn(Ste))
        cm = confusion_matrix(yte, pr, labels=families)
        pd.DataFrame(cm, index=families, columns=families).to_csv(P(cfg, "stage3", f"confusion_{name}.csv"))
        per = f1_score(yte, pr, labels=families, average=None)
        rows.append({"representation": name, "lambda": lam, "val_macro_f1": f1v,
                     "test_accuracy": accuracy_score(yte, pr),
                     "test_macro_f1": f1_score(yte, pr, average="macro"),
                     **{f"f1_{f}": v for f, v in zip(families, per)}})
        ok = pr == yte                      # eligible set I_m: detected and correctly diagnosed
        eligible[name] = {"rows": rte[ok].tolist(),
                          "per_family": pd.Series(yte[ok]).value_counts().to_dict()}
        log(f"  diagnoser {name}: test macro-F1 {rows[-1]['test_macro_f1']:.4f}, "
            f"eligible {ok.sum():,}/{len(ok):,}")
    pd.DataFrame(rows).to_csv(P(cfg, "stage3", "diagnoser_metrics.csv"), index=False)
    _atomic_json(P(cfg, "stage3", "eligible_test.json"), eligible)
    open(done_flag, "w").write(time.strftime("%Y-%m-%d %H:%M:%S"))
    log("stage 3 done")
    print("top features:", imp.head(10).round(4).to_dict())
    print(pd.DataFrame(rows).round(4).to_string())
    off = ~np.eye(len(families), dtype=bool)
    print("contrast decoy groups:", json.dumps(G, indent=1))
    print("mean off-diagonal Jaccard: contrast", round(jac.values[off].mean(), 3),
          "| magnitude", round(jac_mag.values[off].mean(), 3))


STAGES = {0: stage0_data, 1: stage1_detectors, 2: stage2_taxonomy, 3: stage3_explain}

if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("stage", type=int, nargs="+")
    ap.add_argument("--data", required=True); ap.add_argument("--out", required=True)
    ap.add_argument("--max-files", type=int, default=None)
    ap.add_argument("--drop", nargs="*", default=None, help="feature columns to exclude")
    ap.add_argument("--reuse-stage0", default=None, help="results folder whose stage-0 splits to reuse")
    ap.add_argument("--cache-from", default=None, help="results folder whose stage-0 file cache to reuse")
    ap.add_argument("--split", choices=["file", "row"], default=None)
    ap.add_argument("--dataset", default=None, help="CICIoT2023 (default) or EdgeIIoTset")
    a = ap.parse_args()
    extra = {}
    if a.drop is not None: extra["drop_features"] = a.drop
    if a.reuse_stage0: extra["stage0_from"] = a.reuse_stage0
    if a.cache_from: extra["cache_from"] = a.cache_from
    if a.split: extra["split_mode"] = a.split
    if a.dataset: extra["dataset"] = a.dataset
    cfg = make_cfg(data_dir=a.data, out_dir=a.out, max_files=a.max_files, **extra)
    for s in a.stage:
        STAGES[s](cfg)
