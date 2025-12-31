import argparse
from datetime import timedelta
import math
import sys
from typing import List, Optional
from pathlib import Path

import numpy as np
import pandas as pd

# -------- Global merge window (overridden by --gap-min) -------- #
MERGE_WINDOW_MIN = 5

# -------- Risk helpers -------- #
RISK_ORDER = {"Low": 1, "Medium": 2, "High": 3}
RISK_INV = {v: k for k, v in RISK_ORDER.items()}

# Column aliases
COL_ALIASES = {
    "Start Time": ["Start Time", "Start", "Time Start"],
    "End Time": ["End Time", "End", "Time End"],
    "Device IP Address": ["Device IP Address", "Device IP", "Device"],
    "Destination IP Address": ["Destination IP Address", "Destination IP", "Dst IP", "DstIP"],
    "Destination Port": ["Destination Port", "Dst Port", "DstPort", "Port"],
    "Threat Category": ["Threat Category", "Category"],
    "Attack Name": ["Attack Name", "Attack", "Vector"],
    "Action": ["Action"],
    "Protocol": ["Protocol", "Proto"],
    "Total Packets Dropped": ["Total Packets Dropped", "Packets Dropped"],
    "Total Mbits Dropped": ["Total Mbits Dropped", "Mbits Dropped"],
    "Max pps": ["Max pps", "Peak pps", "pps max"],
    "Max bps": ["Max bps", "Peak bps", "bps max"],
    "Risk": ["Risk"],
    "Policy Name": ["Policy Name", "Policy"],
}


def resolve_columns(df: pd.DataFrame) -> dict:
    present = {c.lower().strip(): c for c in df.columns}
    resolved = {}
    def find_match(candidates: List[str]) -> Optional[str]:
        for c in candidates:
            if c in df.columns:
                return c
            low = c.lower().strip()
            if low in present:
                return present[low]
        return None
    for canon, candidates in COL_ALIASES.items():
        match = find_match(candidates)
        if match:
            resolved[canon] = match
    required = ["Destination IP Address", "Start Time", "End Time"]
    missing = [r for r in required if r not in resolved]
    if missing:
        raise ValueError(f"Missing required columns: {missing}. Available: {list(df.columns)}")
    return resolved


def parse_datetime_col(s: pd.Series, fmt: Optional[str]) -> pd.Series:
    if fmt:
        return pd.to_datetime(s, format=fmt, errors="coerce")
    return pd.to_datetime(s, errors="coerce", infer_datetime_format=True)


def normalize_port(val) -> Optional[int]:
    if pd.isna(val):
        return None
    s = str(val).strip().lower()
    if s in {"multiple", "unknown", "n/a", "na", "none", "0", ""}:
        return None
    try:
        return int(float(s))
    except Exception:
        return None


def max_risk_label(series: pd.Series) -> str:
    vals = [RISK_ORDER.get(str(x), 0) for x in series.dropna()]
    m = max(vals, default=0)
    return RISK_INV.get(m, "N/A")


def group_campaigns_by_dst(df: pd.DataFrame, cols: dict, gap_minutes: int, split_by_port: bool=False) -> pd.DataFrame:
    w = df.copy()
    if "Destination Port" in cols:
        w["_DestPortNorm"] = w[cols["Destination Port"]].apply(normalize_port)
    else:
        w["_DestPortNorm"] = np.nan
    key_cols = [cols["Destination IP Address"]]
    if split_by_port:
        key_cols.append("_DestPortNorm")
    w = w.sort_values(key_cols + [cols["Start Time"]])

    campaigns = []
    for key, grp in w.groupby(key_cols, dropna=False):
        grp = grp.sort_values(cols["Start Time"])
        current = None
        for _, r in grp.iterrows():
            st = r[cols["Start Time"]]
            et = r[cols["End Time"]]
            if pd.isna(st) or pd.isna(et):
                continue
            if current is None:
                current = {
                    "Destination IP": r[cols["Destination IP Address"]],
                    "PortKey": r.get("_DestPortNorm", None) if split_by_port else None,
                    "Window Start": st,
                    "Window End": et,
                    "Events": [r],
                }
                continue
            gap = st - current["Window End"]
            if gap <= timedelta(minutes=gap_minutes):
                if et > current["Window End"]:
                    current["Window End"] = et
                current["Events"].append(r)
            else:
                campaigns.append(current)
                current = {
                    "Destination IP": r[cols["Destination IP Address"]],
                    "PortKey": r.get("_DestPortNorm", None) if split_by_port else None,
                    "Window Start": st,
                    "Window End": et,
                    "Events": [r],
                }
        if current is not None:
            campaigns.append(current)

    rows = []
    for c in campaigns:
        edf = pd.DataFrame(c["Events"])
        devices = sorted(set(edf.get(cols.get("Device IP Address", "Device IP Address"), pd.Series(dtype="object")).dropna().astype(str)))
        protocols = sorted(set(edf.get(cols.get("Protocol", "Protocol"), pd.Series(dtype="object")).dropna().astype(str)))
        cats = sorted(set(edf.get(cols.get("Threat Category", "Threat Category"), pd.Series(dtype="object")).dropna().astype(str)))
        names = sorted(set(edf.get(cols.get("Attack Name", "Attack Name"), pd.Series(dtype="object")).dropna().astype(str)))
        ports = [int(p) for p in edf.get("_DestPortNorm", pd.Series(dtype="float")).dropna().unique()] if "_DestPortNorm" in edf.columns else []
        dest_ports_label = ",".join(map(str, sorted(ports))) if ports else "Multiple/Unknown"
        total_pkts = edf.get(cols.get("Total Packets Dropped", "Total Packets Dropped"), pd.Series(dtype="float")).sum(skipna=True)
        total_mbits = edf.get(cols.get("Total Mbits Dropped", "Total Mbits Dropped"), pd.Series(dtype="float")).sum(skipna=True)
        peak_pps = edf.get(cols.get("Max pps", "Max pps"), pd.Series(dtype="float")).max(skipna=True)
        peak_bps = edf.get(cols.get("Max bps", "Max bps"), pd.Series(dtype="float")).max(skipna=True)
        risk = max_risk_label(edf.get(cols.get("Risk", "Risk"), pd.Series(dtype="object")))
        rows.append({
            "Destination IP": c["Destination IP"],
            **({"Destination Port (key)": int(c["PortKey"]) if (split_by_port and pd.notna(c["PortKey"])) else np.nan} if split_by_port else {}),
            "Attack Window Start": c["Window Start"],
            "Attack Window End": c["Window End"],
            "Duration (mins)": round((c["Window End"] - c["Window Start"]).total_seconds()/60.0, 2),
            "# Events": int(edf.shape[0]),
            "Devices Involved": ", ".join(devices) if devices else "N/A",
            "Protocols Seen": ", ".join(protocols) if protocols else "N/A",
            "Threat Categories": ", ".join(cats) if cats else "N/A",
            "Vectors (Attack Names)": "; ".join(names) if names else "N/A",
            "Dest Ports": dest_ports_label,
            "Total Packets Dropped": int(total_pkts) if not math.isnan(total_pkts) else np.nan,
            "Total Mbits Dropped": float(total_mbits) if not math.isnan(total_mbits) else np.nan,
            "Peak pps": float(peak_pps) if not math.isnan(peak_pps) else np.nan,
            "Peak bps": float(peak_bps) if not math.isnan(peak_bps) else np.nan,
            "Max Risk": risk,
        })
    out = pd.DataFrame(rows).sort_values(["Attack Window Start", "Destination IP"]).reset_index(drop=True)
    return out


def pick_latest_csv(input_dir: Path) -> Path:
    """Return the latest-modified .csv file in input_dir. Raises SystemExit if none found."""
    input_dir.mkdir(parents=True, exist_ok=True)
    csvs = list(input_dir.glob('*.csv'))
    if not csvs:
        print(f"[ERROR] No .csv files found in {input_dir}. Please place your Radware CSV export there or provide input_csv.", file=sys.stderr)
        sys.exit(4)
    latest = max(csvs, key=lambda p: p.stat().st_mtime)
    print(f"[INFO] Auto-selected latest CSV: {latest}")
    return latest


def main():
    ap = argparse.ArgumentParser(description="Summarize Radware attacks grouped by Destination IP and time windows (optional port split).")
    ap.add_argument("input_csv", nargs='?', default=None, help="Radware CSV filename or path (optional if --input-dir is set; will auto-pick latest .csv)")
    ap.add_argument("--input-dir", default=r"C:\DATA\Scripts\radware_FR_attack_parser\input", help="Directory containing the input CSV (default: C:/DATA/Inputs). If input_csv is omitted, the latest .csv in this dir is used.")
    ap.add_argument("--output-dir", default=None, help="Directory to save output reports (CSV/XLSX). If omitted, outputs are saved next to the input file or current directory.")
    ap.add_argument("--out-csv", default="Attack_Campaigns_By_DstIP_Time.csv", help="Output CSV filename (placed in --output-dir if provided)")
    ap.add_argument("--out-xlsx", default=None, help="Output Excel filename (placed in --output-dir if provided)")
    ap.add_argument("--gap-min", type=int, default=MERGE_WINDOW_MIN, help="Max gap in minutes to merge events into the same attack window (default: MERGE_WINDOW_MIN)")
    ap.add_argument("--time-format", default="%m.%d.%Y %H:%M:%S", help="Datetime format for Start/End Time (default: %m.%d.%Y %H:%M:%S). Leave empty to infer.")
    ap.add_argument("--split-by-port", action="store_true", help="Add Destination Port to the grouping key (split attacks per dest port).")
    ap.add_argument("--encoding", default=None, help="Optional file encoding override (e.g., latin1). If not set, tries utf-8 then latin1.")
    ap.add_argument("--skip-bad-lines", action="store_true", help="Skip malformed CSV lines if any (on_bad_lines='skip').")

    args = ap.parse_args()

    # Resolve input path (auto-pick latest CSV if input_csv omitted)
    input_dir = Path(args.input_dir)
    input_dir.mkdir(parents=True, exist_ok=True)

    if args.input_csv:
        input_path = Path(args.input_csv)
        if not input_path.is_absolute():
            # If a relative/filename-only arg is provided, read from input_dir
            input_path = input_dir / input_path.name
    else:
        input_path = pick_latest_csv(input_dir)

    # Read input CSV
    read_kwargs = dict(engine="python")
    read_kwargs["encoding"] = args.encoding or "utf-8"
    if args.skip_bad_lines:
        read_kwargs["on_bad_lines"] = "skip"
    try:
        df = pd.read_csv(input_path, **read_kwargs)
    except UnicodeDecodeError:
        read_kwargs["encoding"] = "latin1"
        df = pd.read_csv(input_path, **read_kwargs)
    except Exception as ex:
        print(f"[ERROR] Failed reading CSV from {input_path}: {ex}", file=sys.stderr)
        sys.exit(1)

    # Clean columns
    df.columns = [c.strip() for c in df.columns]

    # Resolve columns
    try:
        cols = resolve_columns(df)
    except ValueError as ex:
        print(f"[ERROR] {ex}", file=sys.stderr)
        sys.exit(2)

    # Parse datetimes
    dt_fmt = args.time_format if args.time_format else None
    try:
        df[cols["Start Time"]] = parse_datetime_col(df[cols["Start Time"]], dt_fmt)
        df[cols["End Time"]] = parse_datetime_col(df[cols["End Time"]], dt_fmt)
    except Exception as ex:
        print(f"[ERROR] Failed parsing datetimes: {ex}", file=sys.stderr)
        sys.exit(3)

    # Numeric conversions
    for num_col_key in ["Total Packets Dropped", "Total Mbits Dropped", "Max pps", "Max bps"]:
        if num_col_key in cols:
            df[cols[num_col_key]] = pd.to_numeric(df[cols[num_col_key]], errors="coerce")

    # Build campaigns
    out = group_campaigns_by_dst(df=df, cols=cols, gap_minutes=int(args.gap_min), split_by_port=bool(args.split_by_port))

    # Resolve and create output directory
    if args.output_dir:
        out_dir = Path(args.output_dir)
    else:
        out_dir = input_path.parent if str(input_path.parent) != '.' else Path.cwd()
    out_dir.mkdir(parents=True, exist_ok=True)

    # Write outputs
    csv_path = out_dir / args.out_csv
    out.to_csv(csv_path, index=False)
    print(f"[OK] Wrote CSV: {csv_path} (rows={len(out)})")

    if args.out_xlsx:
        xlsx_path = out_dir / args.out_xlsx
        try:
            out.to_excel(xlsx_path, index=False, engine="openpyxl")
        except Exception:
            out.to_excel(xlsx_path, index=False)
        print(f"[OK] Wrote Excel: {xlsx_path}")


if __name__ == "__main__":
    main()