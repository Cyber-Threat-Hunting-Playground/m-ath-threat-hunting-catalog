#!/usr/bin/env python3
"""
Detect suspicious GitHub PAT reuse from anomalous network context.

This script baselines each PAT on historical usage and then scores newer events
for context drift:
- country change
- network carrier / ASN change
- user-agent family change
- unrealistic travel speed between consecutive uses
- uncommon hour compared with token baseline
"""

from __future__ import annotations

import argparse
import math
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

import pandas as pd


SCENARIO_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCENARIO_DIR.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts.kpi_tracker import KPITracker  # noqa: E402

DEFAULT_INPUT = SCENARIO_DIR / "input" / "github_pat_audit_sample.csv"
DEFAULT_OUTPUT_DIR = SCENARIO_DIR / "output"


REQUIRED_COLUMNS = [
    "@timestamp",
    "actor",
    "pat_id",
    "action",
    "ip_address",
    "country_code",
    "city",
    "latitude",
    "longitude",
    "asn",
    "network_carrier",
    "user_agent",
]


def ua_family(user_agent: str) -> str:
    text = (user_agent or "").lower()
    if "git/" in text:
        return "git-cli"
    if "github-cli" in text or "gh/" in text:
        return "github-cli"
    if "requests/" in text or "python-requests" in text:
        return "python-requests"
    if "curl/" in text:
        return "curl"
    if "go-http-client" in text:
        return "go-http-client"
    if "mozilla/" in text:
        return "browser"
    if "postmanruntime" in text:
        return "postman"
    return "other"


def haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    radius_km = 6371.0
    d_lat = math.radians(lat2 - lat1)
    d_lon = math.radians(lon2 - lon1)
    a = (
        math.sin(d_lat / 2) ** 2
        + math.cos(math.radians(lat1))
        * math.cos(math.radians(lat2))
        * math.sin(d_lon / 2) ** 2
    )
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
    return radius_km * c


@dataclass
class Baseline:
    countries: set[str]
    carriers: set[str]
    asns: set[str]
    ua_families: set[str]
    common_hours: set[int]


def build_baseline(df_train: pd.DataFrame) -> dict[str, Baseline]:
    baselines: dict[str, Baseline] = {}
    for pat_id, group in df_train.groupby("pat_id"):
        hours = group["hour_utc"].dropna().astype(int)
        hour_freq = hours.value_counts(normalize=True)
        # Frequent token usage windows. Floor at 6 hours to avoid overfitting.
        common_hours = set(hour_freq[hour_freq >= 0.05].index.astype(int))
        if len(common_hours) < 6:
            common_hours = set(hours.value_counts().head(6).index.astype(int))

        baselines[pat_id] = Baseline(
            countries={str(v) for v in group["country_code"].dropna().astype(str).unique()},
            carriers={str(v) for v in group["network_carrier"].dropna().astype(str).unique()},
            asns={str(v) for v in group["asn"].dropna().astype(str).unique()},
            ua_families={str(v) for v in group["ua_family"].dropna().astype(str).unique()},
            common_hours=common_hours,
        )
    return baselines


def detect(
    df: pd.DataFrame,
    min_score: int = 3,
    baseline_ratio: float = 0.7,
) -> tuple[pd.DataFrame, pd.DataFrame]:
    work = df.copy()
    work["@timestamp"] = pd.to_datetime(work["@timestamp"], utc=True, errors="coerce")
    work = work.dropna(subset=["@timestamp", "pat_id"]).sort_values("@timestamp").reset_index(drop=True)
    work["ua_family"] = work["user_agent"].fillna("").map(ua_family)
    work["hour_utc"] = work["@timestamp"].dt.hour

    cutoff_idx = int(len(work) * baseline_ratio)
    if cutoff_idx < 1:
        raise ValueError("Not enough data to construct a baseline.")
    if cutoff_idx >= len(work):
        cutoff_idx = len(work) - 1

    cutoff_ts = work.iloc[cutoff_idx]["@timestamp"]
    df_train = work[work["@timestamp"] <= cutoff_ts].copy()
    df_eval = work[work["@timestamp"] > cutoff_ts].copy()

    baselines = build_baseline(df_train)

    # Previous event per PAT for velocity and abrupt drift checks.
    work["prev_timestamp"] = work.groupby("pat_id")["@timestamp"].shift(1)
    work["prev_country"] = work.groupby("pat_id")["country_code"].shift(1)
    work["prev_city"] = work.groupby("pat_id")["city"].shift(1)
    work["prev_lat"] = work.groupby("pat_id")["latitude"].shift(1)
    work["prev_lon"] = work.groupby("pat_id")["longitude"].shift(1)
    work["hours_since_prev"] = (
        (work["@timestamp"] - work["prev_timestamp"]).dt.total_seconds() / 3600.0
    )

    scored_rows: list[dict] = []
    eval_index = set(df_eval.index.to_list())
    for idx, row in work.iterrows():
        reasons: list[str] = []
        score = 0
        velocity_kmh = 0.0
        impossible_travel = False

        baseline = baselines.get(str(row["pat_id"]))
        if idx in eval_index and baseline is not None:
            country = str(row.get("country_code", ""))
            carrier = str(row.get("network_carrier", ""))
            asn = str(row.get("asn", ""))
            family = str(row.get("ua_family", ""))
            hour = int(row.get("hour_utc", 0))

            if country and country not in baseline.countries:
                score += 2
                reasons.append("new_country_for_pat")
            if carrier and carrier not in baseline.carriers:
                score += 2
                reasons.append("new_network_carrier_for_pat")
            if asn and asn not in baseline.asns:
                score += 1
                reasons.append("new_asn_for_pat")
            if family and family not in baseline.ua_families:
                score += 2
                reasons.append("new_user_agent_family_for_pat")
            if hour not in baseline.common_hours:
                score += 1
                reasons.append("uncommon_hour_for_pat")

            prev_lat = row.get("prev_lat")
            prev_lon = row.get("prev_lon")
            cur_lat = row.get("latitude")
            cur_lon = row.get("longitude")
            delta_h = row.get("hours_since_prev")

            if (
                pd.notna(prev_lat)
                and pd.notna(prev_lon)
                and pd.notna(cur_lat)
                and pd.notna(cur_lon)
                and pd.notna(delta_h)
                and float(delta_h) > 0
            ):
                distance_km = haversine_km(float(prev_lat), float(prev_lon), float(cur_lat), float(cur_lon))
                velocity_kmh = distance_km / float(delta_h)
                if velocity_kmh >= 900:
                    impossible_travel = True
                    score += 2
                    reasons.append("impossible_travel_velocity")
                elif velocity_kmh >= 600:
                    score += 1
                    reasons.append("high_geo_velocity")

            if bool(row.get("is_proxy_or_vpn", False)):
                score += 1
                reasons.append("proxy_or_vpn_source")

            if str(row.get("token_scope", "")).startswith("admin:"):
                score += 1
                reasons.append("high_privilege_pat_scope")

            if str(row.get("action", "")).startswith("repo.") and "write" in str(row.get("token_scope", "")):
                score += 1
                reasons.append("write_action_with_write_scope")

        scored_rows.append(
            {
                **row.to_dict(),
                "is_eval_period": idx in eval_index,
                "score": score,
                "reasons": ";".join(reasons),
                "velocity_kmh": round(velocity_kmh, 2),
                "impossible_travel": impossible_travel,
                "risk_level": "high" if score >= 5 else "medium" if score >= min_score else "low",
            }
        )

    scored = pd.DataFrame(scored_rows)
    scored["source_timestamp_utc"] = scored["@timestamp"].dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    findings = scored[(scored["is_eval_period"]) & (scored["score"] >= min_score)].copy()
    findings = findings.sort_values(["score", "@timestamp"], ascending=[False, False])

    ordered_columns = [
        "source_timestamp_utc",
        "actor",
        "pat_id",
        "action",
        "ip_address",
        "country_code",
        "city",
        "asn",
        "network_carrier",
        "user_agent",
        "ua_family",
        "token_scope",
        "is_proxy_or_vpn",
        "hours_since_prev",
        "velocity_kmh",
        "impossible_travel",
        "score",
        "risk_level",
        "reasons",
    ]
    keep_columns = [c for c in ordered_columns if c in findings.columns]
    findings = findings[keep_columns]
    return scored, findings


def validate_columns(df: pd.DataFrame, required: Iterable[str]) -> None:
    missing = [col for col in required if col not in df.columns]
    if missing:
        raise ValueError(f"Input CSV missing required columns: {missing}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Detect suspicious GitHub PAT reuse in unusual network contexts."
    )
    parser.add_argument(
        "--input",
        type=Path,
        default=DEFAULT_INPUT,
        help="Input GitHub PAT telemetry CSV path.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=DEFAULT_OUTPUT_DIR,
        help="Directory where output CSV files are written.",
    )
    parser.add_argument(
        "--min-score",
        type=int,
        default=3,
        help="Minimum score to include a finding.",
    )
    parser.add_argument(
        "--baseline-ratio",
        type=float,
        default=0.7,
        help="Percentage of earliest events used as baseline (0-1).",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    kpi_tracker = KPITracker(
        scenario_name="github_pat_reuse_anomalous_network_context",
        input_dir=args.input,
    )

    df = pd.read_csv(args.input)
    validate_columns(df, REQUIRED_COLUMNS)
    kpi_tracker.record_rows(len(df))

    args.output_dir.mkdir(parents=True, exist_ok=True)
    scored, findings = detect(df, min_score=args.min_score, baseline_ratio=args.baseline_ratio)

    scored_out = args.output_dir / "github_pat_reuse_scored_events.csv"
    findings_out = args.output_dir / "github_pat_reuse_findings.csv"
    scored.to_csv(scored_out, index=False)
    findings.to_csv(findings_out, index=False)

    print(f"Loaded rows: {len(df)}")
    print(f"Scored rows: {len(scored)} -> {scored_out}")
    print(f"Findings (score >= {args.min_score}): {len(findings)} -> {findings_out}")
    if len(findings):
        print("\nTop 10 findings:")
        preview_cols = [
            "source_timestamp_utc",
            "actor",
            "pat_id",
            "country_code",
            "network_carrier",
            "ua_family",
            "score",
            "reasons",
        ]
        available = [c for c in preview_cols if c in findings.columns]
        print(findings[available].head(10).to_string(index=False))

    kpi_tracker.stop_and_report()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
