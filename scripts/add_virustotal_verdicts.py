from __future__ import annotations

import argparse
import base64
import ipaddress
import os
import re
import time
from pathlib import Path
from urllib.parse import urlparse

import pandas as pd
import requests


VT_BASE_URL = "https://www.virustotal.com/api/v3"


def normalize_value(value: str) -> str:
    return str(value or "").strip()


def looks_like_domain(value: str) -> bool:
    if not value:
        return False
    domain_regex = r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$"
    return bool(re.match(domain_regex, value.lower()))


def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except Exception:
        return False


def encode_url_id(raw_url: str) -> str:
    encoded = base64.urlsafe_b64encode(raw_url.encode("utf-8")).decode("ascii")
    return encoded.rstrip("=")


def coerce_to_url(value: str) -> str:
    if value.startswith(("http://", "https://")):
        return value
    return f"http://{value}"


def get_vt_stats(session: requests.Session, api_key: str, value: str) -> tuple[str, dict] | tuple[None, None]:
    normalized = normalize_value(value)
    if not normalized:
        return None, None

    if is_ip(normalized):
        endpoint = f"/ip_addresses/{normalized}"
    else:
        parsed = urlparse(coerce_to_url(normalized))
        is_explicit_url = normalized.startswith(("http://", "https://"))
        if parsed.path not in {"", "/"} or parsed.query or is_explicit_url:
            candidate_url = normalized if is_explicit_url else coerce_to_url(normalized)
            endpoint = f"/urls/{encode_url_id(candidate_url)}"
        elif looks_like_domain(parsed.hostname or normalized):
            endpoint = f"/domains/{(parsed.hostname or normalized).lower()}"
        else:
            return None, None

    response = session.get(
        f"{VT_BASE_URL}{endpoint}",
        headers={"x-apikey": api_key},
        timeout=30,
    )

    if response.status_code == 404:
        return "not_found", {}

    if response.status_code == 429:
        raise RuntimeError("VirusTotal API rate limit reached (HTTP 429).")

    response.raise_for_status()
    payload = response.json()
    stats = (
        payload.get("data", {})
        .get("attributes", {})
        .get("last_analysis_stats", {})
    )
    return "ok", stats


def classify_verdict(stats: dict) -> str:
    malicious = int(stats.get("malicious", 0) or 0)
    suspicious = int(stats.get("suspicious", 0) or 0)
    harmless = int(stats.get("harmless", 0) or 0)
    undetected = int(stats.get("undetected", 0) or 0)

    if malicious > 0:
        return "malicious"
    if suspicious > 0:
        return "suspicious"
    if harmless > 0 and malicious == 0 and suspicious == 0:
        return "clean"
    if undetected > 0:
        return "undetected"
    return "unknown"


def enrich_file(file_path: Path, session: requests.Session, api_key: str, sleep_seconds: float) -> None:
    df = pd.read_csv(file_path)
    if "value" not in df.columns:
        print(f"[skip] {file_path}: missing 'value' column")
        return

    verdict_cache: dict[str, tuple[str, dict]] = {}
    vt_verdicts = []
    vt_details = []
    value_with_verdict = []

    for raw_value in df["value"].fillna("").astype(str):
        value = normalize_value(raw_value)

        if value in verdict_cache:
            status, stats = verdict_cache[value]
        else:
            try:
                status, stats = get_vt_stats(session, api_key, value)
            except Exception as ex:
                status, stats = "error", {"error": str(ex)}

            verdict_cache[value] = (status, stats)
            if sleep_seconds > 0:
                time.sleep(sleep_seconds)

        if status == "ok":
            verdict = classify_verdict(stats)
            detail = (
                f"malicious={int(stats.get('malicious', 0) or 0)};"
                f"suspicious={int(stats.get('suspicious', 0) or 0)};"
                f"harmless={int(stats.get('harmless', 0) or 0)};"
                f"undetected={int(stats.get('undetected', 0) or 0)}"
            )
        elif status == "not_found":
            verdict = "not_found"
            detail = "not_found"
        elif status is None:
            verdict = "unsupported"
            detail = "unsupported_value_type"
        else:
            verdict = "error"
            detail = stats.get("error", "unknown_error")

        vt_verdicts.append(verdict)
        vt_details.append(detail)
        value_with_verdict.append(f"{value} [vt:{verdict}]")

    df["vt_verdict"] = vt_verdicts
    df["vt_details"] = vt_details
    df["value"] = value_with_verdict

    df.to_csv(file_path, index=False)
    print(f"[ok] enriched {file_path}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Add VirusTotal verdicts to high-confidence findings CSV files.")
    parser.add_argument(
        "--output-dir",
        default="scenarios/dns_url_anomaly_analysis/output",
        help="Directory containing *_findings_high_confidence.csv files",
    )
    parser.add_argument("--sleep-seconds", type=float, default=0.2, help="Delay between VirusTotal API calls")
    args = parser.parse_args()

    api_key = os.environ.get("VT_API_KEY", "").strip()
    if not api_key:
        raise RuntimeError("VT_API_KEY environment variable is required.")

    output_dir = Path(args.output_dir)
    targets = sorted(output_dir.glob("*_findings_high_confidence.csv"))
    if not targets:
        print(f"No matching files found in {output_dir.resolve()}")
        return

    with requests.Session() as session:
        for target in targets:
            enrich_file(target, session, api_key, args.sleep_seconds)


if __name__ == "__main__":
    main()
