#!/usr/bin/env python3
"""
Generate realistic fake GitHub PAT usage telemetry.

The generated CSV is suitable for testing:
scenarios/github_pat_reuse_anomalous_network_context/github_pat_reuse_anomalous_network_context.py
"""

from __future__ import annotations

import argparse
import random
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pandas as pd


SCENARIO_DIR = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT = SCENARIO_DIR / "input" / "github_pat_audit_sample.csv"


@dataclass(frozen=True)
class Location:
    country_code: str
    country_name: str
    city: str
    latitude: float
    longitude: float
    asn: str
    network_carrier: str


LOCATIONS = {
    "paris": Location("FR", "France", "Paris", 48.8566, 2.3522, "AS3215", "Orange France"),
    "lyon": Location("FR", "France", "Lyon", 45.7640, 4.8357, "AS3215", "Orange France"),
    "london": Location("GB", "United Kingdom", "London", 51.5072, -0.1276, "AS5607", "Sky UK"),
    "dublin": Location("IE", "Ireland", "Dublin", 53.3498, -6.2603, "AS15502", "Vodafone Ireland"),
    "newyork": Location("US", "United States", "New York", 40.7128, -74.0060, "AS7018", "AT&T US"),
    "montreal": Location("CA", "Canada", "Montreal", 45.5019, -73.5674, "AS577", "Bell Canada"),
    "warsaw": Location("PL", "Poland", "Warsaw", 52.2297, 21.0122, "AS5617", "Orange Polska"),
    "singapore": Location("SG", "Singapore", "Singapore", 1.3521, 103.8198, "AS3758", "Singtel"),
    "moscow": Location("RU", "Russia", "Moscow", 55.7558, 37.6176, "AS8359", "MTS PJSC"),
    "lagos": Location("NG", "Nigeria", "Lagos", 6.5244, 3.3792, "AS29465", "MTN Nigeria"),
}


NORMAL_UAS = [
    "git/2.44.0",
    "git/2.43.0",
    "GitHub CLI 2.52.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/126.0.0.0 Safari/537.36",
]

ANOMALOUS_UAS = [
    "curl/8.7.1",
    "python-requests/2.32.3",
    "Go-http-client/1.1",
]

REPO_ACTIONS = [
    "repo.clone",
    "repo.fetch",
    "repo.pull_request.read",
    "repo.contents.read",
]

RISKY_ACTIONS = [
    "repo.contents.write",
    "repo.settings.write",
]

TOKEN_SCOPES = [
    "repo:read,user:email",
    "repo:read,workflow:read",
    "admin:org,repo:write",
]


def random_ip(rng: random.Random, private: bool = False) -> str:
    if private:
        return f"10.{rng.randint(0,255)}.{rng.randint(0,255)}.{rng.randint(1,254)}"
    return f"{rng.randint(11,223)}.{rng.randint(0,255)}.{rng.randint(0,255)}.{rng.randint(1,254)}"


def generate_rows(seed: int, days: int) -> pd.DataFrame:
    rng = random.Random(seed)
    start = datetime.now(timezone.utc) - timedelta(days=days)

    users = [
        ("alice.martin", "paris", "FR"),
        ("benoit.dupont", "lyon", "FR"),
        ("charlotte.reid", "london", "GB"),
        ("daniel.kelly", "dublin", "IE"),
        ("eva.rossi", "newyork", "US"),
        ("felix.tremblay", "montreal", "CA"),
        ("grzegorz.nowak", "warsaw", "PL"),
        ("han.lee", "singapore", "SG"),
    ]

    rows: list[dict] = []
    pat_ids: list[tuple[str, str, Location]] = []
    for idx, (user, city_key, _) in enumerate(users, start=1):
        pat = f"pat_{idx:03d}_fgp"
        pat_ids.append((user, pat, LOCATIONS[city_key]))

    for user, pat_id, loc in pat_ids:
        event_count = rng.randint(35, 55)
        for _ in range(event_count):
            day_offset = rng.randint(0, days - 1)
            hour = int(min(max(rng.gauss(10.5, 2.5), 6), 19))
            minute = rng.randint(0, 59)
            second = rng.randint(0, 59)
            ts = start + timedelta(days=day_offset, hours=hour, minutes=minute, seconds=second)

            rows.append(
                {
                    "@timestamp": ts.isoformat().replace("+00:00", "Z"),
                    "actor": user,
                    "pat_id": pat_id,
                    "action": rng.choice(REPO_ACTIONS),
                    "ip_address": random_ip(rng),
                    "country_code": loc.country_code,
                    "country_name": loc.country_name,
                    "city": loc.city,
                    "latitude": loc.latitude + rng.uniform(-0.03, 0.03),
                    "longitude": loc.longitude + rng.uniform(-0.03, 0.03),
                    "asn": loc.asn,
                    "network_carrier": loc.network_carrier,
                    "user_agent": rng.choice(NORMAL_UAS),
                    "token_scope": rng.choice(TOKEN_SCOPES[:2]),
                    "is_proxy_or_vpn": False,
                    "event_source": "github.audit_log",
                }
            )

    # Inject suspected stolen PAT reuse events.
    attack_injections = [
        ("alice.martin", "pat_001_fgp", LOCATIONS["moscow"]),
        ("charlotte.reid", "pat_003_fgp", LOCATIONS["lagos"]),
        ("eva.rossi", "pat_005_fgp", LOCATIONS["singapore"]),
        ("han.lee", "pat_008_fgp", LOCATIONS["newyork"]),
    ]
    for i, (user, pat_id, loc) in enumerate(attack_injections):
        ts = start + timedelta(days=days - 2, hours=1 + i, minutes=15 + i * 7)
        rows.append(
            {
                "@timestamp": ts.isoformat().replace("+00:00", "Z"),
                "actor": user,
                "pat_id": pat_id,
                "action": rng.choice(RISKY_ACTIONS),
                "ip_address": random_ip(rng),
                "country_code": loc.country_code,
                "country_name": loc.country_name,
                "city": loc.city,
                "latitude": loc.latitude + rng.uniform(-0.02, 0.02),
                "longitude": loc.longitude + rng.uniform(-0.02, 0.02),
                "asn": loc.asn,
                "network_carrier": loc.network_carrier,
                "user_agent": rng.choice(ANOMALOUS_UAS),
                "token_scope": "admin:org,repo:write",
                "is_proxy_or_vpn": True,
                "event_source": "github.audit_log",
            }
        )

    df = pd.DataFrame(rows).sort_values("@timestamp").reset_index(drop=True)
    return df


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate fake GitHub PAT audit telemetry CSV.")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT, help="Destination CSV path.")
    parser.add_argument("--seed", type=int, default=42, help="Random seed.")
    parser.add_argument("--days", type=int, default=21, help="Lookback time span in days.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    df = generate_rows(seed=args.seed, days=args.days)
    df.to_csv(args.output, index=False)
    print(f"Wrote {len(df)} rows to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
