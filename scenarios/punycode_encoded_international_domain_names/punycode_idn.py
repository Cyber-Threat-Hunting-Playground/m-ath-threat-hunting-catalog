#!/usr/bin/env python3
"""Punycode-encoded International Domain Names — automated analysis script.

Standalone equivalent of punycode_idn.ipynb, designed for headless/crontab
execution with no human interaction.  All outputs are written to output/.

If input/brand_domains.txt exists and contains at least one non-comment line,
the pipeline first runs input/generate_brand_domain_impersonations.py to refresh
input/brand_domains_impersonation.txt (max 100000 variants per domain).

Usage:
    python punycode_idn.py                         # run with defaults
    python punycode_idn.py --vt-workers 4          # limit VT parallelism
    python punycode_idn.py --no-translate          # skip Google Translate
    python punycode_idn.py --no-dns-sibling        # skip DNS sibling IP check
    python punycode_idn.py --log-level DEBUG       # verbose logging
"""

from __future__ import annotations

import argparse
import base64
import glob
import ipaddress
import json
import logging
import math
import os
import re
import subprocess
import sys
import time
import unicodedata
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import pandas as pd
import seaborn as sns

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
log = logging.getLogger("punycode_idn")

# ---------------------------------------------------------------------------
# Path resolution
# ---------------------------------------------------------------------------

def find_repo_root(start: Path) -> Path:
    cur = start.resolve()
    while cur != cur.parent:
        if (cur / "detection_logics").exists() and (cur / "scenarios").exists():
            return cur
        cur = cur.parent
    raise RuntimeError("Unable to locate repository root from current working directory.")


def _setup_paths():
    """Resolve all directory constants and add repo root to sys.path."""
    repo_root = find_repo_root(Path(__file__).resolve().parent)
    scenario_dir = repo_root / "scenarios" / "punycode_encoded_international_domain_names"
    if not scenario_dir.exists():
        raise FileNotFoundError(f"Scenario folder not found: {scenario_dir.relative_to(repo_root)}")

    if str(repo_root) not in sys.path:
        sys.path.insert(0, str(repo_root))
    os.chdir(repo_root)

    paths = {
        "REPO_ROOT": repo_root,
        "SCENARIO_DIR": scenario_dir,
        "INPUT_DIR": scenario_dir / "input",
        "OUTPUT_DIR": scenario_dir / "output",
        "SCENARIO_CONFIG_DIR": scenario_dir / "config",
        "EXCLUSIONS_DIR": scenario_dir / "exclusions",
        "REPO_EXCLUSIONS_DIR": repo_root / "exclusions",
        "ROOT_CONFIG_DIR": repo_root / "config",
    }
    paths["OUTPUT_DIR"].mkdir(parents=True, exist_ok=True)
    return paths


PATHS = _setup_paths()
REPO_ROOT = PATHS["REPO_ROOT"]
SCENARIO_DIR = PATHS["SCENARIO_DIR"]
INPUT_DIR = PATHS["INPUT_DIR"]
OUTPUT_DIR = PATHS["OUTPUT_DIR"]
SCENARIO_CONFIG_DIR = PATHS["SCENARIO_CONFIG_DIR"]
EXCLUSIONS_DIR = PATHS["EXCLUSIONS_DIR"]
REPO_EXCLUSIONS_DIR = PATHS["REPO_EXCLUSIONS_DIR"]
ROOT_CONFIG_DIR = PATHS["ROOT_CONFIG_DIR"]

BRAND_DOMAINS_FILE = INPUT_DIR / "brand_domains.txt"
BRAND_IMPERSONATION_SCRIPT = INPUT_DIR / "generate_brand_domain_impersonations.py"
BRAND_IMPERSONATION_OUTPUT = INPUT_DIR / "brand_domains_impersonation.txt"
BRAND_IMPERSONATION_MAX_VARIANTS = 100_000

# ---------------------------------------------------------------------------
# Detection logic imports (must come after sys.path adjustment)
# ---------------------------------------------------------------------------
from detection_logics import apply_dns_logics          # noqa: E402
from detection_logics import dns_suspicious_string     # noqa: E402
from detection_logics.idn_security_analysis import (   # noqa: E402
    analyze_idn_domain,
    derive_ascii_sibling,
    normalize_idn_dashes_for_decode,
    score_idn_security_signals,
)

pd.set_option("display.max_colwidth", 180)

# ---------------------------------------------------------------------------
# Exclusion / config file paths
# ---------------------------------------------------------------------------
EXCLUDED_VALUES_FILE = EXCLUSIONS_DIR / "excluded_values.conf"
EXCLUDED_VALUE_REASONS_FILE = EXCLUSIONS_DIR / "excluded_values+reasons.conf"
EXCLUDED_PARENT_DOMAINS_FILE = EXCLUSIONS_DIR / "excluded_parent_domains.conf"
REVIEWED_PARENT_DOMAINS_FILE = REPO_EXCLUSIONS_DIR / "reviewed_parent_domains.conf"
RISKY_TLDS_FILE = SCENARIO_CONFIG_DIR / "risky_tlds.conf"
MANAGED_AUTHORITATIVE_NS_FILE = SCENARIO_CONFIG_DIR / "authoritative_dns_nameservers.conf"
ENGINE_CONFIG_FILE = SCENARIO_CONFIG_DIR / "engine_weights.json"

ENGINE_CONFIG_DEFAULT = {
    "score_threshold": 2,
    "engines": {
        "dns_heuristics": {"enabled": True, "weight": 1.0},
        "idn_security_tr39": {"enabled": True, "weight": 1.0},
        "dns_sibling_compare": {
            "enabled": True,
            "score_match": -2,
            "score_range_match": -1,
            "score_mismatch": 2,
            "ipv4_prefix": 24,
            "ipv6_prefix": 48,
            "display_weight": "-2 / -1 / +2",
        },
        "managed_authoritative_ns": {"enabled": True, "weight": -5},
        "dns_logic_registry": {"enabled": True, "weight": 1.0},
        "low_prevalence": {"enabled": True, "threshold": 2, "weight": 1},
        "vt_tags": {"enabled": True, "weight_per_tag": 1},
        "suspicious_registrar": {"enabled": True, "weight": 2},
        "newly_registered": {
            "enabled": True,
            "new_threshold_days": 30,
            "recent_threshold_days": 90,
            "new_weight": 2,
            "recent_weight": 1,
            "display_weight": "+2 (<=30d) / +1 (<=90d)",
        },
        "otx_verdict": {
            "enabled": True,
            "malicious_weight": 2,
            "suspicious_weight": 1,
            "display_weight": "+2 (malicious) / +1 (suspicious)",
        },
        "pulsedive_verdict": {
            "enabled": True,
            "malicious_weight": 2,
            "suspicious_weight": 1,
            "display_weight": "+2 (malicious) / +1 (suspicious)",
        },
        "brand_impersonation": {"enabled": True, "weight": 3},
        "translation": {"enabled": True, "display_weight": "N/A"},
    },
}

# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------

def brand_domains_file_has_non_comment_lines(path: Path) -> bool:
    """True if file exists and has at least one non-empty, non-# line."""
    if not path.is_file():
        return False
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as e:
        log.warning("Could not read %s: %s", path, e)
        return False
    for raw in text.splitlines():
        s = raw.strip()
        if s and not s.startswith("#"):
            return True
    return False


def maybe_run_brand_domain_impersonation_generator() -> None:
    """
    If input/brand_domains.txt exists with real entries, run input/generate_brand_domain_impersonations.py
    to refresh input/brand_domains_impersonation.txt (max variants per domain: BRAND_IMPERSONATION_MAX_VARIANTS).
    """
    if not brand_domains_file_has_non_comment_lines(BRAND_DOMAINS_FILE):
        return
    if not BRAND_IMPERSONATION_SCRIPT.is_file():
        log.warning(
            "Brand domains file has entries but generator script missing: %s",
            _rel(BRAND_IMPERSONATION_SCRIPT),
        )
        return
    cmd = [
        sys.executable,
        str(BRAND_IMPERSONATION_SCRIPT),
        "--input",
        str(BRAND_DOMAINS_FILE),
        "--output",
        str(BRAND_IMPERSONATION_OUTPUT),
        "--max-variants",
        str(BRAND_IMPERSONATION_MAX_VARIANTS),
    ]
    log.info(
        "Running brand impersonation generator (%s max variants per domain)...",
        BRAND_IMPERSONATION_MAX_VARIANTS,
    )
    try:
        proc = subprocess.run(
            cmd,
            cwd=str(REPO_ROOT),
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError as e:
        log.warning("Could not run brand impersonation generator: %s", e)
        return
    if proc.returncode != 0:
        log.warning(
            "Brand impersonation generator exited %s. stderr: %s",
            proc.returncode,
            (proc.stderr or "").strip()[:2000],
        )
        return
    if proc.stdout.strip():
        log.info(proc.stdout.strip())
    log.info("Brand impersonation list: %s", _rel(BRAND_IMPERSONATION_OUTPUT))


def load_conf_set(conf_path: Path) -> set:
    """Load a .conf file (one entry per line, # comments) into a lowercase set."""
    if not conf_path.exists():
        return set()
    entries = set()
    with open(conf_path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line and not line.startswith("#"):
                entries.add(line.lower())
    return entries


def _deep_merge_dict(base: dict, override: dict) -> dict:
    merged = json.loads(json.dumps(base))
    for key, value in (override or {}).items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _deep_merge_dict(merged[key], value)
        else:
            merged[key] = value
    return merged


def _safe_int(value, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _safe_float(value, default: float) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def load_engine_config(config_path: Path) -> dict:
    cfg = json.loads(json.dumps(ENGINE_CONFIG_DEFAULT))
    if config_path.exists():
        with config_path.open("r", encoding="utf-8") as handle:
            user_cfg = json.load(handle)
        cfg = _deep_merge_dict(cfg, user_cfg)
    cfg["score_threshold"] = _safe_int(cfg.get("score_threshold", 2), 2)
    for name, engine_cfg in cfg.get("engines", {}).items():
        if isinstance(engine_cfg, dict):
            engine_cfg["enabled"] = bool(engine_cfg.get("enabled", True))
            cfg["engines"][name] = engine_cfg
    return cfg


def engine_enabled(engine_cfg: dict, name: str, default: bool = True) -> bool:
    return bool(engine_cfg.get("engines", {}).get(name, {}).get("enabled", default))


def engine_numeric(engine_cfg: dict, name: str, key: str, default):
    raw = engine_cfg.get("engines", {}).get(name, {}).get(key, default)
    if isinstance(default, int):
        return _safe_int(raw, default)
    if isinstance(default, float):
        return _safe_float(raw, default)
    return raw


def engine_display_weight(engine_cfg: dict, name: str, default="") -> str:
    conf = engine_cfg.get("engines", {}).get(name, {})
    return str(conf.get("display_weight", conf.get("weight", default)))


def _format_engine_weight(weight_value, active: bool) -> str:
    return str(weight_value) if active else "N/A"


def build_engine_weight_rows(
    engine_cfg: dict,
    *,
    dns_sibling_runtime: bool,
    otx_runtime: bool,
    pulsedive_runtime: bool,
    brand_runtime: bool,
    translation_runtime: bool,
) -> list[dict]:
    rows: list[dict] = []

    def _append(name: str, label: str, weight, runtime_enabled: bool = True):
        active = engine_enabled(engine_cfg, name, True) and runtime_enabled
        rows.append({
            "Engine": label,
            "Status": "active" if active else "inactive",
            "Weight": _format_engine_weight(weight, active),
        })

    _append("dns_heuristics", "DNS heuristics", engine_display_weight(engine_cfg, "dns_heuristics", "1.0"))
    _append("idn_security_tr39", "IDN / TR39", engine_display_weight(engine_cfg, "idn_security_tr39", "1.0"))
    _append("dns_sibling_compare", "DNS sibling compare", engine_display_weight(engine_cfg, "dns_sibling_compare", "-2 / -1 / +2"), runtime_enabled=dns_sibling_runtime)
    _append("managed_authoritative_ns", "Managed authoritative NS", engine_display_weight(engine_cfg, "managed_authoritative_ns", "-5"))
    _append("dns_logic_registry", "DNS logic registry", engine_display_weight(engine_cfg, "dns_logic_registry", "1.0"))
    _append("low_prevalence", "Low prevalence", engine_display_weight(engine_cfg, "low_prevalence", "+1"))
    _append("vt_tags", "VirusTotal tags", engine_numeric(engine_cfg, "vt_tags", "weight_per_tag", 1))
    _append("suspicious_registrar", "Suspicious registrar", engine_display_weight(engine_cfg, "suspicious_registrar", "+2"))
    _append("newly_registered", "Newly registered", engine_display_weight(engine_cfg, "newly_registered", "+2 / +1"))
    _append("otx_verdict", "OTX verdict", engine_display_weight(engine_cfg, "otx_verdict", "+2 / +1"), runtime_enabled=otx_runtime)
    _append("pulsedive_verdict", "Pulsedive verdict", engine_display_weight(engine_cfg, "pulsedive_verdict", "+2 / +1"), runtime_enabled=pulsedive_runtime)
    _append("brand_impersonation", "Brand impersonation", engine_display_weight(engine_cfg, "brand_impersonation", "+3"), runtime_enabled=brand_runtime)
    _append("translation", "Translation (display)", "N/A", runtime_enabled=translation_runtime)
    return rows

# ---------------------------------------------------------------------------
# Risky TLDs
# ---------------------------------------------------------------------------
RISKY_TLDS = load_conf_set(RISKY_TLDS_FILE)


def _rel(p: Path) -> Path:
    try:
        if p.is_relative_to(REPO_ROOT):
            return p.relative_to(REPO_ROOT)
    except (ValueError, AttributeError):
        pass
    return p

# ---------------------------------------------------------------------------
# Punycode decode helper
# ---------------------------------------------------------------------------

def normalize_domain(value: str) -> str:
    value = (value or "").strip().lower().rstrip(".")
    value = re.sub(r"\s+", "", value)
    return value


BRAND_IMPERSONATION_REASON = "brand-impersonation-candidate"
BRAND_IMPERSONATION_SCORE_DELTA = ENGINE_CONFIG_DEFAULT["engines"]["brand_impersonation"]["weight"]


def load_brand_impersonation_index(path: Path) -> tuple[frozenset[str], dict[str, str]]:
    """
    Load brand_domains_impersonation.txt lines as ``ascii_brand,punycode_fqdn``.
    Returns (frozenset of normalized punycode hostnames, map punycode -> brand string).
    """
    puny_set: set[str] = set()
    by_puny: dict[str, str] = {}
    if not path.is_file():
        return frozenset(), {}
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as e:
        log.warning("Could not read brand impersonation list %s: %s", path, e)
        return frozenset(), {}
    for raw in text.splitlines():
        s = raw.strip()
        if not s or s.startswith("#"):
            continue
        if "," not in s:
            continue
        brand_part, puny_part = s.split(",", 1)
        brand = brand_part.strip()
        puny = normalize_domain(puny_part)
        if not puny:
            continue
        puny_set.add(puny)
        if puny not in by_puny and brand:
            by_puny[puny] = brand
    return frozenset(puny_set), by_puny


def decode_punycode_domain(value: str) -> str:
    domain = normalize_domain(value)
    domain = normalize_idn_dashes_for_decode(domain)
    if not domain or "xn--" not in domain:
        return ""
    decoded_labels = []
    changed = False
    for label in domain.split("."):
        if label.startswith("xn--"):
            try:
                decoded_label = label.encode("ascii").decode("idna")
            except Exception:
                try:
                    decoded_label = label[4:].encode("ascii").decode("punycode")
                except Exception:
                    decoded_label = label
            decoded_labels.append(decoded_label)
            changed = changed or decoded_label != label
        else:
            decoded_labels.append(label)
    decoded_domain = ".".join(decoded_labels)
    return decoded_domain if changed and decoded_domain != domain else ""

# ---------------------------------------------------------------------------
# English translation of decoded domains (optional)
# ---------------------------------------------------------------------------

_NON_LATIN_SCRIPTS = frozenset({
    "CJK", "HANGUL", "ARABIC", "CYRILLIC", "THAI", "DEVANAGARI",
    "HEBREW", "BENGALI", "TAMIL", "TELUGU", "KANNADA", "GEORGIAN",
    "ARMENIAN", "ETHIOPIC", "KHMER", "LAO", "MYANMAR", "TIBETAN",
    "KATAKANA", "HIRAGANA",
})

TRANSLATE_MAX_WORKERS = 4
TRANSLATE_SLEEP_SECONDS = 0.1

try:
    from deep_translator import GoogleTranslator  # noqa: E402
    _TRANSLATOR_AVAILABLE = True
except ImportError:
    _TRANSLATOR_AVAILABLE = False


def needs_translation(text: str) -> bool:
    if not text:
        return False
    for ch in text:
        if not ch.isalpha():
            continue
        try:
            name = unicodedata.name(ch, "")
        except ValueError:
            continue
        name_upper = name.upper()
        if any(script in name_upper for script in _NON_LATIN_SCRIPTS):
            return True
    return False


def translate_domain_to_english(decoded: str) -> str:
    if not decoded or not _TRANSLATOR_AVAILABLE:
        return ""
    if not needs_translation(decoded):
        return ""
    labels = decoded.split(".")
    translatable_parts = [
        cleaned
        for label in labels
        if (cleaned := label.replace("-", " ").strip()) and needs_translation(cleaned)
    ]
    if not translatable_parts:
        return ""
    text_to_translate = " | ".join(translatable_parts)
    try:
        result = GoogleTranslator(source="auto", target="en").translate(text_to_translate)
        return str(result).strip() if result else ""
    except Exception:
        return ""


def batch_translate_domains(decoded_series, *, enabled: bool) -> dict:
    if not enabled or not _TRANSLATOR_AVAILABLE:
        return {}
    unique_decoded = sorted({
        str(v).strip() for v in decoded_series
        if str(v).strip() and needs_translation(str(v).strip())
    })
    if not unique_decoded:
        return {}
    log.info("Translating %d unique non-Latin decoded domain(s) to English (%d workers)...",
             len(unique_decoded), TRANSLATE_MAX_WORKERS)
    translations: dict[str, str] = {}
    completed = 0

    def _do_translate(text):
        if TRANSLATE_SLEEP_SECONDS > 0:
            time.sleep(TRANSLATE_SLEEP_SECONDS)
        return text, translate_domain_to_english(text)

    with ThreadPoolExecutor(max_workers=TRANSLATE_MAX_WORKERS) as executor:
        futures = {executor.submit(_do_translate, d): d for d in unique_decoded}
        for future in as_completed(futures):
            original, translated = future.result()
            if translated:
                translations[original] = translated
            completed += 1
            if completed % 50 == 0 or completed == len(unique_decoded):
                log.info("  Translation progress: %d/%d", completed, len(unique_decoded))
    log.info("Translated %d/%d domains successfully.", len(translations), len(unique_decoded))
    return translations

# ---------------------------------------------------------------------------
# DNS risk scoring and exclusions
# ---------------------------------------------------------------------------

def shannon_entropy(text: str) -> float:
    text = (text or "").strip()
    if not text:
        return 0.0
    probs = [text.count(ch) / len(text) for ch in set(text)]
    return -sum(p * math.log2(p) for p in probs)


def looks_like_domain(value: str) -> bool:
    if not value or not isinstance(value, str):
        return False
    value = value.strip().lower()
    if value.startswith(("http://", "https://")):
        return False
    domain_regex = r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$"
    return bool(re.match(domain_regex, value))


def score_dns(domain: str):
    d = normalize_domain(domain)
    reasons: list[str] = []
    score = 0

    if not looks_like_domain(d):
        return 0, ["not-domain"]

    labels = d.split(".")
    joined = "".join(labels)
    entropy = shannon_entropy(joined)

    if len(d) > 55:
        score += 2; reasons.append("very-long-domain")
    elif len(d) > 40:
        score += 1; reasons.append("long-domain")

    if len(labels) >= 5:
        score += 1; reasons.append("many-subdomains")

    max_label_len = max(len(x) for x in labels)
    if max_label_len > 25:
        score += 1; reasons.append("long-label")

    if entropy > 4.0:
        score += 2; reasons.append("high-entropy")
    elif entropy > 3.6:
        score += 1; reasons.append("medium-entropy")

    if "xn--" in d:
        score += 1; reasons.append("punycode")
    if "--" in d:
        score += 1; reasons.append("double-hyphen")
    if labels[-1] in RISKY_TLDS:
        score += 1; reasons.append("risky-tld")
    if re.search(r"[a-z]{8,}\d{3,}|\d{5,}[a-z]{4,}", joined):
        score += 2; reasons.append("dga-like-pattern")

    return score, reasons


LOW_PREVALENCE_THRESHOLD = ENGINE_CONFIG_DEFAULT["engines"]["low_prevalence"]["threshold"]
LOW_PREVALENCE_SCORE_DELTA = ENGINE_CONFIG_DEFAULT["engines"]["low_prevalence"]["weight"]


def score_prevalence(prevalence_value) -> tuple[int, list[str]]:
    if prevalence_value is None:
        return 0, []
    try:
        val = int(float(prevalence_value))
    except (TypeError, ValueError):
        return 0, []
    if val <= LOW_PREVALENCE_THRESHOLD:
        return LOW_PREVALENCE_SCORE_DELTA, ["low-prevalence"]
    return 0, []


NEWLY_REGISTERED_THRESHOLD_DAYS = ENGINE_CONFIG_DEFAULT["engines"]["newly_registered"]["new_threshold_days"]
RECENTLY_REGISTERED_THRESHOLD_DAYS = ENGINE_CONFIG_DEFAULT["engines"]["newly_registered"]["recent_threshold_days"]
NEWLY_REGISTERED_SCORE_DELTA = ENGINE_CONFIG_DEFAULT["engines"]["newly_registered"]["new_weight"]
RECENTLY_REGISTERED_SCORE_DELTA = ENGINE_CONFIG_DEFAULT["engines"]["newly_registered"]["recent_weight"]


def score_newly_registered(creation_date_epoch) -> tuple[int, list[str], str, int | None]:
    if creation_date_epoch is None:
        return 0, [], "", None
    try:
        ts = int(creation_date_epoch)
    except (TypeError, ValueError):
        return 0, [], "", None
    age_days = int((time.time() - ts) // 86400)
    creation_date_str = time.strftime("%Y-%m-%d", time.gmtime(ts))
    if age_days <= NEWLY_REGISTERED_THRESHOLD_DAYS:
        return NEWLY_REGISTERED_SCORE_DELTA, ["newly-registered"], creation_date_str, age_days
    if age_days <= RECENTLY_REGISTERED_THRESHOLD_DAYS:
        return RECENTLY_REGISTERED_SCORE_DELTA, ["recently-registered"], creation_date_str, age_days
    return 0, [], creation_date_str, age_days


def score_managed_authoritative_ns(vt_nameservers_set: set[str], managed_authoritative_ns: set[str], weight: int = -5) -> tuple[int, list[str]]:
    if not vt_nameservers_set or not managed_authoritative_ns:
        return 0, []
    overlap = vt_nameservers_set & managed_authoritative_ns
    if overlap:
        return weight, ["managed-authoritative-ns-match"]
    return 0, []


def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except Exception:
        return False


def encode_url_id(raw_url: str) -> str:
    return base64.urlsafe_b64encode(raw_url.encode("utf-8")).decode("ascii").rstrip("=")


def coerce_to_url(value: str) -> str:
    if value.startswith(("http://", "https://")):
        return value
    return f"http://{value}"


VT_MAX_RETRIES = 3
VT_RETRY_BACKOFF_BASE_SECONDS = 1.5
VT_RETRY_BACKOFF_MAX_SECONDS = 20.0


def _vt_backoff_seconds(attempt: int) -> float:
    # Exponential backoff with cap for transient VT failures / rate limiting.
    return min(VT_RETRY_BACKOFF_MAX_SECONDS, VT_RETRY_BACKOFF_BASE_SECONDS * (2 ** max(0, attempt - 1)))


def _vt_retry_after_seconds(ex: HTTPError) -> float | None:
    retry_after = ex.headers.get("Retry-After")
    if not retry_after:
        return None
    try:
        parsed = float(str(retry_after).strip())
    except (TypeError, ValueError):
        return None
    return parsed if parsed > 0 else None


def _extract_dns_ips(attrs: dict) -> set[str]:
    """Extract A/AAAA IPs from VT last_dns_records (passive DNS, no local query)."""
    records = attrs.get("last_dns_records", []) or []
    return {
        r["value"] for r in records
        if isinstance(r, dict) and r.get("type") in ("A", "AAAA") and r.get("value")
    }


def _extract_dns_nameservers(attrs: dict) -> set[str]:
    records = attrs.get("last_dns_records", []) or []
    nameservers: set[str] = set()
    for record in records:
        if not isinstance(record, dict):
            continue
        if record.get("type") != "NS":
            continue
        value = str(record.get("value", "") or "").strip().lower().rstrip(".")
        if value:
            nameservers.add(value)
    return nameservers


def get_vt_stats(api_key: str, value: str) -> tuple[str | None, dict | None, list, str, set[str], set[str], int | None]:
    """Returns (status, last_analysis_stats, tags, registrar, dns_ips, dns_nameservers, creation_date)."""
    normalized = str(value or "").strip()
    if not normalized:
        return None, None, [], "", set(), set(), None

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
            return None, None, [], "", set(), set(), None

    req = Request(
        f"https://www.virustotal.com/api/v3{endpoint}",
        headers={"x-apikey": api_key},
    )
    payload: dict = {}
    for attempt in range(1, VT_MAX_RETRIES + 1):
        try:
            with urlopen(req, timeout=30) as resp:
                payload = json.loads(resp.read().decode("utf-8"))
            break
        except HTTPError as ex:
            if ex.code == 404:
                return "not_found", {}, [], "", set(), set(), None
            if ex.code == 429:
                if attempt < VT_MAX_RETRIES:
                    delay = _vt_retry_after_seconds(ex) or _vt_backoff_seconds(attempt)
                    log.debug("VT rate-limited for %s; retrying in %.1fs (attempt %d/%d).",
                              normalized, delay, attempt, VT_MAX_RETRIES)
                    time.sleep(delay)
                    continue
                return "rate_limited", {}, [], "", set(), set(), None
            if ex.code in {500, 502, 503, 504} and attempt < VT_MAX_RETRIES:
                delay = _vt_backoff_seconds(attempt)
                log.debug("VT transient HTTP %s for %s; retrying in %.1fs (attempt %d/%d).",
                          ex.code, normalized, delay, attempt, VT_MAX_RETRIES)
                time.sleep(delay)
                continue
            raise RuntimeError(f"VirusTotal HTTP error: {ex.code}")
        except URLError as ex:
            if attempt < VT_MAX_RETRIES:
                delay = _vt_backoff_seconds(attempt)
                log.debug("VT network error for %s: %s; retrying in %.1fs (attempt %d/%d).",
                          normalized, ex.reason, delay, attempt, VT_MAX_RETRIES)
                time.sleep(delay)
                continue
            raise RuntimeError(f"VirusTotal network error: {ex.reason}")

    attrs = payload.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    tags = attrs.get("tags", []) or []
    if not isinstance(tags, list):
        tags = []
    registrar = str(attrs.get("registrar", "") or "").strip()
    dns_ips = _extract_dns_ips(attrs)
    dns_nameservers = _extract_dns_nameservers(attrs)
    creation_date = attrs.get("creation_date")
    return "ok", stats, tags, registrar, dns_ips, dns_nameservers, creation_date


def get_vt_domain_ips(api_key: str, domain: str, sleep: float = 0.0) -> set[str]:
    """Retrieve passive DNS IPs for a domain via VirusTotal (no local DNS query)."""
    req = Request(
        f"https://www.virustotal.com/api/v3/domains/{domain.lower()}",
        headers={"x-apikey": api_key},
    )
    payload: dict = {}
    for attempt in range(1, VT_MAX_RETRIES + 1):
        try:
            with urlopen(req, timeout=30) as resp:
                payload = json.loads(resp.read().decode("utf-8"))
            break
        except HTTPError as ex:
            if ex.code in {404}:
                return set()
            if ex.code in {429, 500, 502, 503, 504} and attempt < VT_MAX_RETRIES:
                delay = _vt_retry_after_seconds(ex) or _vt_backoff_seconds(attempt)
                time.sleep(delay)
                continue
            return set()
        except URLError:
            if attempt < VT_MAX_RETRIES:
                time.sleep(_vt_backoff_seconds(attempt))
                continue
            return set()
    if sleep > 0:
        time.sleep(sleep)
    attrs = payload.get("data", {}).get("attributes", {})
    return _extract_dns_ips(attrs)


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


def _parse_env_file(env_path: Path) -> dict:
    data: dict[str, str] = {}
    if not env_path.exists():
        return data
    with env_path.open("r", encoding="utf-8") as handle:
        for raw in handle:
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            key = key.strip()
            value = value.strip().strip('"').strip("'")
            if key:
                data[key] = value
    return data


def resolve_vt_api_key() -> tuple[str, str]:
    env_path = SCENARIO_DIR / ".env"
    if env_path.exists():
        env_data = _parse_env_file(env_path)
        key = str(env_data.get("VT_API_KEY", "") or "").strip()
        if key:
            return key, "scenario .env"
    key = str(os.environ.get("VT_API_KEY", "") or "").strip()
    if key:
        return key, "environment"
    return "", "missing"


def resolve_ti_api_key(key_name: str) -> tuple[str, str]:
    env_path = SCENARIO_DIR / ".env"
    if env_path.exists():
        env_data = _parse_env_file(env_path)
        key = str(env_data.get(key_name, "") or "").strip()
        if key:
            return key, "scenario .env"
    key = str(os.environ.get(key_name, "") or "").strip()
    if key:
        return key, "environment"
    return "", "missing"


def resolve_otx_api_key() -> tuple[str, str]:
    return resolve_ti_api_key("OTX_API_KEY")


def resolve_pulsedive_api_key() -> tuple[str, str]:
    return resolve_ti_api_key("PULSEDIVE_API_KEY")


def query_otx_domain(api_key: str, domain: str) -> dict:
    req = Request(
        f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general",
        headers={"X-OTX-API-KEY": api_key, "Accept": "application/json"},
    )
    try:
        with urlopen(req, timeout=30) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
    except (HTTPError, URLError):
        return {"pulse_count": 0, "verdict": "", "tags": []}
    pulse_info = payload.get("pulse_info", {}) or {}
    pulses = pulse_info.get("pulses", []) or []
    pulse_count = len(pulses)
    tags: set[str] = set()
    for pulse in pulses:
        for tag in (pulse or {}).get("tags", []) or []:
            norm = str(tag).strip().lower()
            if norm:
                tags.add(norm)
    if pulse_count >= 3:
        verdict = "malicious"
    elif pulse_count >= 1:
        verdict = "suspicious"
    else:
        verdict = "clean"
    return {"pulse_count": pulse_count, "verdict": verdict, "tags": sorted(tags)}


def query_pulsedive_domain(api_key: str, domain: str) -> dict:
    req = Request(
        f"https://pulsedive.com/api/info.php?indicator={domain}&key={api_key}",
        headers={"Accept": "application/json"},
    )
    try:
        with urlopen(req, timeout=30) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
    except (HTTPError, URLError):
        return {"risk": "", "verdict": "", "threats": []}
    risk = str(payload.get("risk", "") or "").strip().lower()
    threats = payload.get("threats", []) or []
    threats_norm = [str(t).strip().lower() for t in threats if str(t).strip()]
    if risk in {"critical", "high"}:
        verdict = "malicious"
    elif risk == "medium":
        verdict = "suspicious"
    elif risk in {"low", "none"}:
        verdict = "clean"
    else:
        verdict = ""
    return {"risk": risk, "verdict": verdict, "threats": threats_norm}


def normalize_exclusion_value(value) -> str:
    return str(value or "").strip().lower()


def read_conf_lines(path: Path) -> list[str]:
    if not path.exists():
        return []
    lines: list[str] = []
    with path.open("r", encoding="utf-8") as handle:
        for raw in handle:
            line = raw.split("#", 1)[0].strip()
            if line:
                lines.append(line)
    return lines


def load_exclusions_from_files(values_file: Path, value_reason_file: Path):
    excluded_values = {
        normalize_exclusion_value(v)
        for v in read_conf_lines(values_file)
        if normalize_exclusion_value(v)
    }
    excluded_pairs: set[tuple[str, str]] = set()
    for line in read_conf_lines(value_reason_file):
        if "||" not in line:
            continue
        value_part, reason_part = line.split("||", 1)
        v_norm = normalize_exclusion_value(value_part)
        r_norm = str(reason_part or "").strip().lower()
        if v_norm and r_norm:
            excluded_pairs.add((v_norm, r_norm))
    return excluded_values, excluded_pairs


def load_excluded_parent_domains(parent_domains_file: Path) -> tuple[str, ...]:
    """Load parent domain exclusions. Returns tuple of plain domain names (e.g., 'aventis.com')."""
    return tuple(
        normalize_exclusion_value(v)
        for v in read_conf_lines(parent_domains_file)
        if normalize_exclusion_value(v)
    )


def matches_excluded_parent_suffix(domain: str, parent_domains: tuple[str, ...]) -> bool:
    """Check if domain matches any parent domain suffix (robust matching).
    Handles cases like:
    - domain='xn--pharma.aventis.com', parent='aventis.com' → True
    - domain='pharma.aventis.com', parent='aventis.com' → True
    - domain='aventis.com', parent='aventis.com' → True
    """
    if not parent_domains:
        return False
    domain_norm = normalize_exclusion_value(domain)
    
    for parent in parent_domains:
        parent_norm = normalize_exclusion_value(parent)
        # Exact match (entire domain is the parent)
        if domain_norm == parent_norm:
            return True
        # Suffix match (domain ends with .parent)
        if domain_norm.endswith(f".{parent_norm}"):
            return True
    
    return False


def is_excluded(value, reasons, excluded_values, excluded_pairs, excluded_parent_suffixes=()):
    value_norm = normalize_exclusion_value(value)
    if value_norm in excluded_values:
        return True
    if matches_excluded_parent_suffix(value, excluded_parent_suffixes):
        return True
    reason_list = [str(r or "").strip().lower() for r in reasons]
    for reason in reason_list:
        if (value_norm, reason) in excluded_pairs:
            return True
    return False

# ---------------------------------------------------------------------------
# DNS sibling IP comparison (via VirusTotal passive DNS — no local DNS queries)
# ---------------------------------------------------------------------------

DNS_SIBLING_SCORE_MATCH = -2
DNS_SIBLING_SCORE_RANGE_MATCH = -1
DNS_SIBLING_SCORE_MISMATCH = 2
DNS_SIBLING_IPV4_PREFIX = 24
DNS_SIBLING_IPV6_PREFIX = 48


def _ip_to_subnet(ip_str: str) -> str | None:
    try:
        addr = ipaddress.ip_address(ip_str)
        if isinstance(addr, ipaddress.IPv4Address):
            return str(ipaddress.ip_network(f"{ip_str}/{DNS_SIBLING_IPV4_PREFIX}", strict=False))
        return str(ipaddress.ip_network(f"{ip_str}/{DNS_SIBLING_IPV6_PREFIX}", strict=False))
    except ValueError:
        return None


def _subnets_for_ips(ips: set[str]) -> set[str]:
    return {subnet for ip in ips if (subnet := _ip_to_subnet(ip)) is not None}


def compare_sibling_ips(
    ips_puny: set[str],
    ips_sibling: set[str],
    ascii_sibling: str,
) -> tuple[int, list[str], dict]:
    """Compare pre-fetched IP sets for punycode domain and its ASCII sibling.

    Returns (score_delta, reason_list, metadata_dict).
    """
    meta: dict = {
        "ascii_sibling": ascii_sibling,
        "punycode_ips": ",".join(sorted(ips_puny)) if ips_puny else "",
        "sibling_ips": ",".join(sorted(ips_sibling)) if ips_sibling else "",
        "ip_overlap": False,
        "sibling_dns_status": "",
    }

    if not ips_puny or not ips_sibling:
        meta["sibling_dns_status"] = "resolve-failed"
        return 0, [], meta

    overlap = ips_puny & ips_sibling
    if overlap:
        meta["ip_overlap"] = True
        meta["sibling_dns_status"] = "ip-match"
        return DNS_SIBLING_SCORE_MATCH, ["dns-ip-match-ascii-sibling"], meta

    subnets_puny = _subnets_for_ips(ips_puny)
    subnets_sibling = _subnets_for_ips(ips_sibling)
    if subnets_puny & subnets_sibling:
        meta["ip_overlap"] = True
        meta["sibling_dns_status"] = "ip-range-match"
        return DNS_SIBLING_SCORE_RANGE_MATCH, ["dns-ip-range-match-ascii-sibling"], meta

    meta["sibling_dns_status"] = "ip-mismatch"
    return DNS_SIBLING_SCORE_MISMATCH, ["dns-ip-mismatch-ascii-sibling"], meta


def batch_resolve_siblings(
    pairs: list[tuple[str, str]],
    api_key: str,
    domain_dns_cache: dict[str, set[str]],
    max_workers: int = 8,
    vt_sleep: float = 0.2,
) -> dict[tuple[str, str], tuple[int, list[str], dict]]:
    """Resolve all (punycode_domain, ascii_sibling) pairs via VT passive DNS.

    Uses domain_dns_cache for punycode IPs (already fetched during VT enrichment)
    and queries VT for sibling IPs that aren't cached yet.
    """
    if not pairs:
        return {}
    unique_pairs = sorted(set(pairs))
    log.info("DNS sibling check (VT passive DNS): comparing %d unique pair(s) (%d workers)...",
             len(unique_pairs), max_workers)

    siblings_to_resolve = sorted({
        sib for _, sib in unique_pairs if sib not in domain_dns_cache
    })
    if siblings_to_resolve:
        log.info("  Fetching VT passive DNS for %d unique ASCII sibling domain(s)...",
                 len(siblings_to_resolve))
        resolved = 0

        def _fetch_sibling_ips(sib):
            return sib, get_vt_domain_ips(api_key, sib, sleep=vt_sleep)

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(_fetch_sibling_ips, s): s for s in siblings_to_resolve}
            for future in as_completed(futures):
                sib, ips = future.result()
                domain_dns_cache[sib] = ips
                resolved += 1
                if resolved % 100 == 0 or resolved == len(siblings_to_resolve):
                    log.info("  Sibling VT progress: %d/%d", resolved, len(siblings_to_resolve))

    results: dict[tuple[str, str], tuple[int, list[str], dict]] = {}
    for puny, sib in unique_pairs:
        ips_puny = domain_dns_cache.get(puny, set())
        ips_sib = domain_dns_cache.get(sib, set())
        results[(puny, sib)] = compare_sibling_ips(ips_puny, ips_sib, sib)

    statuses: dict[str, int] = {}
    for _, (_, _, m) in results.items():
        s = m.get("sibling_dns_status", "")
        statuses[s] = statuses.get(s, 0) + 1
    log.info("DNS sibling results: %s", statuses)
    return results


# ---------------------------------------------------------------------------
# Top-100 export helpers
# ---------------------------------------------------------------------------

NO_PASSIVE_DNS_OUTPUT_COLUMNS = [
    "domain",
    "decoded",
    "ascii_sibling",
    "punycode_passive_dns_ip_count",
    "sibling_passive_dns_ip_count",
    "prevalence",
    "vt_verdict",
    "vt_lookup_status",
]

OUTPUT_COLUMNS = [
    "domain", "decoded", "decoded_translation_en", "homograph_risk", "unicode_skeleton",
    "tr39_confusable_count", "tr39_confusable_detail", "mixed_script", "mixed_script_list",
    "bidi_rtl", "idn_punycode_tld", "idna_valid", "idna_errors", "vt_verdict", "vt_lookup_status", "vt_tags",
    "vt_nameservers", "managed_ns_match", "vt_creation_date", "domain_age_days",
    "otx_verdict", "otx_pulse_count", "pulsedive_verdict", "pulsedive_risk",
    "vt_registrar", "ascii_sibling", "sibling_dns_status", "punycode_ips", "sibling_ips",
    "ip_overlap", "brand_impersonation_target", "score", "reasons", "source_file", "prevalence",
]

TOP100_OUTPUT_COLUMNS = [
    "Full domain (Punycode)",
    "Full domain (Unicode)",
    "Full domain (English translation)",
    "Suspicious punycode",
    "Suspicious unicode version of the suspicious punycode string",
]


def decode_punycode_label(label: str) -> str:
    normalized_label = normalize_domain(label)
    normalized_label = normalize_idn_dashes_for_decode(normalized_label)
    if not normalized_label.startswith("xn--"):
        return ""
    try:
        return normalized_label.encode("ascii").decode("idna")
    except Exception:
        try:
            return normalized_label[4:].encode("ascii").decode("punycode")
        except Exception:
            return ""


def extract_suspicious_matches(domain: str, decoded_domain: str) -> tuple[list[str], list[str]]:
    normalized_domain = normalize_domain(domain)
    normalized_decoded_domain = str(decoded_domain or "").strip()
    punycode_matches: list[str] = []
    unicode_matches: list[str] = []

    for candidate in getattr(dns_suspicious_string, "DNS_SUSPICIOUS_STRINGS", []):
        normalized_candidate = normalize_domain(candidate)
        if normalized_candidate and normalized_candidate in normalized_domain and normalized_candidate not in punycode_matches:
            punycode_matches.append(normalized_candidate)
            decoded_candidate = decode_punycode_label(normalized_candidate)
            unicode_matches.append(decoded_candidate if decoded_candidate else normalized_candidate)

    decoded_indicators = [
        str(item or "").strip()
        for item in getattr(dns_suspicious_string, "DECODED_SUSPICIOUS_STRINGS", [])
        if str(item or "").strip()
    ]
    if decoded_indicators and normalized_decoded_domain:
        punycode_labels = [
            label for label in normalized_domain.split(".")
            if label.startswith("xn--")
        ]
        for label in punycode_labels:
            decoded_label = decode_punycode_label(label)
            if not decoded_label:
                continue
            for indicator in decoded_indicators:
                if indicator in decoded_label and label not in punycode_matches:
                    punycode_matches.append(label)
                    unicode_matches.append(decoded_label)
                    break

    return punycode_matches, unicode_matches


def build_top100_export_frame(source_df: pd.DataFrame) -> pd.DataFrame:
    ranked_df = source_df.sort_values(["score", "domain"], ascending=[False, True]).head(100)
    records = []
    for _, row in ranked_df.iterrows():
        full_domain_punycode = str(row.get("domain", "") or "")
        full_domain_unicode = str(row.get("decoded", "") or "").strip() or full_domain_punycode
        translation = str(row.get("decoded_translation_en", "") or "").strip()
        suspicious_matches, suspicious_unicode_matches = extract_suspicious_matches(
            full_domain_punycode, full_domain_unicode,
        )
        records.append({
            "Full domain (Punycode)": full_domain_punycode,
            "Full domain (Unicode)": full_domain_unicode,
            "Full domain (English translation)": translation,
            "Suspicious punycode": ",".join(suspicious_matches),
            "Suspicious unicode version of the suspicious punycode string": ",".join(suspicious_unicode_matches),
        })
    return pd.DataFrame(records, columns=TOP100_OUTPUT_COLUMNS)

# ---------------------------------------------------------------------------
# Low-prevalence keyword extraction helpers
# ---------------------------------------------------------------------------

_STOP_WORDS = frozenset({
    "the", "a", "an", "and", "or", "but", "in", "on", "at", "to", "for",
    "of", "with", "by", "from", "is", "it", "as", "be", "was", "are",
    "this", "that", "not", "no", "so", "if", "do", "has", "had", "have",
    "will", "can", "all", "its", "my", "your", "we", "he", "she", "you",
    "com", "www", "net", "org",
})

LOW_PREV_KW_MAX = 100
LOW_PREV_KW_MAX_DOMAINS = 20


def _normalize_decoded_text(text: str) -> str:
    return unicodedata.normalize("NFKD", text).casefold()


def _resolve_keyword_source(row) -> str:
    translation = str(row.get("decoded_translation_en", "") or "").strip()
    if translation:
        return translation
    decoded = str(row.get("decoded", "") or "").strip()
    if decoded:
        return _normalize_decoded_text(decoded)
    return ""


# ---------------------------------------------------------------------------
# False-positive parent-domain candidates
# ---------------------------------------------------------------------------

def extract_parent_domain(domain: str) -> str:
    labels = str(domain or "").strip().lower().rstrip(".").split(".")
    last_xn_idx = -1
    for i, label in enumerate(labels):
        if label.startswith("xn--"):
            last_xn_idx = i
    if last_xn_idx < 0 or last_xn_idx >= len(labels) - 1:
        return ""
    return ".".join(labels[last_xn_idx + 1:])


FP_MAX_SCORE = 3

# ---------------------------------------------------------------------------
# KPI visualization
# ---------------------------------------------------------------------------

def generate_kpi_chart(
    findings_df: pd.DataFrame,
    raw: pd.DataFrame,
    punycode_only: pd.DataFrame,
    excluded_count: int,
    suspicious_registrars: set,
    score_threshold: int,
    engine_weight_rows: list[dict],
) -> None:
    """Build the 8-panel KPI chart and save to output/."""
    total_dns = len(raw)
    total_punycode = len(punycode_only)
    unique_punycode = punycode_only["domain"].nunique() if not punycode_only.empty else 0
    findings_count = len(findings_df)
    punycode_pct = 100 * total_punycode / total_dns if total_dns else 0
    findings_rate = 100 * findings_count / unique_punycode if unique_punycode else 0
    avg_score = float(findings_df["score"].mean()) if findings_count > 0 else 0
    max_score = int(findings_df["score"].max()) if findings_count > 0 else 0
    malicious_count = (findings_df["vt_verdict"] == "malicious").sum() if findings_count > 0 else 0
    suspicious_count_val = (findings_df["vt_verdict"] == "suspicious").sum() if findings_count > 0 else 0

    low_prevalence_count = int((findings_df["prevalence"].fillna(0).astype(int) <= LOW_PREVALENCE_THRESHOLD).sum()) if findings_count > 0 else 0
    vt_dga_count = int(findings_df["vt_tags"].fillna("").str.lower().str.contains("dga").sum()) if findings_count > 0 else 0
    risky_tld_count = int(findings_df["domain"].str.split(".").str[-1].str.lower().isin(RISKY_TLDS).sum()) if findings_count > 0 else 0
    vt_undetected_count = int(findings_df["vt_verdict"].isin(["undetected", "not_found", ""]).sum()) if findings_count > 0 else 0
    total_prevalence = int(findings_df["prevalence"].sum()) if findings_count > 0 and "prevalence" in findings_df.columns else 0
    dns_suspicious_count = int(findings_df["reasons"].fillna("").str.contains("dns_suspicious_string", regex=False).sum()) if findings_count > 0 else 0
    unique_source_files = findings_df["source_file"].nunique() if findings_count > 0 and "source_file" in findings_df.columns else 0
    tr39_confusable_findings = int((findings_df["tr39_confusable_count"] > 0).sum()) if findings_count > 0 and "tr39_confusable_count" in findings_df.columns else 0
    homograph_high = int((findings_df["homograph_risk"] == "high").sum()) if findings_count > 0 and "homograph_risk" in findings_df.columns else 0
    idna_invalid_findings = int((~findings_df["idna_valid"].fillna(True).astype(bool)).sum()) if findings_count > 0 and "idna_valid" in findings_df.columns else 0
    mixed_script_findings = int(findings_df["mixed_script"].fillna(False).astype(bool).sum()) if findings_count > 0 and "mixed_script" in findings_df.columns else 0
    suspicious_registrar_count = int(findings_df["reasons"].fillna("").str.contains("suspicious-registrar", regex=False).sum()) if findings_count > 0 else 0

    kpi_data = [
        ("Total DNS records scanned", f"{total_dns:,}"),
        ("Punycode domains (xn--)", f"{total_punycode:,} ({punycode_pct:.2f}%)"),
        ("Unique punycode domains", f"{unique_punycode:,}"),
        (f"High-risk findings (score >= {score_threshold})", f"{findings_count:,}"),
        ("Findings rate (of punycode)", f"{findings_rate:.1f}%"),
        ("Excluded (whitelisted)", f"{excluded_count:,}"),
        ("Average risk score", f"{avg_score:.2f}"),
        ("Max risk score", f"{max_score}"),
        ("VT malicious", f"{malicious_count:,}"),
        ("VT suspicious", f"{suspicious_count_val:,}"),
        (f"Low-prevalence findings (<= {LOW_PREVALENCE_THRESHOLD})", f"{low_prevalence_count:,}"),
        ("Findings with VT DGA tag", f"{vt_dga_count:,}"),
        ("Findings with risky TLD", f"{risky_tld_count:,}"),
        ("Suspicious registrar (findings)", f"{suspicious_registrar_count:,}"),
        ("VT undetected/not_found", f"{vt_undetected_count:,}"),
        ("Total prevalence (findings)", f"{total_prevalence:,}"),
        ("With dns_suspicious_string", f"{dns_suspicious_count:,}"),
        ("TR39 confusable hit (findings)", f"{tr39_confusable_findings:,}"),
        ("Homograph risk high", f"{homograph_high:,}"),
        ("IDNA/UTS46 invalid (findings)", f"{idna_invalid_findings:,}"),
        ("Mixed-script (findings)", f"{mixed_script_findings:,}"),
        ("Unique source files", f"{unique_source_files:,}"),
    ]
    kpi_df = pd.DataFrame(kpi_data, columns=["KPI", "Value"])
    log.info("KPI summary:\n%s", kpi_df.to_string(index=False))

    # -- Chart --
    sns.set_style("whitegrid")
    fig = plt.figure(figsize=(20, 12))
    grid = fig.add_gridspec(3, 4, height_ratios=[1, 1, 0.52], hspace=0.35)
    ax1 = fig.add_subplot(grid[0, 0])
    ax2 = fig.add_subplot(grid[0, 1])
    ax3 = fig.add_subplot(grid[0, 2])
    ax4 = fig.add_subplot(grid[0, 3])
    ax5 = fig.add_subplot(grid[1, 0])
    ax6 = fig.add_subplot(grid[1, 1])
    ax7 = fig.add_subplot(grid[1, 2])
    ax8 = fig.add_subplot(grid[1, 3])
    ax_table = fig.add_subplot(grid[2, :])
    ax_table.axis("off")

    # 1. DNS composition
    labels = ["Regular DNS", "Punycode (xn--)"]
    sizes = [total_dns - total_punycode, total_punycode]
    colors = ["#4CAF50", "#FF9800"]
    explode = (0, 0.05) if total_punycode > 0 else (0, 0)
    ax1.pie(sizes, labels=labels, autopct="%1.1f%%", colors=colors, explode=explode, startangle=90)
    ax1.set_title("DNS Query Composition")

    # 2. TLD distribution
    if findings_count > 0:
        tlds = findings_df["domain"].str.split(".").str[-1].str.lower()
        tld_counts = tlds.value_counts().head(10)
        if len(tld_counts) > 0:
            colors_tld = ["#D32F2F" if t in RISKY_TLDS else "#1976D2" for t in tld_counts.index]
            ax2.bar(tld_counts.index, tld_counts.values, color=colors_tld, alpha=0.8)
            ax2.tick_params(axis="x", labelrotation=45)
            for lbl in ax2.get_xticklabels():
                lbl.set_horizontalalignment("right")
        else:
            ax2.text(0.5, 0.5, "No TLDs", ha="center", va="center", transform=ax2.transAxes)
    else:
        ax2.text(0.5, 0.5, "No findings", ha="center", va="center", transform=ax2.transAxes)
    ax2.set_title("Top TLDs (red = risky)")
    ax2.set_ylabel("Domain count")

    # 3. Top risk reasons
    if findings_count > 0 and "reasons" in findings_df.columns:
        all_reasons = []
        for r in findings_df["reasons"].dropna():
            all_reasons.extend(str(r).split(","))
        reason_counts = pd.Series(all_reasons).str.strip().value_counts().head(10)
        if len(reason_counts) > 0:
            r_names = list(reason_counts.index[::-1])
            r_vals = list(reason_counts.values[::-1])
            bars3 = ax3.barh(range(len(r_names)), r_vals, color="#9C27B0", alpha=0.8)
            ax3.set_yticks(range(len(r_names)))
            ax3.set_yticklabels([f"{v:,}" for v in r_vals], fontsize=9)
            for bar, name in zip(bars3, r_names):
                ax3.text(0.5, bar.get_y() + bar.get_height() / 2,
                         name, ha="left", va="center", fontsize=7.5, color="black", fontweight="bold")
        else:
            ax3.text(0.5, 0.5, "No reasons", ha="center", va="center", transform=ax3.transAxes)
    else:
        ax3.text(0.5, 0.5, "No findings", ha="center", va="center", transform=ax3.transAxes)
    ax3.set_title("Top Risk Reasons")
    ax3.set_xlabel("")

    # 4. Risk score distribution
    if findings_count > 0:
        score_counts = findings_df["score"].value_counts().sort_index()
        ax4.bar(score_counts.index.astype(str), score_counts.values, color="#2196F3", edgecolor="#1565C0")
    else:
        ax4.text(0.5, 0.5, "No findings", ha="center", va="center", transform=ax4.transAxes)
    ax4.set_title("Risk Score Distribution")
    ax4.set_xlabel("Score")
    ax4.set_ylabel("Domain count")

    vt_verdict_series = pd.Series(dtype="str")
    if findings_count > 0 and "vt_verdict" in findings_df.columns:
        vt_verdict_series = findings_df["vt_verdict"].fillna("").astype(str).str.strip().str.lower()
    vt_lookup_status_series = pd.Series(dtype="str")
    if findings_count > 0 and "vt_lookup_status" in findings_df.columns:
        vt_lookup_status_series = findings_df["vt_lookup_status"].fillna("").astype(str).str.strip().str.lower()
    vt_error_count = int((vt_verdict_series == "error").sum()) if len(vt_verdict_series) > 0 else 0
    vt_lookup_ok_count = int((vt_lookup_status_series == "ok").sum()) if len(vt_lookup_status_series) > 0 else 0
    vt_rate_limited_count = int((vt_lookup_status_series == "rate_limited").sum()) if len(vt_lookup_status_series) > 0 else 0

    # 5. VT tags distribution
    if findings_count > 0 and "vt_tags" in findings_df.columns:
        all_tags = []
        for t in findings_df["vt_tags"].fillna(""):
            all_tags.extend(str(t).lower().split(","))
        tag_counts = pd.Series(all_tags).str.strip().replace("", pd.NA).dropna().value_counts().head(10)
        if len(tag_counts) > 0:
            t_names = list(tag_counts.index[::-1])
            t_vals = list(tag_counts.values[::-1])
            bars5 = ax5.barh(range(len(t_names)), t_vals, color="#E65100", alpha=0.8)
            ax5.set_yticks(range(len(t_names)))
            ax5.set_yticklabels([f"{v:,}" for v in t_vals], fontsize=9)
            for bar, name in zip(bars5, t_names):
                w = bar.get_width()
                x_in = bar.get_x() + (w * 0.02 if w > 0 else 0)
                ax5.text(x_in, bar.get_y() + bar.get_height() / 2, name,
                         va="center", ha="left", fontsize=9, color="black", fontweight="bold", clip_on=True)
        else:
            msg = "No VT tags"
            if vt_error_count > 0:
                msg = f"No VT tags ({vt_error_count} VT lookup errors)"
            elif vt_lookup_ok_count == 0 and findings_count > 0:
                msg = "No VT tags (0 successful VT lookups)"
            elif vt_rate_limited_count > 0:
                msg = f"No VT tags ({vt_rate_limited_count} rate-limited)"
            ax5.text(0.5, 0.5, msg, ha="center", va="center", transform=ax5.transAxes)
    else:
        ax5.text(0.5, 0.5, "No findings", ha="center", va="center", transform=ax5.transAxes)
    ax5.set_title("VirusTotal Tags (Findings)")
    ax5.set_xlabel("")

    # 6. VT verdict distribution
    vt_panel_title = "VirusTotal Verdict (Findings)"
    if findings_count > 0 and len(vt_verdict_series) > 0:
        vt_counts = vt_verdict_series.replace("", "unknown").value_counts()
        vt_order = ["malicious", "suspicious", "clean", "undetected", "not_found", "error", "unknown"]
        extra_labels = [v for v in vt_counts.index if v not in vt_order]
        ordered_labels = [v for v in vt_order if v in vt_counts.index] + sorted(extra_labels)
        vt_counts = vt_counts.reindex(ordered_labels, fill_value=0)
        _vt_verdict_colors = {
            "malicious": "#D62728", "suspicious": "#FF7F0E", "clean": "#2CA02C",
            "undetected": "#7F7F7F", "not_found": "#7F7F7F", "error": "#8E24AA", "unknown": "#7F7F7F",
        }
        if len(vt_counts) > 0:
            only_unknown = set(vt_counts.index.tolist()) <= {"unknown"}
            if only_unknown and len(vt_lookup_status_series) > 0:
                status_counts = vt_lookup_status_series.replace("", "lookup_failed").value_counts()
                status_order = ["ok", "not_found", "rate_limited", "lookup_failed", "error", "invalid_input"]
                extra_statuses = [v for v in status_counts.index if v not in status_order]
                ordered_statuses = [v for v in status_order if v in status_counts.index] + sorted(extra_statuses)
                status_counts = status_counts.reindex(ordered_statuses, fill_value=0)
                status_colors = {
                    "ok": "#2CA02C",
                    "not_found": "#7F7F7F",
                    "rate_limited": "#E65100",
                    "lookup_failed": "#8E24AA",
                    "error": "#8E24AA",
                    "invalid_input": "#607D8B",
                }
                ax6.bar(
                    status_counts.index,
                    status_counts.values,
                    color=[status_colors.get(str(l).lower(), "#7F7F7F") for l in status_counts.index],
                )
                ax6.tick_params(axis="x", labelrotation=45)
                for lbl in ax6.get_xticklabels():
                    lbl.set_horizontalalignment("right")
                vt_panel_title = "VirusTotal Lookup Status (Findings)"
            else:
                ax6.bar(vt_counts.index, vt_counts.values,
                        color=[_vt_verdict_colors.get(str(l).lower(), "#7F7F7F") for l in vt_counts.index])
                ax6.tick_params(axis="x", labelrotation=45)
                for lbl in ax6.get_xticklabels():
                    lbl.set_horizontalalignment("right")
        else:
            ax6.text(0.5, 0.5, "No VT verdicts", ha="center", va="center", transform=ax6.transAxes)
    else:
        ax6.text(0.5, 0.5, "No VT verdicts", ha="center", va="center", transform=ax6.transAxes)
    ax6.set_title(vt_panel_title)
    ax6.set_ylabel("Count")

    # 7. TR39 confusable-count values
    if findings_count > 0 and "tr39_confusable_count" in findings_df.columns:
        confusable_counts = pd.to_numeric(findings_df["tr39_confusable_count"], errors="coerce").fillna(0).astype(int)
        confusable_distribution = confusable_counts.value_counts().sort_index()
        bars7 = ax7.bar(confusable_distribution.index.astype(str), confusable_distribution.values,
                        color="#6A1B9A", edgecolor="#4A148C")
        ax7.bar_label(bars7, padding=3, fontsize=7)
        ax7.tick_params(axis="x", labelsize=7)
    else:
        ax7.text(0.5, 0.5, "No TR39 data", ha="center", va="center", transform=ax7.transAxes)
    ax7.set_title("TR39 confusable-count values")
    ax7.set_xlabel("Confusable count")
    ax7.set_ylabel("Domain count")

    # 8. Top domain registrars
    if findings_count > 0 and "vt_registrar" in findings_df.columns:
        registrar_series = findings_df["vt_registrar"].replace("", pd.NA).dropna()
        if not registrar_series.empty:
            reg_counts = registrar_series.value_counts().head(15)
            rg_names = list(reg_counts.index[::-1])
            rg_vals = list(reg_counts.values[::-1])
            colors_reg = ["#D32F2F" if name.lower() in suspicious_registrars else "#1976D2" for name in rg_names]
            bars8 = ax8.barh(range(len(rg_names)), rg_vals, color=colors_reg, alpha=0.85)
            ax8.set_yticks(range(len(rg_names)))
            ax8.set_yticklabels([f"{v:,}" for v in rg_vals], fontsize=8)
            for bar, name in zip(bars8, rg_names):
                ax8.text(0.5, bar.get_y() + bar.get_height() / 2,
                         name, ha="left", va="center", fontsize=7, color="black", fontweight="bold")
        else:
            msg = "No registrar data"
            if vt_error_count > 0:
                msg = f"No registrar data ({vt_error_count} VT lookup errors)"
            elif vt_lookup_ok_count == 0 and findings_count > 0:
                msg = "No registrar data (0 successful VT lookups)"
            elif vt_rate_limited_count > 0:
                msg = f"No registrar data ({vt_rate_limited_count} rate-limited)"
            ax8.text(0.5, 0.5, msg, ha="center", va="center", transform=ax8.transAxes)
    else:
        ax8.text(0.5, 0.5, "No findings", ha="center", va="center", transform=ax8.transAxes)
    ax8.set_title("Top Registrars (red = suspicious)")
    ax8.set_xlabel("")

    if engine_weight_rows:
        table_df = pd.DataFrame(engine_weight_rows)[["Engine", "Status", "Weight"]]
        table = ax_table.table(
            cellText=table_df.values,
            colLabels=table_df.columns,
            cellLoc="left",
            loc="center",
        )
        table.auto_set_font_size(False)
        table.set_fontsize(8)
        table.scale(1, 1.2)
        ax_table.set_title("Detection Engines and Configured Weights", loc="left", fontsize=11, fontweight="bold")
    else:
        ax_table.text(0.01, 0.5, "Engine weights unavailable", ha="left", va="center")

    plt.tight_layout()
    chart_path = OUTPUT_DIR / "punycode_idn_kpis.png"
    plt.savefig(chart_path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    log.info("Saved chart to %s", _rel(chart_path))


# ===========================================================================
# Main pipeline
# ===========================================================================

def main(args: argparse.Namespace) -> int:
    """Run the full pipeline. Returns 0 on success, 1 on failure."""

    maybe_run_brand_domain_impersonation_generator()

    translate_enabled = args.translate
    vt_max_workers = args.vt_workers
    vt_sleep = args.vt_sleep
    dns_sibling_enabled = args.dns_sibling
    dns_sibling_workers = args.dns_sibling_workers
    otx_max_workers = args.otx_workers
    otx_sleep = args.otx_sleep
    pulsedive_max_workers = args.pulsedive_workers
    pulsedive_sleep = args.pulsedive_sleep

    runtime_engine_config_file = Path(args.engine_config_file).expanduser() if args.engine_config_file else ENGINE_CONFIG_FILE
    engine_cfg = load_engine_config(runtime_engine_config_file)
    if args.engine_config_overrides_json:
        try:
            override_cfg = json.loads(args.engine_config_overrides_json)
        except json.JSONDecodeError as exc:
            log.error("Invalid --engine-config-overrides-json: %s", exc)
            return 1
        if not isinstance(override_cfg, dict):
            log.error("--engine-config-overrides-json must decode to a JSON object.")
            return 1
        engine_cfg = _deep_merge_dict(engine_cfg, override_cfg)
    score_threshold = _safe_int(engine_cfg.get("score_threshold", 2), 2)

    dns_heuristics_enabled = engine_enabled(engine_cfg, "dns_heuristics", True)
    dns_heuristics_weight = engine_numeric(engine_cfg, "dns_heuristics", "weight", 1.0)
    idn_security_enabled = engine_enabled(engine_cfg, "idn_security_tr39", True)
    idn_security_weight = engine_numeric(engine_cfg, "idn_security_tr39", "weight", 1.0)
    dns_logic_enabled = engine_enabled(engine_cfg, "dns_logic_registry", True)
    dns_logic_weight = engine_numeric(engine_cfg, "dns_logic_registry", "weight", 1.0)
    low_prevalence_enabled = engine_enabled(engine_cfg, "low_prevalence", True)
    vt_tags_enabled = engine_enabled(engine_cfg, "vt_tags", True)
    vt_tag_weight = engine_numeric(engine_cfg, "vt_tags", "weight_per_tag", 1)
    managed_ns_enabled = engine_enabled(engine_cfg, "managed_authoritative_ns", True)
    managed_ns_weight = engine_numeric(engine_cfg, "managed_authoritative_ns", "weight", -5)
    suspicious_registrar_enabled = engine_enabled(engine_cfg, "suspicious_registrar", True)
    suspicious_registrar_weight = engine_numeric(engine_cfg, "suspicious_registrar", "weight", 2)
    newly_registered_enabled = engine_enabled(engine_cfg, "newly_registered", True)
    otx_verdict_enabled = engine_enabled(engine_cfg, "otx_verdict", True)
    pulsedive_verdict_enabled = engine_enabled(engine_cfg, "pulsedive_verdict", True)
    brand_impersonation_enabled = engine_enabled(engine_cfg, "brand_impersonation", True)
    translation_engine_enabled = engine_enabled(engine_cfg, "translation", True)
    translation_runtime_enabled = bool(translation_engine_enabled and translate_enabled)

    dns_sibling_enabled = bool(dns_sibling_enabled and engine_enabled(engine_cfg, "dns_sibling_compare", True))
    dns_sibling_score_match = engine_numeric(engine_cfg, "dns_sibling_compare", "score_match", -2)
    dns_sibling_score_range_match = engine_numeric(engine_cfg, "dns_sibling_compare", "score_range_match", -1)
    dns_sibling_score_mismatch = engine_numeric(engine_cfg, "dns_sibling_compare", "score_mismatch", 2)
    dns_sibling_ipv4_prefix = engine_numeric(engine_cfg, "dns_sibling_compare", "ipv4_prefix", 24)
    dns_sibling_ipv6_prefix = engine_numeric(engine_cfg, "dns_sibling_compare", "ipv6_prefix", 48)

    global LOW_PREVALENCE_THRESHOLD, LOW_PREVALENCE_SCORE_DELTA, BRAND_IMPERSONATION_SCORE_DELTA
    global NEWLY_REGISTERED_THRESHOLD_DAYS, RECENTLY_REGISTERED_THRESHOLD_DAYS
    global NEWLY_REGISTERED_SCORE_DELTA, RECENTLY_REGISTERED_SCORE_DELTA
    global DNS_SIBLING_SCORE_MATCH, DNS_SIBLING_SCORE_RANGE_MATCH, DNS_SIBLING_SCORE_MISMATCH
    global DNS_SIBLING_IPV4_PREFIX, DNS_SIBLING_IPV6_PREFIX
    LOW_PREVALENCE_THRESHOLD = engine_numeric(engine_cfg, "low_prevalence", "threshold", LOW_PREVALENCE_THRESHOLD)
    LOW_PREVALENCE_SCORE_DELTA = engine_numeric(engine_cfg, "low_prevalence", "weight", LOW_PREVALENCE_SCORE_DELTA)
    BRAND_IMPERSONATION_SCORE_DELTA = engine_numeric(engine_cfg, "brand_impersonation", "weight", BRAND_IMPERSONATION_SCORE_DELTA)
    NEWLY_REGISTERED_THRESHOLD_DAYS = engine_numeric(engine_cfg, "newly_registered", "new_threshold_days", NEWLY_REGISTERED_THRESHOLD_DAYS)
    RECENTLY_REGISTERED_THRESHOLD_DAYS = engine_numeric(engine_cfg, "newly_registered", "recent_threshold_days", RECENTLY_REGISTERED_THRESHOLD_DAYS)
    NEWLY_REGISTERED_SCORE_DELTA = engine_numeric(engine_cfg, "newly_registered", "new_weight", NEWLY_REGISTERED_SCORE_DELTA)
    RECENTLY_REGISTERED_SCORE_DELTA = engine_numeric(engine_cfg, "newly_registered", "recent_weight", RECENTLY_REGISTERED_SCORE_DELTA)
    DNS_SIBLING_SCORE_MATCH = dns_sibling_score_match
    DNS_SIBLING_SCORE_RANGE_MATCH = dns_sibling_score_range_match
    DNS_SIBLING_SCORE_MISMATCH = dns_sibling_score_mismatch
    DNS_SIBLING_IPV4_PREFIX = dns_sibling_ipv4_prefix
    DNS_SIBLING_IPV6_PREFIX = dns_sibling_ipv6_prefix

    log.info("Engine config loaded from %s (score threshold=%d).", _rel(runtime_engine_config_file), score_threshold)

    # -- Load exclusions --
    excluded_values_cfg, excluded_value_reason_cfg = load_exclusions_from_files(
        EXCLUDED_VALUES_FILE, EXCLUDED_VALUE_REASONS_FILE,
    )
    excluded_parent_suffixes_cfg = load_excluded_parent_domains(EXCLUDED_PARENT_DOMAINS_FILE)
    reviewed_parent_domains_cfg = {
        normalize_exclusion_value(v)
        for v in read_conf_lines(REVIEWED_PARENT_DOMAINS_FILE)
        if normalize_exclusion_value(v)
    }
    log.info("Exclusion files loaded: values=%d, value+reason=%d, parent-domains=%d",
             len(excluded_values_cfg), len(excluded_value_reason_cfg), len(excluded_parent_suffixes_cfg))
    log.info("Reviewed parent domains (kept in findings): %d", len(reviewed_parent_domains_cfg))

    SUSPICIOUS_REGISTRARS = load_conf_set(ROOT_CONFIG_DIR / "suspicious_registrars.conf")
    managed_authoritative_ns = load_conf_set(MANAGED_AUTHORITATIVE_NS_FILE)

    # -----------------------------------------------------------------------
    # EXECUTE — Load DNS data
    # -----------------------------------------------------------------------
    csv_paths = sorted(glob.glob(str(INPUT_DIR / "**" / "*.csv"), recursive=True))
    log.info("Found %d CSV file(s) in %s.", len(csv_paths), _rel(INPUT_DIR))
    if not csv_paths:
        log.error("No CSV files in %s. Add DNS logs with event.dns.request or equivalent.", _rel(INPUT_DIR))
        return 1

    dfs = []
    for p in csv_paths:
        df = pd.read_csv(p)
        try:
            src_rel = str(Path(p).relative_to(REPO_ROOT))
        except (ValueError, AttributeError):
            src_rel = p
        df["_source_file"] = src_rel
        dfs.append(df)
    raw = pd.concat(dfs, ignore_index=True)

    domain_col = next(
        (c for c in raw.columns if "dns.request" in c.lower() or c in ("query", "domain")), None
    )
    if not domain_col:
        log.error("No DNS request column found. Columns: %s", list(raw.columns))
        return 1

    PREVALENCE_COL_HINTS = ["count", "prevalence", "frequency", "occurrences",
                            "event_count", "num_events", "hits", "seen"]
    prevalence_col = next(
        (c for c in raw.columns
         if c.lower() in PREVALENCE_COL_HINTS or any(h in c.lower() for h in PREVALENCE_COL_HINTS)),
        None,
    )

    raw["domain"] = raw[domain_col].astype(str).str.strip().str.lower().str.rstrip(".")
    raw = raw[raw["domain"].str.len() > 0]
    punycode_only = raw[raw["domain"].str.contains("xn--", na=False)].copy()

    # -----------------------------------------------------------------------
    # VirusTotal enrichment
    # -----------------------------------------------------------------------
    domain_vt_verdict: dict[str, str] = {}
    domain_vt_tags: dict[str, list[str]] = {}
    domain_vt_registrar: dict[str, str] = {}
    domain_vt_creation_date: dict[str, int | None] = {}
    domain_vt_dns_ips: dict[str, set[str]] = {}
    domain_vt_dns_nameservers: dict[str, set[str]] = {}
    domain_vt_lookup_status: dict[str, str] = {}
    unique_domains: list[str] = []

    if not punycode_only.empty:
        vt_api_key, vt_key_source = resolve_vt_api_key()
        if not vt_api_key:
            log.error("VT_API_KEY is required. Set it in scenario .env or OS environment variable.")
            return 1

        unique_domains = sorted(set(punycode_only["domain"].astype(str).tolist()))
        log.info("Querying VirusTotal for %d unique punycode domain(s) (%d workers, %.1fs delay)...",
                 len(unique_domains), vt_max_workers, vt_sleep)

        def _query_vt(domain):
            tags: list = []
            registrar = ""
            dns_ips: set[str] = set()
            dns_nameservers: set[str] = set()
            creation_date = None
            vt_lookup_status = "lookup_failed"
            try:
                status, stats, tags, registrar, dns_ips, dns_nameservers, creation_date = get_vt_stats(vt_api_key, domain)
                if status == "ok":
                    vt_lookup_status = "ok"
                    verdict = classify_verdict(stats)
                elif status == "not_found":
                    vt_lookup_status = "not_found"
                    verdict = "not_found"
                elif status == "rate_limited":
                    vt_lookup_status = "rate_limited"
                    verdict = ""
                elif status is None:
                    vt_lookup_status = "invalid_input"
                    verdict = ""
                else:
                    vt_lookup_status = "error"
                    verdict = ""
            except Exception:
                verdict = ""
                vt_lookup_status = "lookup_failed"
            if vt_sleep > 0:
                time.sleep(vt_sleep)
            return domain, verdict, tags, registrar, dns_ips, dns_nameservers, vt_lookup_status, creation_date

        completed = 0
        with ThreadPoolExecutor(max_workers=vt_max_workers) as executor:
            futures = {executor.submit(_query_vt, d): d for d in unique_domains}
            for future in as_completed(futures):
                d, verdict, tags, registrar, dns_ips, dns_nameservers, vt_lookup_status, creation_date = future.result()
                if verdict:
                    domain_vt_verdict[d] = verdict
                if tags:
                    domain_vt_tags[d] = [str(t).strip().lower() for t in tags if str(t).strip()]
                if registrar:
                    domain_vt_registrar[d] = registrar
                domain_vt_creation_date[d] = creation_date
                domain_vt_dns_ips[d] = dns_ips
                domain_vt_dns_nameservers[d] = dns_nameservers
                domain_vt_lookup_status[d] = vt_lookup_status
                completed += 1
                if completed % 100 == 0 or completed == len(unique_domains):
                    log.info("  VT progress: %d/%d", completed, len(unique_domains))

    # -----------------------------------------------------------------------
    # Prevalence
    # -----------------------------------------------------------------------
    domain_prevalence: dict = {}
    if prevalence_col:
        prevalence_numeric = pd.to_numeric(punycode_only[prevalence_col], errors="coerce")
        if prevalence_numeric.notna().any():
            punycode_only["_prevalence_numeric"] = prevalence_numeric
            domain_prevalence = (
                punycode_only.groupby("domain")["_prevalence_numeric"]
                .sum(min_count=1)
                .fillna(0)
                .to_dict()
            )
            log.info("Prevalence column detected: %s", prevalence_col)
        else:
            log.info("Prevalence column detected but non-numeric: %s; falling back to observed counts.", prevalence_col)
    if not domain_prevalence:
        domain_prevalence = punycode_only.groupby("domain").size().astype(int).to_dict()
        log.info("Prevalence fallback: using observed domain counts from input rows.")

    domain_otx_data: dict[str, dict] = {}
    otx_api_key, _ = resolve_otx_api_key()
    if otx_api_key and unique_domains:
        log.info("Querying AlienVault OTX for %d unique punycode domain(s) (%d workers, %.1fs delay)...",
                 len(unique_domains), otx_max_workers, otx_sleep)

        def _query_otx(domain: str):
            result = query_otx_domain(otx_api_key, domain)
            if otx_sleep > 0:
                time.sleep(otx_sleep)
            return domain, result

        otx_completed = 0
        with ThreadPoolExecutor(max_workers=otx_max_workers) as executor:
            futures = {executor.submit(_query_otx, d): d for d in unique_domains}
            for future in as_completed(futures):
                d, result = future.result()
                domain_otx_data[d] = result
                otx_completed += 1
                if otx_completed % 100 == 0 or otx_completed == len(unique_domains):
                    log.info("  OTX progress: %d/%d", otx_completed, len(unique_domains))
    elif not otx_api_key:
        log.info("OTX_API_KEY not configured — skipping AlienVault OTX enrichment.")

    domain_pulsedive_data: dict[str, dict] = {}
    pulsedive_api_key, _ = resolve_pulsedive_api_key()
    if pulsedive_api_key and unique_domains:
        log.info("Querying Pulsedive for %d unique punycode domain(s) (%d workers, %.1fs delay)...",
                 len(unique_domains), pulsedive_max_workers, pulsedive_sleep)

        def _query_pulsedive(domain: str):
            result = query_pulsedive_domain(pulsedive_api_key, domain)
            if pulsedive_sleep > 0:
                time.sleep(pulsedive_sleep)
            return domain, result

        pulsedive_completed = 0
        with ThreadPoolExecutor(max_workers=pulsedive_max_workers) as executor:
            futures = {executor.submit(_query_pulsedive, d): d for d in unique_domains}
            for future in as_completed(futures):
                d, result = future.result()
                domain_pulsedive_data[d] = result
                pulsedive_completed += 1
                if pulsedive_completed % 100 == 0 or pulsedive_completed == len(unique_domains):
                    log.info("  Pulsedive progress: %d/%d", pulsedive_completed, len(unique_domains))
    elif not pulsedive_api_key:
        log.info("PULSEDIVE_API_KEY not configured — skipping Pulsedive enrichment.")

    log.info("Domains with VT verdict from API: %d",
             sum(1 for v in domain_vt_verdict.values() if v))
    if domain_vt_lookup_status:
        vt_status_counts = pd.Series(domain_vt_lookup_status.values()).value_counts().to_dict()
        log.info("VT lookup status counts: %s", vt_status_counts)
    log.info("Loaded %s DNS records. %s contain xn-- (punycode).",
             f"{len(raw):,}", f"{len(punycode_only):,}")

    # -----------------------------------------------------------------------
    # DNS sibling IP comparison (via VT passive DNS)
    # -----------------------------------------------------------------------
    dns_sibling_cache: dict[tuple[str, str], tuple[int, list[str], dict]] = {}
    if dns_sibling_enabled and not punycode_only.empty:
        _sibling_pairs: list[tuple[str, str]] = []
        for _d in punycode_only["domain"].unique():
            _dec = decode_punycode_domain(_d)
            _idn = analyze_idn_domain(_d, _dec if _dec else "")
            _sib = derive_ascii_sibling(_dec if _dec else "", _idn.get("unicode_skeleton", ""))
            if _sib:
                _sibling_pairs.append((_d, _sib))
        if _sibling_pairs:
            dns_sibling_cache = batch_resolve_siblings(
                _sibling_pairs,
                api_key=vt_api_key,
                domain_dns_cache=domain_vt_dns_ips,
                max_workers=dns_sibling_workers,
                vt_sleep=vt_sleep,
            )
    elif not dns_sibling_enabled:
        log.info("DNS sibling check disabled via --no-dns-sibling.")

    # -----------------------------------------------------------------------
    # Export: punycode domains with no VT passive DNS (0 A/AAAA in last_dns_records)
    # -----------------------------------------------------------------------
    no_pdns_path = OUTPUT_DIR / "punycode_idn_no_passive_dns_domains.csv"
    if not unique_domains:
        pd.DataFrame(columns=NO_PASSIVE_DNS_OUTPUT_COLUMNS).to_csv(no_pdns_path, index=False)
        log.info("No punycode domains — empty no-passive-DNS export saved to %s", _rel(no_pdns_path))
    else:
        no_pdns_rows: list[dict] = []
        no_pdns_parent_excluded = 0
        for d in sorted(unique_domains):
            if len(domain_vt_dns_ips.get(d, set())) > 0:
                continue
            if matches_excluded_parent_suffix(d, excluded_parent_suffixes_cfg):
                no_pdns_parent_excluded += 1
                continue
            dec = decode_punycode_domain(d)
            idn_r = analyze_idn_domain(d, dec if dec else "")
            sib = derive_ascii_sibling(dec if dec else "", idn_r.get("unicode_skeleton", ""))
            if sib and dns_sibling_enabled:
                sib_cnt: int | str = len(domain_vt_dns_ips.get(sib, set()))
            else:
                sib_cnt = ""
            prev = domain_prevalence.get(d)
            if prev is not None:
                try:
                    prev_out = max(1, int(float(prev)))
                except (TypeError, ValueError):
                    prev_out = ""
            else:
                prev_out = ""
            no_pdns_rows.append({
                "domain": d,
                "decoded": dec if dec else "",
                "ascii_sibling": sib if sib else "",
                "punycode_passive_dns_ip_count": 0,
                "sibling_passive_dns_ip_count": sib_cnt,
                "prevalence": prev_out,
                "vt_verdict": str(domain_vt_verdict.get(d, "") or "").strip().lower(),
                "vt_lookup_status": str(domain_vt_lookup_status.get(d, "") or ""),
            })
        no_pdns_df = pd.DataFrame(no_pdns_rows, columns=NO_PASSIVE_DNS_OUTPUT_COLUMNS)
        no_pdns_df.to_csv(no_pdns_path, index=False)
        log.info("Domains with no VT passive DNS (0 A/AAAA): %s — saved to %s",
                 f"{len(no_pdns_df):,}", _rel(no_pdns_path))
        if no_pdns_parent_excluded:
            log.info("No-passive-DNS export: skipped %s domain(s) matching excluded_parent_domains.conf.",
                     f"{no_pdns_parent_excluded:,}")

    # -----------------------------------------------------------------------
    # Decode and score punycode domains
    # -----------------------------------------------------------------------
    brand_imp_puny, brand_imp_by_puny = load_brand_impersonation_index(BRAND_IMPERSONATION_OUTPUT)
    if brand_imp_puny:
        log.info(
            "Brand impersonation list loaded: %s punycode hostname(s) for scoring.",
            f"{len(brand_imp_puny):,}",
        )

    otx_malicious_weight = engine_numeric(engine_cfg, "otx_verdict", "malicious_weight", 2)
    otx_suspicious_weight = engine_numeric(engine_cfg, "otx_verdict", "suspicious_weight", 1)
    pulsedive_malicious_weight = engine_numeric(engine_cfg, "pulsedive_verdict", "malicious_weight", 2)
    pulsedive_suspicious_weight = engine_numeric(engine_cfg, "pulsedive_verdict", "suspicious_weight", 1)

    findings: list[dict] = []
    seen: set[str] = set()
    excluded_count = 0

    for _, row in punycode_only.iterrows():
        domain = row["domain"]
        if domain in seen:
            continue
        seen.add(domain)
        decoded = decode_punycode_domain(domain)
        idn_report = analyze_idn_domain(domain, decoded if decoded else "")

        score = 0
        reasons: list[str] = []

        if dns_heuristics_enabled:
            d_dns, r_dns = score_dns(domain)
            score += int(round(d_dns * dns_heuristics_weight))
            reasons.extend(r_dns)

        if idn_security_enabled:
            d_idn, r_idn = score_idn_security_signals(idn_report)
            score += int(round(d_idn * idn_security_weight))
            reasons.extend(r_idn)

        sibling_meta: dict = {}
        if dns_sibling_enabled:
            sibling = derive_ascii_sibling(decoded if decoded else "", idn_report.get("unicode_skeleton", ""))
            if sibling and (domain, sibling) in dns_sibling_cache:
                delta_sib, reasons_sib, sibling_meta = dns_sibling_cache[(domain, sibling)]
                score += delta_sib
                reasons.extend(reasons_sib)

        vt_nameservers_set = domain_vt_dns_nameservers.get(domain, set())
        reasons_managed_ns: list[str] = []
        if managed_ns_enabled:
            delta_managed_ns, reasons_managed_ns = score_managed_authoritative_ns(
                vt_nameservers_set,
                managed_authoritative_ns,
                weight=managed_ns_weight,
            )
            score += delta_managed_ns
            reasons.extend(reasons_managed_ns)

        decoded_for_logic = f"punycode:{decoded}" if decoded else "punycode:"
        vt_verdict = str(domain_vt_verdict.get(domain, "") or "").strip().lower()
        if vt_verdict:
            decoded_for_logic = f"{decoded_for_logic}|vt:{vt_verdict}"

        logic_reasons: list[str] = []
        if dns_logic_enabled:
            delta, logic_reasons = apply_dns_logics(domain, decoded_for_logic)
            score += int(round(delta * dns_logic_weight))
            reasons.extend(logic_reasons)

            if "dns_suspicious_string" not in logic_reasons:
                extra_delta, extra_reason = dns_suspicious_string.apply(domain, decoded_for_logic)
                if extra_delta > 0 and extra_reason:
                    score += int(round(extra_delta * dns_logic_weight))
                    reasons.append(extra_reason)

        prevalence_val = domain_prevalence.get(domain) if domain_prevalence else None
        if low_prevalence_enabled:
            delta_prev, prev_reasons = score_prevalence(prevalence_val)
            score += delta_prev
            reasons.extend(prev_reasons)

        vt_tags_list = domain_vt_tags.get(domain, []) or []
        if vt_tags_enabled:
            for tag in vt_tags_list:
                score += vt_tag_weight
                reasons.append(f"vt-tag:{tag}")
        vt_tags_str = ",".join(vt_tags_list) if vt_tags_list else ""
        vt_nameservers = ",".join(sorted(vt_nameservers_set)) if vt_nameservers_set else ""
        managed_ns_match = bool(reasons_managed_ns)

        registrar = str(domain_vt_registrar.get(domain, "") or "").strip()
        if suspicious_registrar_enabled and registrar and registrar.lower() in SUSPICIOUS_REGISTRARS:
            score += suspicious_registrar_weight
            reasons.append("suspicious-registrar")

        creation_date_epoch = domain_vt_creation_date.get(domain)
        vt_creation_date_str = ""
        domain_age_days = None
        if newly_registered_enabled:
            delta_new, reasons_new, vt_creation_date_str, domain_age_days = score_newly_registered(creation_date_epoch)
            score += delta_new
            reasons.extend(reasons_new)

        otx_info = domain_otx_data.get(domain, {})
        otx_verdict = str(otx_info.get("verdict", "") or "").strip().lower()
        otx_pulses = int(otx_info.get("pulse_count", 0) or 0)
        if otx_verdict_enabled:
            if otx_verdict == "malicious":
                score += otx_malicious_weight
                reasons.append("otx-malicious")
            elif otx_verdict == "suspicious":
                score += otx_suspicious_weight
                reasons.append("otx-suspicious")

        pulsedive_info = domain_pulsedive_data.get(domain, {})
        pulsedive_verdict = str(pulsedive_info.get("verdict", "") or "").strip().lower()
        pulsedive_risk = str(pulsedive_info.get("risk", "") or "").strip().lower()
        if pulsedive_verdict_enabled:
            if pulsedive_verdict == "malicious":
                score += pulsedive_malicious_weight
                reasons.append("pulsedive-malicious")
            elif pulsedive_verdict == "suspicious":
                score += pulsedive_suspicious_weight
                reasons.append("pulsedive-suspicious")

        brand_impersonation_target = ""
        if brand_impersonation_enabled and brand_imp_puny and domain in brand_imp_puny:
            score += BRAND_IMPERSONATION_SCORE_DELTA
            reasons.append(BRAND_IMPERSONATION_REASON)
            brand_impersonation_target = brand_imp_by_puny.get(domain, "")

        if score >= score_threshold:
            if is_excluded(domain, reasons, excluded_values_cfg, excluded_value_reason_cfg, excluded_parent_suffixes_cfg):
                excluded_count += 1
                continue
            rec = {
                "domain": domain,
                "decoded": decoded if decoded else "",
                "homograph_risk": idn_report["homograph_risk"],
                "unicode_skeleton": idn_report["unicode_skeleton"],
                "tr39_confusable_count": idn_report["tr39_confusable_count"],
                "tr39_confusable_detail": idn_report["tr39_confusable_detail"],
                "mixed_script": idn_report["mixed_script"],
                "mixed_script_list": idn_report["mixed_script_list"],
                "bidi_rtl": idn_report["bidi_rtl"],
                "idn_punycode_tld": idn_report["idn_punycode_tld"],
                "idna_valid": idn_report["idna_valid"],
                "idna_errors": idn_report["idna_errors"],
                "vt_verdict": vt_verdict if vt_verdict else "",
                "vt_lookup_status": str(domain_vt_lookup_status.get(domain, "") or ""),
                "vt_tags": vt_tags_str,
                "vt_nameservers": vt_nameservers,
                "managed_ns_match": managed_ns_match,
                "vt_registrar": registrar,
                "vt_creation_date": vt_creation_date_str,
                "domain_age_days": domain_age_days if domain_age_days is not None else "",
                "otx_verdict": otx_verdict,
                "otx_pulse_count": otx_pulses,
                "pulsedive_verdict": pulsedive_verdict,
                "pulsedive_risk": pulsedive_risk,
                "ascii_sibling": sibling_meta.get("ascii_sibling", ""),
                "sibling_dns_status": sibling_meta.get("sibling_dns_status", ""),
                "punycode_ips": sibling_meta.get("punycode_ips", ""),
                "sibling_ips": sibling_meta.get("sibling_ips", ""),
                "ip_overlap": sibling_meta.get("ip_overlap", ""),
                "brand_impersonation_target": brand_impersonation_target,
                "score": score,
                "reasons": ",".join(reasons),
                "source_file": row.get("_source_file", ""),
            }
            rec["prevalence"] = max(1, int(float(prevalence_val))) if prevalence_val is not None else 1
            findings.append(rec)

    findings_df = pd.DataFrame(findings)
    if len(findings_df) > 0:
        findings_df = findings_df.sort_values("score", ascending=False).reset_index(drop=True)
        translation_map = batch_translate_domains(findings_df["decoded"], enabled=translation_runtime_enabled)
        findings_df["decoded_translation_en"] = findings_df["decoded"].map(
            lambda d: translation_map.get(str(d).strip(), "")
        )
    else:
        findings_df["decoded_translation_en"] = pd.Series(dtype="str")

    log.info("Excluded records: %d", excluded_count)
    log.info("Found %s unique punycode domains (score >= %d).", f"{len(findings_df):,}", score_threshold)

    # -----------------------------------------------------------------------
    # Save results and top-100 export
    # -----------------------------------------------------------------------
    out_path = OUTPUT_DIR / "punycode_idn_results.csv"
    top100_out_path = OUTPUT_DIR / "punycode_idn_top100.csv"

    if len(findings_df) > 0:
        findings_df[OUTPUT_COLUMNS].to_csv(out_path, index=False)
        log.info("Saved to %s", _rel(out_path))
        top100_df = build_top100_export_frame(findings_df)
        top100_df.to_csv(top100_out_path, index=False)
        log.info("Saved top-100 export to %s", _rel(top100_out_path))
    else:
        top100_df = pd.DataFrame(columns=TOP100_OUTPUT_COLUMNS)
        pd.DataFrame(columns=OUTPUT_COLUMNS).to_csv(out_path, index=False)
        top100_df.to_csv(top100_out_path, index=False)
        log.info("Empty results saved to %s", _rel(out_path))
        log.info("Empty top-100 export saved to %s", _rel(top100_out_path))

    # -----------------------------------------------------------------------
    # Low-prevalence keyword extraction
    # -----------------------------------------------------------------------
    low_prev_kw_path = OUTPUT_DIR / "punycode_idn_top100_low_prevalence_keywords.csv"
    low_prev_kw_df: pd.DataFrame | None = None

    if len(findings_df) > 0:
        keyword_to_domains: dict[str, set[str]] = {}
        for _, row in findings_df.iterrows():
            text = _resolve_keyword_source(row).lower()
            if not text:
                continue
            tokens = re.split(r"[^a-z0-9]+", text)
            domain_label = str(row.get("domain", "")).strip()
            seen_in_row: set[str] = set()
            for tok in tokens:
                if len(tok) <= 2 or tok in _STOP_WORDS or tok.isdigit():
                    continue
                if tok not in seen_in_row:
                    seen_in_row.add(tok)
                    keyword_to_domains.setdefault(tok, set()).add(domain_label)

        if keyword_to_domains:
            kw_records = [
                {
                    "keyword": kw,
                    "prevalence": len(domains),
                    "domains": ", ".join(sorted(domains)[:LOW_PREV_KW_MAX_DOMAINS]),
                }
                for kw, domains in keyword_to_domains.items()
            ]
            low_prev_kw_df = (
                pd.DataFrame(kw_records)
                .sort_values(["prevalence", "keyword"], ascending=[True, True])
                .head(LOW_PREV_KW_MAX)
                .reset_index(drop=True)
            )
            low_prev_kw_df.to_csv(low_prev_kw_path, index=False)
            log.info("Saved top-%d low-prevalence keywords to %s", LOW_PREV_KW_MAX, _rel(low_prev_kw_path))
            log.info("Total unique keywords extracted: %s", f"{len(keyword_to_domains):,}")
        else:
            pd.DataFrame(columns=["keyword", "prevalence", "domains"]).to_csv(low_prev_kw_path, index=False)
            log.info("No keywords found. Empty file saved to %s", _rel(low_prev_kw_path))
    else:
        pd.DataFrame(columns=["keyword", "prevalence", "domains"]).to_csv(low_prev_kw_path, index=False)
        log.info("No findings. Empty keywords file saved to %s", _rel(low_prev_kw_path))

    # -----------------------------------------------------------------------
    # Word cloud (optional — skip silently if wordcloud not installed)
    # -----------------------------------------------------------------------
    try:
        from wordcloud import WordCloud as _WordCloud

        word_cloud_path = OUTPUT_DIR / "punycode_idn_top100_low_prevalence_keywords-word_cloud.png"
        if len(findings_df) > 0 and low_prev_kw_df is not None and len(low_prev_kw_df) > 0:
            max_prev = low_prev_kw_df["prevalence"].max()
            word_weights = {
                r["keyword"]: (max_prev + 1 - r["prevalence"])
                for _, r in low_prev_kw_df.iterrows()
            }
            wc = _WordCloud(
                width=1600, height=800, background_color="white", colormap="inferno",
                max_words=LOW_PREV_KW_MAX, prefer_horizontal=0.7, min_font_size=8,
            ).generate_from_frequencies(word_weights)
            wc_fig, wc_ax = plt.subplots(figsize=(16, 8))
            wc_ax.imshow(wc, interpolation="bilinear")
            wc_ax.axis("off")
            wc_ax.set_title("Top-100 Low-Prevalence Keywords (larger = rarer)", fontsize=16, pad=12)
            plt.tight_layout()
            wc_fig.savefig(word_cloud_path, dpi=150, bbox_inches="tight")
            plt.close(wc_fig)
            log.info("Saved word cloud to %s", _rel(word_cloud_path))
    except ImportError:
        log.debug("wordcloud not installed — skipping word cloud generation.")

    # -----------------------------------------------------------------------
    # False-positive parent-domain candidates
    # -----------------------------------------------------------------------
    fp_candidates_path = OUTPUT_DIR / "punycode_idn_false_positive_parent_domains_candidates.csv"
    FP_OUTPUT_COLUMNS = OUTPUT_COLUMNS + ["parent_domain"]

    if len(findings_df) > 0:
        no_suspicious = ~findings_df["reasons"].fillna("").str.contains("dns_suspicious_string", regex=False)
        low_score = findings_df["score"] <= FP_MAX_SCORE
        fp_df = findings_df.loc[no_suspicious & low_score].copy()
        fp_df["parent_domain"] = fp_df["domain"].apply(extract_parent_domain)

        if excluded_parent_suffixes_cfg:
            before_parent_excl = len(fp_df)
            fp_df = fp_df[
                ~fp_df["domain"].apply(lambda dom: matches_excluded_parent_suffix(dom, excluded_parent_suffixes_cfg))
            ].reset_index(drop=True)
            parent_excl_removed = before_parent_excl - len(fp_df)
        else:
            parent_excl_removed = 0

        if reviewed_parent_domains_cfg:
            before_reviewed = len(fp_df)
            fp_df = fp_df[~fp_df["parent_domain"].str.lower().isin(reviewed_parent_domains_cfg)].reset_index(drop=True)
            reviewed_removed = before_reviewed - len(fp_df)
        else:
            reviewed_removed = 0

        fp_df = fp_df.sort_values(["score", "parent_domain", "domain"], ascending=True).reset_index(drop=True)
        fp_df[FP_OUTPUT_COLUMNS].to_csv(fp_candidates_path, index=False)
        log.info("False-positive candidates: %s entries (score <= %d, no dns_suspicious_string).",
                 f"{len(fp_df):,}", FP_MAX_SCORE)
        if parent_excl_removed:
            log.info("Removed %s entries whose parent domain is in excluded_parent_domains.conf.",
                     f"{parent_excl_removed:,}")
        if reviewed_removed:
            log.info("Removed %s entries whose parent domain was already reviewed.", f"{reviewed_removed:,}")
        log.info("Unique parent domains: %s", f'{fp_df["parent_domain"].nunique():,}')
        log.info("Saved FP candidates to %s", _rel(fp_candidates_path))
    else:
        fp_df = pd.DataFrame(columns=FP_OUTPUT_COLUMNS)
        fp_df.to_csv(fp_candidates_path, index=False)
        log.info("No findings — empty FP candidates saved to %s", _rel(fp_candidates_path))

    # -----------------------------------------------------------------------
    # KPI chart
    # -----------------------------------------------------------------------
    engine_weight_rows = build_engine_weight_rows(
        engine_cfg,
        dns_sibling_runtime=dns_sibling_enabled,
        otx_runtime=bool(otx_api_key and domain_otx_data),
        pulsedive_runtime=bool(pulsedive_api_key and domain_pulsedive_data),
        brand_runtime=bool(brand_imp_puny),
        translation_runtime=bool(translation_runtime_enabled and _TRANSLATOR_AVAILABLE),
    )
    generate_kpi_chart(
        findings_df,
        raw,
        punycode_only,
        excluded_count,
        SUSPICIOUS_REGISTRARS,
        score_threshold,
        engine_weight_rows,
    )

    log.info("Pipeline finished successfully.")
    return 0


# ===========================================================================
# CLI entry point
# ===========================================================================

def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Punycode IDN threat-hunting pipeline (headless / crontab mode).",
    )
    parser.add_argument(
        "--vt-workers", type=int, default=8,
        help="Parallel VirusTotal API workers (default: 8; use 1 for free-tier keys).",
    )
    parser.add_argument(
        "--vt-sleep", type=float, default=0.2,
        help="Delay in seconds between VT requests per worker (default: 0.2).",
    )
    parser.add_argument(
        "--otx-workers", type=int, default=4,
        help="Parallel AlienVault OTX API workers (default: 4).",
    )
    parser.add_argument(
        "--otx-sleep", type=float, default=0.3,
        help="Delay in seconds between OTX requests per worker (default: 0.3).",
    )
    parser.add_argument(
        "--pulsedive-workers", type=int, default=2,
        help="Parallel Pulsedive API workers (default: 2).",
    )
    parser.add_argument(
        "--pulsedive-sleep", type=float, default=1.0,
        help="Delay in seconds between Pulsedive requests per worker (default: 1.0).",
    )
    parser.add_argument(
        "--no-translate", dest="translate", action="store_false", default=True,
        help="Disable Google Translate for non-Latin decoded domains.",
    )
    parser.add_argument(
        "--no-dns-sibling", dest="dns_sibling", action="store_false", default=True,
        help="Disable DNS sibling IP comparison (VT passive DNS-based, OPSEC-safe).",
    )
    parser.add_argument(
        "--dns-sibling-workers", type=int, default=8,
        help="Parallel VT passive DNS workers for sibling resolution (default: 8).",
    )
    parser.add_argument(
        "--engine-config-file", default="",
        help="Optional alternate engine_weights.json path.",
    )
    parser.add_argument(
        "--engine-config-overrides-json", default="",
        help="Optional JSON object merged on top of engine config.",
    )
    parser.add_argument(
        "--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Logging verbosity (default: INFO).",
    )
    return parser.parse_args(argv)


if __name__ == "__main__":
    args = parse_args()
    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )
    if not args.translate:
        log.info("Translation disabled via --no-translate.")
    if not _TRANSLATOR_AVAILABLE and args.translate:
        log.warning("deep-translator not installed — translations will be skipped. "
                     "Install with: pip install deep-translator>=1.11")
    sys.exit(main(args))
