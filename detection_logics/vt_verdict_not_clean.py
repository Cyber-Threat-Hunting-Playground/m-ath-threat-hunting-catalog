"""
Detection logic: vt_verdict_not_clean
Increases score when a VirusTotal verdict exists and is not clean.
"""
from __future__ import annotations

import re


REASON_NAME = "vt_verdict_not_clean"
_VERDICT_PATTERN = re.compile(r"(?:\[\s*vt\s*:\s*|\bvt(?:_verdict)?\s*[:=])([a-z_]+)", re.IGNORECASE)


def _extract_vt_verdict(*values: str) -> str:
    """Extract the last VT verdict token from text fragments."""
    verdict = ""
    for value in values:
        text = str(value or "")
        for match in _VERDICT_PATTERN.finditer(text):
            verdict = (match.group(1) or "").strip().lower()
    return verdict


def apply(value: str, decoded_value: str) -> tuple[int, str | None]:
    """Apply weighted score for VT verdicts: malicious=+2, other non-clean=+1."""
    verdict = _extract_vt_verdict(decoded_value, value)
    if not verdict or verdict == "clean":
        return 0, None
    if verdict == "malicious":
        return 2, REASON_NAME
    if verdict == "suspicious":
        return 1, REASON_NAME
    return 1, REASON_NAME
