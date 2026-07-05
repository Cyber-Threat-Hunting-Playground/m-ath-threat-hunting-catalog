"""
Detection logic: dns_suspicious_string
Alerts when DNS value or its punycode-decoded form contains known suspicious strings.
Score increases with more unique strings found.
"""
import csv
import os

REASON_NAME = "dns_suspicious_string"

# Load suspicious strings from input file
DNS_SUSPICIOUS_STRINGS = []
DNS_PUNYCODE_SUSPICIOUS_STRINGS = []

_INPUT_FILE = os.path.join(os.path.dirname(__file__), "dns_suspicious_string.input")
if os.path.exists(_INPUT_FILE):
    with open(_INPUT_FILE, "r", encoding="utf-8") as _f:
        for _row in csv.reader(_f):
            if len(_row) >= 2:
                _type, _val = _row[0].strip(), _row[1].strip()
                if _type == "DNS_SUSPICIOUS_STRINGS":
                    DNS_SUSPICIOUS_STRINGS.append(_val)
                elif _type == "DNS_PUNYCODE_SUSPICIOUS_STRINGS":
                    DNS_PUNYCODE_SUSPICIOUS_STRINGS.append(_val)


def _extract_decoded_for_search(decoded_value: str) -> str:
    """Extract decoded content from decoded_value (e.g. punycode:xxx)."""
    if not decoded_value:
        return ""
    decoded = str(decoded_value).strip()
    for prefix in ("punycode:", "base64:"):
        if decoded.startswith(prefix):
            return decoded[len(prefix) :].strip()
    return decoded


def apply(value: str, decoded_value: str) -> tuple[int, str | None]:
    """
    Check value and decoded_value for suspicious strings.
    Returns (score_delta, reason_name) or (0, None) if no hit.
    """
    value = (value or "").strip().lower()
    decoded_for_search = _extract_decoded_for_search(decoded_value)

    found: set[str] = set()
    for s in DNS_SUSPICIOUS_STRINGS:
        if s in value:
            found.add(s)
    for s in DNS_PUNYCODE_SUSPICIOUS_STRINGS:
        if s in decoded_for_search:
            found.add(s)

    if not found:
        return 0, None
    return len(found), REASON_NAME
