"""
Detection logics: modular rules that increase risk score and add reasons on hit.
Each logic is a separate file. Apply via apply_dns_logics() or apply_url_logics().
"""
from . import dns_suspicious_string
from . import vt_verdict_not_clean
from . import s1_triage
from .s1_triage import apply_s1_triage

_DNS_LOGIC_FUNCTIONS = [
    ("dns_suspicious_string", dns_suspicious_string.apply),
    ("vt_verdict_not_clean", vt_verdict_not_clean.apply),
]
_URL_LOGIC_FUNCTIONS: list[tuple[str, object]] = [
    ("vt_verdict_not_clean", vt_verdict_not_clean.apply),
]


def apply_dns_logics(value: str, decoded_value: str) -> tuple[int, list[str]]:
    """
    Run all DNS detection logics. Returns (total_score_delta, list of reason names).
    """
    total_delta = 0
    reason_names: list[str] = []
    for _name, fn in _DNS_LOGIC_FUNCTIONS:
        delta, reason = fn(value, decoded_value)
        if delta > 0 and reason:
            total_delta += delta
            reason_names.append(reason)
    return total_delta, reason_names


def apply_url_logics(value: str, decoded_value: str) -> tuple[int, list[str]]:
    """
    Run all URL detection logics. Returns (total_score_delta, list of reason names).
    """
    total_delta = 0
    reason_names: list[str] = []
    for _name, fn in _URL_LOGIC_FUNCTIONS:
        delta, reason = fn(value, decoded_value)
        if delta > 0 and reason:
            total_delta += delta
            reason_names.append(reason)
    return total_delta, reason_names
