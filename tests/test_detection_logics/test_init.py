import pytest
from detection_logics import apply_dns_logics, apply_url_logics

def test_apply_dns_logics_no_hits():
    score, reasons = apply_dns_logics("google.com", "google.com")
    assert score == 0
    assert reasons == []

def test_apply_dns_logics_with_hits():
    # Trigger vt_verdict_not_clean (+2) and dns_suspicious_string (+1 for xn--9natb9hpd983r4ahence3e6h0b)
    value = "xn--9natb9hpd983r4ahence3e6h0b"
    decoded_value = "vt:malicious"
    score, reasons = apply_dns_logics(value, decoded_value)
    
    assert score == 3
    assert "dns_suspicious_string" in reasons
    assert "vt_verdict_not_clean" in reasons

def test_apply_url_logics_no_hits():
    score, reasons = apply_url_logics("google.com", "google.com")
    assert score == 0
    assert reasons == []

def test_apply_url_logics_with_hits():
    # Only vt_verdict_not_clean is registered for URLs in __init__.py
    value = "xn--9natb9hpd983r4ahence3e6h0b" # Shouldn't match dns_suspicious_string for URL logics
    decoded_value = "vt:malicious"
    score, reasons = apply_url_logics(value, decoded_value)
    
    assert score == 2
    assert "vt_verdict_not_clean" in reasons
    assert "dns_suspicious_string" not in reasons
