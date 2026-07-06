import pytest
from detection_logics.dns_suspicious_string import apply, REASON_NAME

def test_dns_suspicious_string_no_match():
    score, reason = apply("google.com", "google.com")
    assert score == 0
    assert reason is None

def test_dns_suspicious_string_match_value():
    # 'xn--9natb9hpd983r4ahence3e6h0b' is in DNS_SUSPICIOUS_STRINGS
    score, reason = apply("some-prefix-xn--9natb9hpd983r4ahence3e6h0b-suffix.com", "")
    assert score == 1
    assert reason == REASON_NAME

def test_dns_suspicious_string_match_decoded():
    # 'ᴘᴀʏᴍᴇɴᴛᴅᴇᴄʟɪɴᴇᴅ' is in DNS_PUNYCODE_SUSPICIOUS_STRINGS
    # Should extract decoded search term (punycode: or base64: prefix or raw)
    score, reason = apply("other.com", "punycode: ᴘᴀʏᴍᴇɴᴛᴅᴇᴄʟɪɴᴇᴅ")
    assert score == 1
    assert reason == REASON_NAME

    score2, reason2 = apply("other.com", "ᴘᴀʏᴍᴇɴᴛᴅᴇᴄʟɪɴᴇᴅ")
    assert score2 == 1
    assert reason2 == REASON_NAME

def test_dns_suspicious_string_multiple_matches():
    # Both xn--9natb9hpd983r4ahence3e6h0b and xn----91a3ab6kzds46t8aiepce9esi3b are suspicious
    value = "xn--9natb9hpd983r4ahence3e6h0b.xn----91a3ab6kzds46t8aiepce9esi3b.com"
    score, reason = apply(value, "")
    assert score == 2
    assert reason == REASON_NAME
