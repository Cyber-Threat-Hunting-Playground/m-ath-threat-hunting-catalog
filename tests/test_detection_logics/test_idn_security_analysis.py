import pytest
from detection_logics.idn_security_analysis import (
    confusable_skeleton,
    mixed_script_letters,
    has_strong_bidi,
    idn_punycode_tld,
    idna_uts46_validate,
    homograph_risk_level,
    analyze_idn_domain,
    derive_ascii_sibling,
    score_idn_security_signals,
    REASON_TR39_CONFUSABLE,
    REASON_MIXED_SCRIPT,
    REASON_BIDI_RTL,
    REASON_IDNA_INVALID,
    REASON_IDN_TLD
)

def test_confusable_skeleton_basic():
    # If no confusables map can be loaded or empty text
    assert confusable_skeleton("") == ""
    assert confusable_skeleton("google.com") == "google.corn"

def test_mixed_script_letters():
    # ASCII only letters -> Latin
    mixed, scripts = mixed_script_letters("google")
    assert not mixed
    assert scripts == ["Latin"]

    # Latin mixed with Cyrillic (e.g. Cyrillic small letter a: '\u0430')
    mixed, scripts = mixed_script_letters("googl\u0430")
    assert mixed
    assert "Latin" in scripts
    assert "Cyrillic" in scripts

def test_has_strong_bidi():
    # Left-to-right only
    assert not has_strong_bidi("google.com")
    # Strong RTL (e.g. Arabic letter: '\u0627')
    assert has_strong_bidi("\u0627")

def test_idn_punycode_tld():
    assert not idn_punycode_tld("google.com")
    assert idn_punycode_tld("google.xn--vermgensberater-ctb")
    assert idn_punycode_tld("google.XN--VERMGENSBERATER-CTB")

def test_idna_uts46_validate():
    # Valid domain
    ok, errs = idna_uts46_validate("google.com")
    assert ok
    assert not errs

    # Leading/trailing hyphens
    ok, errs = idna_uts46_validate("-google.com")
    assert not ok
    assert "leading-or-trailing-hyphen" in errs

    # Label too long (> 63 chars)
    ok, errs = idna_uts46_validate("a" * 64 + ".com")
    assert not ok
    assert "label-too-long" in errs

def test_homograph_risk_level():
    assert homograph_risk_level(confusable_hits=0, idna_ok=True, mixed_script=False, bidi_rtl=False) == "low"
    assert homograph_risk_level(confusable_hits=0, idna_ok=True, mixed_script=True, bidi_rtl=False) == "medium"
    assert homograph_risk_level(confusable_hits=1, idna_ok=True, mixed_script=False, bidi_rtl=False) == "high"
    assert homograph_risk_level(confusable_hits=0, idna_ok=False, mixed_script=False, bidi_rtl=False) == "high"

def test_derive_ascii_sibling():
    # Accented German u: 'ü' -> 'u'
    sibling = derive_ascii_sibling("m-üchen.de")
    assert sibling == "m-uchen.de"

    # Already ASCII
    assert derive_ascii_sibling("google.com") is None

def test_score_idn_security_signals():
    # Low risk
    analysis = {
        "tr39_confusable_count": 0,
        "mixed_script": False,
        "bidi_rtl": False,
        "idna_valid": True,
        "idn_punycode_tld": False
    }
    score, reasons = score_idn_security_signals(analysis)
    assert score == 0
    assert not reasons

    # All signals active
    analysis_bad = {
        "tr39_confusable_count": 1,
        "mixed_script": True,
        "mixed_script_list": "Latin,Cyrillic",
        "bidi_rtl": True,
        "idna_valid": False,
        "idn_punycode_tld": True
    }
    score, reasons = score_idn_security_signals(analysis_bad)
    # tr39_confusable_count > 0: +2
    # mixed_script: +1 (2 scripts)
    # bidi_rtl: +1
    # not idna_valid: +2
    # idn_punycode_tld: +1
    # Total: 7
    assert score == 7
    assert REASON_TR39_CONFUSABLE in reasons
    assert REASON_MIXED_SCRIPT in reasons
    assert REASON_BIDI_RTL in reasons
    assert REASON_IDNA_INVALID in reasons
    assert REASON_IDN_TLD in reasons
