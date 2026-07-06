import pytest
from detection_logics.vt_verdict_not_clean import apply, REASON_NAME

def test_vt_verdict_clean_or_empty():
    # Clean verdict
    score, reason = apply("vt:clean", "vt:clean")
    assert score == 0
    assert reason is None

    # Empty verdict
    score, reason = apply("no verdict here", "some plain text")
    assert score == 0
    assert reason is None

def test_vt_verdict_malicious():
    # Direct match in value
    score, reason = apply("vt:malicious", "")
    assert score == 2
    assert reason == REASON_NAME

    # In decoded_value
    score, reason = apply("", "vt_verdict=malicious")
    assert score == 2
    assert reason == REASON_NAME

    # In brackets format
    score, reason = apply("[vt: malicious]", "")
    assert score == 2
    assert reason == REASON_NAME

def test_vt_verdict_suspicious_or_other():
    # Suspicious gives +1
    score, reason = apply("vt:suspicious", "")
    assert score == 1
    assert reason == REASON_NAME

    # Other non-clean (e.g., untrusted, unsafe, risk) gives +1
    score, reason = apply("vt:untrusted", "")
    assert score == 1
    assert reason == REASON_NAME
