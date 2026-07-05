"""
IDN / punycode security signals aligned with common TR39 + UTS #46 checks
(e.g. visual confusables, skeleton, mixed-script, BiDi, IDNA validity, IDN TLD).

Data: Unicode TR39 confusables mapping file (unicode_TR39_confusables.txt).
See https://www.unicode.org/reports/tr39/
"""
from __future__ import annotations

import re
import unicodedata
from functools import lru_cache
from pathlib import Path

# Reason tags used by notebooks / scoring (stable identifiers)
REASON_TR39_CONFUSABLE = "tr39-visual-confusable"
REASON_MIXED_SCRIPT = "tr39-mixed-script"
REASON_BIDI_RTL = "tr39-bidi-rtl"
REASON_IDNA_INVALID = "idna-uts46-invalid"
REASON_IDN_TLD = "idn-punycode-tld"
REASON_DNS_IP_MATCH_SIBLING = "dns-ip-match-ascii-sibling"
REASON_DNS_IP_MISMATCH_SIBLING = "dns-ip-mismatch-ascii-sibling"


def _resources_dir() -> Path:
    return Path(__file__).resolve().parent / "resources"


def _default_confusables_path() -> Path:
    base = _resources_dir()
    p = base / "unicode_TR39_confusables.txt"
    if p.is_file():
        return p
    raise FileNotFoundError(
        f"TR39 confusables file not found. Expected unicode_TR39_confusables.txt under {base}"
    )


def _parse_confusables_file(path: Path) -> dict[int, str]:
    mp: dict[int, str] = {}
    with path.open("r", encoding="utf-8") as f:
        for raw in f:
            line = raw.split("#", 1)[0].strip()
            if not line or ";" not in line:
                continue
            parts = [p.strip() for p in line.split(";")]
            if len(parts) < 3:
                continue
            src_tok, tgt_tok = parts[0], parts[1]
            if not src_tok or not tgt_tok:
                continue
            try:
                src = int(src_tok, 16)
            except ValueError:
                continue
            try:
                repl = "".join(chr(int(x, 16)) for x in tgt_tok.split())
            except ValueError:
                continue
            mp[src] = repl
    return mp


@lru_cache(maxsize=4)
def load_tr39_confusable_map(confusables_path: str | None = None) -> dict[int, str]:
    """
    Parse confusables.txt-style lines: SOURCE ; TARGET [TARGET...] ; TYPE
    Returns mapping codepoint -> replacement string (may be multiple chars).
    """
    path = (
        Path(confusables_path).resolve()
        if confusables_path
        else _default_confusables_path().resolve()
    )
    if not path.is_file():
        path = _default_confusables_path().resolve()
    return _parse_confusables_file(path)


def confusable_skeleton(text: str, confusables_path: str | None = None) -> str:
    """Apply TR39-style confusable mappings until fixpoint (identifier skeleton approximation)."""
    mp = load_tr39_confusable_map(
        str(Path(confusables_path).resolve()) if confusables_path else None
    )
    if not mp or not text:
        return text or ""
    cur = text
    for _ in range(256):
        nxt_chars: list[str] = []
        changed = False
        for ch in cur:
            c = ord(ch)
            if c in mp:
                nxt_chars.append(mp[c])
                changed = True
            else:
                nxt_chars.append(ch)
        nxt = "".join(nxt_chars)
        if not changed:
            return nxt
        cur = nxt
    return cur


def list_tr39_confusable_hits(text: str, confusables_path: str | None = None) -> list[tuple[str, str, str]]:
    """
    Characters that have a non-identity TR39 mapping (source appears in string).
    Returns list of (char, U+XXXX, replacement_desc).
    """
    mp = load_tr39_confusable_map(
        str(Path(confusables_path).resolve()) if confusables_path else None
    )
    hits: list[tuple[str, str, str]] = []
    seen: set[tuple[int, str]] = set()
    for ch in text:
        c = ord(ch)
        if c not in mp:
            continue
        repl = mp[c]
        if repl == ch:
            continue
        key = (c, repl)
        if key in seen:
            continue
        seen.add(key)
        hits.append((ch, f"U+{c:04X}", repl))
    return hits


def normalize_idn_dashes_for_decode(host: str, confusables_path: str | None = None) -> str:
    """Map dash confusables to HYPHEN-MINUS so spoofed 'xn–' labels may decode as punycode."""
    mp = load_tr39_confusable_map(
        str(Path(confusables_path).resolve()) if confusables_path else None
    )
    hy = chr(0x002D)
    out: list[str] = []
    for ch in host:
        c = ord(ch)
        if c in mp and mp[c] == hy:
            out.append(hy)
        else:
            out.append(ch)
    return "".join(out)


def _letter_script_bucket(ch: str) -> str | None:
    if unicodedata.category(ch)[0] != "L":
        return None
    name = unicodedata.name(ch, "")
    if "LATIN" in name:
        return "Latin"
    if "CYRILLIC" in name:
        return "Cyrillic"
    if "GREEK" in name:
        return "Greek"
    if "ARABIC" in name:
        return "Arabic"
    if "HEBREW" in name:
        return "Hebrew"
    if "HIRAGANA" in name or "KATAKANA" in name:
        return "Kana"
    if "HANGUL" in name:
        return "Hangul"
    if "CJK UNIFIED" in name or "BOPOMOFO" in name:
        return "Han"
    if "DEVANAGARI" in name:
        return "Devanagari"
    if "THAI" in name:
        return "Thai"
    return "OtherLetter"


def mixed_script_letters(text: str) -> tuple[bool, list[str]]:
    """True if two or more distinct script buckets among letter characters (TR39-style signal)."""
    buckets: set[str] = set()
    for ch in text:
        if ch in ".@":
            continue
        b = _letter_script_bucket(ch)
        if b:
            buckets.add(b)
    scripts = sorted(buckets)
    return len(buckets) >= 2, scripts


def has_strong_bidi(text: str) -> bool:
    """True if any character has strong RTL bidirectional class."""
    for ch in text:
        if unicodedata.bidirectional(ch) in ("R", "AL"):
            return True
    return False


def idn_punycode_tld(ascii_domain: str) -> bool:
    """Registrable domain's public suffix / last label is punycode (xn--)."""
    labels = [x for x in (ascii_domain or "").strip().lower().rstrip(".").split(".") if x]
    return bool(labels) and labels[-1].startswith("xn--")


def idna_uts46_validate(hostname_unicode: str) -> tuple[bool, list[str]]:
    """
    UTS #46 / IDNA 2008 validity via idna package when available; structural checks always.
    Returns (ok, error_messages).
    """
    errors: list[str] = []
    host = (hostname_unicode or "").strip().lower().rstrip(".")
    if not host:
        return False, ["empty-hostname"]
    labels = host.split(".")
    for label in labels:
        if label == "":
            errors.append("empty-label")
            continue
        if label.startswith("-") or label.endswith("-"):
            errors.append("leading-or-trailing-hyphen")
        if len(label.encode("utf-8")) > 63:
            errors.append("label-too-long")
    try:
        import idna

        try:
            idna.encode(host, uts46=True, transitional=False)
        except idna.IDNAError as e:
            errors.append(str(e).split("\n")[0][:200])
    except ImportError:
        pass
    return len(errors) == 0, errors


def homograph_risk_level(
    *,
    confusable_hits: int,
    idna_ok: bool,
    mixed_script: bool,
    bidi_rtl: bool,
) -> str:
    """Coarse Low / Medium / High, similar to public IDN security summaries."""
    if confusable_hits > 0 or not idna_ok:
        return "high"
    if mixed_script or bidi_rtl:
        return "medium"
    return "low"


def analyze_idn_domain(
    ascii_domain: str,
    decoded_unicode: str,
    *,
    confusables_path: Path | str | None = None,
) -> dict:
    """
    Run all IDN security checks used in tools like PunycodeConverter domain analysis.

    ascii_domain: hostname as seen in logs (often punycode / ASCII).
    decoded_unicode: Unicode form after punycode decode (may equal ASCII for ASCII-only).
    """
    cpath = str(Path(confusables_path).resolve()) if confusables_path else None

    # Analyze Unicode surface (decoded); also scan raw for dash spoofs etc.
    uni = decoded_unicode or ""
    raw = ascii_domain or ""

    hits_uni = list_tr39_confusable_hits(uni, cpath)
    hits_raw = list_tr39_confusable_hits(raw, cpath)
    all_hits = hits_uni + [h for h in hits_raw if h not in hits_uni]

    skel = confusable_skeleton(uni, cpath) if uni else ""
    mixed, scripts = mixed_script_letters(uni)
    bidi = has_strong_bidi(uni)
    idn_tld = idn_punycode_tld(raw)
    host_for_idna = uni if re.search(r"[^\x00-\x7f]", uni) else (raw or uni)
    idna_ok, idna_errs = idna_uts46_validate(host_for_idna)

    risk = homograph_risk_level(
        confusable_hits=len(all_hits),
        idna_ok=idna_ok,
        mixed_script=mixed,
        bidi_rtl=bidi,
    )

    return {
        "unicode_skeleton": skel,
        "tr39_confusable_count": len(all_hits),
        "tr39_confusable_detail": ";".join(f"{u}:{desc}" for _, u, desc in all_hits[:20]),
        "mixed_script": mixed,
        "mixed_script_list": ",".join(scripts),
        "bidi_rtl": bidi,
        "idn_punycode_tld": idn_tld,
        "idna_valid": idna_ok,
        "idna_errors": ";".join(idna_errs[:10]),
        "homograph_risk": risk,
    }


def derive_ascii_sibling(decoded_unicode: str, unicode_skeleton: str = "") -> str | None:
    """Derive the ASCII equivalent of a decoded IDN domain for DNS comparison.

    Two strategies:
    1. Strip diacritics (NFD decomposition + remove combining marks) — covers
       accented Latin scripts (German ü→u, French é→e, etc.).
    2. Fallback to the TR39 confusable skeleton — covers Cyrillic/Greek homographs
       where the skeleton maps back to Latin characters.

    Returns the ASCII sibling domain string, or None when no meaningful sibling
    can be derived (e.g. the decoded domain is already pure ASCII).
    """
    if not decoded_unicode:
        return None
    nfd = unicodedata.normalize("NFD", decoded_unicode)
    stripped = "".join(ch for ch in nfd if unicodedata.category(ch) != "Mn")
    ascii_sibling = stripped.encode("ascii", "ignore").decode("ascii").strip().lower()
    if ascii_sibling and ascii_sibling != decoded_unicode.lower() and "." in ascii_sibling:
        return ascii_sibling
    if unicode_skeleton:
        skel_ascii = unicode_skeleton.encode("ascii", "ignore").decode("ascii").strip().lower()
        if skel_ascii and skel_ascii != decoded_unicode.lower() and "." in skel_ascii:
            return skel_ascii
    return None


def score_idn_security_signals(analysis: dict) -> tuple[int, list[str]]:
    """Map analysis dict to score delta and reason strings for the punycode notebook.

    Mixed-script scoring is graduated: +1 for 2 scripts, +2 for 3, etc.
    (i.e. ``num_scripts - 1``).
    """
    delta = 0
    reasons: list[str] = []
    if analysis.get("tr39_confusable_count", 0) > 0:
        delta += 2
        reasons.append(REASON_TR39_CONFUSABLE)
    if analysis.get("mixed_script"):
        script_list = [s for s in analysis.get("mixed_script_list", "").split(",") if s]
        num_scripts = max(len(script_list), 2)
        delta += num_scripts - 1
        reasons.append(REASON_MIXED_SCRIPT)
    if analysis.get("bidi_rtl"):
        delta += 1
        reasons.append(REASON_BIDI_RTL)
    if not analysis.get("idna_valid", True):
        delta += 2
        reasons.append(REASON_IDNA_INVALID)
    if analysis.get("idn_punycode_tld"):
        delta += 1
        reasons.append(REASON_IDN_TLD)
    return delta, reasons
