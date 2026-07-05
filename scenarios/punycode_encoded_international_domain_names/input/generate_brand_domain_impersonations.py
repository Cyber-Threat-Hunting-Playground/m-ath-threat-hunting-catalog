#!/usr/bin/env python3
"""
Generate Punycode (xn--) impersonation variants for brand domains using Unicode
TR39 visual confusables (same data as detection_logics/idn_security_analysis.py).

Reads ASCII (or mixed) FQDNs from input/brand_domains.txt, emits lines:
    <original_domain>,<idna_ascii_with_xn-->

Only variants whose IDNA encoding contains at least one ``xn--`` label are kept
(non-ASCII substitutions in at least one label).

By default, every *single*-character TR39 inverse substitution is emitted for each
substitutable codepoint. Use --max-substitutions > 1 for multi-position combinations
(capped by --max-variants per input domain).

Usage (from repo root or any cwd):
    python scenarios/punycode_encoded_international_domain_names/input/generate_brand_domain_impersonations.py
    python .../generate_brand_domain_impersonations.py --max-substitutions 2 --max-variants 200000
"""

from __future__ import annotations

import argparse
import itertools
import sys
from pathlib import Path


def find_repo_root(start: Path) -> Path:
    cur = start.resolve()
    while cur != cur.parent:
        if (cur / "detection_logics").is_dir() and (cur / "scenarios").is_dir():
            return cur
        cur = cur.parent
    raise RuntimeError(
        "Could not find repository root (need detection_logics/ and scenarios/)."
    )


def _inverse_singlechar_confusables(conf_map: dict[int, str]) -> dict[str, tuple[str, ...]]:
    """
    TR39 file maps source codepoint -> skeleton/target string.
    For each ASCII target character T, collect every source character S (len 1)
    such that conf_map[ord(S)] == T and S is not identical to T.
    """
    buckets: dict[str, set[str]] = {}
    for src_cp, tgt in conf_map.items():
        if len(tgt) != 1:
            continue
        if ord(tgt) == src_cp:
            continue
        buckets.setdefault(tgt, set()).add(chr(src_cp))
    return {k: tuple(sorted(v)) for k, v in buckets.items()}


def _substitutable_spots(labels: list[str], inverse: dict[str, tuple[str, ...]]) -> list[tuple[int, int, str, tuple[str, ...]]]:
    """List of (label_index, char_index, original_char, substitutes) for spots with ≥1 substitute."""
    spots: list[tuple[int, int, str, tuple[str, ...]]] = []
    for li, lab in enumerate(labels):
        for ci, ch in enumerate(lab):
            subs = inverse.get(ch)
            if subs:
                spots.append((li, ci, ch, subs))
    return spots


def _apply_spot_replacements(
    labels: list[str],
    replacements: list[tuple[int, int, str]],
) -> str:
    """replacements: list of (label_idx, char_idx, new_char) — must not double-book a spot."""
    out_labels: list[str] = []
    for li, lab in enumerate(labels):
        chars = list(lab)
        for (rli, rci, new_ch) in replacements:
            if rli == li:
                chars[rci] = new_ch
        out_labels.append("".join(chars))
    return ".".join(out_labels)


def _idna_encode_hostname(unicode_host: str) -> str | None:
    try:
        return unicode_host.encode("idna").decode("ascii")
    except UnicodeError:
        return None


def _variants_for_domain(
    hostname: str,
    inverse: dict[str, tuple[str, ...]],
    max_substitutions: int,
    max_variants: int,
) -> list[str]:
    """
    Return sorted unique Punycode ASCII hostnames (each contains 'xn--') derived from hostname.
    """
    host = hostname.strip().lower()
    if not host:
        return []
    labels = host.split(".")
    if any(not lab for lab in labels):
        return []

    spots = _substitutable_spots(labels, inverse)
    seen: set[str] = set()
    out: list[str] = []

    def try_add(unicode_host: str) -> None:
        nonlocal out
        if len(seen) >= max_variants:
            return
        ascii_host = _idna_encode_hostname(unicode_host)
        if not ascii_host or "xn--" not in ascii_host:
            return
        if ascii_host in seen:
            return
        seen.add(ascii_host)
        out.append(ascii_host)

    # k = number of simultaneous character replacements (distinct spots)
    for k in range(1, min(max_substitutions, len(spots)) + 1):
        for spot_combo in itertools.combinations(spots, k):
            sub_lists = [s[3] for s in spot_combo]
            for choice in itertools.product(*sub_lists):
                reps = [(spot_combo[i][0], spot_combo[i][1], choice[i]) for i in range(k)]
                unicode_host = _apply_spot_replacements(labels, reps)
                try_add(unicode_host)
                if len(seen) >= max_variants:
                    return sorted(out)

    return sorted(out)


def _read_domains(path: Path) -> list[tuple[str, str]]:
    """Return (line_as_in_file_stripped, lowercase_for_generation) per domain."""
    lines: list[tuple[str, str]] = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        s = raw.strip()
        if not s or s.startswith("#"):
            continue
        lines.append((s, s.lower()))
    return lines


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    script_dir = Path(__file__).resolve().parent
    # Script may live in scenario/input/ or in scenario/ — brand files are always under scenario/input/.
    input_dir = script_dir if script_dir.name == "input" else script_dir / "input"
    default_input = input_dir / "brand_domains.txt"
    default_output = input_dir / "brand_domains_impersonation.txt"
    parser.add_argument("--input", type=Path, default=default_input, help="Path to brand_domains.txt")
    parser.add_argument(
        "--output",
        type=Path,
        default=default_output,
        help="Path for brand_domains_impersonation.txt (default: scenario input/)",
    )
    parser.add_argument(
        "--max-substitutions",
        type=int,
        default=1,
        metavar="N",
        help="Replace up to N positions at once with TR39 confusables (default: 1).",
    )
    parser.add_argument(
        "--max-variants",
        type=int,
        default=500_000,
        metavar="M",
        help="Stop collecting variants per input domain after M unique Punycode outputs.",
    )
    args = parser.parse_args()

    repo = find_repo_root(script_dir)
    if str(repo) not in sys.path:
        sys.path.insert(0, str(repo))

    from detection_logics.idn_security_analysis import load_tr39_confusable_map

    if not args.input.is_file():
        print(f"Input file not found: {args.input}", file=sys.stderr)
        return 1

    conf_map = load_tr39_confusable_map()
    inverse = _inverse_singlechar_confusables(conf_map)

    domains = _read_domains(args.input)
    if not domains:
        print(f"No domains in {args.input}", file=sys.stderr)
        return 1

    args.output.parent.mkdir(parents=True, exist_ok=True)

    total_lines = 0
    with args.output.open("w", encoding="utf-8", newline="\n") as fout:
        for domain_display, domain_key in domains:
            variants = _variants_for_domain(
                domain_key,
                inverse,
                max_substitutions=max(1, args.max_substitutions),
                max_variants=args.max_variants,
            )
            for puny in variants:
                fout.write(f"{domain_display},{puny}\n")
                total_lines += 1

    print(f"Wrote {total_lines} lines to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
