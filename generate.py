#!/usr/bin/env python3
"""Generate strong passwords and passphrases with secrets."""
from __future__ import annotations

import argparse
import math
import secrets
import string
import sys

WORDS = [
    "anchor", "breeze", "cactus", "delta", "ember", "forest", "glacier", "harbor",
    "island", "jungle", "kernel", "lantern", "meadow", "nectar", "orbit", "pepper",
    "quartz", "ripple", "summit", "tundra", "umber", "velvet", "willow", "xenon",
    "yonder", "zephyr", "amber", "basalt", "cobalt", "dune", "fjord", "granite",
]

AMBIGUOUS = "Il1O0o"


def build_alphabet(lower=True, upper=True, digits=True, symbols=True, avoid_ambiguous=False):
    pools = []
    if lower:
        pools.append(string.ascii_lowercase)
    if upper:
        pools.append(string.ascii_uppercase)
    if digits:
        pools.append(string.digits)
    if symbols:
        pools.append("!@#$%^&*()-_=+[]{};:,.?")
    if not pools:
        raise ValueError("at least one character class is required")
    if avoid_ambiguous:
        pools = ["".join(ch for ch in pool if ch not in AMBIGUOUS) for pool in pools]
        pools = [pool for pool in pools if pool]
    alphabet = "".join(pools)
    return alphabet, pools


def generate_password(length=16, **classes) -> str:
    if length < 4:
        raise ValueError("length must be at least 4")
    alphabet, pools = build_alphabet(**classes)
    # guarantee at least one character from every selected class
    chars = [secrets.choice(pool) for pool in pools]
    chars += [secrets.choice(alphabet) for _ in range(length - len(chars))]
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)


def generate_passphrase(words=4, separator="-", wordlist=None) -> str:
    if words < 3:
        raise ValueError("use at least 3 words")
    source = wordlist or WORDS
    return separator.join(secrets.choice(source) for _ in range(words))


def entropy_bits(password: str, pool_size: int) -> float:
    return round(len(password) * math.log2(pool_size), 1) if pool_size > 1 else 0.0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Generate passwords with secrets")
    parser.add_argument("--length", type=int, default=16)
    parser.add_argument("--count", type=int, default=1)
    parser.add_argument("--no-symbols", action="store_true")
    parser.add_argument("--no-digits", action="store_true")
    parser.add_argument("--no-upper", action="store_true")
    parser.add_argument("--avoid-ambiguous", action="store_true")
    parser.add_argument("--passphrase", type=int, metavar="WORDS")
    parser.add_argument("--separator", default="-")
    parser.add_argument("--show-entropy", action="store_true")
    args = parser.parse_args(argv)

    try:
        if args.passphrase:
            for _ in range(args.count):
                print(generate_passphrase(args.passphrase, args.separator))
            return 0
        alphabet, _ = build_alphabet(
            upper=not args.no_upper,
            digits=not args.no_digits,
            symbols=not args.no_symbols,
            avoid_ambiguous=args.avoid_ambiguous,
        )
        for _ in range(args.count):
            password = generate_password(
                args.length,
                upper=not args.no_upper,
                digits=not args.no_digits,
                symbols=not args.no_symbols,
                avoid_ambiguous=args.avoid_ambiguous,
            )
            if args.show_entropy:
                print(f"{password}  ({entropy_bits(password, len(alphabet))} bits)")
            else:
                print(password)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
