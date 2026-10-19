# simple-password-generator

Generate passwords and passphrases with Python's `secrets` module — the
cryptographically secure generator, not `random`.

## Features

- Password mode with selectable character classes and guaranteed inclusion.
- Optional exclusion of ambiguous characters (`Il1O0`).
- Passphrase mode from the built-in word list (or your own file), with a separator.
- No password is written to disk; the tool only prints to stdout.
- Tests check length, character classes, entropy lower bounds and error cases.

## Installation

```bash
git clone https://github.com/victor-harden/simple-password-generator.git
cd simple-password-generator
```

## Usage

```bash
python3 generate.py --length 24
python3 generate.py --length 20 --no-symbols
python3 generate.py --passphrase 5 --separator -
python3 generate.py --length 16 --count 3
```

## Tests

```bash
python3 -m unittest discover -s tests -v
```

## License

MIT — see [LICENSE](LICENSE).
