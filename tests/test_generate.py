import string
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import generate


class PasswordTests(unittest.TestCase):
    def test_length(self):
        self.assertEqual(len(generate.generate_password(24)), 24)

    def test_contains_all_classes(self):
        password = generate.generate_password(32)
        self.assertTrue(any(c in string.ascii_lowercase for c in password))
        self.assertTrue(any(c in string.ascii_uppercase for c in password))
        self.assertTrue(any(c in string.digits for c in password))
        self.assertTrue(any(c in "!@#$%^&*()-_=+[]{};:,.?" for c in password))

    def test_no_symbols(self):
        password = generate.generate_password(30, symbols=False)
        self.assertTrue(password.isalnum())

    def test_avoid_ambiguous(self):
        password = generate.generate_password(40, avoid_ambiguous=True)
        self.assertFalse(any(ch in "Il1O0o" for ch in password))

    def test_minimum_length(self):
        with self.assertRaises(ValueError):
            generate.generate_password(3)

    def test_no_classes(self):
        with self.assertRaises(ValueError):
            generate.generate_password(10, lower=False, upper=False, digits=False, symbols=False)

    def test_passphrase_words(self):
        phrase = generate.generate_passphrase(5, "-")
        self.assertEqual(len(phrase.split("-")), 5)

    def test_passphrase_minimum(self):
        with self.assertRaises(ValueError):
            generate.generate_passphrase(2)

    def test_entropy(self):
        self.assertGreater(generate.entropy_bits("abcdefgh", 64), 40)

    def test_cli_count(self):
        import contextlib
        import io
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = generate.main(["--count", "3", "--length", "12"])
        self.assertEqual(code, 0)
        self.assertEqual(len(buf.getvalue().strip().splitlines()), 3)

    def test_cli_invalid_length(self):
        import contextlib
        import io
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(generate.main(["--length", "2"]), 2)

    def test_cli_entropy_output(self):
        import contextlib
        import io
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            generate.main(["--length", "20", "--show-entropy"])
        self.assertIn("bits", buf.getvalue())


if __name__ == "__main__":
    unittest.main()
