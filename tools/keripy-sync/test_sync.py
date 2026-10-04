"""Guard against silently reporting every code as missing after a source move."""

from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

import sync


class SourceTables(unittest.TestCase):
    def test_workspace_tables_include_their_leading_code(self):
        root = Path(__file__).resolve().parents[2]
        for table, code in zip(sync.TABLES, ("A", "-A", "-A", "A"), strict=True):
            with self.subTest(table=table["title"]):
                codes = sync.parse_cesr_codes(
                    [root / path for path in table["cesr_files"]], table["cesr_mode"]
                )
                self.assertIn(code, codes)

    def test_missing_source_fails(self):
        with TemporaryDirectory() as temporary:
            with self.assertRaises(FileNotFoundError):
                sync.parse_cesr_codes([Path(temporary) / "missing.rs"], "strum")

    def test_documented_strum_example_is_not_a_code(self):
        with TemporaryDirectory() as temporary:
            source = Path(temporary) / "code.rs"
            source.write_text(
                '/// Example: #[strum(serialize = "fake")]\n'
                '#[strum(serialize = "A")]\n'
            )
            self.assertEqual(sync.parse_cesr_codes([source], "strum"), {"A"})


if __name__ == "__main__":
    unittest.main()
