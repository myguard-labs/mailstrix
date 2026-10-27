"""Rule-boundary controls; --native also checks the pinned YARA 4.5.2 compiler."""

import contextlib
import importlib.util
import io
import pathlib
import runpy
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "filter_rules", ROOT / "docker/filter-rules.py"
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("filter-rules loader unavailable")
FILTER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(FILTER)
NATIVE = False


class FilterRulesRegexTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if NATIVE:
            if shutil.which("yarac") is None:
                raise RuntimeError("--native requires yarac 4.5.2")
            version = subprocess.run(
                ["yarac", "--version"], capture_output=True, text=True, check=True
            ).stdout.strip()
            if version != "4.5.2":
                raise RuntimeError(f"--native requires yarac 4.5.2, got {version}")

    def setUp(self):
        self.root = pathlib.Path(tempfile.mkdtemp(prefix="filter-regex-"))
        self.addCleanup(shutil.rmtree, self.root)

    def compile(self, source, valid):
        if not NATIVE:
            return
        result = subprocess.run(
            ["yarac", "-d", "filename=fixture", str(source), str(source) + ".yac"],
            capture_output=True,
            text=True,
            check=False,
        )
        if valid:
            self.assertEqual(result.returncode, 0, result.stderr)
        else:
            self.assertNotEqual(result.returncode, 0, "malformed input was accepted")

    def filtered(self, text, *, valid=True):
        source, output = self.root / "in.yar", self.root / "out.yar"
        source.write_text(text, encoding="utf-8")
        self.compile(source, valid)
        with (
            mock.patch.object(
                sys, "argv", ["filter-rules.py", str(source), str(output)]
            ),
            contextlib.redirect_stdout(io.StringIO()),
        ):
            FILTER.main()
        self.compile(output, valid)
        result = output.read_text(encoding="utf-8")
        # A second pass must not remove or rewrite another rule.
        with (
            mock.patch.object(
                sys, "argv", ["filter-rules.py", str(output), str(source)]
            ),
            contextlib.redirect_stdout(io.StringIO()),
        ):
            FILTER.main()
        self.assertEqual(source.read_text(encoding="utf-8"), result)
        return result

    def assert_dropped(self, body):
        preamble = 'import "math"\n/* preamble stays byte-exact */\n'
        sibling = "rule Keep { condition: true }\n// trailing comment stays\n"
        source = preamble + "rule LINUX_Only { " + body + " }\n" + sibling
        self.assertEqual(self.filtered(source), preamble + "\n" + sibling)

    def test_condition_regex_brace_keeps_sibling(self):
        self.assert_dropped("condition: filename matches /[}]/")

    def test_condition_regex_escapes_classes_and_flags(self):
        for regex in (
            r"/\}/",
            r"/[{}]+/",
            r"/[\/}]/",
            r"/[\]]}/",
            r"/[\\]}/",
            r"/a\/\/[}]/",
            r"/a\/\*[}]/",
            r"/[}]/is",
        ):
            with self.subTest(regex=regex):
                self.assert_dropped("condition: filename matches " + regex)

    def test_comments_between_matches_and_regex(self):
        for gap in (" ", "\n", '/* } / " */', ' // } / "\n'):
            with self.subTest(gap=gap):
                self.assert_dropped("condition: filename matches" + gap + "/[}]/")

    def test_numeric_division_and_comments_keep_rule_boundary(self):
        self.assert_dropped('condition: 8 \\ 2 == 4 /* } / " */ // {\n')

    def test_string_regex_and_hex_declarations(self):
        for body in (
            r"strings: $a = /[}\/]+/ condition: $a",
            r'strings: $a = "}/*\\\"" condition: $a',
            "strings: $a = { 41 ( 42 | 43 ) [1-2] 44 } condition: $a",
        ):
            with self.subTest(body=body):
                self.assert_dropped(body)

    def test_kept_private_and_licensed_rules_with_regex(self):
        kept = (
            "private rule Linux_Helper { condition: filename matches /[}]/ }\n"
            "rule Linux_Maldoc_Carrier { condition: true }\n"
            "rule Keep { condition: Linux_Helper }\n"
        )
        dropped = "rule MALPEDIA_example { condition: filename matches /[}]/ }\n"
        self.assertEqual(self.filtered(dropped + kept), "\n" + kept)

    def test_retained_regex_leaves_original_bytes_unchanged(self):
        source = (
            '// retained rules, comments and imports are not reformatted\nimport "math"\n'
            "rule Keep { condition: filename matches /[}]/ }\n"
            "rule Sibling { condition: true }\n"
        )
        self.assertEqual(self.filtered(source), source)

    def test_malformed_retained_inputs_stay_rejected(self):
        for body in (
            "condition: filename matches /[}",
            "condition: filename matches /[a/}]/ }",
            'strings: $a = "unterminated } condition: $a }',
            "condition: true",
        ):
            with self.subTest(body=body):
                source = "rule Keep { " + body
                self.assertEqual(self.filtered(source, valid=False), source)

    def test_incomplete_rule_headers_stay_rejected(self):
        for source in ("rule Keep", "rule ", "rule Keep : MEMORY /* unterminated {"):
            with self.subTest(source=source):
                self.assertEqual(self.filtered(source, valid=False), source)

    def test_hard_policy_drops_still_leave_clean_sibling(self):
        source = (
            'rule Vendor_Maldoc { meta: license_url = "CC-BY-NC" '
            "condition: filename matches /[}]/ }\n"
            'rule Vendor_Memory { meta: tags = "MEMORY" '
            "condition: filename matches /[}]/ }\n"
            "rule Vendor_LOLDRIVERS_Only { condition: filename matches /[}]/ }\n"
            "rule Keep { condition: true }\n"
        )
        self.assertEqual(self.filtered(source), "\n\n\nrule Keep { condition: true }\n")

    def test_header_and_metadata_tags_drive_mail_profile(self):
        dropped = (
            "rule HeaderMemory : neutral MEMORY second { condition: true }\n"
            'rule MetadataLog { meta: tags = "neutral, LOG, second" '
            "condition: true }\n"
            'rule Combined : neutral { meta: tags = "MEMORY" condition: true }\n'
        )
        kept = (
            'rule Neutral : neutral second { meta: tags = "mail, document" '
            "condition: true }\n"
            "rule Comments : neutral /* MEMORY { */ second {\n"
            '  meta: // tags = "LOG"\n'
            '    note = "https://example.test/MEMORY"\n'
            '    /* tags = "MEMORY" */\n'
            "  condition: true\n"
            "}\n"
            'private rule PrivateMemory : MEMORY { meta: tags = "LOG" '
            "condition: true }\n"
            'rule StringNamedTags : neutral { strings: $tags = "MEMORY" '
            "condition: $tags }\n"
        )
        self.assertEqual(self.filtered(dropped + kept), "\n\n\n" + kept)

    def test_license_gate_still_precedes_combined_tags(self):
        source = (
            "rule Vendor_Maldoc : neutral MEMORY {\n"
            "  meta:\n"
            '    tags = "document"\n'
            '    license_url = "https://creativecommons.org/licenses/by-nc/4.0/"\n'
            "  condition: true\n"
            "}\n"
            "rule CommentedLicense : neutral {\n"
            '  meta: note = "redistributable"\n'
            '    /* license_url = "https://example.test/by-nc" */\n'
            "  condition: true\n"
            "}\n"
        )
        expected = "\n" + source[source.index("rule CommentedLicense") :]
        self.assertEqual(self.filtered(source), expected)

    def test_cli_usage_still_fails(self):
        with (
            mock.patch.object(sys, "argv", ["filter-rules.py"]),
            self.assertRaisesRegex(SystemExit, "usage: filter-rules.py"),
        ):
            runpy.run_path(str(ROOT / "docker/filter-rules.py"), run_name="__main__")

    def test_empty_and_no_rule_inputs(self):
        for source in ("", "// no rules\n", 'import "math"\n'):
            with self.subTest(source=source):
                # Native yarac accepts an empty ruleset; filtering still must
                # leave these bytes unchanged rather than add a rule.
                self.assertEqual(self.filtered(source), source)


if __name__ == "__main__":
    if "--native" in sys.argv:
        sys.argv.remove("--native")
        NATIVE = True
    print("filter regex controls: " + ("native YARA 4.5.2" if NATIVE else "stdlib"))
    unittest.main()
