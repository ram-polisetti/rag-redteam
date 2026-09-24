"""CLI end-to-end tests (subprocess-free: call main() directly)."""
import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stdout

from ragredteam.cli import main


def _run_cli(*argv):
    buf = io.StringIO()
    with redirect_stdout(buf):
        code = main(list(argv))
    return code, buf.getvalue()


class TestCli(unittest.TestCase):
    def test_modules_lists_families(self):
        code, out = _run_cli("modules")
        self.assertEqual(code, 0)
        for fam in ("direct-injection", "jailbreak", "indirect-injection",
                    "exfiltration", "refusal", "citation-faithfulness",
                    "control"):
            self.assertIn(fam, out)

    def test_run_mock_hardened_exits_zero(self):
        code, out = _run_cli("run", "--target", "mock-hardened",
                             "--families", "control,refusal")
        self.assertEqual(code, 0)
        self.assertIn("attack-pass rate", out)

    def test_run_mock_vulnerable_exits_one(self):
        code, _ = _run_cli("run", "--target", "mock-vulnerable",
                           "--families", "refusal")
        self.assertEqual(code, 1)

    def test_run_writes_json_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            rp = os.path.join(tmp, "report.json")
            ap = os.path.join(tmp, "audit.jsonl")
            code, _ = _run_cli("run", "--target", "mock-hardened",
                               "--families", "control", "--out", rp,
                               "--audit", ap)
            self.assertEqual(code, 0)
            d = json.load(open(rp))
            self.assertEqual(d["target"], "mock-hardened")
            self.assertEqual(len(d["results"]), 6)
            # audit log written and verifiable
            vcode, vout = _run_cli("verify", ap)
            self.assertEqual(vcode, 0)
            self.assertIn("OK", vout)

    def test_report_renders(self):
        with tempfile.TemporaryDirectory() as tmp:
            rp = os.path.join(tmp, "report.json")
            _run_cli("run", "--target", "mock-vulnerable",
                     "--families", "refusal", "--out", rp)
            code, out = _run_cli("report", rp, "--failures-only")
            self.assertEqual(code, 0)
            self.assertIn("refusal-01", out)

    def test_verify_detects_tamper(self):
        with tempfile.TemporaryDirectory() as tmp:
            ap = os.path.join(tmp, "audit.jsonl")
            _run_cli("run", "--target", "mock-hardened",
                     "--families", "control", "--audit", ap)
            recs = [json.loads(ln) for ln in open(ap) if ln.strip()]
            recs[0]["verdict"] = "succeeded"
            with open(ap, "w") as f:
                for r in recs:
                    f.write(json.dumps(r) + "\n")
            code, out = _run_cli("verify", ap)
            self.assertEqual(code, 1)
            self.assertIn("FAIL", out)

    def test_unknown_target_errors(self):
        with self.assertRaises(SystemExit):
            _run_cli("run", "--target", "nope")

    def test_run_with_target_errors_exits_two(self):
        # A run with target errors is incomplete: exit 2, not 1, even when
        # every scored case passes.
        import ragredteam.cli as cli_mod
        from ragredteam.target import Target, TargetResponse

        class Flaky(Target):
            name = "flaky"
            def ask(self, query, context=None):
                if (context or {}).get("case_id") == "refusal-01":
                    raise ConnectionError("connection refused")
                return TargetResponse(text="Here is a normal grounded answer.")

        orig = cli_mod._build_target
        cli_mod._build_target = lambda name, demo_path: Flaky()  # noqa: E731
        try:
            code, out = _run_cli("run", "--target", "mock-hardened",
                                 "--families", "refusal")
        finally:
            cli_mod._build_target = orig
        self.assertEqual(code, 2)
        self.assertIn("WARNING", out)

    def test_unknown_family_errors(self):
        with self.assertRaises(SystemExit):
            _run_cli("run", "--target", "mock-hardened",
                     "--families", "nope")


if __name__ == "__main__":
    unittest.main()
