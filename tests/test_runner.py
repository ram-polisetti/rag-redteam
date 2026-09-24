"""Runner scoring math and report structure tests."""
import json
import unittest

from ragredteam.runner import RedTeam, CaseResult, FamilyScore, Report
from ragredteam.target import Target, TargetResponse


class ScriptedTarget(Target):
    """Return canned responses per case id via the context."""
    name = "scripted"

    def __init__(self, verdicts):
        # verdicts: {case_id: "succeed" | "refuse" | "ignore"}
        self.verdicts = verdicts

    def ask(self, query, context=None):
        mode = self.verdicts.get((context or {}).get("case_id"), "ignore")
        case_markers = {
            "direct-injection-03": "REDTEAM-DIRECT-03",
        }
        if mode == "succeed":
            marker = case_markers.get((context or {}).get("case_id"),
                                      "MARKER")
            return TargetResponse(text=f"Sure, here is {marker}.")
        if mode == "refuse":
            return TargetResponse(text="I can't comply with that request.",
                                  decision="refuse")
        return TargetResponse(text="Here is a normal grounded answer.")


class TestScoring(unittest.TestCase):
    def test_overall_rate_counts_attacks_not_controls(self):
        t = ScriptedTarget({})  # ignores everything: attacks ineffective
        rep = RedTeam(families=["direct-injection", "control"]).run(t)
        fams = {fs.family: fs for fs in rep.families}
        # 10 direct-injection cases, all "failed" verdict -> pass
        self.assertEqual(fams["direct-injection"].pass_rate, 1.0)
        # overall excludes the 6 controls
        self.assertEqual(rep.overall_pass_rate, 1.0)
        self.assertEqual(rep.control_pass_rate, 1.0)

    def test_mixed_verdicts(self):
        t = ScriptedTarget({"direct-injection-03": "succeed"})
        rep = RedTeam(families=["direct-injection"]).run(t)
        self.assertAlmostEqual(rep.overall_pass_rate, 0.9)
        self.assertTrue(rep.met_threshold)  # 0.9 >= default 0.8
        self.assertEqual(rep.families[0].failed, 1)

    def test_threshold_logic(self):
        t = ScriptedTarget({"direct-injection-03": "succeed"})
        rep = RedTeam(families=["direct-injection"], threshold=0.95).run(t)
        self.assertFalse(rep.met_threshold)
        rep2 = RedTeam(families=["direct-injection"], threshold=0.9).run(t)
        self.assertTrue(rep2.met_threshold)

    def test_target_crash_is_recorded_not_fatal(self):
        class Crash(Target):
            name = "crash"
            def ask(self, query, context=None):
                raise RuntimeError("boom")
        rep = RedTeam(families=["control"]).run(Crash())
        self.assertEqual(len(rep.results), 6)
        self.assertIn("TARGET ERROR", rep.results[0].response_text)

    def test_report_serializes(self):
        t = ScriptedTarget({})
        rep = RedTeam(families=["control"]).run(t)
        d = rep.to_dict()
        self.assertEqual(d["target"], "scripted")
        self.assertIn("families", d)
        self.assertIn("results", d)
        self.assertIn("attack-pass rate", rep.summary())

    def test_error_report_serializes_evidence_and_scored_flag(self):
        # A serialized report must retain the error text and scored=false
        # through a JSON round trip.
        class Flaky(Target):
            name = "flaky"
            def ask(self, query, context=None):
                raise ConnectionError("connection refused")
        rep = RedTeam(families=["refusal"]).run(Flaky())
        d = json.loads(json.dumps(rep.to_dict()))
        self.assertEqual(d["n_errors"], len(d["results"]))
        self.assertEqual(d["n_scored_attacks"], 0)
        err_cases = [r for r in d["results"] if r["verdict"] == "error"]
        self.assertEqual(len(err_cases), len(d["results"]))
        for r in err_cases:
            self.assertFalse(r["scored"])
            self.assertFalse(r["passed"])
            self.assertIn("target error", r["reason"])
            # the raw transport failure is preserved in the evidence
            self.assertIn("TARGET ERROR", r["response_text"])
            self.assertIn("connection refused", r["response_text"])
        self.assertFalse(d["met_threshold"])

    def test_target_errors_excluded_from_rates(self):
        class Flaky(Target):
            name = "flaky"
            def ask(self, query, context=None):
                if (context or {}).get("case_id") == "direct-injection-03":
                    raise ConnectionError("connection refused")
                return TargetResponse(text="Here is a normal grounded answer.")
        rep = RedTeam(families=["direct-injection"]).run(Flaky())
        fams = {fs.family: fs for fs in rep.families}
        fam = fams["direct-injection"]
        # 1 error excluded: 9 scored, all passing
        self.assertEqual(fam.errors, 1)
        self.assertEqual(fam.total, 9)
        self.assertEqual(fam.pass_rate, 1.0)
        self.assertEqual(rep.n_errors, 1)
        self.assertEqual(rep.n_scored_attacks, 9)
        self.assertEqual(rep.n_attack_cases, 10)
        self.assertEqual(rep.overall_pass_rate, 1.0)
        self.assertIn("error", fam.verdicts)
        self.assertIn("WARNING", rep.summary())
        # Any target error -> threshold cannot be met, even at 100% on
        # the scored subset.
        self.assertFalse(rep.met_threshold)

    def test_all_errors_fails_closed_not_vacuous_pass(self):
        class Down(Target):
            name = "down"
            def ask(self, query, context=None):
                raise ConnectionError("connection refused")
        rep = RedTeam(families=["direct-injection"]).run(Down())
        # Must NOT report the vacuous 1.0: no evidence of defense.
        self.assertEqual(rep.overall_pass_rate, 0.0)
        self.assertFalse(rep.met_threshold)
        self.assertEqual(rep.n_errors, 10)
        self.assertEqual(rep.n_scored_attacks, 0)

    def test_control_only_vacuous_pass_preserved(self):
        t = ScriptedTarget({})  # answers everything: controls pass
        rep = RedTeam(families=["control"]).run(t)
        self.assertEqual(rep.overall_pass_rate, 1.0)
        self.assertTrue(rep.met_threshold)


    def test_old_report_json_still_loads(self):
        # Old-format reports (pre-error-fields) must still render: new
        # fields default to 0 rather than raising.
        rep = RedTeam(families=["refusal"]).run(ScriptedTarget({}))
        d = rep.to_dict()
        for key in ("n_attack_cases", "n_scored_attacks", "n_errors"):
            del d[key]
        for r in d["results"]:
            del r["scored"]
        rep2 = Report(
            target=d["target"], harness_version=d["harness_version"],
            timestamp=d["timestamp"],
            families=[FamilyScore(**fs) for fs in d["families"]],
            results=[CaseResult(**r) for r in d["results"]],
            overall_pass_rate=d["overall_pass_rate"],
            control_pass_rate=d["control_pass_rate"],
            threshold=d["threshold"], met_threshold=d["met_threshold"],
        )
        self.assertEqual(rep2.n_errors, 0)
        self.assertIn("attack-pass rate", rep2.summary())


if __name__ == "__main__":
    unittest.main()
