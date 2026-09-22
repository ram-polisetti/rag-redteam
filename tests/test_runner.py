"""Runner scoring math and report structure tests."""
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


if __name__ == "__main__":
    unittest.main()
