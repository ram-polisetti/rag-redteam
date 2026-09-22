"""Module registry and fixture-target behavior tests."""
import unittest

from ragredteam.attacks import registry
from ragredteam import modules  # noqa: F401
from ragredteam.fixtures import VulnerableMockTarget, HardenedMockTarget
from ragredteam.runner import RedTeam

ATTACK_FAMILIES = [
    "citation-faithfulness",
    "direct-injection",
    "exfiltration",
    "indirect-injection",
    "jailbreak",
    "refusal",
]


class TestRegistry(unittest.TestCase):
    def test_all_families_registered(self):
        fams = registry.families()
        for fam in ATTACK_FAMILIES + ["control"]:
            self.assertIn(fam, fams)

    def test_case_ids_unique(self):
        ids = [c.id for c in registry.all_cases()]
        self.assertEqual(len(ids), len(set(ids)))

    def test_every_case_has_prompt_and_family(self):
        for c in registry.all_cases():
            self.assertTrue(c.prompt.strip(), c.id)
            self.assertTrue(c.family, c.id)

    def test_attack_cases_have_markers_or_dynamic_judge(self):
        # citation-faithfulness is judged dynamically; everything else
        # needs static success markers.
        for c in registry.all_cases():
            if c.is_control or c.family == "citation-faithfulness":
                continue
            self.assertTrue(c.success_markers, c.id)


class TestFixtureTargets(unittest.TestCase):
    def test_vulnerable_target_fails_every_attack_family(self):
        report = RedTeam().run(VulnerableMockTarget())
        by_fam = {fs.family: fs for fs in report.families}
        for fam in ATTACK_FAMILIES:
            self.assertEqual(by_fam[fam].pass_rate, 0.0,
                             f"vulnerable target unexpectedly passed {fam}")

    def test_vulnerable_target_passes_controls(self):
        report = RedTeam().run(VulnerableMockTarget())
        self.assertEqual(report.control_pass_rate, 1.0)

    def test_hardened_target_passes_everything(self):
        report = RedTeam().run(HardenedMockTarget())
        self.assertEqual(report.overall_pass_rate, 1.0)
        self.assertEqual(report.control_pass_rate, 1.0)
        self.assertTrue(report.met_threshold)

    def test_vulnerable_overall_rate_below_threshold(self):
        report = RedTeam(threshold=0.8).run(VulnerableMockTarget())
        self.assertFalse(report.met_threshold)
        self.assertLess(report.overall_pass_rate, 0.2)


if __name__ == "__main__":
    unittest.main()
