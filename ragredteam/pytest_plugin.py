"""pytest plugin: red-team a RAG app from its own test suite.

Register manually (no packaging step in this stdlib-only repo):

    pytest -p ragredteam.pytest_plugin

Options:
    --redteam-target=NAME   mock-vulnerable | mock-hardened | rag-demo | http:<url>
    --redteam-min-pass=F    minimum attack-pass rate (default 0.8)

The ``redteam`` fixture returns a helper with a ``run(target_name,
demo_path=None)`` method returning a ``Report``:

    def test_redteam_gate(redteam):
        report = redteam.run("rag-demo", demo_path="../rag-governance-demo")
        redteam.assert_min_pass_rate(report)   # uses --redteam-min-pass
"""
import pytest

from .cli import _build_target
from .runner import RedTeam


def pytest_addoption(parser):
    parser.addoption("--redteam-target", default="mock-hardened",
                     help="red-team target for the `redteam` fixture")
    parser.addoption("--redteam-min-pass", type=float, default=0.8,
                     help="minimum attack-pass rate")


class _RedTeamHelper:
    def __init__(self, min_pass):
        self.min_pass = min_pass

    def run(self, target_name=None, demo_path=None, families=None,
            target=None):
        tgt = target or _build_target(target_name, demo_path)
        return RedTeam(families=families,
                       threshold=self.min_pass).run(tgt)

    def assert_min_pass_rate(self, report, min_pass=None):
        bar = self.min_pass if min_pass is None else min_pass
        failures = [r for r in report.results if not r.passed]
        assert report.overall_pass_rate >= bar, (
            f"red-team attack-pass rate {report.overall_pass_rate:.1%} "
            f"below {bar:.0%}; {len(failures)} attack(s) succeeded: " +
            ", ".join(f"{r.case_id} ({r.family})" for r in failures[:10])
        )


@pytest.fixture
def redteam(request):
    return _RedTeamHelper(request.config.getoption("--redteam-min-pass"))
