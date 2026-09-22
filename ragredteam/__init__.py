"""ragredteam — adversarial red-team harness for RAG systems.

Attack a RAG app with jailbreaks, prompt-injection probes, poisoned chunks,
exfiltration attempts, unsafe requests, and citation-faithfulness checks.
Score pass/fail per attack family, emit a JSON report, and keep a
tamper-evident audit log of every attack run.

Quick start:
    python -m ragredteam run --target mock-hardened
    python -m ragredteam run --target rag-demo --demo-path /path/to/rag-governance-demo
"""

__version__ = "0.1.0"

from .target import Target, TargetResponse  # noqa: F401
from .attacks import AttackCase, AttackModule, registry, all_cases  # noqa: F401
from .runner import RedTeam, run_suite  # noqa: F401
