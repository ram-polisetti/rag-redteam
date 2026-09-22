# Changelog

## 0.1.0 — 2026-09-22

Initial release.

- 7 attack families, 49 cases: direct-injection (10), jailbreak (8),
  indirect-injection / poisoned chunks (6), exfiltration (8), refusal (8),
  citation-faithfulness (3), benign controls (6).
- Verdict engine: `blocked` / `failed` / `succeeded`; refusal-quality
  grading; dynamic claim-support check for citation faithfulness.
- Scoring: per-family pass rates, overall attack-pass rate, separate
  control (false-positive) rate, configurable `--min-pass` threshold.
- `python -m ragredteam` CLI: `run`, `modules`, `report`, `verify`.
- Hash-chained JSONL audit log with tamper detection.
- Fixture targets: `mock-vulnerable` (0% vs attacks) and `mock-hardened`
  (100%), for harness self-testing.
- In-process adapter for `ram-polisetti/rag-governance-demo`.
- pytest plugin (`-p ragredteam.pytest_plugin`) with `redteam` fixture.
- 45 unittest tests, all green.
- Docs: methodology, attack taxonomy, limitations, adding modules.
- Demo finding: 4/6 poisoned-chunk attacks succeed against
  rag-governance-demo's stub-backend configuration — the gate's
  pattern-based output check misses their phrasing.
