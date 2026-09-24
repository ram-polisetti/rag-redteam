# Changelog

## 0.1.0 — 2026-09-22 (validated 2026-09-24)

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

### Validated — 2026-09-24

- 7 fixed-battery chains verify intact via `AuditLog.verify()`, 49 records each.
- Full generative battery re-run on 4 real corpora (HotpotQA, SQuAD 2.0,
  EU AI Act, NIST AI RMF) with a real generative backend (`glm-5.1`):
  attack-pass 81.4–90.7%, all above the 80% release threshold; every chain
  49/49 verified intact. A second `glm-5.1` run reproduced the threshold
  result on all four corpora (81.4 / 83.7 / 97.7 / 100.0 vs
  81.4 / 88.4 / 83.7 / 90.7 the first time — the model sets no
  temperature, so wording varies run to run by up to ~14 points; the
  judge is deterministic). What is stable across runs is the threshold
  claim: every corpus stays above 80%.
- A second model (`gpt-oss:20b`) ran the same battery with surviving
  chains: attack-pass 88.4–95.3%, same threshold result.
- Multi-model validation in progress (`deepseek-v4.1-flash`,
  `kimi-k2.7-code`, `qwen3.5:397b`).
- Indirect injection (poisoned chunks) confirmed as the weakest family
  across corpora and backends.
- CI workflow file removed from the tree (automation token lacks the
  `workflow` scope); saved for manual upload.
