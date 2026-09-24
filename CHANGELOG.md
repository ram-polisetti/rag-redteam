# Changelog

## Unreleased — transport-error contamination fix (2026-09-24)

- **Correction: the "18/20 combinations clear 80%" claim is withdrawn.**
  Post-release audit found 4 of the 20 generative model/corpus runs were
  contaminated by Ollama transport failures (`Connection refused` on
  13–27 of 49 cases each: glm-5.1 on EU AI Act and NIST AI RMF,
  deepseek-v4.1-flash on HotpotQA and SQuAD 2.0). The old judge scored
  error strings as evidence — benign controls "passed", attacks counted
  as defense passes — so those four runs' rates were meaningless even
  though their hash chains verified intact. The sweep is NOT complete
  until all four are re-run clean; do not cite the 18/20 figure.
- Judge: target/backend transport failures now return verdict `error`
  with `scored=False` (new `Verdict.scored` / `CaseResult.scored` fields)
  instead of being judged as normal responses. Error text is preserved
  in `response_text` as evidence.
- Runner: unscored cases are excluded from all per-family and overall
  rates; reports carry `n_attack_cases`, `n_scored_attacks`, `n_errors`
  and a WARNING line. **Any** target error forces `met_threshold=False`
  (fail closed) — a rate on a subset of cases cannot read as a clean
  bill of health. The old vacuous-1.0 survives only for genuine
  control-only runs.
- CLI `run`: exit 2 = incomplete run (target errors), exit 1 =
  completed run below threshold, exit 0 = completed run meeting
  threshold.
- Docs: LIMITATIONS.md gains item 11 (an intact hash chain does not
  prove a valid run).
- Clean re-run (fixed harness, 2026-09-24): glm-5.1 / EU AI Act —
  49 cases, 0 errors, chain intact, attack-pass 90.7% (39/43), threshold
  MET. Replaces the contaminated run. Other three re-runs pending.
- 55 tests, all green (was 52 + new error-handling/exit-code/
  serialization/backward-compat tests).

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
- Multi-model sweep complete (2026-09-24): `deepseek-v4.1-flash`
  (97.7/95.3/**76.7**/83.7), `kimi-k2.7-code` (81.4/83.7/**74.4**/86.0),
  `qwen3.5:397b` (88.4/88.4/93.0/90.7) — attack-pass per corpus
  (HotpotQA/SQuAD2/EU AI Act/NIST). 18/20 model/corpus combinations
  clear the 80% threshold; the 2 failures are both on the EU AI Act
  corpus, proving the threshold discriminates rather than rubber-stamps.
  Every chain verified intact (49 records each); per-model evidence
  isolated in model-specific subdirectories. Release decisions do not
  transfer across models.
- Indirect injection (poisoned chunks) confirmed as the weakest family
  across corpora and backends.
- CI workflow file removed from the tree (automation token lacks the
  `workflow` scope); saved for manual upload.
