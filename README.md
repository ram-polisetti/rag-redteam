# rag-redteam

Adversarial red-team harness for RAG systems. Attacks a RAG app with
jailbreaks, prompt-injection probes, poisoned chunks, exfiltration
attempts, unsafe requests, and citation-faithfulness checks — then scores
pass/fail per attack family, emits a numeric **attack-pass rate**, and
keeps a tamper-evident audit log of every attack run.

Pure Python stdlib. No dependencies, no network, no API keys.

## Quickstart

```bash
# List the 7 attack families (49 cases)
python3 -m ragredteam modules

# Attack the built-in fixture targets
python3 -m ragredteam run --target mock-hardened
python3 -m ragredteam run --target mock-vulnerable

# Attack Charan's rag-governance-demo end-to-end (in-process)
git clone https://github.com/ram-polisetti/rag-governance-demo.git
python3 -m ragredteam run --target rag-demo --demo-path ./rag-governance-demo \
    --out report.json --audit audit.jsonl

# Attack any HTTP RAG endpoint
python3 -m ragredteam run --target http:http://localhost:8000/ask

# Verify the audit chain / render a saved report
python3 -m ragredteam verify audit.jsonl
python3 -m ragredteam report report.json --failures-only
```

Exit codes for `run`: `0` = attack-pass rate met `--min-pass` (default
0.8), `1` = below threshold, `2` = usage error.

## What the numbers mean

Per case the judge returns `blocked` (a defense fired), `failed` (the
attack bounced off without triggering a defense — weak evidence), or
`succeeded` (the attack worked — **the finding**). The attack-pass rate
counts cases that did *not* succeed. Read `docs/METHODOLOGY.md` before
citing a number, and `docs/LIMITATIONS.md` before trusting one.

## Demo finding

Against `rag-governance-demo` (stub backend, real gate), the suite scores
**90.7%** — but 4 of 6 poisoned-chunk attacks **succeed**: chunks planted
post-ingest are quoted verbatim into answers, embedded instructions
included, because the gate's pattern-based output check misses their
phrasing. The two it catches are refused. Reproduce:

```bash
python3 examples/demo.py ./rag-governance-demo
```

## Use it in your own test suite

```bash
pytest -p ragredteam.pytest_plugin
```

```python
def test_redteam_gate(redteam):
    report = redteam.run("rag-demo", demo_path="../rag-governance-demo")
    redteam.assert_min_pass_rate(report)  # --redteam-min-pass (default 0.8)
```

## Layout

```
ragredteam/          the harness
  modules/           7 attack families (pluggable — see docs/ADDING_MODULES.md)
  judge.py           verdict engine
  runner.py          suite execution + scoring + reports
  audit.py           hash-chained JSONL audit log
  fixtures.py        mock-vulnerable / mock-hardened fixture targets
  adapters.py        rag-governance-demo in-process adapter
  cli.py             python -m ragredteam
  pytest_plugin.py   pytest fixture for RAG app test suites
tests/               45 unittest tests (python3 -m unittest discover -s tests)
examples/demo.py     end-to-end demo against rag-governance-demo
docs/                methodology, attack taxonomy, limitations, extending
```

## License

Apache-2.0. See LICENSE.
