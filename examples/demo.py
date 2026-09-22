"""End-to-end demo: red-team Charan's rag-governance-demo.

Runs the full attack suite against the real RAG app in-process (real
corpus, real TF-IDF retriever, real stub backend, real governance gate)
and prints the scored report.

Usage:
    python3 examples/demo.py /path/to/rag-governance-demo [--out DIR]

Writes report.json + audit.jsonl into the output dir (default:
examples/output/). No network, no API keys — pure stdlib.
"""
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from ragredteam.adapters import RagGovernanceDemoTarget
from ragredteam.runner import RedTeam
from ragredteam.audit import AuditLog


def main():
    if len(sys.argv) < 2:
        sys.exit("usage: demo.py /path/to/rag-governance-demo [--out DIR]")
    demo_path = sys.argv[1]
    out_dir = os.path.join(os.path.dirname(__file__), "output")
    if "--out" in sys.argv:
        out_dir = sys.argv[sys.argv.index("--out") + 1]
    os.makedirs(out_dir, exist_ok=True)
    audit_path = os.path.join(out_dir, "audit.jsonl")
    if os.path.exists(audit_path):
        os.remove(audit_path)

    print(f"target: rag-governance-demo ({demo_path})\n")
    target = RagGovernanceDemoTarget(demo_path)
    report = RedTeam(audit_path=audit_path).run(target)

    rp = os.path.join(out_dir, "report.json")
    with open(rp, "w", encoding="utf-8") as f:
        json.dump(report.to_dict(), f, indent=2, ensure_ascii=True)

    print(report.summary())
    print(f"\nreport: {rp}\naudit:  {audit_path}")

    ok, msg = AuditLog(audit_path).verify()
    print(f"audit chain: {'OK' if ok else 'FAIL'} ({msg})")

    failures = [r for r in report.results if not r.passed]
    if failures:
        print(f"\n{len(failures)} attack(s) SUCCEEDED against the target:")
        for r in failures:
            print(f"  [{r.family}] {r.case_id}: {r.reason}")
            print(f"      evidence: {r.evidence[:120]}")
    return 0 if report.met_threshold else 1


if __name__ == "__main__":
    sys.exit(main())
