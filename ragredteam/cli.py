"""CLI: python -m ragredteam <command>

Commands:
  run      attack a target and write a JSON report
  modules  list attack modules and case counts
  report   render a JSON report as human-readable text
  verify   verify a hash-chained audit log

Targets for `run --target`:
  mock-vulnerable   fixture RAG with no defenses (everything should fail)
  mock-hardened     fixture RAG with layered defenses (everything should pass)
  rag-demo          Charan's rag-governance-demo, run in-process
                    (requires --demo-path)
  http:<url>        POST {"query","context"} to an HTTP RAG endpoint

Exit codes for `run`: 0 = attack-pass rate met --min-pass (default 0.8),
1 = below threshold, 2 = usage error.
"""
import argparse
import json
import sys

from . import __version__
from .attacks import registry
from . import modules  # noqa: F401  (registers all modules)
from .fixtures import VulnerableMockTarget, HardenedMockTarget
from .runner import RedTeam
from .target import HttpTarget


def _build_target(name, demo_path):
    if name == "mock-vulnerable":
        return VulnerableMockTarget()
    if name == "mock-hardened":
        return HardenedMockTarget()
    if name == "rag-demo":
        if not demo_path:
            raise SystemExit("error: --demo-path is required for target rag-demo")
        from .adapters import RagGovernanceDemoTarget
        return RagGovernanceDemoTarget(demo_path)
    if name.startswith("http:"):
        return HttpTarget(name)
    raise SystemExit(f"error: unknown target {name!r} "
                     f"(see `modules` output / --help)")


def cmd_run(args):
    target = _build_target(args.target, args.demo_path)
    families = args.families.split(",") if args.families else None
    if families:
        unknown = [f for f in families if f not in registry.families()]
        if unknown:
            raise SystemExit(f"error: unknown families {unknown}; "
                             f"known: {registry.families()}")
    report = RedTeam(families=families, threshold=args.min_pass,
                     audit_path=args.audit).run(target)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            json.dump(report.to_dict(), f, indent=2, ensure_ascii=True)
        print(f"report written to {args.out}")
    print(report.summary())
    return 0 if report.met_threshold else 1


def cmd_modules(_args):
    for fam in registry.families():
        mod = registry.get(fam)
        n = len(mod.cases())
        print(f"{fam:22s} {n:3d} cases  {mod.description}")
    return 0


def cmd_report(args):
    from .runner import Report, FamilyScore, CaseResult
    with open(args.report, encoding="utf-8") as f:
        d = json.load(f)
    rep = Report(
        target=d["target"], harness_version=d["harness_version"],
        timestamp=d["timestamp"],
        families=[FamilyScore(**fs) for fs in d["families"]],
        results=[CaseResult(**r) for r in d["results"]],
        overall_pass_rate=d["overall_pass_rate"],
        control_pass_rate=d["control_pass_rate"],
        threshold=d["threshold"], met_threshold=d["met_threshold"],
    )
    print(rep.summary())
    if args.failures_only:
        print("\nfailed cases (attack succeeded):")
        for r in rep.results:
            if not r.passed:
                print(f"  [{r.family}] {r.case_id}: {r.reason}")
    return 0


def cmd_verify(args):
    from .audit import AuditLog
    ok, msg = AuditLog(args.log).verify()
    print(("OK  " if ok else "FAIL") + f" {args.log}: {msg}")
    return 0 if ok else 1


def main(argv=None):
    ap = argparse.ArgumentParser(prog="rag-redteam",
                                 description="Adversarial red-team harness for RAG systems")
    ap.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("run", help="attack a target")
    p.add_argument("--target", required=True,
                   help="mock-vulnerable | mock-hardened | rag-demo | http:<url>")
    p.add_argument("--demo-path", default=None,
                   help="path to rag-governance-demo checkout (for rag-demo)")
    p.add_argument("--families", default=None,
                   help="comma-separated families to run (default: all)")
    p.add_argument("--out", default=None, help="write JSON report to file")
    p.add_argument("--audit", default=None,
                   help="append every attack to a hash-chained JSONL audit log")
    p.add_argument("--min-pass", type=float, default=0.8,
                   help="pass-rate threshold for exit code 0 (default 0.8)")
    p.set_defaults(fn=cmd_run)

    p = sub.add_parser("modules", help="list attack modules")
    p.set_defaults(fn=cmd_modules)

    p = sub.add_parser("report", help="render a JSON report")
    p.add_argument("report", help="report JSON from `run --out`")
    p.add_argument("--failures-only", action="store_true",
                   help="also list every case where the attack succeeded")
    p.set_defaults(fn=cmd_report)

    p = sub.add_parser("verify", help="verify an audit log's hash chain")
    p.add_argument("log", help="audit JSONL file")
    p.set_defaults(fn=cmd_verify)

    args = ap.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
