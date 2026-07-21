from __future__ import annotations

import argparse
import shutil
import sys
from pathlib import Path

from .evidence import EvidenceStore
from .knowledge import list_routes, open_notes, required_bundle
from .planner import plan_step
from .policy_guard import ScopePolicy, host_from_target, policy_quote_for
from .redaction import redact_text
from .reporting import render_bugcrowd, render_hackerone, render_intigriti
from .runners import burp, hexstrike, projectdiscovery, reconftw


ROOT = Path(__file__).resolve().parents[1]
TARGETS = ROOT / "targets"
TEMPLATE = ROOT / "templates" / "target"


def target_init(name: str) -> int:
    slug = name.strip().replace(" ", "-").lower()
    target_dir = TARGETS / slug
    target_dir.mkdir(parents=True, exist_ok=True)
    for path in TEMPLATE.iterdir():
        if path.is_file():
            dest = target_dir / path.name
            if not dest.exists():
                shutil.copyfile(path, dest)
    for subdir in ("evidence", "evidence/raw", "evidence/safe", "recon", "reports", "secrets"):
        (target_dir / subdir).mkdir(parents=True, exist_ok=True)
    print(f"target ready: {target_dir}")
    return 0


def scope_check(target_dir: str, host: str | None, action: str | None) -> int:
    policy = ScopePolicy.load(Path(target_dir))
    rc = 0
    if host:
        parsed_host = host_from_target(host)
        if policy.is_explicitly_out_of_scope(parsed_host):
            status = "OUT_OF_SCOPE"
            rc = 1
        elif policy.contains_host(parsed_host):
            status = "IN_SCOPE"
        else:
            status = "NOT_CONFIRMED"
            rc = 1
        print(f"host={parsed_host} status={status}")
    if action:
        level = policy.classify_aggression(action)
        print(f"action_level={level}")
        print(f"policy_quote={policy_quote_for(policy, level)}")
        if level >= 2 and not policy.mentions_active_testing():
            print("warning=active/moderate action requested; confirm policy text before running")
        if level >= 3 and not policy.allows_level3():
            print("warning=level3 not explicitly allowed in SCOPE.md")
            rc = 1
    return rc


def context(target_dir: str) -> int:
    target = Path(target_dir)
    files = [
        ROOT / "docs" / "OPERATING_RULES.md",
        ROOT / "bounty_knowledge" / "study_notes" / "INDEX.md",
        ROOT / "bounty_knowledge" / "study_notes" / "STUDY_MATERIAL_ROUTING.md",
        target / "SCOPE.md",
        target / "PLAN.md",
        target / "FINDINGS.md",
        target / "RESUME.md",
    ]
    for file in files:
        print(f"\n--- {file} ---")
        if file.exists():
            text = file.read_text(encoding="utf-8", errors="replace")
            print(text[:8000])
        else:
            print("missing")
    return 0


def knowledge_cmd(task: str, routes_only: bool) -> int:
    if routes_only:
        print(list_routes())
        return 0
    bundle = required_bundle(task)
    print(f"class={bundle.class_name}")
    print(open_notes(task))
    return 0


def plan_cmd(args: argparse.Namespace) -> int:
    step = plan_step(
        Path(args.target_dir),
        hypothesis=args.hypothesis,
        target=args.target,
        action=args.action,
        command=args.command,
        expected_evidence=args.expected_evidence,
        stop_criteria=args.stop,
        cleanup=args.cleanup,
    )
    md = step.to_markdown()
    print(md)
    if args.write:
        out = Path(args.target_dir) / "PLAN.md"
        out.write_text(md, encoding="utf-8")
        print(f"wrote {out}")
    if not step.in_scope:
        return 1
    return 0


def evidence_cmd(args: argparse.Namespace) -> int:
    store = EvidenceStore(Path(args.target_dir))
    if args.list:
        for path in store.list_safe():
            print(path)
        return 0
    if args.file:
        content = Path(args.file).read_text(encoding="utf-8", errors="replace")
    else:
        content = args.text or ""
    if not content:
        print("provide --text or --file")
        return 2
    saved = store.save(args.name or "note.txt", content, keep_raw=args.keep_raw)
    print(f"saved={saved}")
    return 0


def redact_cmd(path: str) -> int:
    text = Path(path).read_text(encoding="utf-8", errors="replace")
    print(redact_text(text))
    return 0


def report_cmd(args: argparse.Namespace) -> int:
    common = dict(
        title=args.title,
        preconditions=args.preconditions,
        steps=args.steps,
        impact=args.impact,
        evidence=args.evidence,
    )
    if args.platform == "bugcrowd":
        body = render_bugcrowd(vrt=args.vrt or "TBD", target=args.target, **common)
    elif args.platform == "hackerone":
        body = render_hackerone(
            weakness=args.weakness or "TBD",
            target=args.target,
            **common,
        )
    else:
        body = render_intigriti(
            endpoint=args.target,
            vulnerability_type=args.weakness or "TBD",
            **common,
        )
    out = Path(args.target_dir) / "reports" / f"{args.platform}_draft.md"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(body, encoding="utf-8")
    print(f"wrote {out}")
    return 0


def run_cmd(args: argparse.Namespace) -> int:
    target = Path(args.target_dir)
    approve = args.approve
    tool = args.tool
    host = args.host
    try:
        if tool == "httpx":
            result = projectdiscovery.httpx_probe(target, host, approve=approve)
        elif tool == "katana":
            result = projectdiscovery.katana_crawl(
                target, host, depth=args.depth, approve=approve
            )
        elif tool == "nuclei":
            result = projectdiscovery.nuclei_scan(
                target,
                host,
                templates=args.templates,
                rate_limit=args.rate_limit,
                concurrency=args.concurrency,
                approve=approve,
            )
        elif tool == "ffuf":
            if not args.wordlist:
                print("--wordlist required for ffuf")
                return 2
            result = projectdiscovery.ffuf_dir(
                target, host, args.wordlist, approve=approve
            )
        elif tool == "reconftw":
            result = reconftw.run_recon(target, host, mode=args.mode, approve=approve)
        elif tool == "hexstrike":
            result = hexstrike.start_server(port=args.port, approve=approve)
        elif tool == "burp":
            if not args.burp_xml:
                print("--burp-xml required for burp")
                return 2
            result = burp.summarize_xml(
                target, Path(args.burp_xml), approve=approve, limit=args.limit
            )
        else:
            print(f"unknown tool: {tool}")
            return 2
    except (FileNotFoundError, PermissionError) as exc:
        print(f"blocked: {exc}")
        return 1
    return 0 if (result.returncode in (None, 0) or not result.executed) else result.returncode


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="hackbot",
        description="Authorized bug bounty / lab automation CLI",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    init_p = sub.add_parser("target-init", help="Create targets/<name> from templates")
    init_p.add_argument("name")

    scope_p = sub.add_parser("scope-check", help="Check host/action against SCOPE.md")
    scope_p.add_argument("target_dir")
    scope_p.add_argument("--host")
    scope_p.add_argument("--action")

    context_p = sub.add_parser("context", help="Print mandatory operating context")
    context_p.add_argument("target_dir")

    know_p = sub.add_parser("knowledge", help="Open study notes for a task class")
    know_p.add_argument("task", nargs="?", default="recon")
    know_p.add_argument("--routes", action="store_true")

    plan_p = sub.add_parser("plan", help="Emit a falsifiable hunt step")
    plan_p.add_argument("target_dir")
    plan_p.add_argument("--hypothesis", required=True)
    plan_p.add_argument("--target", required=True, help="Host or URL")
    plan_p.add_argument("--action", required=True, help="Tool/action for aggression level")
    plan_p.add_argument("--command", required=True)
    plan_p.add_argument("--expected-evidence", default="Differential response + negative control")
    plan_p.add_argument("--stop", default="Hypothesis falsified, impact proved, or policy limit hit")
    plan_p.add_argument("--cleanup", default="Stop traffic; redact evidence; restore test state")
    plan_p.add_argument("--write", action="store_true", help="Overwrite PLAN.md")

    ev_p = sub.add_parser("evidence", help="Save redacted evidence")
    ev_p.add_argument("target_dir")
    ev_p.add_argument("--name", default="note.txt")
    ev_p.add_argument("--text")
    ev_p.add_argument("--file")
    ev_p.add_argument("--keep-raw", action="store_true")
    ev_p.add_argument("--list", action="store_true")

    red_p = sub.add_parser("redact", help="Redact a file to stdout")
    red_p.add_argument("path")

    rep_p = sub.add_parser("report", help="Write a platform report draft")
    rep_p.add_argument("target_dir")
    rep_p.add_argument("--platform", choices=("bugcrowd", "hackerone", "intigriti"), default="bugcrowd")
    rep_p.add_argument("--title", required=True)
    rep_p.add_argument("--target", required=True)
    rep_p.add_argument("--preconditions", default="Two test accounts in-scope")
    rep_p.add_argument("--steps", default="1. ...")
    rep_p.add_argument("--impact", default="TBD")
    rep_p.add_argument("--evidence", default="See evidence/safe/")
    rep_p.add_argument("--vrt", help="Bugcrowd VRT category")
    rep_p.add_argument("--weakness", help="H1 weakness / Intigriti type")

    run_p = sub.add_parser("run", help="Print tool command; execute only with --approve")
    run_p.add_argument("target_dir")
    run_p.add_argument(
        "--tool",
        required=True,
        choices=("httpx", "katana", "nuclei", "ffuf", "reconftw", "hexstrike", "burp"),
    )
    run_p.add_argument("--host", default="", help="In-scope host or URL")
    run_p.add_argument("--approve", action="store_true")
    run_p.add_argument("--wordlist")
    run_p.add_argument("--templates")
    run_p.add_argument("--depth", type=int, default=2)
    run_p.add_argument("--rate-limit", type=int, default=10)
    run_p.add_argument("--concurrency", type=int, default=5)
    run_p.add_argument("--mode", default="recon", help="reconftw mode flag body")
    run_p.add_argument("--port", type=int, default=8888)
    run_p.add_argument("--burp-xml")
    run_p.add_argument("--limit", type=int, default=20)

    return parser


def main(argv: list[str] | None = None) -> int:
    # Windows consoles often use cp1252; study notes contain unicode arrows etc.
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if callable(reconfigure):
            try:
                reconfigure(errors="replace")
            except Exception:
                pass

    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "target-init":
        return target_init(args.name)
    if args.command == "scope-check":
        return scope_check(args.target_dir, args.host, args.action)
    if args.command == "context":
        return context(args.target_dir)
    if args.command == "knowledge":
        return knowledge_cmd(args.task, args.routes)
    if args.command == "plan":
        return plan_cmd(args)
    if args.command == "evidence":
        return evidence_cmd(args)
    if args.command == "redact":
        return redact_cmd(args.path)
    if args.command == "report":
        return report_cmd(args)
    if args.command == "run":
        return run_cmd(args)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
