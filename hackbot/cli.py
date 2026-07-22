from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path

from . import ui
from .evidence import EvidenceStore
from .knowledge import list_routes, open_notes, required_bundle
from .planner import plan_step
from .policy_guard import ScopePolicy, host_from_target, policy_quote_for
from .redaction import redact_text
from .repl import start_repl
from .reporting import render_bugcrowd, render_hackerone, render_intigriti
from .runners import burp, hexstrike, projectdiscovery, rate_probe, reconftw

ROOT = Path(__file__).resolve().parents[1]
TARGETS = ROOT / "targets"
TEMPLATE = ROOT / "templates" / "target"

SUBCOMMANDS = frozenset(
    {
        "target-init",
        "scope-check",
        "show-config",
        "context",
        "knowledge",
        "playbook",
        "policy-import",
        "plan",
        "evidence",
        "redact",
        "report",
        "run",
        "cmd",
        "ask",
        "demo",
        "ui",
        "acp",
        "tui",
    }
)


def target_init(name: str) -> int:
    slug = name.strip().replace(" ", "-").lower()
    target_dir = TARGETS / slug
    target_dir.mkdir(parents=True, exist_ok=True)
    for path in TEMPLATE.iterdir():
        if path.is_file():
            dest = target_dir / path.name
            if not dest.exists():
                shutil.copyfile(path, dest)
    for subdir in (
        "evidence",
        "evidence/raw",
        "evidence/safe",
        "recon",
        "reports",
        "secrets",
        "hunt",
        "hunt/workflows",
    ):
        (target_dir / subdir).mkdir(parents=True, exist_ok=True)
    # Copy secrets example (safe to commit); live sessions.yaml stays gitignored.
    example_src = TEMPLATE / "secrets" / "sessions.example.yaml"
    example_dst = target_dir / "secrets" / "sessions.example.yaml"
    if example_src.exists() and not example_dst.exists():
        shutil.copyfile(example_src, example_dst)
    # Example workflow YAML (safe template — edit base_url before ACTIVE).
    wf_src = TEMPLATE / "hunt" / "workflows" / "idor_invite_accept.yaml"
    wf_dst = target_dir / "hunt" / "workflows" / "idor_invite_accept.yaml"
    if wf_src.exists() and not wf_dst.exists():
        shutil.copyfile(wf_src, wf_dst)
    ui.success("target ready")
    ui.path_line("path", str(target_dir))
    ui.info("copy secrets/sessions.example.yaml -> secrets/sessions.yaml and fill A/B tokens")
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
        ui.scope_result(parsed_host, status)
    if action:
        level = policy.classify_aggression(action)
        warnings: list[str] = []
        if level >= 2 and not policy.mentions_active_testing():
            warnings.append("active/moderate action: confirm policy text before running")
        if level >= 3 and not policy.allows_level3():
            warnings.append("level 3 not explicitly allowed in SCOPE.md")
            rc = 1
        ui.aggression_result(level, policy_quote_for(policy, level), warnings)
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
    ui.rule("context")
    for file in files:
        if file.exists():
            text = file.read_text(encoding="utf-8", errors="replace")
            ui.file_panel(str(file), text[:6000], title=file.name)
        else:
            ui.warn(f"missing  {file}")
    return 0


def knowledge_cmd(task: str, routes_only: bool) -> int:
    if routes_only:
        ui.routes_table(list_routes())
        return 0
    bundle = required_bundle(task)
    ui.kv("class", bundle.class_name)
    ui.markdown_panel(open_notes(task, max_chars=3500), title="knowledge")
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
    ui.markdown_panel(md, title="hunt step")
    if step.notes:
        for line in step.notes.splitlines():
            if line.strip():
                ui.warn(line.strip())
    if args.write:
        out = Path(args.target_dir) / "PLAN.md"
        out.write_text(md, encoding="utf-8")
        ui.success(f"wrote {out}")
    if not step.in_scope:
        return 1
    return 0


def evidence_cmd(args: argparse.Namespace) -> int:
    store = EvidenceStore(Path(args.target_dir))
    if args.list:
        paths = store.list_safe()
        if not paths:
            ui.info("no safe evidence yet")
            return 0
        for path in paths:
            ui.path_line("safe", str(path))
        return 0
    if args.file:
        content = Path(args.file).read_text(encoding="utf-8", errors="replace")
    else:
        content = args.text or ""
    if not content:
        ui.error("provide --text or --file")
        return 2
    saved = store.save(args.name or "note.txt", content, keep_raw=args.keep_raw)
    ui.success("evidence saved (redacted)")
    ui.path_line("path", str(saved))
    return 0


def redact_cmd(path: str) -> int:
    text = Path(path).read_text(encoding="utf-8", errors="replace")
    ui.code_panel(redact_text(text), title="redacted", lexer="text")
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
    ui.markdown_panel(body, title=f"{args.platform} draft")
    ui.success(f"wrote {out}")
    return 0


def run_cmd(args: argparse.Namespace) -> int:
    target = Path(args.target_dir)
    approve = args.approve
    tool = args.tool
    host = args.host
    force = bool(getattr(args, "force", False))
    try:
        if tool == "httpx":
            result = projectdiscovery.httpx_probe(target, host, approve=approve, force=force)
        elif tool == "katana":
            result = projectdiscovery.katana_crawl(
                target, host, depth=args.depth, approve=approve, force=force
            )
        elif tool == "nuclei":
            result = projectdiscovery.nuclei_scan(
                target,
                host,
                templates=args.templates,
                rate_limit=args.rate_limit,
                concurrency=args.concurrency,
                approve=approve,
                force=force,
            )
        elif tool == "ffuf":
            if not args.wordlist:
                ui.error("--wordlist required for ffuf")
                return 2
            result = projectdiscovery.ffuf_dir(
                target, host, args.wordlist, approve=approve, force=force
            )
        elif tool == "reconftw":
            result = reconftw.run_recon(
                target, host, mode=args.mode, approve=approve, force=force
            )
        elif tool == "hexstrike":
            result = hexstrike.start_server(
                port=args.port, approve=approve, docker=bool(getattr(args, "docker", False))
            )
        elif tool == "burp":
            if not args.burp_xml:
                ui.error("--burp-xml required for burp")
                return 2
            result = burp.summarize_xml(
                target, Path(args.burp_xml), approve=approve, limit=args.limit
            )
        elif tool == "rate_probe":
            result = rate_probe.rate_probe(
                target,
                host,
                concurrency=args.concurrency,
                total=getattr(args, "total", 25),
                timeout=getattr(args, "timeout", 5.0),
                method=getattr(args, "method", "GET"),
                approve=approve,
                force=force,
            )
        else:
            ui.error(f"unknown tool: {tool}")
            return 2
    except (FileNotFoundError, PermissionError) as exc:
        ui.blocked(str(exc))
        return 1
    return 0 if (result.returncode in (None, 0) or not result.executed) else result.returncode


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="hackbot",
        description="Authorized bug bounty agent CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest="subcommand", required=False)

    init_p = sub.add_parser("target-init", help="Create targets/<name> from templates")
    init_p.add_argument("name")

    scope_p = sub.add_parser("scope-check", help="Check host/action against SCOPE.md")
    scope_p.add_argument("target_dir")
    scope_p.add_argument("--host")
    scope_p.add_argument("--action")

    sub.add_parser(
        "show-config",
        help="Print effective safety/config knobs (configs/hackbot.yaml + env)",
    )

    context_p = sub.add_parser("context", help="Print operating rules + target files")
    context_p.add_argument("target_dir")

    know_p = sub.add_parser("knowledge", help="Open study notes for a bug class")
    know_p.add_argument("task", nargs="?", default="recon")
    know_p.add_argument("--routes", action="store_true")

    pb_p = sub.add_parser("playbook", help="Print or dry-run/execute a class playbook")
    pb_p.add_argument("task", nargs="?", default="recon")
    pb_p.add_argument("--endpoint", default="")
    pb_p.add_argument("--host", default="", help="Host for --run (defaults to --endpoint)")
    pb_p.add_argument("--target-dir", default="targets/demo", help="Target folder for --run")
    pb_p.add_argument("--run", action="store_true", help="Dry-run executable steps (or --approve)")
    pb_p.add_argument("--approve", action="store_true", help="Execute playbook (asks confirmation)")
    pb_p.add_argument("--force", action="store_true", help="Operator force override for soft SCOPE gates")
    pb_p.add_argument("--max-aggression", type=int, default=None)

    pol_p = sub.add_parser("policy-import", help="Import policy text into SCOPE.md YAML")
    pol_p.add_argument("target_dir")
    pol_p.add_argument("--file", help="Policy markdown/text file")
    pol_p.add_argument("--text", help="Policy text inline")
    pol_p.add_argument("--write", action="store_true", help="Write SCOPE.md")

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
        choices=(
            "httpx",
            "katana",
            "nuclei",
            "ffuf",
            "reconftw",
            "hexstrike",
            "burp",
            "rate_probe",
        ),
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
    run_p.add_argument("--docker", action="store_true", help="hexstrike via docker compose")
    run_p.add_argument("--burp-xml")
    run_p.add_argument("--limit", type=int, default=20)
    run_p.add_argument("--force", action="store_true", help="Operator force override")
    run_p.add_argument("--total", type=int, default=25, help="rate_probe total requests")
    run_p.add_argument("--timeout", type=float, default=5.0, help="rate_probe timeout seconds")
    run_p.add_argument("--method", default="GET", help="rate_probe HTTP method")

    sub.add_parser("cmd", help="Show low-level command menu")
    ask_p = sub.add_parser("ask", help="One-shot agent prompt")
    ask_p.add_argument("prompt", nargs=argparse.REMAINDER)
    sub.add_parser("demo", help="Prepare targets/demo + dry-run smoke (proves the pitch)")

    ui_p = sub.add_parser(
        "ui",
        help="(deprecated) Browser UI — prefer `hackbot tui`",
    )
    ui_p.add_argument("--host", default="127.0.0.1", help="Bind address (default 127.0.0.1)")
    ui_p.add_argument("--port", type=int, default=8765, help="Port (default 8765)")
    ui_p.add_argument(
        "--no-browser",
        action="store_true",
        help="Do not open a browser tab",
    )
    sub.add_parser(
        "acp",
        help="Run as ACP agent for Toad/Zed (stdio JSON-RPC; stdout reserved)",
    )
    sub.add_parser(
        "tui",
        help="Fullscreen Textual TUI (hackbot brand + slash commands)",
    )

    return parser


def _dispatch(args: argparse.Namespace) -> int:
    if args.subcommand == "cmd" or args.subcommand is None:
        ui.splash()
        return 0
    # ACP owns stdout — no Rich banner.
    if args.subcommand == "acp":
        from .acp_agent import start_acp_agent

        return start_acp_agent()
    if args.subcommand == "tui":
        from .tui_app import start_tui

        return start_tui()
    ui.rule(f"hackbot {args.subcommand}")
    if args.subcommand == "target-init":
        return target_init(args.name)
    if args.subcommand == "scope-check":
        return scope_check(args.target_dir, args.host, args.action)
    if args.subcommand == "show-config":
        from .config import get_config

        cfg = get_config(reload=True)
        ui.code_panel(
            json.dumps(cfg.to_public_dict(), indent=2),
            title="effective config",
            lexer="json",
        )
        return 0
    if args.subcommand == "context":
        return context(args.target_dir)
    if args.subcommand == "knowledge":
        return knowledge_cmd(args.task, args.routes)
    if args.subcommand == "playbook":
        from .playbooks import playbook_for, playbook_markdown
        from .tools import execute_tool

        pb = playbook_for(args.task)
        if not args.run and not args.approve:
            ui.markdown_panel(
                playbook_markdown(pb, endpoint=args.endpoint),
                title=f"playbook:{pb.class_name}",
            )
            return 0
        host = args.host or args.endpoint
        if not host:
            ui.error("--host or --endpoint required with --run")
            return 2

        def _approve(prompt: str) -> bool:
            from rich.prompt import Prompt

            from .operator_gate import operator_prompt_active

            with operator_prompt_active():
                ui.console.print()
                ui.permission(prompt)
                while True:
                    raw = Prompt.ask(
                        "[bold yellow]Allow this action?[/] [dim]y/n[/]",
                        default="n",
                    )
                    ans = (raw or "").strip().lower()
                    if ans in {"y", "yes", "approve", "--approve", "/approve"}:
                        return True
                    if ans in {"n", "no", "deny", ""}:
                        return False
                    ui.warn("enter y or n (also: approve / deny)")

        out = execute_tool(
            "run_playbook",
            {
                "target_dir": args.target_dir,
                "task": args.task,
                "host": host,
                "endpoint": args.endpoint or host,
                "approve": bool(args.approve),
                "force": bool(args.force),
                "max_aggression": args.max_aggression,
            },
            approve_fn=_approve if args.approve else None,
        )
        ui.code_panel(out, title="run_playbook", lexer="json")
        return 0
    if args.subcommand == "policy-import":
        from .policy_import import import_policy_to_target

        if args.file:
            policy_text = Path(args.file).read_text(encoding="utf-8", errors="replace")
        elif args.text:
            policy_text = args.text
        else:
            ui.error("pass --file or --text")
            return 2
        meta, rendered, path = import_policy_to_target(
            args.target_dir, policy_text, write=bool(args.write)
        )
        ui.kv("in_scope", ", ".join(meta.get("in_scope") or []) or "(none)")
        ui.kv("out_of_scope", ", ".join(meta.get("out_of_scope") or []) or "(none)")
        if args.write:
            ui.success(f"wrote {path}")
        else:
            ui.info("dry preview (pass --write to save SCOPE.md)")
            ui.markdown_panel(rendered[:4000], title="SCOPE.md preview")
        return 0
    if args.subcommand == "plan":
        return plan_cmd(args)
    if args.subcommand == "evidence":
        return evidence_cmd(args)
    if args.subcommand == "redact":
        return redact_cmd(args.path)
    if args.subcommand == "report":
        return report_cmd(args)
    if args.subcommand == "run":
        return run_cmd(args)
    if args.subcommand == "ask":
        prompt = " ".join(args.prompt).strip()
        if not prompt:
            ui.error("usage: hackbot ask <prompt>")
            return 2
        return start_repl(one_shot=prompt)
    if args.subcommand == "demo":
        from .demo import run_demo_smoke

        out = run_demo_smoke()
        ui.code_panel(json.dumps(out, indent=2), title="demo smoke", lexer="json")
        return 0 if out.get("ok") else 1
    if args.subcommand == "ui":
        ui.warn("deprecated: prefer `python -m hackbot tui`")
        from .web_server import start_web_ui

        return start_web_ui(
            host=args.host,
            port=args.port,
            open_browser=not args.no_browser,
        )
    return 2


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if callable(reconfigure):
            try:
                reconfigure(errors="replace")
            except Exception:
                pass

    raw = list(sys.argv[1:] if argv is None else argv)

    # Default: interactive agent REPL
    if not raw:
        return start_repl()

    # Natural language one-shot if first token isn't a known subcommand/flag
    head = raw[0]
    if head not in SUBCOMMANDS and not head.startswith("-"):
        return start_repl(one_shot=" ".join(raw))

    parser = build_parser()
    args = parser.parse_args(raw)
    return _dispatch(args)


if __name__ == "__main__":
    raise SystemExit(main())
