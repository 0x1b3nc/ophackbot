"""Tools the agent can call. All active traffic stays behind scope + approve."""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any, Callable

from .evidence import EvidenceStore
from .knowledge import open_notes, required_bundle
from .planner import plan_step
from .policy_guard import ScopePolicy, host_from_target, policy_quote_for
from .redaction import redact_text
from .reporting import render_bugcrowd, render_hackerone, render_intigriti
from .runners import burp, hexstrike, projectdiscovery, reconftw

ROOT = Path(__file__).resolve().parents[1]
TARGETS = ROOT / "targets"

ApproveFn = Callable[[str], bool]


TOOL_SPECS: list[dict[str, Any]] = [
    {
        "name": "list_targets",
        "description": "List target folders under targets/.",
        "parameters": {"type": "object", "properties": {}, "additionalProperties": False},
    },
    {
        "name": "read_file",
        "description": "Read a workspace file (SCOPE, PLAN, notes, docs). Path relative to kit root or absolute under the kit.",
        "parameters": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Relative path e.g. targets/demo/SCOPE.md"},
                "max_chars": {"type": "integer", "default": 8000},
            },
            "required": ["path"],
            "additionalProperties": False,
        },
    },
    {
        "name": "scope_check",
        "description": "Check if a host is in SCOPE.md and classify an optional action's aggression level.",
        "parameters": {
            "type": "object",
            "properties": {
                "target_dir": {"type": "string", "description": "e.g. targets/demo"},
                "host": {"type": "string"},
                "action": {"type": "string", "description": "optional action text for aggression level"},
            },
            "required": ["target_dir", "host"],
            "additionalProperties": False,
        },
    },
    {
        "name": "open_knowledge",
        "description": "Open mandatory study notes for a bug class / task description.",
        "parameters": {
            "type": "object",
            "properties": {
                "task": {"type": "string"},
                "max_chars": {"type": "integer", "default": 4000},
            },
            "required": ["task"],
            "additionalProperties": False,
        },
    },
    {
        "name": "make_plan",
        "description": "Build a falsifiable hunt step bound to scope.",
        "parameters": {
            "type": "object",
            "properties": {
                "target_dir": {"type": "string"},
                "hypothesis": {"type": "string"},
                "target": {"type": "string", "description": "Host or URL"},
                "action": {"type": "string"},
                "command": {"type": "string"},
                "write": {"type": "boolean", "default": False},
            },
            "required": ["target_dir", "hypothesis", "target", "action", "command"],
            "additionalProperties": False,
        },
    },
    {
        "name": "save_evidence",
        "description": "Save redacted evidence under targets/<name>/evidence/safe/.",
        "parameters": {
            "type": "object",
            "properties": {
                "target_dir": {"type": "string"},
                "name": {"type": "string"},
                "text": {"type": "string"},
            },
            "required": ["target_dir", "name", "text"],
            "additionalProperties": False,
        },
    },
    {
        "name": "redact",
        "description": "Redact secrets from text and return the cleaned version.",
        "parameters": {
            "type": "object",
            "properties": {"text": {"type": "string"}},
            "required": ["text"],
            "additionalProperties": False,
        },
    },
    {
        "name": "write_report_draft",
        "description": "Write a platform report draft (bugcrowd|hackerone|intigriti).",
        "parameters": {
            "type": "object",
            "properties": {
                "target_dir": {"type": "string"},
                "platform": {"type": "string", "enum": ["bugcrowd", "hackerone", "intigriti"]},
                "title": {"type": "string"},
                "target": {"type": "string"},
                "preconditions": {"type": "string"},
                "steps": {"type": "string"},
                "impact": {"type": "string"},
                "evidence": {"type": "string"},
                "vrt": {"type": "string"},
                "weakness": {"type": "string"},
            },
            "required": ["target_dir", "platform", "title", "target"],
            "additionalProperties": False,
        },
    },
    {
        "name": "write_file",
        "description": (
            "Create or overwrite a file with the given content. Requires operator approval "
            "before writing. Path is relative to the kit root unless absolute."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "path": {"type": "string"},
                "content": {"type": "string"},
            },
            "required": ["path", "content"],
            "additionalProperties": False,
        },
    },
    {
        "name": "edit_file",
        "description": (
            "Edit a file by replacing an exact string with another. Requires operator approval. "
            "Set replace_all=true to change every occurrence (default: first only)."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "path": {"type": "string"},
                "old_string": {"type": "string"},
                "new_string": {"type": "string"},
                "replace_all": {"type": "boolean", "default": False},
            },
            "required": ["path", "old_string", "new_string"],
            "additionalProperties": False,
        },
    },
    {
        "name": "append_file",
        "description": "Append text to a file (creates it if missing). Requires operator approval.",
        "parameters": {
            "type": "object",
            "properties": {
                "path": {"type": "string"},
                "content": {"type": "string"},
            },
            "required": ["path", "content"],
            "additionalProperties": False,
        },
    },
    {
        "name": "delete_path",
        "description": "Delete a file or directory (recursive for dirs). Requires operator approval.",
        "parameters": {
            "type": "object",
            "properties": {"path": {"type": "string"}},
            "required": ["path"],
            "additionalProperties": False,
        },
    },
    {
        "name": "make_dir",
        "description": "Create a directory (and parents). Requires operator approval.",
        "parameters": {
            "type": "object",
            "properties": {"path": {"type": "string"}},
            "required": ["path"],
            "additionalProperties": False,
        },
    },
    {
        "name": "move_path",
        "description": "Move or rename a file/directory. Requires operator approval.",
        "parameters": {
            "type": "object",
            "properties": {
                "src": {"type": "string"},
                "dst": {"type": "string"},
            },
            "required": ["src", "dst"],
            "additionalProperties": False,
        },
    },
    {
        "name": "run_tool",
        "description": (
            "Run or dry-run an external tool (httpx, katana, nuclei, ffuf, reconftw, hexstrike, burp). "
            "Default approve=false (dry-run only). approve=true sends real traffic and requires operator confirmation."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "target_dir": {"type": "string"},
                "tool": {
                    "type": "string",
                    "enum": ["httpx", "katana", "nuclei", "ffuf", "reconftw", "hexstrike", "burp"],
                },
                "host": {"type": "string"},
                "approve": {"type": "boolean", "default": False},
                "wordlist": {"type": "string"},
                "burp_xml": {"type": "string"},
            },
            "required": ["target_dir", "tool", "host"],
            "additionalProperties": False,
        },
    },
]


def _safe_path(path: str) -> Path:
    p = Path(path)
    if not p.is_absolute():
        p = ROOT / p
    p = p.resolve()
    root = ROOT.resolve()
    if root not in p.parents and p != root:
        raise PermissionError(f"path outside kit: {path}")
    return p


def _resolve_path(path: str) -> Path:
    """Resolve for file mutations. Relative -> kit root; absolute allowed.

    We do NOT hard-block paths here: every mutating action is gated by the
    operator approval instead. The approval prompt always shows the absolute
    path so you see exactly what's about to change.
    """
    p = Path(path)
    if not p.is_absolute():
        p = ROOT / p
    return p.resolve()


def _preview(text: str, limit: int = 500) -> str:
    text = text.replace("\r\n", "\n")
    if len(text) <= limit:
        return text
    return text[:limit] + f"\n... (+{len(text) - limit} more chars)"


def _require_approval(approve_fn: ApproveFn | None, description: str) -> str | None:
    """Ask the operator. Return a refusal JSON string if denied, else None."""
    if approve_fn is None:
        return json.dumps(
            {"ok": False, "error": "action needs approval but no approver is attached; denied."}
        )
    if not approve_fn(description):
        return json.dumps({"ok": False, "error": "operator denied this action."})
    return None


def execute_tool(
    name: str,
    args: dict[str, Any],
    *,
    approve_fn: ApproveFn | None = None,
) -> str:
    try:
        return _execute(name, args, approve_fn=approve_fn)
    except Exception as exc:  # tool errors become model-visible strings
        return json.dumps({"ok": False, "error": f"{type(exc).__name__}: {exc}"})


def _execute(name: str, args: dict[str, Any], *, approve_fn: ApproveFn | None) -> str:
    if name == "list_targets":
        if not TARGETS.exists():
            return json.dumps({"targets": []})
        names = sorted(p.name for p in TARGETS.iterdir() if p.is_dir() and p.name != "__pycache__")
        return json.dumps({"targets": names})

    if name == "read_file":
        path = _safe_path(args["path"])
        if not path.exists():
            return json.dumps({"ok": False, "error": "missing", "path": str(path)})
        max_chars = int(args.get("max_chars") or 8000)
        text = path.read_text(encoding="utf-8", errors="replace")
        return json.dumps(
            {
                "ok": True,
                "path": str(path),
                "text": text[:max_chars],
                "truncated": len(text) > max_chars,
            }
        )

    if name == "scope_check":
        target = Path(args["target_dir"])
        if not target.is_absolute():
            target = ROOT / target
        policy = ScopePolicy.load(target)
        host = host_from_target(args["host"])
        if policy.is_explicitly_out_of_scope(host):
            status = "OUT_OF_SCOPE"
        elif policy.contains_host(host):
            status = "IN_SCOPE"
        else:
            status = "NOT_CONFIRMED"
        out: dict[str, Any] = {"host": host, "status": status}
        action = args.get("action")
        if action:
            level = policy.classify_aggression(action)
            out["aggression"] = level
            out["policy_quote"] = policy_quote_for(policy, level)
        return json.dumps(out)

    if name == "open_knowledge":
        task = args["task"]
        bundle = required_bundle(task)
        return json.dumps(
            {
                "class": bundle.class_name,
                "notes": open_notes(task, max_chars=int(args.get("max_chars") or 4000)),
            }
        )

    if name == "make_plan":
        target = Path(args["target_dir"])
        if not target.is_absolute():
            target = ROOT / target
        step = plan_step(
            target,
            hypothesis=args["hypothesis"],
            target=args["target"],
            action=args["action"],
            command=args["command"],
        )
        md = step.to_markdown()
        if args.get("write"):
            plan_path = target / "PLAN.md"
            refusal = _require_approval(approve_fn, f"WRITE plan to\n  {plan_path}")
            if refusal:
                return refusal
            plan_path.write_text(md, encoding="utf-8")
        return json.dumps({"in_scope": step.in_scope, "aggression": step.aggression, "plan": md})

    if name == "save_evidence":
        target = Path(args["target_dir"])
        if not target.is_absolute():
            target = ROOT / target
        refusal = _require_approval(
            approve_fn, f"SAVE evidence '{args['name']}' under\n  {target / 'evidence' / 'safe'}"
        )
        if refusal:
            return refusal
        saved = EvidenceStore(target).save(args["name"], args["text"])
        return json.dumps({"ok": True, "path": str(saved)})

    if name == "redact":
        return json.dumps({"text": redact_text(args["text"])})

    if name == "write_report_draft":
        target = Path(args["target_dir"])
        if not target.is_absolute():
            target = ROOT / target
        platform = args["platform"]
        common = dict(
            title=args["title"],
            preconditions=args.get("preconditions") or "Two test accounts in-scope",
            steps=args.get("steps") or "1. ...",
            impact=args.get("impact") or "TBD",
            evidence=args.get("evidence") or "See evidence/safe/",
        )
        if platform == "bugcrowd":
            body = render_bugcrowd(vrt=args.get("vrt") or "TBD", target=args["target"], **common)
        elif platform == "hackerone":
            body = render_hackerone(
                weakness=args.get("weakness") or "TBD",
                target=args["target"],
                **common,
            )
        else:
            body = render_intigriti(
                endpoint=args["target"],
                vulnerability_type=args.get("weakness") or "TBD",
                **common,
            )
        out = target / "reports" / f"{platform}_draft.md"
        refusal = _require_approval(approve_fn, f"WRITE {platform} report draft to\n  {out}")
        if refusal:
            return refusal
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(body, encoding="utf-8")
        return json.dumps({"ok": True, "path": str(out)})

    if name == "write_file":
        path = _resolve_path(args["path"])
        content = args["content"]
        existed = path.exists()
        verb = "OVERWRITE" if existed else "CREATE"
        desc = (
            f"{verb} file\n  {path}\n  ({len(content)} bytes)\n"
            f"--- preview ---\n{_preview(content)}"
        )
        refusal = _require_approval(approve_fn, desc)
        if refusal:
            return refusal
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        return json.dumps({"ok": True, "path": str(path), "bytes": len(content), "created": not existed})

    if name == "append_file":
        path = _resolve_path(args["path"])
        content = args["content"]
        desc = f"APPEND to file\n  {path}\n--- adding ---\n{_preview(content)}"
        refusal = _require_approval(approve_fn, desc)
        if refusal:
            return refusal
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as handle:
            handle.write(content)
        return json.dumps({"ok": True, "path": str(path), "appended": len(content)})

    if name == "edit_file":
        path = _resolve_path(args["path"])
        if not path.exists():
            return json.dumps({"ok": False, "error": f"missing file: {path}"})
        text = path.read_text(encoding="utf-8", errors="replace")
        old = args["old_string"]
        new = args["new_string"]
        count = text.count(old)
        if count == 0:
            return json.dumps({"ok": False, "error": "old_string not found"})
        replace_all = bool(args.get("replace_all"))
        if count > 1 and not replace_all:
            return json.dumps(
                {"ok": False, "error": f"old_string found {count}x; pass replace_all=true or add context"}
            )
        desc = (
            f"EDIT file\n  {path}\n"
            f"- remove:\n{_preview(old, 300)}\n"
            f"+ insert:\n{_preview(new, 300)}"
            + (f"\n(applies to {count} occurrences)" if replace_all else "")
        )
        refusal = _require_approval(approve_fn, desc)
        if refusal:
            return refusal
        updated = text.replace(old, new) if replace_all else text.replace(old, new, 1)
        path.write_text(updated, encoding="utf-8")
        return json.dumps({"ok": True, "path": str(path), "replacements": count if replace_all else 1})

    if name == "delete_path":
        path = _resolve_path(args["path"])
        if not path.exists():
            return json.dumps({"ok": False, "error": f"nothing at {path}"})
        kind = "directory (recursive)" if path.is_dir() else "file"
        desc = f"DELETE {kind}\n  {path}"
        refusal = _require_approval(approve_fn, desc)
        if refusal:
            return refusal
        if path.is_dir():
            shutil.rmtree(path)
        else:
            path.unlink()
        return json.dumps({"ok": True, "deleted": str(path)})

    if name == "make_dir":
        path = _resolve_path(args["path"])
        desc = f"CREATE directory\n  {path}"
        refusal = _require_approval(approve_fn, desc)
        if refusal:
            return refusal
        path.mkdir(parents=True, exist_ok=True)
        return json.dumps({"ok": True, "path": str(path)})

    if name == "move_path":
        src = _resolve_path(args["src"])
        dst = _resolve_path(args["dst"])
        if not src.exists():
            return json.dumps({"ok": False, "error": f"missing source: {src}"})
        desc = f"MOVE / RENAME\n  {src}\n  -> {dst}"
        refusal = _require_approval(approve_fn, desc)
        if refusal:
            return refusal
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(src), str(dst))
        return json.dumps({"ok": True, "from": str(src), "to": str(dst)})

    if name == "run_tool":
        target = Path(args["target_dir"])
        if not target.is_absolute():
            target = ROOT / target
        tool = args["tool"]
        host = args["host"]
        approve = bool(args.get("approve"))
        if approve:
            prompt = f"Approve ACTIVE traffic?\n  tool={tool}\n  host={host}\n  target={target}"
            if approve_fn is None or not approve_fn(prompt):
                return json.dumps(
                    {
                        "ok": False,
                        "error": "operator refused approve (or dry-run only). Re-run with approve=false to preview.",
                    }
                )
        if tool == "httpx":
            result = projectdiscovery.httpx_probe(target, host, approve=approve)
        elif tool == "katana":
            result = projectdiscovery.katana_crawl(target, host, approve=approve)
        elif tool == "nuclei":
            result = projectdiscovery.nuclei_scan(target, host, approve=approve)
        elif tool == "ffuf":
            wordlist = args.get("wordlist")
            if not wordlist:
                return json.dumps({"ok": False, "error": "wordlist required for ffuf"})
            result = projectdiscovery.ffuf_dir(target, host, wordlist, approve=approve)
        elif tool == "reconftw":
            result = reconftw.run_recon(target, host, approve=approve)
        elif tool == "hexstrike":
            result = hexstrike.start_server(approve=approve)
        elif tool == "burp":
            xml = args.get("burp_xml")
            if not xml:
                return json.dumps({"ok": False, "error": "burp_xml required"})
            result = burp.summarize_xml(target, Path(xml), approve=approve)
        else:
            return json.dumps({"ok": False, "error": f"unknown tool {tool}"})
        return json.dumps(
            {
                "ok": True,
                "executed": result.executed,
                "message": result.message,
                "returncode": result.returncode,
                "command": result.command,
                "stdout": (result.stdout or "")[:4000],
                "stderr": (result.stderr or "")[:2000],
            }
        )

    return json.dumps({"ok": False, "error": f"unknown tool {name}"})
