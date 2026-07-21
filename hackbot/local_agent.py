"""Offline agent: read the prompt, decide by rules, run tools. No LLM needed.

This is the "brain-lite" path. It cannot free-form reason, but it can:
  - read a plain-language task
  - pull out the host / target folder / bug class / tool / platform
  - build an ordered plan of concrete tool calls
  - execute each one (dry-run first, active traffic still needs --approve)

Everything routes through the same tools the LLM agent uses, so the safety
rails (scope check, redaction, approve gate) are identical.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Callable

from . import ui
from .knowledge import classify
from .tools import TARGETS, execute_tool

ApproveFn = Callable[[str], bool]

TOOL_NAMES = ("httpx", "katana", "nuclei", "ffuf", "reconftw", "hexstrike", "burp")

PLATFORM_ALIASES = {
    "bugcrowd": "bugcrowd",
    "hackerone": "hackerone",
    "h1": "hackerone",
    "intigriti": "intigriti",
}

APPROVE_WORDS = (
    "--approve",
    "approve",
    "for real",
    "actually run",
    "execute it",
    "send traffic",
    "real traffic",
)

# Extract host (+ optional path) or full URL. Requires a dot + TLD so
# "targets/demo" and bare words never match.
_TARGET_RE = re.compile(
    r"(?:https?://)?"
    r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}"
    r"(?::\d+)?"
    r"(?:/[^\s'\"]*)?",
    re.IGNORECASE,
)

# Tokens that look like a domain but are really filenames.
_FILE_SUFFIXES = (".md", ".txt", ".py", ".json", ".xml", ".har", ".yaml", ".yml", ".png", ".jpg")

# bug class -> (hypothesis, action label, concrete command template with {t})
_CLASS_PLAYBOOK: dict[str, tuple[str, str, str]] = {
    "idor": (
        "I can read or change another user's object by swapping an identifier.",
        "authenticated request with a swapped object id (idor/bola)",
        'curl -s -H "Authorization: Bearer <userA>" "{t}"\n'
        "# repeat with <userB> token, diff the responses (200 + other user data = win)",
    ),
    "bola": (
        "The API returns another tenant's object when I change the id.",
        "authenticated bola test with swapped id",
        'curl -s -H "Authorization: Bearer <userA>" "{t}"\n# then <userB>, compare',
    ),
    "bac": (
        "A privileged action is reachable by a low-priv user.",
        "call the privileged endpoint as a low-priv account (bac)",
        'curl -s -H "Authorization: Bearer <lowpriv>" "{t}"  # expect 403; 200 = broken access control',
    ),
    "authz": (
        "Authorization is enforced client-side only.",
        "replay the request without / with a weaker role (authz)",
        'curl -s "{t}"  # strip auth, downgrade role, compare',
    ),
    "ssrf": (
        "The server fetches a user-supplied URL and I can aim it inward.",
        "point a fetch parameter at an internal address (ssrf)",
        'curl -s "{t}" --data-urlencode "url=http://169.254.169.254/latest/meta-data/"',
    ),
    "sqli": (
        "A parameter reaches a SQL query unsanitized.",
        "boolean/time-based payloads with a negative control (sqli)",
        "# add  ' OR 1=1--  and  ' OR sleep(5)--  to params, diff timing/response vs baseline",
    ),
    "injection": (
        "User input reaches an interpreter (SQL/OS/template) unsanitized.",
        "inject marker payloads and diff responses (injection)",
        "# send benign marker, then payloads; compare responses to a clean baseline",
    ),
    "ssti": (
        "A template engine evaluates my input.",
        "inject template math and check for evaluation (ssti)",
        "# try {{7*7}} / ${7*7} in reflected fields; 49 in output = ssti",
    ),
    "xss": (
        "Input is reflected or stored without proper encoding.",
        "inject a unique marker and check DOM/HTML sinks (xss)",
        '# inject hb%3Cscript%3E marker into params, grep response + DOM for unencoded reflection',
    ),
    "race": (
        "A check and an update are not atomic.",
        "fire parallel requests to exploit the window (race condition)",
        "# send N parallel POSTs to {t}, compare outcomes (double-spend / limit bypass)",
    ),
    "oauth": (
        "The OAuth flow trusts an attacker-controlled redirect_uri or state.",
        "tamper redirect_uri / state and observe token leakage (oauth)",
        "# swap redirect_uri to attacker host, drop state, follow the code",
    ),
    "jwt": (
        "The JWT signature or claims can be tampered.",
        "test alg=none / weak key / claim swap (jwt)",
        "# resign token with alg=none or a guessed key; swap sub/role; replay to {t}",
    ),
    "session": (
        "Session handling allows fixation or weak invalidation.",
        "test fixation, logout invalidation, cookie flags (session)",
        "# check Secure/HttpOnly/SameSite, reuse token post-logout on {t}",
    ),
    "graphql": (
        "GraphQL exposes fields/mutations without proper authz.",
        "introspect then query cross-tenant objects (graphql)",
        "# POST introspection query to {t}, then request other tenants' node ids",
    ),
    "api": (
        "An API endpoint leaks or mutates data without proper authz.",
        "map the API and test object/function-level authz (owasp api top 10)",
        "# enumerate endpoints, swap ids, test methods (GET/PUT/DELETE) on {t}",
    ),
    "takeover": (
        "A dangling DNS record points to an unclaimed service.",
        "resolve CNAMEs and fingerprint dangling providers (subdomain takeover)",
        "# check CNAME of {t} against fingerprints (NoSuchBucket, etc.)",
    ),
    "recon": (
        "There are unlinked hosts/endpoints inside the authorized scope.",
        "passive recon + content discovery (httpx/katana)",
        "httpx -silent -u {t}\n# then: katana -silent -u {t} -d 2",
    ),
    "discovery": (
        "There is hidden content reachable under an in-scope host.",
        "content discovery with a sane wordlist (discovery)",
        "# ffuf -u {t}/FUZZ -w <wordlist> -mc 200,204,301,302,401,403",
    ),
    "mobile": (
        "The mobile app's backend API trusts client-side controls.",
        "pull the APK's API calls and test them directly (mobile/api)",
        "# extract endpoints from the app, replay to {t} with tampered params",
    ),
}


@dataclass
class Action:
    thought: str
    tool: str
    args: dict[str, Any]


@dataclass
class Interpretation:
    target_dir: str
    full_target: str | None
    host: str | None
    classes: list[str]
    tool: str | None
    platform: str | None
    approve: bool
    intents: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# parsing
# ---------------------------------------------------------------------------

def _known_targets() -> list[str]:
    if not TARGETS.exists():
        return []
    return sorted(
        p.name for p in TARGETS.iterdir() if p.is_dir() and p.name != "__pycache__"
    )


def _detect_target_dir(text: str) -> str:
    low = text.lower()
    m = re.search(r"targets[/\\]([a-z0-9._-]+)", low)
    if m:
        return f"targets/{m.group(1)}"
    known = _known_targets()
    for name in known:
        if re.search(rf"(?<![a-z0-9]){re.escape(name)}(?![a-z0-9])", low):
            return f"targets/{name}"
    if "demo" in known:
        return "targets/demo"
    if known:
        return f"targets/{known[0]}"
    return "targets/demo"


def _detect_targets(text: str) -> tuple[str | None, str | None]:
    """Return (full_target_with_path, host)."""
    for raw in _TARGET_RE.findall(text):
        token = raw.rstrip(".,);:'\"")
        host_part = token.split("/")[0].split(":")[0].lower()
        if host_part.endswith(_FILE_SUFFIXES):
            continue
        if host_part.startswith("targets"):
            continue
        host = re.sub(r"^https?://", "", host_part)
        return token, host
    return None, None


def _detect_tool(text: str) -> str | None:
    low = text.lower()
    for name in TOOL_NAMES:
        if name in low:
            return name
    return None


def _detect_platform(text: str) -> str | None:
    low = text.lower()
    for alias, canonical in PLATFORM_ALIASES.items():
        if re.search(rf"(?<![a-z]){re.escape(alias)}(?![a-z])", low):
            return canonical
    return None


def _wants(text: str, *words: str) -> bool:
    low = text.lower()
    return any(w in low for w in words)


def interpret(text: str) -> Interpretation:
    full_target, host = _detect_targets(text)
    tool = _detect_tool(text)
    platform = _detect_platform(text)
    classes = classify(text)
    approve = _wants(text, *APPROVE_WORDS)

    intents: list[str] = []
    if _wants(text, "list target", "which target", "what target", "show target"):
        intents.append("list")
    if _wants(text, "scope", "in-scope", "in scope", "allowed", "is it ok"):
        intents.append("scope")
    if _wants(
        text, "note", "notes", "study", "knowledge", "learn", "playbook", "read up", "how do i test", "how to test"
    ):
        intents.append("knowledge")
    if _wants(text, "plan", "hypothesis", "hunt", "test for", "attack", "approach", "strategy"):
        intents.append("plan")
    if tool or _wants(text, "run", "dry-run", "dry run", "scan", "probe", "crawl", "fuzz", "recon"):
        intents.append("run")
    if platform or _wants(text, "report", "write-up", "writeup", "write up", "submit"):
        intents.append("report")
    if _wants(text, "redact"):
        intents.append("redact")
    if _wants(text, "read ", "show me", "open the", "context"):
        intents.append("read")

    return Interpretation(
        target_dir=_detect_target_dir(text),
        full_target=full_target,
        host=host,
        classes=classes,
        tool=tool,
        platform=platform,
        approve=approve,
        intents=intents,
    )


# ---------------------------------------------------------------------------
# planning: interpretation -> ordered tool calls
# ---------------------------------------------------------------------------

def _playbook_for(classes: list[str]) -> tuple[str, str, str, str]:
    """Return (class_key, hypothesis, action, command_template)."""
    for cls in classes:
        if cls in _CLASS_PLAYBOOK:
            hyp, act, cmd = _CLASS_PLAYBOOK[cls]
            return cls, hyp, act, cmd
    hyp, act, cmd = _CLASS_PLAYBOOK["recon"]
    return "recon", hyp, act, cmd


def build_plan(text: str, interp: Interpretation) -> list[Action]:
    plan: list[Action] = []
    intents = interp.intents
    host = interp.host
    target = interp.full_target or host or ""

    if "list" in intents:
        plan.append(Action("List the target folders I know about.", "list_targets", {}))

    if "knowledge" in intents:
        plan.append(
            Action(
                f"Pull the mandatory study notes for this task (class={','.join(interp.classes)}).",
                "open_knowledge",
                {"task": text, "max_chars": 3000},
            )
        )

    # Scope check whenever we have a host, or the user explicitly asked.
    if host and ("scope" in intents or "plan" in intents or "run" in intents):
        action_label = interp.tool or (_playbook_for(interp.classes)[2])
        plan.append(
            Action(
                f"Confirm {host} is in scope for {interp.target_dir} before anything active.",
                "scope_check",
                {"target_dir": interp.target_dir, "host": host, "action": action_label},
            )
        )
    elif "scope" in intents and not host:
        # asked about scope but gave no host -> still show the scope file
        plan.append(
            Action(
                "No host given, so read the SCOPE.md so we can see what's allowed.",
                "read_file",
                {"path": f"{interp.target_dir}/SCOPE.md", "max_chars": 4000},
            )
        )

    if "plan" in intents:
        cls, hyp, act, cmd = _playbook_for(interp.classes)
        t = target or "<in-scope host>"
        plan.append(
            Action(
                f"Draft a falsifiable hunt step for {cls}.",
                "make_plan",
                {
                    "target_dir": interp.target_dir,
                    "hypothesis": hyp,
                    "target": t,
                    "action": act,
                    "command": cmd.format(t=t),
                },
            )
        )

    if "run" in intents:
        tool = interp.tool or "httpx"
        if not host:
            plan.append(
                Action(
                    f"You asked to run {tool} but gave no in-scope host, so I'll stop and ask for one.",
                    "_note",
                    {"message": f"give me a host, e.g. 'dry-run {tool} on example.com for {interp.target_dir}'"},
                )
            )
        else:
            run_args: dict[str, Any] = {
                "target_dir": interp.target_dir,
                "tool": tool,
                "host": host,
                "approve": interp.approve,
            }
            if tool == "ffuf":
                run_args["wordlist"] = "<wordlist>"
            mode = "EXECUTE (active traffic)" if interp.approve else "dry-run (print only)"
            plan.append(
                Action(f"{mode}: {tool} against {host}.", "run_tool", run_args)
            )

    if "report" in intents:
        platform = interp.platform or "bugcrowd"
        cls, hyp, _, _ = _playbook_for(interp.classes)
        plan.append(
            Action(
                f"Write a {platform} report draft skeleton for {cls}.",
                "write_report_draft",
                {
                    "target_dir": interp.target_dir,
                    "platform": platform,
                    "title": f"{cls.upper()} on {host or target or 'target'}",
                    "target": target or host or "TBD",
                    "steps": "1. ...\n2. ...\n3. ...",
                    "impact": "TBD - fill from confirmed evidence",
                },
            )
        )

    if "read" in intents and not any(a.tool == "read_file" for a in plan):
        # try to read a specific file the user named, else SCOPE
        m = re.search(r"([a-z0-9_./\\-]+\.(?:md|txt|json|xml|yaml|yml))", text, re.IGNORECASE)
        path = m.group(1) if m else f"{interp.target_dir}/SCOPE.md"
        plan.append(Action(f"Read {path}.", "read_file", {"path": path, "max_chars": 4000}))

    # Nothing matched: give a useful default based on what we could extract.
    if not plan:
        if host:
            plan.append(
                Action(
                    f"I'll at least verify {host} against {interp.target_dir}'s scope.",
                    "scope_check",
                    {"target_dir": interp.target_dir, "host": host},
                )
            )
        else:
            plan.append(Action("Show the targets I can work with.", "list_targets", {}))

    return plan


# ---------------------------------------------------------------------------
# execution + rendering
# ---------------------------------------------------------------------------

def _render_result(tool: str, result_json: str) -> None:
    try:
        data = json.loads(result_json)
    except json.JSONDecodeError:
        ui.code_panel(result_json, title="result", lexer="text")
        return

    if isinstance(data, dict) and data.get("ok") is False:
        ui.error(data.get("error", "tool error"))
        return

    if tool == "scope_check":
        ui.scope_result(data.get("host", "?"), data.get("status", "?"))
        if "aggression" in data:
            ui.aggression_result(int(data["aggression"]), data.get("policy_quote", ""))
        return

    if tool == "open_knowledge":
        preview = data.get("notes", "")
        ui.kv("class", data.get("class", "?"))
        ui.markdown_panel(preview[:2500] or "(no notes)", title="knowledge")
        return

    if tool == "make_plan":
        ui.markdown_panel(data.get("plan", ""), title="hunt step")
        if not data.get("in_scope", False):
            ui.warn("host NOT confirmed in SCOPE.md - this plan is inference, no active traffic yet")
        return

    if tool == "run_tool":
        # The runner (run_command) already printed the command panel, the
        # dry-run banner, and any stdout/exit code. Nothing to re-render.
        return

    if tool in ("write_report_draft", "save_evidence"):
        if data.get("path"):
            ui.success("wrote file")
            ui.path_line("path", data["path"])
        return

    if tool == "read_file":
        if data.get("ok"):
            ui.file_panel(data.get("path", "file"), (data.get("text") or "")[:4000])
        else:
            ui.warn(f"missing: {data.get('path')}")
        return

    if tool == "list_targets":
        names = data.get("targets", [])
        ui.kv("targets", ", ".join(names) or "(none - run: hackbot cmd target-init demo)")
        return

    ui.code_panel(json.dumps(data, indent=2), title="result", lexer="json")


def run_local_agent(
    user_prompt: str,
    *,
    approve_fn: ApproveFn | None = None,
) -> None:
    """Read the prompt, show the plan, execute each step. No LLM."""
    from .intent import is_chat_prompt

    if is_chat_prompt(user_prompt):
        ui.markdown_panel(
            "Hey. Offline brain here (no model). I can still run scope checks and "
            "dry-run tools if you give me a host or target folder.\n\n"
            "For free-form chat, switch with `/provider` (or `/codex`).",
            title="hackbot (offline)",
        )
        return

    interp = interpret(user_prompt)
    plan = build_plan(user_prompt, interp)

    # Show the "thinking": what I understood + the ordered plan.
    understood = [
        f"- target: `{interp.target_dir}`",
        f"- host: `{interp.host or '(none found)'}`",
        f"- bug class: `{','.join(interp.classes)}`",
    ]
    if interp.tool:
        understood.append(f"- tool: `{interp.tool}`")
    if interp.platform:
        understood.append(f"- platform: `{interp.platform}`")
    understood.append(f"- mode: `{'approve/active' if interp.approve else 'dry-run/safe'}`")
    steps = "\n".join(f"{i}. {a.thought}" for i, a in enumerate(plan, 1))
    ui.markdown_panel(
        "**what I understood**\n" + "\n".join(understood) + "\n\n**plan**\n" + steps,
        title="thinking (offline)",
    )

    for i, action in enumerate(plan, 1):
        ui.rule(f"step {i}/{len(plan)}")
        ui.info(action.thought)
        if action.tool == "_note":
            ui.warn(action.args.get("message", ""))
            continue
        ui.kv("tool", action.tool)
        if action.args:
            ui.code_panel(json.dumps(action.args, indent=2), title="args", lexer="json")
        result = execute_tool(action.tool, action.args, approve_fn=approve_fn)
        _render_result(action.tool, result)

    ui.console.print()
    ui.success("done (offline mode). set an API key for free-form reasoning.")
