"""Tools the agent can call. All active traffic stays behind scope + approve."""

from __future__ import annotations

import json
import os
import shutil
from pathlib import Path
from typing import Any, Callable

from . import ui
from .audit import log_decision
from .campaign import extract_login_path, report_markdown, resolve_modules
from .diffing import assert_idor_diff
from .evidence import EvidenceStore
from .findings import (
    Finding,
    append_finding,
    next_finding_id,
    parse_finding_by_id,
    parse_latest_finding,
    report_fields_from_finding,
    update_resume_next_step,
)
from .boolparse import parse_bool
from .force import is_forced
from .identity import ensure_example, load_identity, save_session
from .yolo import is_yolo
from .knowledge import open_notes, required_bundle
from .planner import plan_step
from .playbooks import (
    executable_steps,
    list_playbooks,
    playbook_for,
    playbook_markdown,
)
from .policy_guard import ScopePolicy, host_from_target, policy_quote_for
from .policy_import import import_policy_to_target
from .redaction import StrictRedactError, redact_text, strict_check, strict_enabled
from .reporting import normalize_platform, render_report
from .runners import browser as browser_runner
from .runners import brute_login as brute_login_runner
from .runners import burp, hexstrike, projectdiscovery, rate_probe, reconftw
from .runners import lab_stack as lab_stack_runner
from .runners import graphql_probe as graphql_probe_runner
from .runners import har_import as har_import_runner
from .runners import http_request as http_request_runner
from .runners import idor_probe as idor_probe_runner
from .runners import js_analyze as js_analyze_runner
from .runners import jwt_analyze as jwt_analyze_runner
from .runners import frida_runner
from .runners import lfi_probe as lfi_probe_runner
from .runners import mobsf as mobsf_runner
from .runners import mobile as mobile_runner
from .runners import content_discovery as content_discovery_runner
from .runners import race_probe as race_probe_runner
from .runners import extract_page as extract_page_runner
from .runners import session_bootstrap as session_bootstrap_runner
from .runners import ssrf_probe as ssrf_probe_runner
from .runners import websocket_probe as websocket_probe_runner
from .runners import oauth_jwt as oauth_jwt_runner
from .runners import param_mine as param_mine_runner
from .runners import secrets_scan as secrets_scan_runner
from .runners import sqli_probe as sqli_probe_runner
from .runners import ssti_probe as ssti_probe_runner
from .runners import web_probes as web_probes_runner
from .runners import xss_probe as xss_probe_runner
from .runners import second_order_xss as second_order_xss_runner
from .runners import xxe_probe as xxe_probe_runner
from .session import get_active, set_active
from . import oob as oob_mod
from . import accounts as accounts_mod

# label -> last http_request response dict (process-local, for assert_diff / playbooks)
_RESPONSE_CACHE: dict[str, dict[str, Any]] = {}

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
        "name": "set_target",
        "description": (
            "Set the active hunt target (loads SCOPE.md, RESUME.md, FINDINGS.md into session). "
            "Pass name like 'demo' or 'targets/demo'."
        ),
        "parameters": {
            "type": "object",
            "properties": {"target": {"type": "string"}},
            "required": ["target"],
            "additionalProperties": False,
        },
    },
    {
        "name": "session_status",
        "description": "Show the active target session (hosts, next step, loaded files).",
        "parameters": {"type": "object", "properties": {}, "additionalProperties": False},
    },
    {
        "name": "capabilities",
        "description": (
            "Show what is actually available: PATH binaries (httpx/katana/nuclei/ffuf), "
            "HexStrike/Burp health, tool packs, and how to call recon via run_tool."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "probe_network": {
                    "type": "boolean",
                    "default": True,
                    "description": "Ping HexStrike/Burp health endpoints",
                }
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "lab_exec",
        "description": (
            "Run a local lab command on this machine (PATH, apt, docker, kill hung tools). "
            "Optional sudo via HACKBOT_SUDO_PASS or .hackbot/sudo_pass. "
            "Does not send traffic to bounty targets. Requires operator approve (auto under /yolo)."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "command": {
                    "type": "string",
                    "description": "Shell command (bash -lc) or single binary invocation",
                },
                "cwd": {"type": "string"},
                "timeout_sec": {"type": "number", "default": 120},
                "sudo": {"type": "boolean", "default": False},
            },
            "required": ["command"],
            "additionalProperties": False,
        },
    },
    {
        "name": "stack_prepare",
        "description": (
            "Fix Go/tool PATH for this process (~/go/bin etc.), smoke-check gau/subfinder/httpx. "
            "Call when recon CLIs are missing or hang. Prefers wayback_urls if gau is flaky."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "persist_shell_rc": {
                    "type": "boolean",
                    "default": False,
                    "description": "Also append PATH export to ~/.zshrc",
                }
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "burp_ensure",
        "description": (
            "Start Burp Community locally (no manual GUI clicks when possible), cache REST "
            "extension under .hackbot/burp/, wait for HACKBOT_BURP_BASE health. "
            "Call when burp_rest is down before burp_* tools."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "base_url": {"type": "string", "default": "http://127.0.0.1:1337"},
                "wait_sec": {"type": "number", "default": 45},
                "download_ext": {"type": "boolean", "default": True},
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "show_identity",
        "description": (
            "Show masked program headers + A/B sessions for a target "
            "(secrets/sessions.yaml). Never returns raw tokens."
        ),
        "parameters": {
            "type": "object",
            "properties": {"target_dir": {"type": "string"}},
            "required": ["target_dir"],
            "additionalProperties": False,
        },
    },
    {
        "name": "set_session",
        "description": (
            "Save account session A/B into targets/<name>/secrets/sessions.yaml (gitignored). "
            "Pass authorization bearer token and/or cookie. Requires approval."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "target_dir": {"type": "string"},
                "name": {"type": "string", "description": "Session name, e.g. A or B"},
                "authorization": {"type": "string"},
                "cookie": {"type": "string"},
                "clear": {"type": "boolean", "default": False},
            },
            "required": ["target_dir", "name"],
            "additionalProperties": False,
        },
    },
    {
        "name": "set_account",
        "description": (
            "Save test login credentials into targets/<name>/secrets/accounts.yaml (gitignored) "
            "for session_bootstrap. Pass username/email + password for A or B. Requires approval. "
            "Use when the operator says to put email/password into accounts.yaml — do NOT ask them "
            "to edit the file by hand."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "target_dir": {"type": "string"},
                "name": {"type": "string", "description": "Account slot, e.g. A or B"},
                "username": {
                    "type": "string",
                    "description": "Username or email for form login",
                },
                "email": {
                    "type": "string",
                    "description": "Alias for username when operator says email",
                },
                "password": {"type": "string"},
                "role": {"type": "string", "default": "user"},
            },
            "required": ["target_dir", "name"],
            "additionalProperties": False,
        },
    },
    {
        "name": "http_request",
        "description": (
            "Authenticated HTTP request using program headers + session A/B. "
            "Returns status, response headers (secrets redacted), body_preview, "
            "and optional saved_body path. Default approve=false (dry-run). "
            "Stores response for assert_diff by label. Prefer GET when you need "
            "headers+body; HEAD still returns headers."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "target_dir": {"type": "string"},
                "url": {"type": "string"},
                "method": {"type": "string", "default": "GET"},
                "session": {"type": "string", "description": "A, B, or other sessions.yaml key"},
                "body": {"type": "string"},
                "content_type": {"type": "string"},
                "label": {"type": "string"},
                "approve": {"type": "boolean", "default": False},
                "force": {"type": "boolean", "default": False},
                "use_jar": {
                    "type": "boolean",
                    "default": True,
                    "description": "Merge/update secrets/cookie_jar.json across hunt acts",
                },
            },
            "required": ["target_dir", "url"],
            "additionalProperties": False,
        },
    },
    {
        "name": "idor_probe",
        "description": (
            "Systematic IDOR/BOLA A/B probe: fetch URL as session A then B "
            "(optional ID param swap) and structured assert_idor_diff. Prefer over "
            "manual http_request+assert_diff when A/B are loaded."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "target_dir": {"type": "string"},
                "url": {"type": "string"},
                "param": {"type": "string", "description": "Optional ID query param to swap for B"},
                "swap_value": {"type": "string", "description": "Value for param when requesting as B"},
                "session_a": {"type": "string", "default": "A"},
                "session_b": {"type": "string", "default": "B"},
                "approve": {"type": "boolean", "default": False},
                "force": {"type": "boolean", "default": False},
                "use_jar": {
                    "type": "boolean",
                    "default": False,
                    "description": "Merge shared cookie jar (off by default for clean A/B)",
                },
                "method": {"type": "string", "default": "GET"},
                "methods": {
                    "type": "string",
                    "description": "CSV of methods e.g. GET,PATCH (write capped)",
                },
                "body": {"type": "string"},
                "matrix": {
                    "type": "string",
                    "default": "bola",
                    "description": "bola | bfla | both | swap",
                },
            },
            "required": ["target_dir", "url"],
            "additionalProperties": False,
        },
    },
    {
        "name": "detect_login",
        "description": (
            "Probe login candidates (form / JSON API / SSO / MFA) under SCOPE. "
            "Optional persist of login.path/fields into accounts.yaml (never passwords). "
            "Dry-run unless approve=true."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "target_dir": {"type": "string"},
                "base_url": {"type": "string"},
                "approve": {"type": "boolean", "default": False},
                "force": {"type": "boolean", "default": False},
                "persist": {
                    "type": "boolean",
                    "default": False,
                    "description": "Write detected login: fields into accounts.yaml",
                },
            },
            "required": ["target_dir", "base_url"],
            "additionalProperties": False,
        },
    },
    {
        "name": "session_smoke",
        "description": (
            "Whoami smoke: GET /api/me-style paths with session A/B to verify auth works. "
            "Dry-run unless approve=true."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "target_dir": {"type": "string"},
                "base_url": {"type": "string"},
                "session": {"type": "string", "default": "A"},
                "smoke_path": {"type": "string"},
                "approve": {"type": "boolean", "default": False},
                "force": {"type": "boolean", "default": False},
            },
            "required": ["target_dir", "base_url"],
            "additionalProperties": False,
        },
    },
    {
        "name": "session_bootstrap",
        "description": (
            "Login with secrets/accounts.yaml (detect form/JSON/SSO, CSRF-aware), persist A/B "
            "sessions + cookie jar, then whoami smoke. MFA/SSO → needs_setup (no bypass). "
            "Prefer before idor_probe when sessions missing."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "target_dir": {"type": "string"},
                "base_url": {"type": "string"},
                "approve": {"type": "boolean", "default": False},
                "force": {"type": "boolean", "default": False},
            },
            "required": ["target_dir", "base_url"],
            "additionalProperties": False,
        },
    },
    {
        "name": "show_accounts",
        "description": "Show masked accounts.yaml readiness for session bootstrap.",
        "parameters": {
            "type": "object",
            "properties": {"target_dir": {"type": "string"}},
            "required": ["target_dir"],
            "additionalProperties": False,
        },
    },
    {
        "name": "extract_page",
        "description": (
            "Extract an in-scope PUBLIC page (login NOT required). GET HTML, pull "
            "__NEXT_DATA__/embedded program JSON, save full artifacts. If the page is a SPA "
            "shell, auto headless-renders with Chromium still WITHOUT login (render=auto). "
            "Pass session only when the page truly returns 401/403. Prefer read_file on "
            "saved_text/saved_json for full program/scope content."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "target_dir": {"type": "string"},
                "url": {"type": "string"},
                "session": {
                    "type": "string",
                    "description": "Optional. Only if page is auth-walled (401/403).",
                },
                "save": {"type": "boolean", "default": True},
                "render": {
                    "type": "boolean",
                    "description": "Force headless Chromium (no login). Default auto on SPA.",
                },
                "approve": {"type": "boolean", "default": False},
                "force": {"type": "boolean", "default": False},
            },
            "required": ["target_dir", "url"],
            "additionalProperties": False,
        },
    },
    {
        "name": "discover_paths",
        "description": (
            "Capped content discovery wordlist against origin; seeds hunt surface.yaml. "
            "High-signal paths only (not a full brute dictionary)."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "target_dir": {"type": "string"},
                "base_url": {"type": "string"},
                "limit": {"type": "integer", "default": 40},
                "approve": {"type": "boolean", "default": False},
                "force": {"type": "boolean", "default": False},
                "seed_surface": {"type": "boolean", "default": True},
            },
            "required": ["target_dir", "base_url"],
            "additionalProperties": False,
        },
    },
    {
        "name": "oob_mint",
        "description": (
            "Mint an OOB/blind canary (SSRF/XSS). Set HACKBOT_OOB_BASE for real "
            "Interactsh/Collaborator URLs; otherwise local reflection markers."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "kind": {"type": "string", "default": "ssrf"},
                "tag": {"type": "string"},
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "oob_poll",
        "description": (
            "Poll HACKBOT_OOB_POLL_URL for canary hits (token placeholder TOKEN). "
            "Pass canary dict from oob_mint / ssrf_probe."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "canary": {"type": "object"},
                "token": {"type": "string", "description": "Or pass token alone to rebuild minimal canary"},
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "assert_diff",
        "description": (
            "Compare two cached http_request responses (by label) for IDOR/authz. "
            "Returns verdict: confirmed|likely|negative|inconclusive and saves evidence."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "target_dir": {"type": "string"},
                "label_a": {"type": "string"},
                "label_b": {"type": "string"},
                "kind": {"type": "string", "default": "idor"},
                "object_hint": {"type": "string"},
            },
            "required": ["target_dir", "label_a", "label_b"],
            "additionalProperties": False,
        },
    },
    {
        "name": "log_finding",
        "description": (
            "Append a structured finding to FINDINGS.md and optionally update RESUME next step. "
            "Requires approval."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "target_dir": {"type": "string"},
                "title": {"type": "string"},
                "class_name": {"type": "string"},
                "endpoint": {"type": "string"},
                "verdict": {"type": "string"},
                "asset": {"type": "string"},
                "observed": {"type": "string"},
                "impact": {"type": "string"},
                "evidence": {"type": "string"},
                "next_step": {"type": "string"},
                "update_resume": {"type": "boolean", "default": True},
            },
            "required": ["target_dir", "title", "class_name", "endpoint", "verdict"],
            "additionalProperties": False,
        },
    },
    {
        "name": "update_resume",
        "description": "Update RESUME.md Safe Next Step (and optional accounts note). Requires approval.",
        "parameters": {
            "type": "object",
            "properties": {
                "target_dir": {"type": "string"},
                "next_step": {"type": "string"},
                "accounts_note": {"type": "string"},
            },
            "required": ["target_dir", "next_step"],
            "additionalProperties": False,
        },
    },
    {
        "name": "open_playbook",
        "description": (
            "Open a falsifiable playbook for a bug class (idor, ssrf, xss, sqli, race, "
            "recon, rate-limit, ...). Returns ordered steps with hypothesis, aggression, "
            "command, expected evidence, stop. Use run_playbook to execute steps."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "task": {"type": "string", "description": "bug class or free-text task"},
                "endpoint": {"type": "string", "description": "optional endpoint to fill into commands"},
            },
            "required": ["task"],
            "additionalProperties": False,
        },
    },
    {
        "name": "run_playbook",
        "description": (
            "Execute (or dry-run) a class playbook: scope check then tool_call steps up to "
            "max aggression. Default approve=false. Level-3 needs SCOPE allowed or force. "
            "force=true is operator responsibility (/force)."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "target_dir": {"type": "string"},
                "task": {"type": "string", "description": "bug class or free-text task"},
                "host": {"type": "string"},
                "endpoint": {"type": "string"},
                "approve": {"type": "boolean", "default": False},
                "force": {"type": "boolean", "default": False},
                "max_aggression": {
                    "type": "integer",
                    "description": "Cap step aggression (default 2; 3 if SCOPE allows level3 or force)",
                },
            },
            "required": ["target_dir", "task", "host"],
            "additionalProperties": False,
        },
    },
    {
        "name": "run_campaign",
        "description": (
            "Run a multi-attack campaign from natural language (DDoS/rate-limit, bruteforce, "
            "auth-bypass, secrets/token leak, IDOR). Returns FOUND/NOT_FOUND/BLOCKED per module. "
            "Respects SCOPE; level-3 needs allowed wording or force. Default dry-run."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "target_dir": {"type": "string"},
                "host": {"type": "string"},
                "prompt": {"type": "string", "description": "Natural language attack list"},
                "approve": {"type": "boolean", "default": False},
                "force": {"type": "boolean", "default": False},
                "login_url": {"type": "string"},
                "endpoint": {"type": "string"},
            },
            "required": ["target_dir", "host", "prompt"],
            "additionalProperties": False,
        },
    },
    {
        "name": "secrets_scan",
        "description": "Fetch common paths on a host and scan for exposed tokens/credentials.",
        "parameters": {
            "type": "object",
            "properties": {
                "target_dir": {"type": "string"},
                "host": {"type": "string"},
                "approve": {"type": "boolean", "default": False},
                "force": {"type": "boolean", "default": False},
            },
            "required": ["target_dir", "host"],
            "additionalProperties": False,
        },
    },
    {
        "name": "brute_login",
        "description": (
            "Capped password spray (max 20) against a login URL. Level-3 or /force required."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "target_dir": {"type": "string"},
                "url": {"type": "string"},
                "username": {"type": "string", "default": "test"},
                "approve": {"type": "boolean", "default": False},
                "force": {"type": "boolean", "default": False},
            },
            "required": ["target_dir", "url"],
            "additionalProperties": False,
        },
    },
    {
        "name": "sqli_probe",
        "description": (
            "Capped SQLi boolean/error differential probe on one URL param. "
            "Stops early on signal. Default dry-run."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "target_dir": {"type": "string"},
                "url": {"type": "string"},
                "param": {"type": "string", "default": "id"},
                "approve": {"type": "boolean", "default": False},
                "force": {"type": "boolean", "default": False},
            },
            "required": ["target_dir", "url"],
            "additionalProperties": False,
        },
    },
    {
        "name": "xss_probe",
        "description": (
            "Capped reflected XSS canary probe on one URL param. Default dry-run."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "target_dir": {"type": "string"},
                "url": {"type": "string"},
                "param": {"type": "string", "default": "q"},
                "approve": {"type": "boolean", "default": False},
                "force": {"type": "boolean", "default": False},
            },
            "required": ["target_dir", "url"],
            "additionalProperties": False,
        },
    },
    {
        "name": "second_order_xss",
        "description": (
            "Capped stored/second-order XSS: one inject + one trigger GET. Default dry-run."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "target_dir": {"type": "string"},
                "url": {"type": "string", "description": "store/inject URL"},
                "trigger_url": {"type": "string"},
                "param": {"type": "string", "default": "comment"},
                "method": {"type": "string", "default": "POST"},
                "approve": {"type": "boolean", "default": False},
                "force": {"type": "boolean", "default": False},
            },
            "required": ["target_dir", "url"],
            "additionalProperties": False,
        },
    },
    {
        "name": "map_surface",
        "description": (
            "Map attack surface from a seed host/URL into targets/<name>/hunt/surface.yaml "
            "(links, params, optional katana). Feeds the autonomous /hunt loop."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "target_dir": {"type": "string"},
                "seed": {"type": "string"},
                "approve": {"type": "boolean", "default": False},
                "force": {"type": "boolean", "default": False},
            },
            "required": ["target_dir", "seed"],
            "additionalProperties": False,
        },
    },
    {
        "name": "run_hunt",
        "description": (
            "Autonomous OODA hunt: map surface → prioritize → specialist modules with chaining "
            "→ validate → FINDINGS. Session approve (--approve) unlocks active traffic for the "
            "whole loop; OOS blocked unless /force (YOLO turns force on). Prefer this over run_campaign for open-ended hunts."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "target_dir": {"type": "string"},
                "prompt": {"type": "string"},
                "host": {"type": "string"},
                "approve": {
                    "type": "boolean",
                    "default": False,
                    "description": "Session approve for the full hunt loop",
                },
                "force": {"type": "boolean", "default": False},
                "budget": {"type": "integer", "description": "Max acts (default ~28)"},
                "resume": {
                    "type": "boolean",
                    "default": False,
                    "description": "Resume from hunt/state.yaml (after needs_setup / pause)",
                },
            },
            "required": ["target_dir", "prompt"],
            "additionalProperties": False,
        },
    },
    {
        "name": "hunt_status",
        "description": "Show autonomous hunt state (phase, budget, candidates, surface size).",
        "parameters": {
            "type": "object",
            "properties": {"target_dir": {"type": "string"}},
            "required": ["target_dir"],
            "additionalProperties": False,
        },
    },
    {
        "name": "analyze_js",
        "description": (
            "Analyze a JS bundle (URL or local file) for hidden API endpoints and secrets. "
            "Seeds hunt surface. Use when user points at app.js / main.*.js."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "target_dir": {"type": "string"},
                "source": {"type": "string", "description": "https://…/app.js or local path"},
                "approve": {"type": "boolean", "default": False},
                "force": {"type": "boolean", "default": False},
            },
            "required": ["target_dir", "source"],
            "additionalProperties": False,
        },
    },
    {
        "name": "mine_params",
        "description": "Capped hidden-parameter miner against a URL (Arjun-style lite).",
        "parameters": {
            "type": "object",
            "properties": {
                "target_dir": {"type": "string"},
                "url": {"type": "string"},
                "approve": {"type": "boolean", "default": False},
                "force": {"type": "boolean", "default": False},
            },
            "required": ["target_dir", "url"],
            "additionalProperties": False,
        },
    },
    {
        "name": "analyze_jwt",
        "description": (
            "Decode a JWT and flag alg=none, jku/x5u, privileged claims. Offline — no cracking."
        ),
        "parameters": {
            "type": "object",
            "properties": {"token": {"type": "string"}},
            "required": ["token"],
            "additionalProperties": False,
        },
    },
    {
        "name": "graphql_probe",
        "description": "GraphQL introspection / custom query probe. Default dry-run.",
        "parameters": {
            "type": "object",
            "properties": {
                "target_dir": {"type": "string"},
                "url": {"type": "string"},
                "query": {"type": "string"},
                "approve": {"type": "boolean", "default": False},
                "force": {"type": "boolean", "default": False},
            },
            "required": ["target_dir", "url"],
            "additionalProperties": False,
        },
    },
    {
        "name": "import_har",
        "description": (
            "Parse a HAR file the operator named; seed endpoints into hunt/surface.yaml. "
            "Use when user says traffic is in file.har / Burp export."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "target_dir": {"type": "string"},
                "path": {"type": "string"},
            },
            "required": ["target_dir", "path"],
            "additionalProperties": False,
        },
    },
    {
        "name": "cors_probe",
        "description": "Probe CORS Origin reflection / credentials misconfig.",
        "parameters": {
            "type": "object",
            "properties": {
                "target_dir": {"type": "string"},
                "url": {"type": "string"},
                "origin": {"type": "string", "default": "https://evil.example"},
                "approve": {"type": "boolean", "default": False},
                "force": {"type": "boolean", "default": False},
            },
            "required": ["target_dir", "url"],
            "additionalProperties": False,
        },
    },
    {
        "name": "open_redirect_probe",
        "description": "Probe open redirect via a query param (default next).",
        "parameters": {
            "type": "object",
            "properties": {
                "target_dir": {"type": "string"},
                "url": {"type": "string"},
                "param": {"type": "string", "default": "next"},
                "approve": {"type": "boolean", "default": False},
                "force": {"type": "boolean", "default": False},
            },
            "required": ["target_dir", "url"],
            "additionalProperties": False,
        },
    },
    {
        "name": "analyze_headers",
        "description": "Fetch response headers; list missing security headers + tech hints.",
        "parameters": {
            "type": "object",
            "properties": {
                "target_dir": {"type": "string"},
                "url": {"type": "string"},
                "approve": {"type": "boolean", "default": False},
                "force": {"type": "boolean", "default": False},
            },
            "required": ["target_dir", "url"],
            "additionalProperties": False,
        },
    },
    {
        "name": "crt_subdomains",
        "description": "Passive subdomain enum via crt.sh (no active traffic).",
        "parameters": {
            "type": "object",
            "properties": {"domain": {"type": "string"}},
            "required": ["domain"],
            "additionalProperties": False,
        },
    },
    {
        "name": "wayback_urls",
        "description": "Passive historical URLs via Wayback CDX API.",
        "parameters": {
            "type": "object",
            "properties": {
                "domain": {"type": "string"},
                "limit": {"type": "integer", "default": 100},
            },
            "required": ["domain"],
            "additionalProperties": False,
        },
    },
    {
        "name": "list_dir",
        "description": (
            "List files in a folder the operator named (Downloads, Desktop, target dirs). "
            "Use when they say 'na pasta X'."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "path": {"type": "string"},
                "glob": {"type": "string", "description": "optional suffix filter e.g. *.har"},
            },
            "required": ["path"],
            "additionalProperties": False,
        },
    },
    {
        "name": "lfi_probe",
        "description": "Capped LFI/path traversal probe on one URL param.",
        "parameters": {
            "type": "object",
            "properties": {
                "target_dir": {"type": "string"},
                "url": {"type": "string"},
                "param": {"type": "string", "default": "file"},
                "approve": {"type": "boolean", "default": False},
                "force": {"type": "boolean", "default": False},
            },
            "required": ["target_dir", "url"],
            "additionalProperties": False,
        },
    },
    {
        "name": "ssti_probe",
        "description": "Capped SSTI math-canary probe on one URL param.",
        "parameters": {
            "type": "object",
            "properties": {
                "target_dir": {"type": "string"},
                "url": {"type": "string"},
                "param": {"type": "string", "default": "q"},
                "approve": {"type": "boolean", "default": False},
                "force": {"type": "boolean", "default": False},
            },
            "required": ["target_dir", "url"],
            "additionalProperties": False,
        },
    },
    {
        "name": "xxe_probe",
        "description": "Capped XXE file-read probe (XML POST body).",
        "parameters": {
            "type": "object",
            "properties": {
                "target_dir": {"type": "string"},
                "url": {"type": "string"},
                "approve": {"type": "boolean", "default": False},
                "force": {"type": "boolean", "default": False},
            },
            "required": ["target_dir", "url"],
            "additionalProperties": False,
        },
    },
    {
        "name": "ssrf_probe",
        "description": "Capped SSRF probe on one URL param (benign markers only).",
        "parameters": {
            "type": "object",
            "properties": {
                "target_dir": {"type": "string"},
                "url": {"type": "string"},
                "param": {"type": "string", "default": "url"},
                "approve": {"type": "boolean", "default": False},
                "force": {"type": "boolean", "default": False},
            },
            "required": ["target_dir", "url"],
            "additionalProperties": False,
        },
    },
    {
        "name": "race_probe",
        "description": "Bounded race/TOCTOU probe — parallel identical requests.",
        "parameters": {
            "type": "object",
            "properties": {
                "target_dir": {"type": "string"},
                "url": {"type": "string"},
                "method": {"type": "string", "default": "GET"},
                "workers": {"type": "integer", "default": 8},
                "burst": {"type": "integer", "default": 16},
                "session": {"type": "string"},
                "approve": {"type": "boolean", "default": False},
                "force": {"type": "boolean", "default": False},
            },
            "required": ["target_dir", "url"],
            "additionalProperties": False,
        },
    },
    {
        "name": "websocket_probe",
        "description": "Websocket handshake probe; optional send one text frame.",
        "parameters": {
            "type": "object",
            "properties": {
                "target_dir": {"type": "string"},
                "url": {"type": "string"},
                "message": {"type": "string", "default": ""},
                "approve": {"type": "boolean", "default": False},
                "force": {"type": "boolean", "default": False},
            },
            "required": ["target_dir", "url"],
            "additionalProperties": False,
        },
    },
    {
        "name": "jwt_active_probe",
        "description": (
            "Active JWT tests: alg=none + privileged claim variants against a URL "
            "(Authorization Bearer). Pair with analyze_jwt first."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "target_dir": {"type": "string"},
                "url": {"type": "string"},
                "token": {"type": "string"},
                "approve": {"type": "boolean", "default": False},
                "force": {"type": "boolean", "default": False},
            },
            "required": ["target_dir", "url", "token"],
            "additionalProperties": False,
        },
    },
    {
        "name": "oauth_probe",
        "description": (
            "OAuth authorize URL checks: missing state, redirect_uri looseness, "
            "evil redirect acceptance."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "target_dir": {"type": "string"},
                "authorize_url": {"type": "string"},
                "approve": {"type": "boolean", "default": False},
                "force": {"type": "boolean", "default": False},
            },
            "required": ["target_dir", "authorize_url"],
            "additionalProperties": False,
        },
    },
    {
        "name": "build_chains",
        "description": (
            "Build A→B exploit chains from FINDINGS + hunt memory. Writes hunt/chains.md "
            "and updates RESUME. Use after findings appear."
        ),
        "parameters": {
            "type": "object",
            "properties": {"target_dir": {"type": "string"}},
            "required": ["target_dir"],
            "additionalProperties": False,
        },
    },
    {
        "name": "browser_navigate",
        "description": (
            "Open a URL in headless Chromium (Playwright), return title + text preview. "
            "Requires: pip install playwright && playwright install chromium. Scope+approve."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "target_dir": {"type": "string"},
                "url": {"type": "string"},
                "approve": {"type": "boolean", "default": False},
                "force": {"type": "boolean", "default": False},
            },
            "required": ["target_dir", "url"],
            "additionalProperties": False,
        },
    },
    {
        "name": "browser_screenshot",
        "description": "Screenshot a URL via Playwright into evidence/safe/. Scope+approve.",
        "parameters": {
            "type": "object",
            "properties": {
                "target_dir": {"type": "string"},
                "url": {"type": "string"},
                "approve": {"type": "boolean", "default": False},
                "force": {"type": "boolean", "default": False},
            },
            "required": ["target_dir", "url"],
            "additionalProperties": False,
        },
    },
    {
        "name": "browser_eval",
        "description": "Evaluate a short JS expression in page context (Playwright). Scope+approve.",
        "parameters": {
            "type": "object",
            "properties": {
                "target_dir": {"type": "string"},
                "url": {"type": "string"},
                "expression": {"type": "string"},
                "approve": {"type": "boolean", "default": False},
                "force": {"type": "boolean", "default": False},
            },
            "required": ["target_dir", "url", "expression"],
            "additionalProperties": False,
        },
    },
    {
        "name": "browser_cookies",
        "description": (
            "Navigate then list cookies (values redacted). Playwright. Scope+approve."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "target_dir": {"type": "string"},
                "url": {"type": "string"},
                "approve": {"type": "boolean", "default": False},
                "force": {"type": "boolean", "default": False},
            },
            "required": ["target_dir", "url"],
            "additionalProperties": False,
        },
    },
    {
        "name": "browser_storage",
        "description": (
            "Dump localStorage/sessionStorage keys after navigate (values redacted). "
            "Playwright. Scope+approve."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "target_dir": {"type": "string"},
                "url": {"type": "string"},
                "approve": {"type": "boolean", "default": False},
                "force": {"type": "boolean", "default": False},
            },
            "required": ["target_dir", "url"],
            "additionalProperties": False,
        },
    },
    {
        "name": "browser_network",
        "description": (
            "Capture network requests during page load; seed hunt surface with XHR/fetch URLs. "
            "Playwright. Scope+approve."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "target_dir": {"type": "string"},
                "url": {"type": "string"},
                "approve": {"type": "boolean", "default": False},
                "force": {"type": "boolean", "default": False},
                "seed_surface": {"type": "boolean", "default": True},
            },
            "required": ["target_dir", "url"],
            "additionalProperties": False,
        },
    },
    {
        "name": "browser_capture_session",
        "description": (
            "Open headed Chromium for operator IdP/MFA login, then save cookies/token into "
            "sessions.yaml for session A/B. Never types IdP passwords. Dry-run unless approve."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "target_dir": {"type": "string"},
                "url": {"type": "string", "description": "Login or SSO start URL"},
                "session": {"type": "string", "default": "A"},
                "approve": {"type": "boolean", "default": False},
                "force": {"type": "boolean", "default": False},
                "timeout_s": {"type": "number", "description": "Seconds to wait for operator login"},
            },
            "required": ["target_dir", "url"],
            "additionalProperties": False,
        },
    },
    {
        "name": "browser_capture_session",
        "description": (
            "Open headed Chromium for operator IdP/MFA login, then save cookies/token into "
            "sessions.yaml for session A/B. Never types IdP passwords. Dry-run unless approve."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "target_dir": {"type": "string"},
                "url": {"type": "string", "description": "Login or SSO start URL"},
                "session": {"type": "string", "default": "A"},
                "approve": {"type": "boolean", "default": False},
                "force": {"type": "boolean", "default": False},
                "timeout_s": {"type": "number"},
            },
            "required": ["target_dir", "url"],
            "additionalProperties": False,
        },
    },
    {
        "name": "browser_with_session",
        "description": (
            "Navigate with A/B session from secrets/sessions.yaml injected "
            "(Authorization + Cookie). Values never logged. Playwright. Scope+approve."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "target_dir": {"type": "string"},
                "url": {"type": "string"},
                "session": {"type": "string", "default": "A", "description": "Session key A/B"},
                "approve": {"type": "boolean", "default": False},
                "force": {"type": "boolean", "default": False},
                "capture_network": {"type": "boolean", "default": False},
            },
            "required": ["target_dir", "url"],
            "additionalProperties": False,
        },
    },
    {
        "name": "browser_diff_sessions",
        "description": (
            "Open the same URL as session A and B; compare status/title/body fingerprint. "
            "Soft IDOR hint only — not a confirmed finding. Playwright. Scope+approve."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "target_dir": {"type": "string"},
                "url": {"type": "string"},
                "session_a": {"type": "string", "default": "A"},
                "session_b": {"type": "string", "default": "B"},
                "approve": {"type": "boolean", "default": False},
                "force": {"type": "boolean", "default": False},
                "promote": {
                    "type": "boolean",
                    "default": True,
                    "description": "Auto-promote soft IDOR hint to candidate + FINDINGS (verdict=likely)",
                },
            },
            "required": ["target_dir", "url"],
            "additionalProperties": False,
        },
    },
    {
        "name": "browser_console",
        "description": "Capture console messages during page load (Playwright). Scope+approve.",
        "parameters": {
            "type": "object",
            "properties": {
                "target_dir": {"type": "string"},
                "url": {"type": "string"},
                "approve": {"type": "boolean", "default": False},
                "force": {"type": "boolean", "default": False},
            },
            "required": ["target_dir", "url"],
            "additionalProperties": False,
        },
    },
    {
        "name": "browser_set_cookie",
        "description": (
            "Set one cookie then navigate (value never logged). Playwright. Scope+approve."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "target_dir": {"type": "string"},
                "url": {"type": "string"},
                "name": {"type": "string"},
                "value": {"type": "string"},
                "session": {"type": "string"},
                "approve": {"type": "boolean", "default": False},
                "force": {"type": "boolean", "default": False},
            },
            "required": ["target_dir", "url", "name", "value"],
            "additionalProperties": False,
        },
    },
    {
        "name": "import_burp_xml",
        "description": (
            "Parse Burp Suite XML export; seed hunt/surface.yaml + redacted summary. "
            "Use when operator points at a .xml Burp export."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "target_dir": {"type": "string"},
                "path": {"type": "string"},
            },
            "required": ["target_dir", "path"],
            "additionalProperties": False,
        },
    },
    {
        "name": "burp_rest_health",
        "description": (
            "Probe local Burp HTTP/REST listener (127.0.0.1). Does not talk to the target. "
            "If down, call burp_ensure first."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "base_url": {"type": "string", "default": "http://127.0.0.1:1337"},
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "burp_proxy_history",
        "description": "Best-effort Burp REST proxy history (local).",
        "parameters": {
            "type": "object",
            "properties": {
                "base_url": {"type": "string"},
                "limit": {"type": "integer", "default": 20},
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "burp_issue_list",
        "description": "Best-effort Burp scanner issues via local REST.",
        "parameters": {
            "type": "object",
            "properties": {
                "base_url": {"type": "string"},
                "limit": {"type": "integer", "default": 20},
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "burp_replay",
        "description": (
            "Burp control-plane replay: REST send → optional MCP (HACKBOT_BURP_MCP_CMD) → "
            "scoped http_request fallback. Approve-gated; SCOPE enforced."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "target_dir": {"type": "string"},
                "url": {"type": "string"},
                "method": {"type": "string", "default": "GET"},
                "body": {"type": "string"},
                "approve": {"type": "boolean", "default": False},
                "force": {"type": "boolean", "default": False},
                "base_url": {"type": "string"},
            },
            "required": ["target_dir", "url"],
            "additionalProperties": False,
        },
    },
    {
        "name": "burp_replay_history",
        "description": "Replay item N from Burp proxy history via burp_replay.",
        "parameters": {
            "type": "object",
            "properties": {
                "target_dir": {"type": "string"},
                "index": {"type": "integer", "default": 0},
                "approve": {"type": "boolean", "default": False},
                "force": {"type": "boolean", "default": False},
                "base_url": {"type": "string"},
            },
            "required": ["target_dir"],
            "additionalProperties": False,
        },
    },
    {
        "name": "interactsh_status",
        "description": (
            "Show Interactsh / OOB config (HACKBOT_INTERACTSH*, HACKBOT_OOB_*)."
        ),
        "parameters": {"type": "object", "properties": {}, "additionalProperties": False},
    },
    {
        "name": "interactsh_register",
        "description": (
            "Register with Interactsh (real /register) or mint legacy OOB canary."
        ),
        "parameters": {"type": "object", "properties": {}, "additionalProperties": False},
    },
    {
        "name": "interactsh_poll",
        "description": "Poll Interactsh session (decrypt) or legacy OOB poll URL.",
        "parameters": {
            "type": "object",
            "properties": {
                "canary": {"type": "object"},
                "wait": {"type": "boolean", "default": True},
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "cdp_attach",
        "description": "Probe local Chromium CDP /json/version.",
        "parameters": {
            "type": "object",
            "properties": {
                "cdp_url": {"type": "string", "default": "http://127.0.0.1:9222"},
                "approve": {"type": "boolean", "default": False},
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "hunt_checklist",
        "description": "Pre-hunt checklist: SCOPE, sessions, accounts, OOB, HAR.",
        "parameters": {
            "type": "object",
            "properties": {"target_dir": {"type": "string"}},
            "required": ["target_dir"],
            "additionalProperties": False,
        },
    },
    {
        "name": "hunt_pause",
        "description": "Pause autonomous hunt loop (hunt/PAUSED).",
        "parameters": {
            "type": "object",
            "properties": {"target_dir": {"type": "string"}},
            "required": ["target_dir"],
            "additionalProperties": False,
        },
    },
    {
        "name": "hunt_resume_flag",
        "description": "Clear hunt pause flag.",
        "parameters": {
            "type": "object",
            "properties": {"target_dir": {"type": "string"}},
            "required": ["target_dir"],
            "additionalProperties": False,
        },
    },
    {
        "name": "hunt_telemetry",
        "description": "Local hunt telemetry stats.",
        "parameters": {
            "type": "object",
            "properties": {"target_dir": {"type": "string"}},
            "required": ["target_dir"],
            "additionalProperties": False,
        },
    },
    {
        "name": "submit_ready",
        "description": (
            "Mark RESUME that a draft finding is ready for HUMAN portal submit. "
            "Never calls HackerOne/Bugcrowd APIs."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "target_dir": {"type": "string"},
                "finding_id": {"type": "string"},
            },
            "required": ["target_dir"],
            "additionalProperties": False,
        },
    },
    {
        "name": "mass_assignment_probe",
        "description": "Capped mass-assignment probe (role/admin JSON fields).",
        "parameters": {
            "type": "object",
            "properties": {
                "target_dir": {"type": "string"},
                "url": {"type": "string"},
                "session": {"type": "string"},
                "approve": {"type": "boolean", "default": False},
                "force": {"type": "boolean", "default": False},
            },
            "required": ["target_dir", "url"],
            "additionalProperties": False,
        },
    },
    {
        "name": "method_override_probe",
        "description": "Probe X-HTTP-Method-Override DELETE via POST.",
        "parameters": {
            "type": "object",
            "properties": {
                "target_dir": {"type": "string"},
                "url": {"type": "string"},
                "session": {"type": "string"},
                "approve": {"type": "boolean", "default": False},
                "force": {"type": "boolean", "default": False},
            },
            "required": ["target_dir", "url"],
            "additionalProperties": False,
        },
    },
    {
        "name": "hpp_probe",
        "description": "HTTP parameter pollution (duplicate id=).",
        "parameters": {
            "type": "object",
            "properties": {
                "target_dir": {"type": "string"},
                "url": {"type": "string"},
                "param": {"type": "string", "default": "id"},
                "session": {"type": "string"},
                "approve": {"type": "boolean", "default": False},
                "force": {"type": "boolean", "default": False},
            },
            "required": ["target_dir", "url"],
            "additionalProperties": False,
        },
    },
    {
        "name": "learn_record",
        "description": "Record a technique that worked (cross-program learning log).",
        "parameters": {
            "type": "object",
            "properties": {
                "program": {"type": "string"},
                "module": {"type": "string"},
                "summary": {"type": "string"},
                "host": {"type": "string"},
                "outcome": {"type": "string", "default": "signal"},
            },
            "required": ["program", "module", "summary"],
            "additionalProperties": False,
        },
    },
    {
        "name": "learn_suggest",
        "description": "Suggest modules that worked on past programs (for this host or globally).",
        "parameters": {
            "type": "object",
            "properties": {
                "host": {"type": "string"},
                "module": {"type": "string"},
                "program": {"type": "string"},
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "learn_stats",
        "description": "Cross-program learning log aggregate stats.",
        "parameters": {"type": "object", "properties": {}, "additionalProperties": False},
    },
    {
        "name": "browser_hint",
        "description": (
            "Playwright status / install hint. Prefer browser_navigate, browser_cookies, "
            "browser_storage, browser_network."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "task": {"type": "string", "description": "what you wanted the browser to do"},
            },
            "required": ["task"],
            "additionalProperties": False,
        },
    },
    {
        "name": "mobile_status",
        "description": (
            "Detect adb/frida/objection/aapt on PATH + mobile bounty checklist. "
            "Does not run Frida hooks."
        ),
        "parameters": {
            "type": "object",
            "properties": {"task": {"type": "string"}},
            "additionalProperties": False,
        },
    },
    {
        "name": "adb_devices",
        "description": "List local adb devices/emulators (USB/lab only).",
        "parameters": {
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        },
    },
    {
        "name": "inspect_apk",
        "description": (
            "Local APK inspect: zip listing + optional aapt badging. Writes evidence. No network."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "target_dir": {"type": "string"},
                "path": {"type": "string", "description": "path to .apk"},
            },
            "required": ["target_dir", "path"],
            "additionalProperties": False,
        },
    },
    {
        "name": "mobile_bridge",
        "description": (
            "APK inspect + HAR import → seed surface; optional start_hunt. "
            "Use when operator has app.apk and/or traffic.har from mobile proxy."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "target_dir": {"type": "string"},
                "apk_path": {"type": "string"},
                "har_path": {"type": "string"},
                "start_hunt": {"type": "boolean", "default": False},
                "approve": {"type": "boolean", "default": False},
                "force": {"type": "boolean", "default": False},
                "host": {"type": "string"},
                "budget": {"type": "integer"},
            },
            "required": ["target_dir"],
            "additionalProperties": False,
        },
    },
    {
        "name": "mobile_hint",
        "description": "Alias for mobile_status (checklist + tool detection).",
        "parameters": {
            "type": "object",
            "properties": {"task": {"type": "string"}},
            "required": ["task"],
            "additionalProperties": False,
        },
    },
    {
        "name": "mobsf_health",
        "description": "Probe local/remote MobSF REST health (no target traffic).",
        "parameters": {
            "type": "object",
            "properties": {
                "base_url": {"type": "string"},
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "mobsf_upload",
        "description": "Upload APK to MobSF. Requires API key + approve.",
        "parameters": {
            "type": "object",
            "properties": {
                "target_dir": {"type": "string"},
                "path": {"type": "string"},
                "approve": {"type": "boolean", "default": False},
            },
            "required": ["target_dir", "path"],
            "additionalProperties": False,
        },
    },
    {
        "name": "mobsf_scan",
        "description": "Start MobSF scan by upload hash. Requires approve.",
        "parameters": {
            "type": "object",
            "properties": {
                "hash": {"type": "string"},
                "scan_type": {"type": "string", "default": "apk"},
                "approve": {"type": "boolean", "default": False},
            },
            "required": ["hash"],
            "additionalProperties": False,
        },
    },
    {
        "name": "frida_status",
        "description": "Frida/objection availability + allowlisted scripts.",
        "parameters": {"type": "object", "properties": {}, "additionalProperties": False},
    },
    {
        "name": "frida_list_apps",
        "description": "List USB-attached apps via frida-ps (lab only).",
        "parameters": {"type": "object", "properties": {}, "additionalProperties": False},
    },
    {
        "name": "frida_run_script",
        "description": "Run allowlisted Frida script on package. Approve required.",
        "parameters": {
            "type": "object",
            "properties": {
                "package": {"type": "string"},
                "script": {"type": "string", "default": "ssl_unpin_lab.js"},
                "approve": {"type": "boolean", "default": False},
                "spawn": {"type": "boolean", "default": True},
            },
            "required": ["package"],
            "additionalProperties": False,
        },
    },
    {
        "name": "objection_explore",
        "description": "Objection explore smoke (non-interactive). Approve required.",
        "parameters": {
            "type": "object",
            "properties": {
                "package": {"type": "string"},
                "approve": {"type": "boolean", "default": False},
            },
            "required": ["package"],
            "additionalProperties": False,
        },
    },
    {
        "name": "import_policy",
        "description": (
            "Parse program policy text into SCOPE.md YAML front-matter for a target. "
            "write=true overwrites SCOPE.md (asks approval)."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "target": {"type": "string"},
                "policy_text": {"type": "string"},
                "write": {"type": "boolean", "default": False},
            },
            "required": ["target", "policy_text"],
            "additionalProperties": False,
        },
    },
    {
        "name": "read_file",
        "description": (
            "Read a text file the operator pointed at (SCOPE, notes, credential dumps, "
            "policy). Paths under kit, home, Downloads/Desktop are readable. "
            "When the user says 'the tokens are in file X', use this (or load_sessions_from_file)."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Relative or absolute path"},
                "max_chars": {"type": "integer", "default": 8000},
            },
            "required": ["path"],
            "additionalProperties": False,
        },
    },
    {
        "name": "read_image",
        "description": (
            "Read an image the operator named (screenshot, scope PDF page export, Burp, "
            "program policy screenshot). Uses tesseract OCR if installed; optional vision "
            "model when configured. Use when the user says 'leia essa imagem' / 'read this png'."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "path": {"type": "string"},
                "question": {
                    "type": "string",
                    "description": "What to extract (default: all visible text for hunting)",
                },
            },
            "required": ["path"],
            "additionalProperties": False,
        },
    },
    {
        "name": "load_sessions_from_file",
        "description": (
            "Read a credentials/sessions file (yaml/json/env/prose) and save A/B sessions "
            "into targets/<name>/secrets/sessions.yaml. Use when the user says the tokens "
            "are in file X / pasta Y — do NOT ask them to type /session."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "target_dir": {"type": "string"},
                "path": {"type": "string", "description": "Path to credential file"},
                "write": {
                    "type": "boolean",
                    "default": True,
                    "description": "If false, only parse and return masked preview",
                },
            },
            "required": ["target_dir", "path"],
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
        "name": "show_config",
        "description": (
            "Show effective Hackbot config (safety knobs from configs/hackbot.yaml / "
            "example + env overrides). No secrets."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "reload": {
                    "type": "boolean",
                    "default": False,
                    "description": "Re-read YAML/env instead of using the process cache",
                },
            },
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
        "description": (
            "Write a bug-bounty report draft from FINDINGS (or explicit fields). "
            "platform=generic|bugcrowd|hackerone|intigriti|yeswehack|synack|immunefi|yogosha. "
            "generic is the default portable draft for any portal."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "target_dir": {"type": "string"},
                "platform": {
                    "type": "string",
                    "default": "generic",
                    "description": "Target portal flavor; use generic when unsure",
                },
                "title": {"type": "string"},
                "target": {"type": "string"},
                "preconditions": {"type": "string"},
                "steps": {"type": "string"},
                "impact": {"type": "string"},
                "evidence": {"type": "string"},
                "vrt": {"type": "string"},
                "weakness": {"type": "string"},
                "vuln_type": {"type": "string"},
                "finding_id": {
                    "type": "string",
                    "description": "FINDINGS.md id (e.g. C-001) or 'latest'",
                },
            },
            "required": ["target_dir"],
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
            "Run or dry-run an external tool (httpx, katana, nuclei, ffuf, reconftw, "
            "hexstrike, burp, rate_probe). Default approve=false (dry-run only). "
            "approve=true sends real traffic and requires operator confirmation. "
            "force=true overrides ALL SCOPE gates including OUT_OF_SCOPE "
            "(operator responsibility)."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "target_dir": {"type": "string"},
                "tool": {
                    "type": "string",
                    "enum": [
                        "httpx",
                        "katana",
                        "nuclei",
                        "ffuf",
                        "reconftw",
                        "hexstrike",
                        "burp",
                        "rate_probe",
                        "dos",
                        "stress",
                    ],
                },
                "host": {"type": "string"},
                "approve": {"type": "boolean", "default": False},
                "force": {"type": "boolean", "default": False},
                "wordlist": {"type": "string"},
                "burp_xml": {"type": "string"},
                "concurrency": {"type": "integer"},
                "total": {"type": "integer"},
                "timeout": {"type": "number"},
                "method": {"type": "string"},
            },
            "required": ["target_dir", "tool", "host"],
            "additionalProperties": False,
        },
    },
    {
        "name": "workflow_load",
        "description": (
            "List or parse target workflows under hunt/workflows/*.yaml. "
            "No traffic. Pass workflow_id to preview steps."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "target_dir": {"type": "string"},
                "workflow_id": {
                    "type": "string",
                    "description": "optional id (filename stem); omit to list",
                },
            },
            "required": ["target_dir"],
            "additionalProperties": False,
        },
    },
    {
        "name": "workflow_run",
        "description": (
            "Dry-run or ACTIVE-run a hunt/workflows/<id>.yaml scenario "
            "(request/extract/mutate/assert). Default approve=false. "
            "ACTIVE needs operator confirm; SCOPE gates every request."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "target_dir": {"type": "string"},
                "workflow_id": {"type": "string"},
                "approve": {"type": "boolean", "default": False},
                "force": {"type": "boolean", "default": False},
            },
            "required": ["target_dir", "workflow_id"],
            "additionalProperties": False,
        },
    },
    {
        "name": "workflow_assert",
        "description": (
            "Re-run workflow assert steps against saved state / response cache. No new traffic."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "target_dir": {"type": "string"},
                "workflow_id": {"type": "string"},
            },
            "required": ["target_dir", "workflow_id"],
            "additionalProperties": False,
        },
    },
    {
        "name": "coverage_map",
        "description": (
            "Read/update hunt/coverage.yaml (class×method×path×param×authz → "
            "untested|dry|active|neg|pos). action=summary|list|mark|priorities."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "target_dir": {"type": "string"},
                "action": {
                    "type": "string",
                    "enum": ["summary", "list", "mark", "priorities"],
                    "default": "summary",
                },
                "class": {"type": "string"},
                "method": {"type": "string"},
                "path": {"type": "string"},
                "url": {"type": "string"},
                "param": {"type": "string"},
                "authz": {"type": "string"},
                "status": {
                    "type": "string",
                    "enum": ["untested", "dry", "active", "neg", "pos"],
                },
                "note": {"type": "string"},
            },
            "required": ["target_dir"],
            "additionalProperties": False,
        },
    },
    {
        "name": "hunt_cockpit",
        "description": (
            "Operator summary: surface size, coverage %, budget/phase, next falsifiable "
            "step, pending priorities. No traffic."
        ),
        "parameters": {
            "type": "object",
            "properties": {"target_dir": {"type": "string"}},
            "required": ["target_dir"],
            "additionalProperties": False,
        },
    },
    {
        "name": "finding_score",
        "description": (
            "Score a candidate finding (confidence, FP likelihood) before FINDINGS append. "
            "Uses fp_signatures + verdict. No traffic."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "module": {"type": "string"},
                "verdict": {"type": "string"},
                "observed": {"type": "string"},
                "url": {"type": "string"},
                "has_ownership_diff": {"type": "boolean", "default": False},
            },
            "required": ["module", "verdict"],
            "additionalProperties": False,
        },
    },
    {
        "name": "dedupe_findings",
        "description": (
            "Dedupe FINDINGS.md entries by class+endpoint+title fingerprint. "
            "Dry by default (report only); write=true rewrites file after approve."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "target_dir": {"type": "string"},
                "write": {"type": "boolean", "default": False},
            },
            "required": ["target_dir"],
            "additionalProperties": False,
        },
    },
    {
        "name": "chain_validate",
        "description": (
            "Validate an A→B chain from hunt/chains.md or explicit steps with asserts. "
            "Does not promote FINDINGS unless asserts pass + evidence paths present."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "target_dir": {"type": "string"},
                "chain_id": {"type": "string"},
                "label_a": {"type": "string"},
                "label_b": {"type": "string"},
                "kind": {"type": "string", "default": "idor"},
            },
            "required": ["target_dir"],
            "additionalProperties": False,
        },
    },
    {
        "name": "browser_map_spa",
        "description": (
            "Playwright SPA map: routes, XHR/fetch, GraphQL ops → evidence + optional surface seed. "
            "Default approve=false (dry-run)."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "target_dir": {"type": "string"},
                "url": {"type": "string"},
                "approve": {"type": "boolean", "default": False},
                "force": {"type": "boolean", "default": False},
                "seed_surface": {"type": "boolean", "default": True},
            },
            "required": ["target_dir", "url"],
            "additionalProperties": False,
        },
    },
    {
        "name": "dom_xss_probe",
        "description": (
            "Capped DOM sink scan (innerHTML/eval/postMessage/location*). "
            "Detection markers only; default dry-run."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "target_dir": {"type": "string"},
                "url": {"type": "string"},
                "approve": {"type": "boolean", "default": False},
                "force": {"type": "boolean", "default": False},
            },
            "required": ["target_dir", "url"],
            "additionalProperties": False,
        },
    },
    {
        "name": "postmessage_probe",
        "description": (
            "Capped postMessage listener / origin-check probe via Playwright. Dry-run default."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "target_dir": {"type": "string"},
                "url": {"type": "string"},
                "approve": {"type": "boolean", "default": False},
                "force": {"type": "boolean", "default": False},
            },
            "required": ["target_dir", "url"],
            "additionalProperties": False,
        },
    },
    {
        "name": "prototype_pollution_probe",
        "description": (
            "Capped client-side prototype pollution gadget probe (lab/scoped). Dry-run default."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "target_dir": {"type": "string"},
                "url": {"type": "string"},
                "approve": {"type": "boolean", "default": False},
                "force": {"type": "boolean", "default": False},
            },
            "required": ["target_dir", "url"],
            "additionalProperties": False,
        },
    },
    {
        "name": "browser_har_seed",
        "description": (
            "Capture browser network as HAR-like JSON and seed hunt/surface.yaml. Dry-run default."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "target_dir": {"type": "string"},
                "url": {"type": "string"},
                "approve": {"type": "boolean", "default": False},
                "force": {"type": "boolean", "default": False},
            },
            "required": ["target_dir", "url"],
            "additionalProperties": False,
        },
    },
    {
        "name": "saml_probe",
        "description": (
            "SAML surface checks (ACS URL, RelayState, signature hints). Capped; dry-run default. "
            "Level-2; no assertion forge against real IdPs without SCOPE."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "target_dir": {"type": "string"},
                "url": {"type": "string"},
                "approve": {"type": "boolean", "default": False},
                "force": {"type": "boolean", "default": False},
            },
            "required": ["target_dir", "url"],
            "additionalProperties": False,
        },
    },
    {
        "name": "oidc_probe",
        "description": (
            "OIDC discovery / redirect_uri looseness checks (beyond oauth_probe). Dry-run default."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "target_dir": {"type": "string"},
                "url": {"type": "string", "description": "issuer or authorize URL"},
                "approve": {"type": "boolean", "default": False},
                "force": {"type": "boolean", "default": False},
            },
            "required": ["target_dir", "url"],
            "additionalProperties": False,
        },
    },
    {
        "name": "session_fixation_probe",
        "description": (
            "Session fixation check: capture pre-auth cookie, login, compare. Dry-run default."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "target_dir": {"type": "string"},
                "url": {"type": "string"},
                "login_url": {"type": "string"},
                "approve": {"type": "boolean", "default": False},
                "force": {"type": "boolean", "default": False},
            },
            "required": ["target_dir", "url"],
            "additionalProperties": False,
        },
    },
    {
        "name": "token_binding_check",
        "description": (
            "Check if bearer/cookie tokens appear bound to IP/UA/client (passive + optional replay). "
            "Dry-run default."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "target_dir": {"type": "string"},
                "url": {"type": "string"},
                "session": {"type": "string"},
                "approve": {"type": "boolean", "default": False},
                "force": {"type": "boolean", "default": False},
            },
            "required": ["target_dir", "url"],
            "additionalProperties": False,
        },
    },
    {
        "name": "burp_watch",
        "description": (
            "Poll Burp proxy history for new in-scope requests; return prioritized candidates. "
            "No active attack traffic."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "target_dir": {"type": "string"},
                "limit": {"type": "integer", "default": 40},
            },
            "required": ["target_dir"],
            "additionalProperties": False,
        },
    },
    {
        "name": "proxy_correlate",
        "description": (
            "Correlate Burp/HAR history → deduped method+path+param+authz candidates; "
            "seed surface + suggest next falsifiable step."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "target_dir": {"type": "string"},
                "limit": {"type": "integer", "default": 40},
                "seed_surface": {"type": "boolean", "default": True},
            },
            "required": ["target_dir"],
            "additionalProperties": False,
        },
    },
    {
        "name": "cache_poison_probe",
        "description": (
            "Web cache deception / unkeyed header detection (safe, capped). Dry-run default. "
            "Never volume DoS."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "target_dir": {"type": "string"},
                "url": {"type": "string"},
                "approve": {"type": "boolean", "default": False},
                "force": {"type": "boolean", "default": False},
            },
            "required": ["target_dir", "url"],
            "additionalProperties": False,
        },
    },
    {
        "name": "http_smuggle_probe",
        "description": (
            "HTTP request smuggling / desync DETECTION only (CL.TE / TE.CL timing hints). "
            "Never DoS. Dry-run default; L3 needs SCOPE or force."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "target_dir": {"type": "string"},
                "url": {"type": "string"},
                "approve": {"type": "boolean", "default": False},
                "force": {"type": "boolean", "default": False},
            },
            "required": ["target_dir", "url"],
            "additionalProperties": False,
        },
    },
    {
        "name": "host_header_probe",
        "description": "Host header / password-reset poisoning detection (capped). Dry-run default.",
        "parameters": {
            "type": "object",
            "properties": {
                "target_dir": {"type": "string"},
                "url": {"type": "string"},
                "approve": {"type": "boolean", "default": False},
                "force": {"type": "boolean", "default": False},
            },
            "required": ["target_dir", "url"],
            "additionalProperties": False,
        },
    },
    {
        "name": "absolute_url_probe",
        "description": (
            "Absolute-form request / URL parser differential probe (detection). Dry-run default."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "target_dir": {"type": "string"},
                "url": {"type": "string"},
                "approve": {"type": "boolean", "default": False},
                "force": {"type": "boolean", "default": False},
            },
            "required": ["target_dir", "url"],
            "additionalProperties": False,
        },
    },
    {
        "name": "graphql_batch_probe",
        "description": "GraphQL batching / alias abuse detection (capped). Dry-run default.",
        "parameters": {
            "type": "object",
            "properties": {
                "target_dir": {"type": "string"},
                "url": {"type": "string"},
                "approve": {"type": "boolean", "default": False},
                "force": {"type": "boolean", "default": False},
            },
            "required": ["target_dir", "url"],
            "additionalProperties": False,
        },
    },
    {
        "name": "graphql_authz_probe",
        "description": (
            "GraphQL authz/BOLA probe with session A vs B on a mutation/query. Dry-run default."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "target_dir": {"type": "string"},
                "url": {"type": "string"},
                "query": {"type": "string"},
                "session_a": {"type": "string", "default": "A"},
                "session_b": {"type": "string", "default": "B"},
                "approve": {"type": "boolean", "default": False},
                "force": {"type": "boolean", "default": False},
            },
            "required": ["target_dir", "url", "query"],
            "additionalProperties": False,
        },
    },
    {
        "name": "websocket_authz_probe",
        "description": (
            "WebSocket authz beyond handshake: subscribe/read as A vs B. Dry-run default."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "target_dir": {"type": "string"},
                "url": {"type": "string"},
                "message": {"type": "string"},
                "session": {"type": "string"},
                "approve": {"type": "boolean", "default": False},
                "force": {"type": "boolean", "default": False},
            },
            "required": ["target_dir", "url"],
            "additionalProperties": False,
        },
    },
    {
        "name": "cdn_origin_hint",
        "description": (
            "Passive CDN/origin fingerprint hints (headers/DNS claims) for in-scope hosts. "
            "No origin brute."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "target_dir": {"type": "string"},
                "url": {"type": "string"},
                "approve": {"type": "boolean", "default": False},
                "force": {"type": "boolean", "default": False},
            },
            "required": ["target_dir", "url"],
            "additionalProperties": False,
        },
    },
    {
        "name": "takeover_probe",
        "description": (
            "Subdomain takeover fingerprint / dangling DNS claim check (in-scope only). "
            "No claim registration."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "target_dir": {"type": "string"},
                "host": {"type": "string"},
                "approve": {"type": "boolean", "default": False},
                "force": {"type": "boolean", "default": False},
            },
            "required": ["target_dir", "host"],
            "additionalProperties": False,
        },
    },
    {
        "name": "asset_graph_build",
        "description": (
            "Build hunt/asset_graph.yaml from surface + JS/params/HAR seeds (unify recon graph)."
        ),
        "parameters": {
            "type": "object",
            "properties": {"target_dir": {"type": "string"}},
            "required": ["target_dir"],
            "additionalProperties": False,
        },
    },
    {
        "name": "ssrf_protocol_matrix",
        "description": (
            "SSRF protocol matrix: default http(s) canaries; file/gopher/dict only if SCOPE allows. "
            "Dry-run default."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "target_dir": {"type": "string"},
                "url": {"type": "string"},
                "param": {"type": "string"},
                "approve": {"type": "boolean", "default": False},
                "force": {"type": "boolean", "default": False},
            },
            "required": ["target_dir", "url", "param"],
            "additionalProperties": False,
        },
    },
]

from .api_ai_tool_specs import API_AI_TOOL_SPECS

TOOL_SPECS.extend(API_AI_TOOL_SPECS)


def _safe_path(path: str) -> Path:
    """Resolve a path that must stay under the kit root."""
    p = Path(path)
    if not p.is_absolute():
        p = ROOT / p
    p = p.resolve()
    root = ROOT.resolve()
    if root not in p.parents and p != root:
        raise PermissionError(f"path outside kit: {path}")
    return p


def _readable_path(path: str) -> Path:
    """Resolve a path for reading: kit + home + Downloads/Desktop + HACKBOT_WRITE_DIRS.

    Same allowlist as writable roots (minus sensitive blocklist). Operators often
    point at credential files / screenshots outside the kit — that must work via NL.
    """
    p = Path(path).expanduser()
    if not p.is_absolute():
        # Prefer kit-relative, then home-relative common folders
        kit_try = (ROOT / p).resolve()
        if kit_try.exists():
            p = kit_try
        else:
            home_try = (Path.home() / p).resolve()
            p = home_try if home_try.exists() else kit_try
    else:
        p = p.resolve()
    reason = _path_blocked(p)
    if reason:
        raise PermissionError(reason)
    # Reuse writable-roots allowlist for reads of operator files
    if os.environ.get("HACKBOT_WRITE_ALLOWLIST", "1").strip().lower() not in {
        "0",
        "false",
        "off",
        "no",
    }:
        allowed = False
        for root in _writable_roots():
            try:
                if p == root or p.is_relative_to(root):
                    allowed = True
                    break
            except (AttributeError, TypeError, ValueError):
                if root in p.parents or p == root:
                    allowed = True
                    break
        if not allowed:
            raise PermissionError(
                f"path outside readable roots (kit, home, Downloads/Desktop, "
                f"HACKBOT_WRITE_DIRS): {p}"
            )
    return p


def _resolve_path(path: str) -> Path:
    """Resolve for file mutations. Relative -> kit root; absolute allowed.

    Sensitive roots are hard-blocked. Everything else still needs operator
    approval; the prompt always shows the absolute path.
    """
    p = Path(path)
    if not p.is_absolute():
        p = ROOT / p
    return p.resolve()


def _sensitive_roots() -> list[Path]:
    home = Path.home()
    roots = [
        home / ".ssh",
        home / ".aws",
        home / ".gnupg",
        Path("/etc"),
    ]
    # Windows system config (exists check later)
    windir = Path.home().anchor  # e.g. C:\
    if windir and windir != "/":
        roots.append(Path(windir) / "Windows" / "System32" / "config")
    return roots


def _writable_roots() -> list[Path]:
    """Dirs where file mutations are allowed (kit + home defaults + HACKBOT_WRITE_DIRS)."""
    import tempfile

    roots = [ROOT.resolve(), Path.home().resolve(), Path(tempfile.gettempdir()).resolve()]
    for downloads in (Path.home() / "Downloads", Path.home() / "Desktop"):
        if downloads.exists():
            roots.append(downloads.resolve())
    extra = os.environ.get("HACKBOT_WRITE_DIRS", "")
    for raw in extra.split(os.pathsep):
        raw = raw.strip()
        if not raw:
            continue
        p = Path(raw).expanduser()
        try:
            roots.append(p.resolve())
        except OSError:
            continue
    # Dedup
    out: list[Path] = []
    seen: set[str] = set()
    for r in roots:
        key = str(r).lower()
        if key not in seen:
            out.append(r)
            seen.add(key)
    return out


def _path_blocked(path: Path) -> str | None:
    """Return a reason if path is sensitive or outside writable roots."""
    try:
        resolved = path.resolve()
    except OSError:
        resolved = path
    for root in _sensitive_roots():
        try:
            root_r = root.resolve()
        except OSError:
            root_r = root
        if resolved == root_r or root_r in resolved.parents:
            return f"path under sensitive root: {root_r}"
        try:
            if resolved.is_relative_to(root_r):
                return f"path under sensitive root: {root_r}"
        except (AttributeError, TypeError, ValueError):
            pass
    lowered = str(resolved).replace("\\", "/").lower()
    for marker in ("/.ssh/", "/.aws/", "/.gnupg/", "/etc/"):
        if marker in lowered or lowered.endswith(marker.rstrip("/")):
            return f"path looks sensitive ({marker.strip('/')})"

    # Optional hard allowlist (on by default). Set HACKBOT_WRITE_ALLOWLIST=0 to disable.
    if os.environ.get("HACKBOT_WRITE_ALLOWLIST", "1").strip().lower() not in {
        "0",
        "false",
        "off",
        "no",
    }:
        allowed = False
        for root in _writable_roots():
            try:
                if resolved == root or resolved.is_relative_to(root):
                    allowed = True
                    break
            except (AttributeError, TypeError, ValueError):
                if root in resolved.parents or resolved == root:
                    allowed = True
                    break
        if not allowed:
            return (
                f"path outside writable roots (kit, home, Downloads/Desktop, "
                f"HACKBOT_WRITE_DIRS): {resolved}"
            )
    return None


def _guard_mutate_path(path: Path) -> str | None:
    """If blocked, return JSON error string; else None."""
    reason = _path_blocked(path)
    if reason is None:
        return None
    log_decision("DENY", f"path_blocked {path} ({reason})", kind="path_blocked", tool="fs")
    return json.dumps({"ok": False, "error": reason, "kind": "path_blocked"})


def _preview(text: str, limit: int = 500) -> str:
    text = text.replace("\r\n", "\n")
    if len(text) <= limit:
        return text
    return text[:limit] + f"\n... (+{len(text) - limit} more chars)"


def _domain_arg(args: dict[str, Any]) -> str:
    """Accept domain/host/url for passive OSINT tools (Cursor often sends url)."""
    raw = (
        args.get("domain")
        or args.get("host")
        or args.get("url")
        or args.get("seed")
        or ""
    )
    text = str(raw).strip()
    if not text:
        return ""
    return host_from_target(text) or text.lower().lstrip("*.")


def _active_target_name() -> str:
    s = get_active()
    return s.name if s else ""


def _require_approval(
    approve_fn: ApproveFn | None,
    description: str,
    *,
    kind: str = "approve",
    tool: str = "",
    host: str = "",
    force_override: bool = False,
    aggression: int | None = None,
) -> str | None:
    """Ask the operator. Return a refusal JSON string if denied, else None."""
    target = _active_target_name()
    extra: dict[str, Any] = {}
    if force_override:
        extra["force_override"] = True
    if aggression is not None:
        extra["aggression"] = aggression
    if is_yolo():
        extra["yolo"] = True
        log_decision(
            "ALLOW",
            description,
            kind="yolo_approve",
            target=target,
            tool=tool,
            host=host,
            extra=extra or None,
        )
        return None
    if approve_fn is None:
        log_decision(
            "DENY",
            f"(no approver) {description}",
            kind=kind,
            target=target,
            tool=tool,
            host=host,
            extra=extra or None,
        )
        return json.dumps(
            {
                "ok": False,
                "error": "action needs approval but no approver is attached; denied.",
                "kind": "denied",
            }
        )
    if not approve_fn(description):
        log_decision(
            "DENY",
            description,
            kind=kind,
            target=target,
            tool=tool,
            host=host,
            extra=extra or None,
        )
        return json.dumps({"ok": False, "error": "operator denied this action.", "kind": "denied"})
    log_decision(
        "ALLOW",
        description,
        kind=kind,
        target=target,
        tool=tool,
        host=host,
        extra=extra or None,
    )
    return None


def _unified_diff(old: str, new: str, path: Path, limit: int = 40) -> str:
    import difflib

    lines = list(
        difflib.unified_diff(
            old.splitlines(),
            new.splitlines(),
            fromfile=f"a/{path.name}",
            tofile=f"b/{path.name}",
            lineterm="",
        )
    )
    if not lines:
        return "(no textual diff)"
    if len(lines) > limit:
        return "\n".join(lines[:limit]) + f"\n... (+{len(lines) - limit} diff lines)"
    return "\n".join(lines)


def execute_tool(
    name: str,
    args: dict[str, Any],
    *,
    approve_fn: ApproveFn | None = None,
) -> str:
    try:
        return _execute(name, _normalize_tool_args(name, args or {}), approve_fn=approve_fn)
    except PermissionError as exc:
        ui.warn(f"scope denial: {exc}")
        return json.dumps({"ok": False, "error": str(exc), "kind": "scope_denied"})
    except KeyError as exc:
        key = exc.args[0] if exc.args else "?"
        ui.warn(f"tool args: missing '{key}' for {name}")
        return json.dumps(
            {
                "ok": False,
                "error": f"missing required argument: {key}",
                "kind": "bad_args",
                "tool": name,
            }
        )
    except Exception as exc:
        ui.error(f"tool bug: {type(exc).__name__}: {exc}")
        return json.dumps(
            {"ok": False, "error": f"{type(exc).__name__}: {exc}", "kind": "internal_error"}
        )


def _guess_target_name() -> str:
    """Best-effort program folder when Cursor omits set_target.target."""
    active = get_active()
    if active:
        return active.name
    if not TARGETS.is_dir():
        return ""
    names = sorted(
        p.name
        for p in TARGETS.iterdir()
        if p.is_dir() and p.name not in {"__pycache__", "demo"}
    )
    if len(names) == 1:
        return names[0]
    if "bmwgroup" in names:
        return "bmwgroup"
    return ""


def _normalize_tool_args(name: str, args: dict[str, Any]) -> dict[str, Any]:
    """Fill target_dir/target from the active session when the model omits them."""
    out = dict(args)
    active = get_active()
    active_dir = f"targets/{active.name}" if active else ""

    # Treat blank strings as missing (Cursor sometimes sends target="").
    for key in ("target", "target_dir", "target_name", "program", "name"):
        if key in out and isinstance(out[key], str) and not out[key].strip():
            out.pop(key, None)

    if not out.get("target_dir"):
        alias = out.get("target") or out.get("target_name") or out.get("program") or out.get("name")
        if isinstance(alias, str) and alias.strip():
            cand = alias.strip().replace("\\", "/")
            if cand.startswith("targets/"):
                out["target_dir"] = cand
            elif (ROOT / "targets" / cand).is_dir():
                out["target_dir"] = f"targets/{cand}"
            elif active_dir and cand == active.name:
                out["target_dir"] = active_dir
        elif active_dir:
            # Cursor often calls hunt tools with only url/host — inject active target.
            out["target_dir"] = active_dir

    if not out.get("target"):
        if name == "set_target" and (
            (out.get("target_dir") or "").replace("\\", "/").startswith("targets/")
        ):
            out["target"] = Path(str(out["target_dir"]).replace("\\", "/")).name
        elif name in {"set_target", "write_report_draft", "policy_import"}:
            guessed = _guess_target_name()
            if guessed:
                out["target"] = guessed

    # run_hunt requires prompt — models often omit it; fill a useful default.
    if name == "run_hunt" and not str(out.get("prompt") or "").strip():
        alias = out.get("task") or out.get("goal") or out.get("query") or out.get("instruction")
        if isinstance(alias, str) and alias.strip():
            out["prompt"] = alias.strip()
        else:
            out["prompt"] = (
                "autonomous hunt — keep going until finding candidate, "
                "needs_setup blocker, or budget exhausted"
            )

    # YOLO: coerce active-traffic / force flags so models need not remember them.
    if is_yolo():
        if "approve" in out or name in {
            "run_tool",
            "run_hunt",
            "run_campaign",
            "run_playbook",
            "http_request",
            "map_surface",
            "idor_probe",
            "session_bootstrap",
            "burp_replay",
            "burp_replay_history",
            "discover_paths",
            "browser_navigate",
            "browser_network",
            "browser_with_session",
            "browser_diff_sessions",
            "browser_capture_session",
        }:
            out["approve"] = True
        if name.startswith(
            (
                "sqli_",
                "xss_",
                "lfi_",
                "ssti_",
                "xxe_",
                "ssrf_",
                "cors_",
                "open_redirect",
                "graphql_",
                "jwt_active",
                "oauth_",
                "race_",
                "websocket_",
                "brute_",
                "mass_assignment",
                "method_override",
                "hpp_",
                "second_order",
                "mine_params",
                "analyze_headers",
                "analyze_js",
            )
        ) or name in {
            "http_request",
            "idor_probe",
            "detect_login",
            "session_smoke",
            "crt_subdomains",
            "wayback_urls",
        }:
            out["approve"] = True
        if "force" in out or is_forced():
            out["force"] = True

    return out


def _execute(name: str, args: dict[str, Any], *, approve_fn: ApproveFn | None) -> str:
    if name == "list_targets":
        if not TARGETS.exists():
            return json.dumps({"targets": []})
        names = sorted(p.name for p in TARGETS.iterdir() if p.is_dir() and p.name != "__pycache__")
        return json.dumps({"targets": names})

    if name == "set_target":
        from . import session as sess

        target_name = str(
            args.get("target") or args.get("name") or _guess_target_name() or ""
        ).strip()
        if not target_name:
            available = []
            if TARGETS.is_dir():
                available = sorted(
                    p.name
                    for p in TARGETS.iterdir()
                    if p.is_dir() and p.name != "__pycache__"
                )
            return json.dumps(
                {
                    "ok": False,
                    "error": "target required (e.g. bmwgroup). Call list_targets first.",
                    "kind": "bad_args",
                    "targets": available,
                }
            )
        session = set_active(target_name)
        ui.success(f"active target -> {session.name}")
        ui.info(sess.status_line())
        return json.dumps(
            {
                "ok": True,
                "target": session.name,
                "path": str(session.target_dir),
                "hosts": list(session.in_scope_hosts),
                "next_step": session.next_step,
                "loaded": session.loaded_files,
            }
        )

    if name == "session_status":
        from . import session as sess

        active = get_active()
        if active is None:
            return json.dumps({"ok": True, "active": None, "status": sess.status_line()})
        return json.dumps(
            {
                "ok": True,
                "active": active.name,
                "path": str(active.target_dir),
                "hosts": list(active.in_scope_hosts),
                "next_step": active.next_step,
                "status": sess.status_line(),
                "context": active.context_block()[:4000],
            }
        )

    if name == "lab_exec":
        cmd = str(args.get("command") or "").strip()
        desc = (
            f"LAB EXEC{' (sudo)' if parse_bool(args.get('sudo')) else ''}\n"
            f"  cwd={args.get('cwd') or '.'}\n"
            f"  cmd={cmd[:500]}"
        )
        refusal = _require_approval(approve_fn, desc, kind="lab_exec", tool="lab_exec")
        if refusal:
            return refusal
        result = lab_stack_runner.lab_exec(
            cmd,
            cwd=args.get("cwd"),
            timeout_sec=float(args.get("timeout_sec") or 120),
            sudo=parse_bool(args.get("sudo")),
        )
        return json.dumps(result)

    if name == "stack_prepare":
        result = lab_stack_runner.stack_prepare(
            persist_shell_rc=parse_bool(args.get("persist_shell_rc"))
        )
        return json.dumps(result)

    if name == "burp_ensure":
        desc = (
            "BURP ENSURE\n"
            f"  base={args.get('base_url') or 'http://127.0.0.1:1337'}\n"
            "  start Burp Community + wait for local REST (no target traffic)"
        )
        refusal = _require_approval(approve_fn, desc, kind="lab_exec", tool="burp_ensure")
        if refusal:
            return refusal
        result = lab_stack_runner.burp_ensure(
            base_url=args.get("base_url"),
            wait_sec=float(args.get("wait_sec") or 45),
            download_ext=parse_bool(args.get("download_ext"), default=True),
        )
        return json.dumps(result)

    if name == "capabilities":
        from .capabilities import collect_capabilities, print_capabilities

        caps = collect_capabilities(
            probe_network=parse_bool(args.get("probe_network"), default=True)
        )
        print_capabilities(caps, compact=False)
        return json.dumps(caps)

    if name == "show_identity":
        target = _target_path(args["target_dir"])
        ensure_example(target)
        ident = load_identity(target)
        summary = ident.masked_summary()
        ui.kv("ready_sessions", ", ".join(ident.ready_sessions()) or "(none)")
        ui.kv("program_headers", str(summary["program_header_count"]))
        return json.dumps({"ok": True, **summary})

    if name == "set_session":
        target = _target_path(args["target_dir"])
        name_s = args["name"]
        clear = bool(args.get("clear"))
        desc = (
            f"WRITE session '{name_s}' under\n  {target / 'secrets' / 'sessions.yaml'}"
            + (" (CLEAR)" if clear else " (masked values only in UI)")
        )
        refusal = _require_approval(approve_fn, desc, kind="fs", tool="set_session")
        if refusal:
            return refusal
        ident = save_session(
            target,
            name_s,
            authorization=args.get("authorization"),
            cookie=args.get("cookie"),
            clear=clear,
        )
        return json.dumps({"ok": True, "identity": ident.masked_summary()})

    if name == "set_account":
        target = _target_path(args["target_dir"])
        name_s = str(args.get("name") or "A")
        username = str(args.get("username") or args.get("email") or "").strip()
        password = args.get("password")
        role = args.get("role")
        if not username and password is None:
            return json.dumps(
                {
                    "ok": False,
                    "error": "need username/email and/or password",
                    "hint": "ex: set_account name=A username=a@x.com password=secret",
                }
            )
        desc = (
            f"WRITE account '{name_s}' under\n  {target / 'secrets' / 'accounts.yaml'}\n"
            f"  username={username or '(unchanged)'} password={'***' if password is not None else '(unchanged)'}"
        )
        refusal = _require_approval(approve_fn, desc, kind="fs", tool="set_account")
        if refusal:
            return refusal
        accounts_mod.ensure_accounts_example(target)
        data = accounts_mod.save_account(
            target,
            name_s,
            username=username or None,
            password=str(password) if password is not None else None,
            role=str(role) if role else None,
        )
        acct = data.get(name_s)
        return json.dumps(
            {
                "ok": True,
                "saved": name_s,
                "account": acct.masked() if acct else {},
                **data.masked_summary(),
            }
        )

    if name == "http_request":
        return _tool_http_request(args, approve_fn=approve_fn)

    if name == "idor_probe":
        return _tool_idor_probe(args, approve_fn=approve_fn)

    if name == "session_bootstrap":
        return _tool_session_bootstrap(args, approve_fn=approve_fn)

    if name == "detect_login":
        return _tool_detect_login(args, approve_fn=approve_fn)

    if name == "session_smoke":
        return _tool_session_smoke(args, approve_fn=approve_fn)

    if name == "show_accounts":
        target = _target_path(args["target_dir"])
        accounts_mod.ensure_accounts_example(target)
        return json.dumps({"ok": True, **accounts_mod.load_accounts(target).masked_summary()})

    if name == "extract_page":
        return _tool_extract_page(args, approve_fn=approve_fn)

    if name == "discover_paths":
        return _tool_discover_paths(args, approve_fn=approve_fn)

    if name == "oob_mint":
        return json.dumps(oob_mod.mint_canary(kind=str(args.get("kind") or "ssrf"), tag=str(args.get("tag") or "")))

    if name == "oob_poll":
        canary = args.get("canary")
        if not isinstance(canary, dict):
            canary = {"token": args.get("token") or ""}
        return json.dumps(oob_mod.poll_oob(canary))

    if name == "assert_diff":
        return _tool_assert_diff(args)

    if name == "log_finding":
        return _tool_log_finding(args, approve_fn=approve_fn)

    if name == "update_resume":
        target = _target_path(args["target_dir"])
        path = target / "RESUME.md"
        refusal = _require_approval(
            approve_fn,
            f"UPDATE RESUME.md next step\n  {path}\n  -> {args['next_step'][:200]}",
            kind="fs",
            tool="update_resume",
        )
        if refusal:
            return refusal
        written = update_resume_next_step(
            target,
            args["next_step"],
            accounts_note=args.get("accounts_note") or "",
        )
        return json.dumps({"ok": True, "path": str(written)})

    if name == "open_playbook":
        pb = playbook_for(args["task"])
        md = playbook_markdown(pb, endpoint=args.get("endpoint") or "")
        return json.dumps(
            {
                "ok": True,
                "class": pb.class_name,
                "playbooks_available": list_playbooks(),
                "playbook": md,
            }
        )

    if name == "run_playbook":
        return _run_playbook(args, approve_fn=approve_fn)

    if name == "run_campaign":
        return _run_campaign(args, approve_fn=approve_fn)

    if name == "secrets_scan":
        return _tool_secrets_scan(args, approve_fn=approve_fn)

    if name == "brute_login":
        return _tool_brute_login(args, approve_fn=approve_fn)

    if name == "sqli_probe":
        return _tool_sqli_probe(args, approve_fn=approve_fn)

    if name == "xss_probe":
        return _tool_xss_probe(args, approve_fn=approve_fn)

    if name == "second_order_xss":
        return _tool_second_order_xss(args, approve_fn=approve_fn)

    if name == "map_surface":
        return _tool_map_surface(args, approve_fn=approve_fn)

    if name == "run_hunt":
        return _tool_run_hunt(args, approve_fn=approve_fn)

    if name == "hunt_status":
        from .hunt_controller import hunt_status

        target = _target_path(args["target_dir"])
        return json.dumps({"ok": True, **hunt_status(target)})

    if name == "analyze_js":
        return _tool_analyze_js(args, approve_fn=approve_fn)
    if name == "mine_params":
        return _tool_mine_params(args, approve_fn=approve_fn)
    if name == "analyze_jwt":
        return json.dumps(jwt_analyze_runner.analyze_jwt(args["token"]))
    if name == "graphql_probe":
        return _tool_graphql_probe(args, approve_fn=approve_fn)
    if name == "import_har":
        return _tool_import_har(args)
    if name == "import_openapi":
        from .openapi_parse import ingest_openapi_file

        target = _target_path(args["target_dir"])
        path = Path(args["path"])
        if not path.is_absolute():
            path = ROOT / path
        return json.dumps(
            ingest_openapi_file(
                target,
                path,
                base_url=str(args.get("base_url") or ""),
                host=host_from_target(str(args.get("base_url") or "")) or "",
            )
        )
    if name == "import_postman":
        from .postman_parse import ingest_postman_file

        target = _target_path(args["target_dir"])
        path = Path(args["path"])
        if not path.is_absolute():
            path = ROOT / path
        env_raw = str(args.get("environment_path") or "").strip()
        env_path = Path(env_raw) if env_raw else None
        if env_path and not env_path.is_absolute():
            env_path = ROOT / env_path
        return json.dumps(
            ingest_postman_file(
                target,
                path,
                base_url=str(args.get("base_url") or ""),
                environment_path=env_path,
            )
        )
    if name == "cors_probe":
        return _tool_cors_probe(args, approve_fn=approve_fn)
    if name == "open_redirect_probe":
        return _tool_open_redirect(args, approve_fn=approve_fn)
    if name == "analyze_headers":
        return _tool_analyze_headers(args, approve_fn=approve_fn)
    if name == "crt_subdomains":
        domain = _domain_arg(args)
        if not domain:
            return json.dumps({"ok": False, "error": "domain required"})
        return json.dumps(web_probes_runner.crt_subdomains(domain))
    if name == "wayback_urls":
        domain = _domain_arg(args)
        if not domain:
            return json.dumps({"ok": False, "error": "domain required"})
        save_dir: Path | None = None
        tdir = args.get("target_dir") or ""
        if tdir:
            save_dir = _target_path(str(tdir))
        else:
            active = get_active()
            if active:
                save_dir = active.target_dir
        return json.dumps(
            web_probes_runner.wayback_urls(
                domain,
                limit=int(args.get("limit") or 100),
                save_dir=save_dir,
            )
        )
    if name == "list_dir":
        return _tool_list_dir(args)

    if name == "lfi_probe":
        return _tool_param_probe("lfi_probe", lfi_probe_runner.lfi_probe, args, approve_fn=approve_fn, default_param="file", aggression=2)
    if name == "ssti_probe":
        return _tool_param_probe("ssti_probe", ssti_probe_runner.ssti_probe, args, approve_fn=approve_fn, default_param="q", aggression=2)
    if name == "ssrf_probe":
        return _tool_param_probe("ssrf_probe", ssrf_probe_runner.ssrf_probe, args, approve_fn=approve_fn, default_param="url", aggression=2)
    if name == "xxe_probe":
        return _tool_xxe(args, approve_fn=approve_fn)
    if name == "race_probe":
        return _tool_race_probe(args, approve_fn=approve_fn)
    if name == "websocket_probe":
        return _tool_websocket_probe(args, approve_fn=approve_fn)
    if name == "jwt_active_probe":
        return _tool_jwt_active(args, approve_fn=approve_fn)
    if name == "oauth_probe":
        return _tool_oauth(args, approve_fn=approve_fn)
    if name == "build_chains":
        from .chain_builder import build_chains

        target = _target_path(args["target_dir"])
        result = build_chains(target)
        if result.get("report_md"):
            ui.markdown_panel(str(result["report_md"]), title="exploit chains")
        return json.dumps(result)
    if name == "browser_hint":
        if browser_runner.playwright_available():
            return json.dumps(
                {
                    "ok": True,
                    "wired": True,
                    "task": args.get("task"),
                    "message": (
                        "Playwright is available. Use browser_navigate / "
                        "browser_screenshot / browser_eval / browser_cookies / "
                        "browser_storage / browser_network / browser_console / "
                        "browser_set_cookie with approve."
                    ),
                    "tools": [
                        "browser_navigate",
                        "browser_screenshot",
                        "browser_eval",
                        "browser_cookies",
                        "browser_storage",
                        "browser_network",
                        "browser_console",
                        "browser_set_cookie",
                    ],
                }
            )
        return json.dumps(
            {
                "ok": True,
                "wired": False,
                "task": args.get("task"),
                "message": (
                    "Playwright not installed. pip install playwright && "
                    "playwright install chromium. Meanwhile: HAR + http_request/assert_diff."
                ),
            }
        )
    if name == "browser_capture_session":
        return _tool_browser_capture_session(args, approve_fn=approve_fn)
    if name == "browser_navigate":
        return _tool_browser("navigate", args, approve_fn=approve_fn)
    if name == "browser_screenshot":
        return _tool_browser("screenshot", args, approve_fn=approve_fn)
    if name == "browser_eval":
        return _tool_browser("eval", args, approve_fn=approve_fn)
    if name == "browser_cookies":
        return _tool_browser("cookies", args, approve_fn=approve_fn)
    if name == "browser_storage":
        return _tool_browser("storage", args, approve_fn=approve_fn)
    if name == "browser_network":
        return _tool_browser("network", args, approve_fn=approve_fn)
    if name == "browser_with_session":
        return _tool_browser("with_session", args, approve_fn=approve_fn)
    if name == "browser_diff_sessions":
        return _tool_browser("diff_sessions", args, approve_fn=approve_fn)
    if name == "browser_console":
        return _tool_browser("console", args, approve_fn=approve_fn)
    if name == "browser_set_cookie":
        return _tool_browser("set_cookie", args, approve_fn=approve_fn)
    if name == "import_burp_xml":
        return _tool_import_burp_xml(args)
    if name == "burp_rest_health":
        return json.dumps(
            burp.burp_rest_health(base_url=args.get("base_url") or "http://127.0.0.1:1337")
        )
    if name == "burp_proxy_history":
        return json.dumps(
            burp.burp_proxy_history(
                base_url=args.get("base_url") or "http://127.0.0.1:1337",
                limit=int(args.get("limit") or 20),
            )
        )
    if name == "burp_issue_list":
        return json.dumps(
            burp.burp_issue_list(
                base_url=args.get("base_url") or "http://127.0.0.1:1337",
                limit=int(args.get("limit") or 20),
            )
        )
    if name == "burp_replay":
        return _tool_burp_replay(args, approve_fn=approve_fn)
    if name == "burp_replay_history":
        return _tool_burp_replay_history(args, approve_fn=approve_fn)
    if name == "interactsh_status":
        from .interactsh_client import interactsh_status

        return json.dumps(interactsh_status())
    if name == "interactsh_register":
        from .interactsh_client import interactsh_register

        return json.dumps(interactsh_register())
    if name == "interactsh_poll":
        from .interactsh_client import interactsh_poll

        canary = args.get("canary") if isinstance(args.get("canary"), dict) else None
        return json.dumps(interactsh_poll(canary, wait=bool(args.get("wait", True))))
    if name == "cdp_attach":
        return json.dumps(
            browser_runner.cdp_attach(
                args.get("cdp_url") or "http://127.0.0.1:9222",
                approve=parse_bool(args.get("approve")),
            )
        )
    if name == "hunt_checklist":
        from .hunt_telemetry import prehunt_checklist

        return json.dumps(prehunt_checklist(_target_path(args["target_dir"])))
    if name == "hunt_pause":
        from .hunt_telemetry import request_pause

        request_pause(_target_path(args["target_dir"]))
        return json.dumps({"ok": True, "paused": True})
    if name == "hunt_resume_flag":
        from .hunt_telemetry import clear_pause

        clear_pause(_target_path(args["target_dir"]))
        return json.dumps({"ok": True, "paused": False})
    if name == "hunt_telemetry":
        from .hunt_telemetry import telemetry_stats

        return json.dumps(telemetry_stats(_target_path(args["target_dir"])))
    if name == "submit_ready":
        target = _target_path(args["target_dir"])
        fid = str(args.get("finding_id") or "latest")
        update_resume_next_step(
            target,
            f"HUMAN SUBMIT GATE: draft ready for {fid} — review PoC, then submit manually to the program portal. Never auto-submit.",
            accounts_note="Confirm A/B evidence still valid before submit.",
        )
        return json.dumps(
            {
                "ok": True,
                "finding_id": fid,
                "message": "RESUME marked submit-ready for human operator (no platform API call).",
            }
        )
    if name == "mass_assignment_probe":
        from .runners import advanced_http as adv

        return _tool_simple_probe(
            "mass_assignment_probe",
            adv.mass_assignment_probe,
            args,
            approve_fn=approve_fn,
            aggression=2,
        )
    if name == "method_override_probe":
        from .runners import advanced_http as adv

        return _tool_simple_probe(
            "method_override_probe",
            adv.method_override_probe,
            args,
            approve_fn=approve_fn,
            aggression=2,
        )
    if name == "hpp_probe":
        from .runners import advanced_http as adv

        target = _target_path(args["target_dir"])
        approve = parse_bool(args.get("approve"))
        force = _resolve_force_arg(args)
        if approve:
            refusal = _require_approval(
                approve_fn,
                f"Approve ACTIVE hpp_probe?\n  url={args['url']}",
                kind="active_traffic",
                tool="hpp_probe",
                host=host_from_target(args["url"]),
                force_override=force,
                aggression=2,
            )
            if refusal:
                return refusal
        result = adv.hpp_probe(
            target,
            args["url"],
            param=str(args.get("param") or "id"),
            approve=approve,
            force=force,
            session=str(args.get("session") or "A"),
        )
        try:
            payload = json.loads(result.stdout) if result.stdout else {}
        except json.JSONDecodeError:
            payload = {}
        return json.dumps(
            {
                "ok": True,
                "executed": result.executed,
                "signal": bool(payload.get("signal")),
                "detail": payload,
                "message": result.message,
            }
        )
    if name == "learn_record":
        from .learning import record_technique

        path = record_technique(
            program=args["program"],
            module=args["module"],
            summary=args["summary"],
            host=args.get("host") or "",
            outcome=args.get("outcome") or "signal",
        )
        return json.dumps({"ok": True, "path": str(path)})
    if name == "learn_suggest":
        from .learning import list_techniques, suggest_for_host

        if args.get("module") or args.get("program"):
            rows = list_techniques(
                module=args.get("module") or "",
                program=args.get("program") or "",
            )
            return json.dumps({"ok": True, "techniques": rows})
        return json.dumps(suggest_for_host(args.get("host") or ""))
    if name == "learn_stats":
        from .learning import learn_stats

        return json.dumps({"ok": True, **learn_stats()})
    if name in {"mobile_hint", "mobile_status"}:
        return json.dumps(mobile_runner.mobile_hint(str(args.get("task") or "")))
    if name == "adb_devices":
        return json.dumps(mobile_runner.adb_devices())
    if name == "inspect_apk":
        target = _target_path(args["target_dir"])
        try:
            path = _readable_path(args["path"])
        except PermissionError as exc:
            return json.dumps({"ok": False, "error": str(exc), "kind": "path_blocked"})
        return json.dumps(mobile_runner.inspect_apk(target, path))
    if name == "mobile_bridge":
        return _tool_mobile_bridge(args, approve_fn=approve_fn)
    if name == "mobsf_health":
        return json.dumps(mobsf_runner.mobsf_health(base_url=args.get("base_url") or ""))
    if name == "mobsf_upload":
        return _tool_mobsf_upload(args, approve_fn=approve_fn)
    if name == "mobsf_scan":
        return _tool_mobsf_scan(args, approve_fn=approve_fn)
    if name == "frida_status":
        return json.dumps(frida_runner.frida_status())
    if name == "frida_list_apps":
        return json.dumps(frida_runner.frida_list_apps())
    if name == "frida_run_script":
        return _tool_frida_run_script(args, approve_fn=approve_fn)
    if name == "objection_explore":
        return _tool_objection_explore(args, approve_fn=approve_fn)

    if name == "import_policy":
        write = bool(args.get("write"))
        meta, rendered, scope_path = import_policy_to_target(
            args["target"], args["policy_text"], write=False
        )
        if write:
            refusal = _require_approval(
                approve_fn,
                f"WRITE imported SCOPE.md to\n  {scope_path}\n--- preview ---\n{_preview(rendered, 800)}",
                kind="fs",
                tool="import_policy",
            )
            if refusal:
                return refusal
            scope_path.parent.mkdir(parents=True, exist_ok=True)
            scope_path.write_text(rendered, encoding="utf-8")
            try:
                set_active(args["target"])
            except FileNotFoundError:
                pass
        return json.dumps(
            {
                "ok": True,
                "written": write,
                "path": str(scope_path),
                "meta": meta,
                "preview": rendered[:3000],
            }
        )

    if name == "read_file":
        try:
            path = _readable_path(args["path"])
        except PermissionError as exc:
            return json.dumps({"ok": False, "error": str(exc), "kind": "path_blocked"})
        if not path.exists():
            return json.dumps({"ok": False, "error": "missing", "path": str(path)})
        if path.suffix.lower() in {
            ".png",
            ".jpg",
            ".jpeg",
            ".webp",
            ".gif",
            ".bmp",
        }:
            return json.dumps(
                {
                    "ok": False,
                    "error": "path is an image — use read_image",
                    "path": str(path),
                    "hint": "call read_image",
                }
            )
        max_chars = int(args.get("max_chars") or 8000)
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            text = handle.read(max_chars + 1)
        truncated = len(text) > max_chars
        if truncated:
            text = text[:max_chars]
        return json.dumps(
            {
                "ok": True,
                "path": str(path),
                "text": text,
                "truncated": truncated,
            }
        )

    if name == "read_image":
        return _tool_read_image(args)

    if name == "load_sessions_from_file":
        return _tool_load_sessions_from_file(args, approve_fn=approve_fn)

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

    if name == "show_config":
        from .config import get_config

        cfg = get_config(reload=parse_bool(args.get("reload")))
        return json.dumps({"ok": True, **cfg.to_public_dict()})

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
        try:
            saved = EvidenceStore(target).save(args["name"], args["text"])
        except StrictRedactError as exc:
            return json.dumps(
                {"ok": False, "error": str(exc), "kind": "strict_redact", "reasons": exc.reasons}
            )
        return json.dumps({"ok": True, "path": str(saved)})

    if name == "redact":
        return json.dumps({"text": redact_text(args["text"])})

    if name == "write_report_draft":
        target = Path(args["target_dir"])
        if not target.is_absolute():
            target = ROOT / target
        platform = normalize_platform(args.get("platform") or "generic")
        title = args.get("title") or "Finding"
        target_asset = args.get("target") or "TBD"
        preconditions = args.get("preconditions") or "Two test accounts in-scope"
        steps = args.get("steps") or "1. ..."
        impact = args.get("impact") or "TBD"
        evidence = args.get("evidence") or "See evidence/safe/"
        vuln_type = args.get("vuln_type") or args.get("weakness") or args.get("vrt") or "TBD"
        observed = ""
        severity_hint = ""
        cvss_vector = ""
        fid = args.get("finding_id") or "latest"
        found = parse_finding_by_id(target, fid)
        vrt_arg = args.get("vrt") or ""
        if found:
            filled = report_fields_from_finding(found)
            title = filled["title"] or title
            target_asset = filled["target"] or target_asset
            preconditions = filled["preconditions"]
            steps = filled["steps"]
            impact = filled["impact"]
            evidence = filled["evidence"]
            vuln_type = filled.get("vuln_type") or vuln_type
            observed = filled.get("observed") or ""
            severity_hint = filled.get("severity_hint") or ""
            cvss_vector = filled.get("cvss_vector") or ""
            vrt_arg = vrt_arg or filled.get("vrt") or ""
        if not severity_hint:
            from .severity import severity_for_class

            sev = severity_for_class(vuln_type)
            severity_hint = sev.line()
            cvss_vector = sev.vector
        if not vrt_arg:
            from .severity import vrt_for_class

            vrt_arg = vrt_for_class(vuln_type)
        body = render_report(
            platform,
            title=title,
            target=target_asset,
            preconditions=preconditions,
            steps=steps,
            impact=impact,
            evidence=evidence,
            vuln_type=vuln_type,
            vrt=vrt_arg or vuln_type,
            weakness=args.get("weakness") or vuln_type,
            observed=observed,
            severity_hint=severity_hint,
            cvss_vector=cvss_vector,
        )
        body = redact_text(body)
        if strict_enabled():
            reasons = strict_check(body)
            if reasons:
                return json.dumps(
                    {
                        "ok": False,
                        "error": "; ".join(reasons),
                        "kind": "strict_redact",
                        "reasons": reasons,
                    }
                )
        out = target / "reports" / f"{platform}_draft.md"
        refusal = _require_approval(
            approve_fn,
            f"WRITE bug-bounty report draft ({platform}) to\n  {out}",
            kind="fs",
            tool="write_report_draft",
        )
        if refusal:
            return refusal
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(body, encoding="utf-8")
        return json.dumps(
            {
                "ok": True,
                "path": str(out),
                "platform": platform,
                "finding_id": (found or {}).get("finding_id") if found else None,
                "severity_hint": severity_hint,
                "cvss_vector": cvss_vector,
                "vrt": vrt_arg or vuln_type,
                "hint": (
                    "Submit-ready draft (HUMAN SUBMIT GATE — paste into the portal). "
                    "Bugcrowd VRT + minimal PoC + CVSS hints from bug class; triage before submit."
                ),
            }
        )

    if name == "write_file":
        path = _resolve_path(args["path"])
        blocked = _guard_mutate_path(path)
        if blocked:
            return blocked
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
        blocked = _guard_mutate_path(path)
        if blocked:
            return blocked
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
        blocked = _guard_mutate_path(path)
        if blocked:
            return blocked
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
        updated = text.replace(old, new) if replace_all else text.replace(old, new, 1)
        diff = _unified_diff(text, updated, path)
        desc = (
            f"EDIT file\n  {path}\n"
            + (f"(applies to {count} occurrences)\n" if replace_all else "")
            + f"--- diff ---\n{diff}"
        )
        refusal = _require_approval(approve_fn, desc, kind="fs", tool="edit_file")
        if refusal:
            return refusal
        path.write_text(updated, encoding="utf-8")
        return json.dumps({"ok": True, "path": str(path), "replacements": count if replace_all else 1})

    if name == "delete_path":
        path = _resolve_path(args["path"])
        blocked = _guard_mutate_path(path)
        if blocked:
            return blocked
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
        blocked = _guard_mutate_path(path)
        if blocked:
            return blocked
        desc = f"CREATE directory\n  {path}"
        refusal = _require_approval(approve_fn, desc)
        if refusal:
            return refusal
        path.mkdir(parents=True, exist_ok=True)
        return json.dumps({"ok": True, "path": str(path)})

    if name == "move_path":
        src = _resolve_path(args["src"])
        dst = _resolve_path(args["dst"])
        blocked = _guard_mutate_path(src) or _guard_mutate_path(dst)
        if blocked:
            return blocked
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
        # Aliases for controlled level-3 probe
        if tool in {"dos", "stress"}:
            tool = "rate_probe"
        host = args["host"]
        approve = parse_bool(args.get("approve"))
        force = _resolve_force_arg(args)

        action_label = tool if tool != "rate_probe" else "rate-limit testing dos stress"
        policy = ScopePolicy.load(target)
        gate = policy.assert_action_allowed(host_from_target(host), action_label, force=force)
        for w in gate.get("warnings") or []:
            ui.warn(str(w))
        if gate.get("force_override"):
            ui.warn("FORCE override active — operator responsibility")

        if approve:
            prompt = (
                f"Approve ACTIVE traffic?\n  tool={tool}\n  host={host}\n  "
                f"target={target}\n  aggression={gate.get('aggression')}\n  "
                f"force={bool(gate.get('force_override'))}"
            )
            refusal = _require_approval(
                approve_fn,
                prompt,
                kind="active_traffic",
                tool=tool,
                host=host,
                force_override=bool(gate.get("force_override")),
                aggression=int(gate.get("aggression") or 0),
            )
            if refusal:
                return refusal
        if tool == "httpx":
            result = projectdiscovery.httpx_probe(target, host, approve=approve, force=force)
        elif tool == "katana":
            result = projectdiscovery.katana_crawl(target, host, approve=approve, force=force)
        elif tool == "nuclei":
            result = projectdiscovery.nuclei_scan(target, host, approve=approve, force=force)
        elif tool == "ffuf":
            wordlist = args.get("wordlist")
            if not wordlist:
                return json.dumps({"ok": False, "error": "wordlist required for ffuf"})
            result = projectdiscovery.ffuf_dir(
                target, host, wordlist, approve=approve, force=force
            )
        elif tool == "reconftw":
            result = reconftw.run_recon(target, host, approve=approve, force=force)
        elif tool == "hexstrike":
            result = hexstrike.start_server(approve=approve)
        elif tool == "burp":
            xml = args.get("burp_xml")
            if not xml:
                return json.dumps({"ok": False, "error": "burp_xml required"})
            result = burp.summarize_xml(target, Path(xml), approve=approve)
        elif tool == "rate_probe":
            result = rate_probe.rate_probe(
                target,
                host,
                concurrency=int(args.get("concurrency") or 5),
                total=int(args.get("total") or 25),
                timeout=float(args.get("timeout") or 5.0),
                method=str(args.get("method") or "GET"),
                approve=approve,
                force=force,
            )
        else:
            return json.dumps({"ok": False, "error": f"unknown tool {tool}"})
        return json.dumps(
            {
                "ok": True,
                "executed": result.executed,
                "message": result.message,
                "returncode": result.returncode,
                "command": result.command,
                "force_override": bool(gate.get("force_override")),
                "aggression": gate.get("aggression"),
                "stdout": (result.stdout or "")[:4000],
                "stderr": (result.stderr or "")[:2000],
            }
        )

    from .elite_dispatch import dispatch_elite

    elite = dispatch_elite(
        name, args, approve_fn=approve_fn, require_approval=_require_approval
    )
    if elite is not None:
        return elite

    return json.dumps({"ok": False, "error": f"unknown tool {name}"})


def _resolve_force_arg(args: dict[str, Any]) -> bool:
    if "force" not in args or args.get("force") is None:
        return is_forced()
    if args.get("force") is False:
        return is_forced()
    return bool(parse_bool(args.get("force"), default=False) or is_forced())


def _target_path(value: str) -> Path:
    target = Path(value)
    if not target.is_absolute():
        target = ROOT / target
    return target


def _cache_key(target_dir: Path, label: str) -> str:
    return f"{target_dir.resolve()}::{label}"


def _headers_for_model(raw: Any) -> dict[str, str]:
    """Normalize runner headers (dict or legacy JSON string) for tool results."""
    if isinstance(raw, dict):
        return {str(k): str(v)[:800] for k, v in list(raw.items())[:60]}
    if isinstance(raw, str) and raw.strip():
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            return {}
        if isinstance(parsed, dict):
            return {str(k): str(v)[:800] for k, v in list(parsed.items())[:60]}
    return {}


def _tool_http_request(args: dict[str, Any], *, approve_fn: ApproveFn | None) -> str:
    target = _target_path(args["target_dir"])
    url = args["url"]
    approve = parse_bool(args.get("approve"))
    force = _resolve_force_arg(args)
    session = args.get("session")
    label = args.get("label") or (f"{session}" if session else "anon")

    if approve:
        refusal = _require_approval(
            approve_fn,
            f"Approve ACTIVE http_request?\n  url={url}\n  session={session}\n  "
            f"method={args.get('method') or 'GET'}\n  force={force}",
            kind="active_traffic",
            tool="http_request",
            host=host_from_target(url),
            force_override=force,
            aggression=2,
        )
        if refusal:
            return refusal

    result = http_request_runner.http_request(
        target,
        url,
        method=str(args.get("method") or "GET"),
        session=session,
        body=args.get("body"),
        content_type=args.get("content_type"),
        approve=approve,
        force=force,
        label=label,
        use_jar=parse_bool(args.get("use_jar"), default=True),
    )
    payload: dict[str, Any]
    try:
        payload = json.loads(result.stdout) if result.stdout else {"dry_run": True}
    except json.JSONDecodeError:
        payload = {"raw": result.stdout}

    saved_body = ""
    looks_js = False
    if result.executed and isinstance(payload, dict):
        _RESPONSE_CACHE[_cache_key(target, label)] = payload
        # Redacted evidence copy (no full secrets)
        try:
            safe_name = f"http_{label}_{payload.get('status', 'x')}.json"
            EvidenceStore(target).save(
                safe_name,
                json.dumps(
                    {k: payload.get(k) for k in (
                        "method", "url", "final_url", "session", "label", "status",
                        "elapsed_ms", "length", "sha256", "headers",
                        "body_preview", "error",
                    )},
                    indent=2,
                ),
            )
        except StrictRedactError:
            pass
        # Persist full JS/text bodies for later read_file / analyze_js (preview alone
        # truncates and made Codex think the file was incomplete).
        body_full = str(payload.get("body") or "")
        url_l = str(payload.get("url") or url or "").lower()
        hdrs_blob = payload.get("headers") or {}
        looks_js = url_l.endswith(".js") or ".js?" in url_l or (
            "javascript" in str(hdrs_blob).lower()
        )
        if body_full and (looks_js or len(body_full) > 4000):
            try:
                from urllib.parse import urlparse

                host = urlparse(str(payload.get("url") or url)).hostname or "asset"
                base = Path(str(payload.get("url") or url)).name.split("?")[0] or "body.txt"
                if looks_js and not base.endswith(".js"):
                    base = base + ".js"
                safe_base = "".join(c if c.isalnum() or c in "._-" else "_" for c in base)[:80]
                out_dir = Path(target) / "recon" / "http_bodies"
                out_dir.mkdir(parents=True, exist_ok=True)
                out_path = out_dir / f"{host}_{safe_base}"
                out_path.write_text(body_full, encoding="utf-8", errors="replace")
                saved_body = str(out_path).replace("\\", "/")
            except OSError:
                saved_body = ""

    preview_cap = 4000 if looks_js or saved_body else 1500
    hops = payload.get("redirect_hops") or []
    if isinstance(hops, list) and len(hops) > 6:
        hops = hops[:6]
    headers = _headers_for_model(payload.get("headers"))
    return json.dumps(
        {
            "ok": result.returncode in (None, 0) or not result.executed,
            "executed": result.executed,
            "message": result.message if not result.executed else "executed",
            "label": label,
            "method": payload.get("method") or args.get("method") or "GET",
            "url": payload.get("url") or url,
            "final_url": payload.get("final_url") or payload.get("url") or url,
            "status": payload.get("status"),
            "elapsed_ms": payload.get("elapsed_ms"),
            "length": payload.get("length"),
            "sha256": payload.get("sha256"),
            "headers": headers,
            "redirect_hops": hops,
            "body_preview": (payload.get("body_preview") or "")[:preview_cap],
            "saved_body": saved_body,
            "hint": (
                f"full body saved — call read_file path={saved_body}"
                if saved_body
                else (
                    "HEAD has no body; headers are in the headers field. "
                    "Use GET if you also need a response body."
                    if str(payload.get("method") or args.get("method") or "GET").upper()
                    == "HEAD"
                    else ""
                )
            ),
            "error": payload.get("error") or result.stderr,
        }
    )


def _tool_idor_probe(args: dict[str, Any], *, approve_fn: ApproveFn | None) -> str:
    target = _target_path(args["target_dir"])
    url = args["url"]
    approve = parse_bool(args.get("approve"))
    force = _resolve_force_arg(args)
    if approve:
        refusal = _require_approval(
            approve_fn,
            f"Approve ACTIVE idor_probe A/B?\n  url={url}\n  force={force}",
            kind="active_traffic",
            tool="idor_probe",
            host=host_from_target(url),
            force_override=force,
            aggression=2,
        )
        if refusal:
            return refusal
    result = idor_probe_runner.idor_probe(
        target,
        url,
        param=str(args.get("param") or ""),
        swap_value=str(args.get("swap_value") or ""),
        session_a=str(args.get("session_a") or "A"),
        session_b=str(args.get("session_b") or "B"),
        approve=approve,
        force=force,
        use_jar=parse_bool(args.get("use_jar"), default=False),
        method=str(args.get("method") or "GET"),
        methods=str(args.get("methods") or ""),
        body=str(args.get("body") or ""),
        matrix=str(args.get("matrix") or "bola"),
    )
    try:
        payload = json.loads(result.stdout) if result.stdout else {}
    except json.JSONDecodeError:
        payload = {"raw": result.stdout}
    # Cache A/B labels if present for follow-up assert_diff
    if result.executed and isinstance(payload, dict):
        _RESPONSE_CACHE[_cache_key(target, "idor_A")] = {
            "status": payload.get("status_a"),
            "body": payload.get("preview_a") or "",
            "url": payload.get("url_a"),
        }
        _RESPONSE_CACHE[_cache_key(target, "idor_B")] = {
            "status": payload.get("status_b"),
            "body": payload.get("preview_b") or "",
            "url": payload.get("url_b"),
        }
    return json.dumps(
        {
            "ok": payload.get("ok", True) if isinstance(payload, dict) else True,
            "executed": result.executed,
            "signal": bool(payload.get("signal")) if isinstance(payload, dict) else False,
            "verdict": payload.get("verdict") if isinstance(payload, dict) else None,
            "reason": payload.get("reason") if isinstance(payload, dict) else "",
            "detail": payload,
            "message": result.message,
        }
    )


def _tool_extract_page(args: dict[str, Any], *, approve_fn: ApproveFn | None) -> str:
    target = _target_path(args["target_dir"])
    url = str(args["url"])
    force = _resolve_force_arg(args)
    approve = parse_bool(args.get("approve"))
    if approve:
        refusal = _require_approval(
            approve_fn,
            f"Approve ACTIVE extract_page?\n  url={url}\n  force={force}",
            kind="active_traffic",
            tool="extract_page",
            host=host_from_target(url),
            force_override=force,
            aggression=1,
        )
        if refusal:
            return refusal
    result = extract_page_runner.extract_page(
        target,
        url,
        approve=approve,
        force=force,
        session=str(args.get("session") or ""),
        save=parse_bool(args.get("save"), default=True),
        render=(
            None
            if args.get("render") is None
            else parse_bool(args.get("render"), default=False)
        ),
    )
    try:
        payload = json.loads(result.stdout) if result.stdout else {}
    except json.JSONDecodeError:
        payload = {"raw": result.stdout}
    if isinstance(payload, dict):
        return json.dumps({"ok": payload.get("ok", True), "executed": result.executed, **payload})
    return json.dumps({"ok": True, "executed": result.executed, "detail": payload})


def _tool_detect_login(args: dict[str, Any], *, approve_fn: ApproveFn | None) -> str:
    from .login_detect import detect_login

    target = _target_path(args["target_dir"])
    base_url = str(args.get("base_url") or args.get("url") or "")
    approve = parse_bool(args.get("approve"))
    force = _resolve_force_arg(args)
    persist = parse_bool(args.get("persist"))
    if approve:
        refusal = _require_approval(
            approve_fn,
            f"Approve ACTIVE detect_login?\n  base={base_url}\n  persist={persist}\n  force={force}",
            kind="active_traffic",
            tool="detect_login",
            host=host_from_target(base_url),
            force_override=force,
            aggression=1,
        )
        if refusal:
            return refusal
    payload = detect_login(
        target,
        base_url,
        approve=approve,
        force=force,
        persist=persist and approve,
    )
    return json.dumps(payload)


def _tool_session_smoke(args: dict[str, Any], *, approve_fn: ApproveFn | None) -> str:
    from .auth_continuity import session_smoke

    target = _target_path(args["target_dir"])
    base_url = str(args.get("base_url") or args.get("url") or "")
    approve = parse_bool(args.get("approve"))
    force = _resolve_force_arg(args)
    if approve:
        refusal = _require_approval(
            approve_fn,
            f"Approve ACTIVE session_smoke?\n  base={base_url}\n  session={args.get('session') or 'A'}\n  force={force}",
            kind="active_traffic",
            tool="session_smoke",
            host=host_from_target(base_url),
            force_override=force,
            aggression=1,
        )
        if refusal:
            return refusal
    payload = session_smoke(
        target,
        base_url,
        session=str(args.get("session") or "A"),
        approve=approve,
        force=force,
        smoke_path=str(args.get("smoke_path") or ""),
    )
    return json.dumps(payload)


def _tool_session_bootstrap(args: dict[str, Any], *, approve_fn: ApproveFn | None) -> str:
    target = _target_path(args["target_dir"])
    base_url = args.get("base_url") or args.get("url") or ""
    approve = parse_bool(args.get("approve"))
    force = _resolve_force_arg(args)
    if approve:
        refusal = _require_approval(
            approve_fn,
            f"Approve ACTIVE session_bootstrap login?\n  base={base_url}\n  force={force}",
            kind="active_traffic",
            tool="session_bootstrap",
            host=host_from_target(base_url),
            force_override=force,
            aggression=2,
        )
        if refusal:
            return refusal
    result = session_bootstrap_runner.session_bootstrap(
        target, base_url, approve=approve, force=force
    )
    try:
        payload = json.loads(result.stdout) if result.stdout else {}
    except json.JSONDecodeError:
        payload = {"raw": result.stdout}
    return json.dumps(
        {
            "ok": payload.get("ok", True) if isinstance(payload, dict) else True,
            "executed": result.executed,
            "signal": bool(payload.get("signal")) if isinstance(payload, dict) else False,
            "needs_setup": bool(payload.get("needs_setup")) if isinstance(payload, dict) else False,
            "reason": payload.get("reason") if isinstance(payload, dict) else "",
            "detail": payload,
            "message": result.message,
        }
    )


def _tool_discover_paths(args: dict[str, Any], *, approve_fn: ApproveFn | None) -> str:
    target = _target_path(args["target_dir"])
    base_url = args.get("base_url") or args.get("url") or ""
    approve = parse_bool(args.get("approve"))
    force = _resolve_force_arg(args)
    if approve:
        refusal = _require_approval(
            approve_fn,
            f"Approve ACTIVE discover_paths?\n  base={base_url}\n  force={force}",
            kind="active_traffic",
            tool="discover_paths",
            host=host_from_target(base_url),
            force_override=force,
            aggression=1,
        )
        if refusal:
            return refusal
    result = content_discovery_runner.discover_paths(
        target,
        base_url,
        approve=approve,
        force=force,
        limit=int(args.get("limit") or 40),
        seed_surface=bool(args.get("seed_surface", True)),
    )
    try:
        payload = json.loads(result.stdout) if result.stdout else {}
    except json.JSONDecodeError:
        payload = {"raw": result.stdout}
    return json.dumps(
        {
            "ok": True,
            "executed": result.executed,
            "signal": bool(payload.get("signal")),
            "reason": payload.get("reason") or "",
            "detail": payload,
            "message": result.message,
        }
    )


def _tool_assert_diff(args: dict[str, Any]) -> str:
    target = _target_path(args["target_dir"])
    label_a = args["label_a"]
    label_b = args["label_b"]
    resp_a = _RESPONSE_CACHE.get(_cache_key(target, label_a))
    resp_b = _RESPONSE_CACHE.get(_cache_key(target, label_b))
    if not resp_a or not resp_b:
        return json.dumps(
            {
                "ok": False,
                "error": (
                    f"missing cached responses for {label_a!r} and/or {label_b!r}. "
                    "Run http_request with those labels first (same process)."
                ),
                "kind": "missing_cache",
            }
        )
    diff = assert_idor_diff(
        resp_a,
        resp_b,
        object_hint=args.get("object_hint") or "",
    )
    ui.kv("verdict", diff.verdict)
    ui.info(diff.reason)
    evidence_path = ""
    try:
        evidence_path = str(
            EvidenceStore(target).save(
                f"diff_{label_a}_vs_{label_b}.json",
                json.dumps(diff.as_dict(), indent=2),
            )
        )
    except StrictRedactError as exc:
        return json.dumps({"ok": False, "error": str(exc), "kind": "strict_redact"})

    return json.dumps(
        {
            "ok": True,
            "verdict": diff.verdict,
            "reason": diff.reason,
            "diff": diff.as_dict(),
            "evidence": evidence_path,
        }
    )


def _tool_log_finding(args: dict[str, Any], *, approve_fn: ApproveFn | None) -> str:
    target = _target_path(args["target_dir"])
    findings_path = target / "FINDINGS.md"
    existing = findings_path.read_text(encoding="utf-8", errors="replace") if findings_path.exists() else ""
    fid = next_finding_id(existing)
    finding = Finding(
        finding_id=fid,
        title=args["title"],
        class_name=args["class_name"],
        endpoint=args["endpoint"],
        verdict=args["verdict"],
        asset=args.get("asset") or host_from_target(args["endpoint"]),
        preconditions=args.get("preconditions") or "Two in-scope test accounts A and B",
        observed=args.get("observed") or args["verdict"],
        impact=args.get("impact")
        or "Cross-account object access (confirm sensitivity before severity).",
        evidence=args.get("evidence") or "See evidence/safe/",
        next_step=args.get("next_step") or "Draft platform report from this finding",
        status="confirmed" if args["verdict"] in {"confirmed", "likely"} else "draft",
    )
    refusal = _require_approval(
        approve_fn,
        f"APPEND finding {fid} to\n  {findings_path}\n  verdict={finding.verdict}\n  {finding.title}",
        kind="fs",
        tool="log_finding",
    )
    if refusal:
        return refusal
    path = append_finding(target, finding)
    resume_path = None
    if args.get("update_resume", True):
        resume_path = str(
            update_resume_next_step(
                target,
                finding.next_step,
                accounts_note="A/B sessions in secrets/sessions.yaml (gitignored)",
            )
        )
    return json.dumps(
        {
            "ok": True,
            "finding_id": fid,
            "path": str(path),
            "resume": resume_path,
            "verdict": finding.verdict,
        }
    )


def _run_playbook(args: dict[str, Any], *, approve_fn: ApproveFn | None) -> str:
    target = Path(args["target_dir"])
    if not target.is_absolute():
        target = ROOT / target
    host = args["host"]
    endpoint = args.get("endpoint") or host
    approve = parse_bool(args.get("approve"))
    force = _resolve_force_arg(args)
    pb = playbook_for(args["task"])

    policy = ScopePolicy.load(target)
    max_agg = args.get("max_aggression")
    if max_agg is None:
        max_agg = 3 if (policy.allows_level3() or force) else 2
    else:
        max_agg = int(max_agg)

    steps = executable_steps(pb, max_aggression=max_agg)
    preview = [
        {
            "title": s.title,
            "aggression": s.aggression,
            "tool_call": s.tool_call,
            "command": s.command,
        }
        for s in steps
    ]
    if not approve:
        ui.dry_run_banner()
        return json.dumps(
            {
                "ok": True,
                "class": pb.class_name,
                "executed": False,
                "message": "dry-run",
                "max_aggression": max_agg,
                "force": force,
                "steps": preview,
                "playbook": playbook_markdown(pb, endpoint=endpoint),
            }
        )

    refusal = _require_approval(
        approve_fn,
        f"Approve ACTIVE playbook run?\n  class={pb.class_name}\n  host={host}\n  "
        f"steps={len(steps)}\n  max_aggression={max_agg}\n  force={force}",
        kind="active_traffic",
        tool="run_playbook",
        host=host,
        force_override=force,
        aggression=max_agg,
    )
    if refusal:
        return refusal

    # Nested run_tool steps already covered by the playbook-level approve.
    def _auto_allow(_desc: str) -> bool:
        return True

    results: list[dict[str, Any]] = []
    verdict: str | None = None
    for step in steps:
        if not step.tool_call:
            results.append(
                {
                    "title": step.title,
                    "skipped": True,
                    "reason": "manual step (no tool_call)",
                    "command": step.command,
                }
            )
            continue
        tool_name = step.tool_call.get("tool", "")
        call_args = dict(step.tool_call.get("args") or {})
        for key, val in list(call_args.items()):
            if isinstance(val, str):
                call_args[key] = (
                    val.replace("{target_dir}", str(target))
                    .replace("{host}", host)
                    .replace("{endpoint}", endpoint)
                )
        call_args.setdefault(
            "target_dir",
            str(target) if target.is_absolute() else args["target_dir"],
        )
        if tool_name in {
            "run_tool",
            "http_request",
            "secrets_scan",
            "brute_login",
            "sqli_probe",
            "xss_probe",
            "second_order_xss",
            "lfi_probe",
            "ssti_probe",
            "xxe_probe",
            "cors_probe",
            "open_redirect_probe",
            "mine_params",
            "graphql_probe",
            "analyze_headers",
            "jwt_active_probe",
            "oauth_probe",
            "analyze_js",
        }:
            call_args["approve"] = True
            call_args["force"] = force
            if tool_name == "run_tool":
                call_args.setdefault("host", host)
            if tool_name == "secrets_scan":
                call_args.setdefault("host", host)
            if tool_name == "brute_login":
                call_args.setdefault("url", endpoint)
        elif tool_name == "scope_check":
            call_args.setdefault("host", host)
            call_args.setdefault("target_dir", args["target_dir"])
        elif tool_name == "assert_diff":
            call_args.setdefault("target_dir", args["target_dir"])
        raw = execute_tool(tool_name, call_args, approve_fn=_auto_allow)
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            parsed = {"raw": raw}
        results.append({"title": step.title, "tool": tool_name, "result": parsed})
        if isinstance(parsed, dict) and parsed.get("verdict"):
            verdict = str(parsed["verdict"])
        if isinstance(parsed, dict) and tool_name == "brute_login" and parsed.get("success"):
            verdict = "confirmed"
        if (
            isinstance(parsed, dict)
            and tool_name == "secrets_scan"
            and int(parsed.get("hit_count") or 0) > 0
        ):
            verdict = "confirmed"
        if isinstance(parsed, dict) and tool_name in {
            "sqli_probe",
            "xss_probe",
            "second_order_xss",
            "lfi_probe",
            "ssti_probe",
            "xxe_probe",
            "cors_probe",
            "open_redirect_probe",
            "graphql_probe",
            "jwt_active_probe",
            "oauth_probe",
        } and parsed.get("signal"):
            verdict = "confirmed"
        if isinstance(parsed, dict) and parsed.get("ok") is False:
            break

    return json.dumps(
        {
            "ok": True,
            "class": pb.class_name,
            "executed": True,
            "max_aggression": max_agg,
            "force": force,
            "verdict": verdict,
            "results": results,
        }
    )


def _tool_simple_probe(
    tool_name: str,
    runner_fn: Any,
    args: dict[str, Any],
    *,
    approve_fn: ApproveFn | None,
    aggression: int,
) -> str:
    target = _target_path(args["target_dir"])
    url = args["url"]
    approve = parse_bool(args.get("approve"))
    force = _resolve_force_arg(args)
    if approve:
        refusal = _require_approval(
            approve_fn,
            f"Approve ACTIVE {tool_name}?\n  url={url}\n  force={force}",
            kind="active_traffic",
            tool=tool_name,
            host=host_from_target(url),
            force_override=force,
            aggression=aggression,
        )
        if refusal:
            return refusal
    result = runner_fn(
        target,
        url,
        approve=approve,
        force=force,
        session=str(args.get("session") or "A"),
    )
    try:
        payload = json.loads(result.stdout) if result.stdout else {}
    except json.JSONDecodeError:
        payload = {"raw": result.stdout}
    return json.dumps(
        {
            "ok": True,
            "executed": result.executed,
            "signal": bool(payload.get("signal")),
            "reason": payload.get("reason") or "",
            "detail": payload,
            "message": result.message,
        }
    )


def _tool_param_probe(
    tool_name: str,
    runner_fn: Any,
    args: dict[str, Any],
    *,
    approve_fn: ApproveFn | None,
    default_param: str,
    aggression: int,
) -> str:
    target = _target_path(args["target_dir"])
    url = args["url"]
    param = args.get("param") or default_param
    approve = parse_bool(args.get("approve"))
    force = _resolve_force_arg(args)
    if approve:
        refusal = _require_approval(
            approve_fn,
            f"Approve ACTIVE {tool_name}?\n  url={url}\n  param={param}\n  force={force}",
            kind="active_traffic",
            tool=tool_name,
            host=host_from_target(url),
            force_override=force,
            aggression=aggression,
        )
        if refusal:
            return refusal
    result = runner_fn(target, url, param=param, approve=approve, force=force)
    try:
        payload = json.loads(result.stdout) if result.stdout else {}
    except json.JSONDecodeError:
        payload = {"raw": result.stdout}
    return json.dumps(
        {
            "ok": True,
            "executed": result.executed,
            "signal": bool(payload.get("signal")),
            "reason": payload.get("reason") or "",
            "detail": payload,
            "message": result.message,
        }
    )


def _tool_xxe(args: dict[str, Any], *, approve_fn: ApproveFn | None) -> str:
    target = _target_path(args["target_dir"])
    url = args["url"]
    approve = parse_bool(args.get("approve"))
    force = _resolve_force_arg(args)
    if approve:
        refusal = _require_approval(
            approve_fn,
            f"Approve ACTIVE xxe_probe?\n  url={url}\n  force={force}",
            kind="active_traffic",
            tool="xxe_probe",
            host=host_from_target(url),
            force_override=force,
            aggression=2,
        )
        if refusal:
            return refusal
    result = xxe_probe_runner.xxe_probe(target, url, approve=approve, force=force)
    try:
        payload = json.loads(result.stdout) if result.stdout else {}
    except json.JSONDecodeError:
        payload = {"raw": result.stdout}
    return json.dumps(
        {
            "ok": True,
            "executed": result.executed,
            "signal": bool(payload.get("signal")),
            "reason": payload.get("reason") or "",
            "detail": payload,
            "message": result.message,
        }
    )


def _tool_jwt_active(args: dict[str, Any], *, approve_fn: ApproveFn | None) -> str:
    target = _target_path(args["target_dir"])
    url = args["url"]
    token = args["token"]
    approve = parse_bool(args.get("approve"))
    force = _resolve_force_arg(args)
    if approve:
        refusal = _require_approval(
            approve_fn,
            f"Approve ACTIVE jwt_active_probe?\n  url={url}\n  force={force}",
            kind="active_traffic",
            tool="jwt_active_probe",
            host=host_from_target(url),
            force_override=force,
            aggression=2,
        )
        if refusal:
            return refusal
    result = oauth_jwt_runner.jwt_active_probe(
        target, url, token=token, approve=approve, force=force
    )
    try:
        payload = json.loads(result.stdout) if result.stdout else {}
    except json.JSONDecodeError:
        payload = {"raw": result.stdout}
    return json.dumps({"ok": True, "executed": result.executed, **payload})


def _tool_oauth(args: dict[str, Any], *, approve_fn: ApproveFn | None) -> str:
    target = _target_path(args["target_dir"])
    url = args["authorize_url"]
    approve = parse_bool(args.get("approve"))
    force = _resolve_force_arg(args)
    if approve:
        refusal = _require_approval(
            approve_fn,
            f"Approve ACTIVE oauth_probe?\n  url={url}\n  force={force}",
            kind="active_traffic",
            tool="oauth_probe",
            host=host_from_target(url),
            force_override=force,
            aggression=2,
        )
        if refusal:
            return refusal
    result = oauth_jwt_runner.oauth_probe(
        target, url, approve=approve, force=force
    )
    try:
        payload = json.loads(result.stdout) if result.stdout else {}
    except json.JSONDecodeError:
        payload = {"raw": result.stdout}
    return json.dumps({"ok": True, "executed": result.executed, **payload})


def _tool_race_probe(args: dict[str, Any], *, approve_fn: ApproveFn | None) -> str:
    target = _target_path(args["target_dir"])
    url = args["url"]
    approve = parse_bool(args.get("approve"))
    force = _resolve_force_arg(args)
    if approve:
        refusal = _require_approval(
            approve_fn,
            (
                f"Approve ACTIVE race_probe?\n  url={url}\n"
                f"  method={args.get('method') or 'GET'}\n"
                f"  workers={args.get('workers') or 8}\n"
                f"  burst={args.get('burst') or 16}\n  force={force}"
            ),
            kind="active_traffic",
            tool="race_probe",
            host=host_from_target(url),
            force_override=force,
            aggression=2,
        )
        if refusal:
            return refusal
    result = race_probe_runner.race_probe(
        target,
        url,
        method=str(args.get("method") or "GET"),
        workers=int(args.get("workers") or 8),
        burst=int(args.get("burst") or 16),
        session=str(args.get("session") or ""),
        approve=approve,
        force=force,
    )
    try:
        payload = json.loads(result.stdout) if result.stdout else {}
    except json.JSONDecodeError:
        payload = {"raw": result.stdout}
    return json.dumps(
        {
            "ok": True,
            "executed": result.executed,
            "signal": bool(payload.get("signal")),
            "reason": payload.get("reason") or "",
            "detail": payload,
            "message": result.message,
        }
    )


def _tool_websocket_probe(args: dict[str, Any], *, approve_fn: ApproveFn | None) -> str:
    target = _target_path(args["target_dir"])
    url = args["url"]
    approve = parse_bool(args.get("approve"))
    force = _resolve_force_arg(args)
    if approve:
        refusal = _require_approval(
            approve_fn,
            f"Approve ACTIVE websocket_probe?\n  url={url}\n  force={force}",
            kind="active_traffic",
            tool="websocket_probe",
            host=host_from_target(url),
            force_override=force,
            aggression=2,
        )
        if refusal:
            return refusal
    result = websocket_probe_runner.websocket_probe(
        target,
        url,
        message=str(args.get("message") or ""),
        approve=approve,
        force=force,
    )
    try:
        payload = json.loads(result.stdout) if result.stdout else {}
    except json.JSONDecodeError:
        payload = {"raw": result.stdout}
    return json.dumps(
        {
            "ok": True,
            "executed": result.executed,
            "signal": bool(payload.get("signal")),
            "reason": payload.get("reason") or "",
            "detail": payload,
            "message": result.message,
        }
    )


def _tool_mobsf_upload(args: dict[str, Any], *, approve_fn: ApproveFn | None) -> str:
    target = _target_path(args["target_dir"])
    approve = parse_bool(args.get("approve"))
    try:
        path = _readable_path(args["path"])
    except PermissionError as exc:
        return json.dumps({"ok": False, "error": str(exc), "kind": "path_blocked"})
    if approve:
        refusal = _require_approval(
            approve_fn,
            f"Approve mobsf_upload?\n  apk={path}",
            kind="fs",
            tool="mobsf_upload",
        )
        if refusal:
            return refusal
    result = mobsf_runner.mobsf_upload(target, path, approve=approve)
    try:
        payload = json.loads(result.stdout) if result.stdout else {}
    except json.JSONDecodeError:
        payload = {"raw": result.stdout}
    return json.dumps({"ok": payload.get("ok", True), "executed": result.executed, **payload})


def _tool_mobsf_scan(args: dict[str, Any], *, approve_fn: ApproveFn | None) -> str:
    hash_id = args["hash"]
    scan_type = str(args.get("scan_type") or "apk")
    approve = parse_bool(args.get("approve"))
    if approve:
        refusal = _require_approval(
            approve_fn,
            f"Approve mobsf_scan?\n  hash={hash_id}\n  scan_type={scan_type}",
            kind="fs",
            tool="mobsf_scan",
        )
        if refusal:
            return refusal
    result = mobsf_runner.mobsf_scan(
        hash_id=hash_id, scan_type=scan_type, approve=approve
    )
    try:
        payload = json.loads(result.stdout) if result.stdout else {}
    except json.JSONDecodeError:
        payload = {"raw": result.stdout}
    return json.dumps({"ok": payload.get("ok", True), "executed": result.executed, **payload})


def _tool_frida_run_script(args: dict[str, Any], *, approve_fn: ApproveFn | None) -> str:
    package = args["package"]
    script = str(args.get("script") or "ssl_unpin_lab.js")
    spawn = True if args.get("spawn") is None else bool(args.get("spawn"))
    approve = parse_bool(args.get("approve"))
    if approve:
        refusal = _require_approval(
            approve_fn,
            (
                f"Approve frida_run_script?\n  package={package}\n"
                f"  script={script}\n  spawn={spawn}"
            ),
            kind="active_traffic",
            tool="frida_run_script",
            aggression=3,
        )
        if refusal:
            return refusal
    result = frida_runner.frida_run_script(
        package=package, script=script, approve=approve, spawn=spawn
    )
    try:
        payload = json.loads(result.stdout) if result.stdout else {}
    except json.JSONDecodeError:
        payload = {"raw": result.stdout}
    return json.dumps({"ok": payload.get("ok", True), "executed": result.executed, **payload})


def _tool_objection_explore(args: dict[str, Any], *, approve_fn: ApproveFn | None) -> str:
    package = args["package"]
    approve = parse_bool(args.get("approve"))
    if approve:
        refusal = _require_approval(
            approve_fn,
            f"Approve objection_explore?\n  package={package}",
            kind="active_traffic",
            tool="objection_explore",
            aggression=2,
        )
        if refusal:
            return refusal
    result = frida_runner.objection_explore(package=package, approve=approve)
    try:
        payload = json.loads(result.stdout) if result.stdout else {}
    except json.JSONDecodeError:
        payload = {"raw": result.stdout}
    return json.dumps({"ok": payload.get("ok", True), "executed": result.executed, **payload})


def _tool_browser_capture_session(args: dict[str, Any], *, approve_fn: ApproveFn | None) -> str:
    target = _target_path(args["target_dir"])
    url = str(args["url"])
    approve = parse_bool(args.get("approve"))
    force = _resolve_force_arg(args)
    session = str(args.get("session") or "A")
    if approve:
        refusal = _require_approval(
            approve_fn,
            (
                f"Approve ACTIVE browser_capture_session (headed IdP)?\n"
                f"  url={url}\n  session={session}\n  force={force}\n"
                f"  Operator must finish login; Hackbot will not type IdP passwords."
            ),
            kind="active_traffic",
            tool="browser_capture_session",
            host=host_from_target(url),
            force_override=force,
            aggression=2,
        )
        if refusal:
            return refusal
    timeout = args.get("timeout_s")
    result = browser_runner.browser_capture_session(
        target,
        url,
        session=session,
        approve=approve,
        force=force,
        timeout_s=float(timeout) if timeout is not None else None,
    )
    try:
        payload = json.loads(result.stdout) if result.stdout else {}
    except json.JSONDecodeError:
        payload = {"raw": result.stdout}
    if isinstance(payload, dict):
        return json.dumps({"ok": payload.get("ok", True), "executed": result.executed, **payload})
    return json.dumps({"ok": True, "executed": result.executed, "detail": payload})


def _tool_browser(
    kind: str, args: dict[str, Any], *, approve_fn: ApproveFn | None
) -> str:
    target = _target_path(args["target_dir"])
    url = args["url"]
    approve = parse_bool(args.get("approve"))
    force = _resolve_force_arg(args)
    tool = f"browser_{kind}"
    if approve:
        extra = f"\n  expr={args.get('expression')}" if kind == "eval" else ""
        if kind == "set_cookie":
            extra = f"\n  cookie={args.get('name')}"
            if args.get("session"):
                extra += f"\n  session={args.get('session')}"
        if kind == "with_session":
            extra = f"\n  session={args.get('session') or 'A'}"
        if kind == "diff_sessions":
            extra = (
                f"\n  session_a={args.get('session_a') or 'A'}"
                f"\n  session_b={args.get('session_b') or 'B'}"
            )
        refusal = _require_approval(
            approve_fn,
            f"Approve ACTIVE {tool}?\n  url={url}{extra}\n  force={force}",
            kind="active_traffic",
            tool=tool,
            host=host_from_target(url),
            force_override=force,
            aggression=1,
        )
        if refusal:
            return refusal
    if kind == "navigate":
        result = browser_runner.browser_navigate(
            target, url, approve=approve, force=force
        )
    elif kind == "screenshot":
        result = browser_runner.browser_screenshot(
            target, url, approve=approve, force=force
        )
    elif kind == "cookies":
        result = browser_runner.browser_cookies(
            target, url, approve=approve, force=force
        )
    elif kind == "storage":
        result = browser_runner.browser_storage(
            target, url, approve=approve, force=force
        )
    elif kind == "network":
        seed = args.get("seed_surface")
        result = browser_runner.browser_network(
            target,
            url,
            approve=approve,
            force=force,
            seed_surface=True if seed is None else bool(seed),
        )
    elif kind == "with_session":
        result = browser_runner.browser_with_session(
            target,
            url,
            session=str(args.get("session") or "A"),
            approve=approve,
            force=force,
            capture_network=bool(args.get("capture_network")),
        )
    elif kind == "diff_sessions":
        promote = args.get("promote")
        result = browser_runner.browser_diff_sessions(
            target,
            url,
            session_a=str(args.get("session_a") or "A"),
            session_b=str(args.get("session_b") or "B"),
            approve=approve,
            force=force,
            promote=True if promote is None else bool(promote),
        )
    elif kind == "console":
        result = browser_runner.browser_console(
            target, url, approve=approve, force=force
        )
    elif kind == "set_cookie":
        result = browser_runner.browser_set_cookie(
            target,
            url,
            name=str(args.get("name") or ""),
            value=str(args.get("value") or ""),
            session=str(args.get("session") or ""),
            approve=approve,
            force=force,
        )
    elif kind == "eval":
        result = browser_runner.browser_eval(
            target,
            url,
            str(args.get("expression") or ""),
            approve=approve,
            force=force,
        )
    else:
        return json.dumps({"ok": False, "error": f"unknown browser kind {kind}"})
    try:
        payload = json.loads(result.stdout) if result.stdout else {}
    except json.JSONDecodeError:
        payload = {"raw": result.stdout}
    return json.dumps({"ok": payload.get("ok", True), "executed": result.executed, **payload})


def _tool_import_burp_xml(args: dict[str, Any]) -> str:
    target = _target_path(args["target_dir"])
    try:
        path = _readable_path(args["path"])
    except PermissionError as exc:
        return json.dumps({"ok": False, "error": str(exc), "kind": "path_blocked"})
    result = burp.seed_surface_from_xml(target, path)
    return json.dumps(result)


def _tool_burp_replay(args: dict[str, Any], *, approve_fn: ApproveFn | None) -> str:
    target = _target_path(args["target_dir"])
    url = args["url"]
    approve = parse_bool(args.get("approve"))
    force = _resolve_force_arg(args)
    if approve:
        refusal = _require_approval(
            approve_fn,
            f"Approve Burp replay / send?\n  url={url}\n  method={args.get('method') or 'GET'}\n  force={force}",
            kind="active_traffic",
            tool="burp_replay",
            host=host_from_target(url),
            force_override=force,
            aggression=2,
        )
        if refusal:
            return refusal
    out = burp.burp_replay_request(
        target,
        url=url,
        method=str(args.get("method") or "GET"),
        body=str(args.get("body") or ""),
        approve=approve,
        force=force,
        base_url=str(args.get("base_url") or ""),
    )
    return json.dumps(out)


def _tool_burp_replay_history(args: dict[str, Any], *, approve_fn: ApproveFn | None) -> str:
    target = _target_path(args["target_dir"])
    approve = parse_bool(args.get("approve"))
    force = _resolve_force_arg(args)
    idx = int(args.get("index") or 0)
    if approve:
        refusal = _require_approval(
            approve_fn,
            f"Approve Burp history replay?\n  index={idx}\n  force={force}",
            kind="active_traffic",
            tool="burp_replay_history",
            host="127.0.0.1",
            force_override=force,
            aggression=2,
        )
        if refusal:
            return refusal
    out = burp.burp_replay_from_history(
        target,
        index=idx,
        approve=approve,
        force=force,
        base_url=str(args.get("base_url") or ""),
    )
    return json.dumps(out)


def _tool_mobile_bridge(args: dict[str, Any], *, approve_fn: ApproveFn | None) -> str:
    target = _target_path(args["target_dir"])
    approve = parse_bool(args.get("approve"))
    force = _resolve_force_arg(args)
    start_hunt = bool(args.get("start_hunt"))
    apk_path = None
    har_path = None
    if args.get("apk_path"):
        try:
            apk_path = _readable_path(args["apk_path"])
        except PermissionError as exc:
            return json.dumps({"ok": False, "error": str(exc), "kind": "path_blocked"})
    if args.get("har_path"):
        try:
            har_path = _readable_path(args["har_path"])
        except PermissionError as exc:
            return json.dumps({"ok": False, "error": str(exc), "kind": "path_blocked"})
    if start_hunt and approve:
        refusal = _require_approval(
            approve_fn,
            f"Approve mobile_bridge → ACTIVE run_hunt?\n  apk={apk_path}\n  har={har_path}\n  force={force}",
            kind="active_traffic",
            tool="mobile_bridge",
            host=args.get("host") or "",
            force_override=force,
            aggression=2,
        )
        if refusal:
            return refusal
    result = mobile_runner.bridge_to_hunt(
        target,
        apk_path=apk_path,
        har_path=har_path,
        start_hunt=start_hunt,
        approve=approve,
        force=force,
        host=str(args.get("host") or ""),
        budget=args.get("budget"),
    )
    return json.dumps(result)


def _tool_list_dir(args: dict[str, Any]) -> str:
    try:
        path = _readable_path(args["path"])
    except PermissionError as exc:
        return json.dumps({"ok": False, "error": str(exc), "kind": "path_blocked"})
    if not path.exists():
        return json.dumps({"ok": False, "error": "missing", "path": str(path)})
    if not path.is_dir():
        return json.dumps({"ok": False, "error": "not a directory", "path": str(path)})
    glob_pat = args.get("glob") or "*"
    try:
        limit = int(args.get("limit") or 40)
    except (TypeError, ValueError):
        limit = 40
    limit = max(1, min(limit, 200))
    children = sorted(path.glob(glob_pat))
    total = len(children)
    entries = []
    for child in children[:limit]:
        entries.append(
            {
                "name": child.name,
                "path": str(child),
                "is_dir": child.is_dir(),
                "bytes": child.stat().st_size if child.is_file() else None,
            }
        )
    return json.dumps(
        {
            "ok": True,
            "path": str(path),
            "count": len(entries),
            "total": total,
            "truncated": total > len(entries),
            "entries": entries,
        }
    )


def _tool_analyze_js(args: dict[str, Any], *, approve_fn: ApproveFn | None) -> str:
    from .hunt_memory import Endpoint, HuntMemory

    target = _target_path(args["target_dir"])
    source = args["source"]
    approve = parse_bool(args.get("approve"))
    force = _resolve_force_arg(args)
    is_url = source.startswith("http://") or source.startswith("https://")
    if is_url and approve:
        refusal = _require_approval(
            approve_fn,
            f"Approve ACTIVE analyze_js fetch?\n  source={source}\n  force={force}",
            kind="active_traffic",
            tool="analyze_js",
            host=host_from_target(source),
            force_override=force,
            aggression=1,
        )
        if refusal:
            return refusal
    result = js_analyze_runner.analyze_js(
        target, source, approve=approve or not is_url, force=force
    )
    try:
        payload = json.loads(result.stdout) if result.stdout else {}
    except json.JSONDecodeError:
        payload = {"raw": result.stdout}
    # Seed surface
    eps = []
    for u in payload.get("endpoints") or []:
        if isinstance(u, str) and u.startswith("http"):
            eps.append(Endpoint(url=u, source="js", params=[]))
    if eps:
        HuntMemory(target).upsert_endpoints(eps[:120], host=host_from_target(source) if is_url else "")
    return json.dumps({"ok": True, "executed": result.executed, **payload})


def _tool_mine_params(args: dict[str, Any], *, approve_fn: ApproveFn | None) -> str:
    target = _target_path(args["target_dir"])
    url = args["url"]
    approve = parse_bool(args.get("approve"))
    force = _resolve_force_arg(args)
    if approve:
        refusal = _require_approval(
            approve_fn,
            f"Approve ACTIVE mine_params?\n  url={url}\n  force={force}",
            kind="active_traffic",
            tool="mine_params",
            host=host_from_target(url),
            force_override=force,
            aggression=2,
        )
        if refusal:
            return refusal
    result = param_mine_runner.mine_params(target, url, approve=approve, force=force)
    try:
        payload = json.loads(result.stdout) if result.stdout else {}
    except json.JSONDecodeError:
        payload = {"raw": result.stdout}
    return json.dumps({"ok": True, "executed": result.executed, **payload})


def _tool_graphql_probe(args: dict[str, Any], *, approve_fn: ApproveFn | None) -> str:
    target = _target_path(args["target_dir"])
    url = args["url"]
    approve = parse_bool(args.get("approve"))
    force = _resolve_force_arg(args)
    if approve:
        refusal = _require_approval(
            approve_fn,
            f"Approve ACTIVE graphql_probe?\n  url={url}\n  force={force}",
            kind="active_traffic",
            tool="graphql_probe",
            host=host_from_target(url),
            force_override=force,
            aggression=2,
        )
        if refusal:
            return refusal
    result = graphql_probe_runner.graphql_probe(
        target, url, query=args.get("query"), approve=approve, force=force
    )
    try:
        payload = json.loads(result.stdout) if result.stdout else {}
    except json.JSONDecodeError:
        payload = {"raw": result.stdout}
    return json.dumps({"ok": True, "executed": result.executed, **payload})


def _tool_import_har(args: dict[str, Any]) -> str:
    target = _target_path(args["target_dir"])
    try:
        path = _readable_path(args["path"])
    except PermissionError as exc:
        return json.dumps({"ok": False, "error": str(exc), "kind": "path_blocked"})
    if not path.exists():
        return json.dumps({"ok": False, "error": "missing", "path": str(path)})
    try:
        result = har_import_runner.import_har(path, target)
    except Exception as exc:  # noqa: BLE001
        return json.dumps({"ok": False, "error": f"{type(exc).__name__}: {exc}"})
    ui.success(f"HAR seeded {result.get('endpoints_seeded')} endpoints")
    return json.dumps(result)


def _tool_cors_probe(args: dict[str, Any], *, approve_fn: ApproveFn | None) -> str:
    target = _target_path(args["target_dir"])
    url = args["url"]
    approve = parse_bool(args.get("approve"))
    force = _resolve_force_arg(args)
    if approve:
        refusal = _require_approval(
            approve_fn,
            f"Approve ACTIVE cors_probe?\n  url={url}\n  force={force}",
            kind="active_traffic",
            tool="cors_probe",
            host=host_from_target(url),
            force_override=force,
            aggression=1,
        )
        if refusal:
            return refusal
    result = web_probes_runner.cors_probe(
        target, url, origin=args.get("origin") or "https://evil.example", approve=approve, force=force
    )
    try:
        payload = json.loads(result.stdout) if result.stdout else {}
    except json.JSONDecodeError:
        payload = {"raw": result.stdout}
    return json.dumps({"ok": True, "executed": result.executed, **payload})


def _tool_open_redirect(args: dict[str, Any], *, approve_fn: ApproveFn | None) -> str:
    target = _target_path(args["target_dir"])
    url = args["url"]
    approve = parse_bool(args.get("approve"))
    force = _resolve_force_arg(args)
    if approve:
        refusal = _require_approval(
            approve_fn,
            f"Approve ACTIVE open_redirect_probe?\n  url={url}\n  force={force}",
            kind="active_traffic",
            tool="open_redirect_probe",
            host=host_from_target(url),
            force_override=force,
            aggression=2,
        )
        if refusal:
            return refusal
    result = web_probes_runner.open_redirect_probe(
        target, url, param=args.get("param") or "next", approve=approve, force=force
    )
    try:
        payload = json.loads(result.stdout) if result.stdout else {}
    except json.JSONDecodeError:
        payload = {"raw": result.stdout}
    return json.dumps({"ok": True, "executed": result.executed, **payload})


def _tool_analyze_headers(args: dict[str, Any], *, approve_fn: ApproveFn | None) -> str:
    target = _target_path(args["target_dir"])
    url = args["url"]
    approve = parse_bool(args.get("approve"))
    force = _resolve_force_arg(args)
    if approve:
        refusal = _require_approval(
            approve_fn,
            f"Approve ACTIVE analyze_headers?\n  url={url}\n  force={force}",
            kind="active_traffic",
            tool="analyze_headers",
            host=host_from_target(url),
            force_override=force,
            aggression=1,
        )
        if refusal:
            return refusal
    result = web_probes_runner.analyze_headers(target, url, approve=approve, force=force)
    try:
        payload = json.loads(result.stdout) if result.stdout else {}
    except json.JSONDecodeError:
        payload = {"raw": result.stdout}
    return json.dumps({"ok": True, "executed": result.executed, **payload})


def _tool_read_image(args: dict[str, Any]) -> str:
    from .image_read import read_image

    try:
        path = _readable_path(args["path"])
    except PermissionError as exc:
        return json.dumps({"ok": False, "error": str(exc), "kind": "path_blocked"})
    result = read_image(path, question=str(args.get("question") or ""))
    if result.get("ok"):
        ui.kv("image", str(path))
        ui.kv("source", str(result.get("source") or "?"))
        preview = result.get("ocr") or result.get("vision") or result.get("message") or ""
        if preview:
            ui.code_panel(str(preview)[:2000], title="image extract", lexer="text")
    return json.dumps(result)


def _tool_load_sessions_from_file(
    args: dict[str, Any], *, approve_fn: ApproveFn | None
) -> str:
    from .session_import import load_sessions_from_path

    target = _target_path(args["target_dir"])
    try:
        path = _readable_path(args["path"])
    except PermissionError as exc:
        return json.dumps({"ok": False, "error": str(exc), "kind": "path_blocked"})
    if not path.exists():
        return json.dumps({"ok": False, "error": "missing", "path": str(path)})

    try:
        parsed = load_sessions_from_path(path)
    except Exception as exc:  # noqa: BLE001
        return json.dumps(
            {"ok": False, "error": f"{type(exc).__name__}: {exc}", "path": str(path)}
        )

    if not parsed:
        return json.dumps(
            {
                "ok": False,
                "error": "no sessions/tokens found in file",
                "path": str(path),
                "hint": "use yaml/json with sessions.A/B bearer|cookie, or prose 'Session A: Bearer …'",
            }
        )

    write = bool(args.get("write", True))
    masked = {
        name: {
            "authorization": "***" if body.get("authorization") else "",
            "cookie": "***" if body.get("cookie") else "",
            "ready": bool(body.get("authorization") or body.get("cookie")),
        }
        for name, body in parsed.items()
    }
    ui.kv("parsed_sessions", ", ".join(sorted(parsed.keys())))

    if not write:
        return json.dumps(
            {"ok": True, "written": False, "path": str(path), "sessions": masked}
        )

    refusal = _require_approval(
        approve_fn,
        f"WRITE sessions from file into secrets/sessions.yaml?\n"
        f"  source={path}\n  target={target}\n  names={', '.join(sorted(parsed.keys()))}",
        kind="fs",
        tool="load_sessions_from_file",
    )
    if refusal:
        return refusal

    saved = []
    for name, body in parsed.items():
        save_session(
            target,
            name,
            authorization=body.get("authorization"),
            cookie=body.get("cookie"),
        )
        saved.append(name)
    ident = load_identity(target)
    return json.dumps(
        {
            "ok": True,
            "written": True,
            "path": str(path),
            "saved": saved,
            "identity": ident.masked_summary(),
            "sessions": masked,
        }
    )


def _tool_secrets_scan(args: dict[str, Any], *, approve_fn: ApproveFn | None) -> str:
    target = _target_path(args["target_dir"])
    host = args["host"]
    approve = parse_bool(args.get("approve"))
    force = _resolve_force_arg(args)
    if approve:
        refusal = _require_approval(
            approve_fn,
            f"Approve ACTIVE secrets_scan?\n  host={host}\n  force={force}",
            kind="active_traffic",
            tool="secrets_scan",
            host=host_from_target(host),
            force_override=force,
            aggression=1,
        )
        if refusal:
            return refusal
    result = secrets_scan_runner.secrets_scan(target, host, approve=approve, force=force)
    try:
        payload = json.loads(result.stdout) if result.stdout else {}
    except json.JSONDecodeError:
        payload = {"raw": result.stdout}
    if result.executed and int(payload.get("hit_count") or 0) > 0:
        try:
            EvidenceStore(target).save("secrets_scan.json", json.dumps(payload, indent=2))
        except StrictRedactError:
            pass
    return json.dumps(
        {
            "ok": True,
            "executed": result.executed,
            "hit_count": payload.get("hit_count", 0),
            "kinds": payload.get("kinds") or [],
            "findings": payload.get("findings") or [],
            "message": result.message,
        }
    )


def _tool_sqli_probe(args: dict[str, Any], *, approve_fn: ApproveFn | None) -> str:
    target = _target_path(args["target_dir"])
    url = args["url"]
    param = args.get("param") or "id"
    approve = parse_bool(args.get("approve"))
    force = _resolve_force_arg(args)
    if approve:
        refusal = _require_approval(
            approve_fn,
            f"Approve ACTIVE sqli_probe?\n  url={url}\n  param={param}\n  force={force}",
            kind="active_traffic",
            tool="sqli_probe",
            host=host_from_target(url),
            force_override=force,
            aggression=2,
        )
        if refusal:
            return refusal
    result = sqli_probe_runner.sqli_probe(
        target, url, param=param, approve=approve, force=force
    )
    try:
        payload = json.loads(result.stdout) if result.stdout else {}
    except json.JSONDecodeError:
        payload = {"raw": result.stdout}
    return json.dumps(
        {
            "ok": True,
            "executed": result.executed,
            "signal": bool(payload.get("signal")),
            "reason": payload.get("reason") or "",
            "detail": payload,
            "message": result.message,
        }
    )


def _tool_xss_probe(args: dict[str, Any], *, approve_fn: ApproveFn | None) -> str:
    target = _target_path(args["target_dir"])
    url = args["url"]
    param = args.get("param") or "q"
    approve = parse_bool(args.get("approve"))
    force = _resolve_force_arg(args)
    if approve:
        refusal = _require_approval(
            approve_fn,
            f"Approve ACTIVE xss_probe?\n  url={url}\n  param={param}\n  force={force}",
            kind="active_traffic",
            tool="xss_probe",
            host=host_from_target(url),
            force_override=force,
            aggression=2,
        )
        if refusal:
            return refusal
    result = xss_probe_runner.xss_probe(
        target, url, param=param, approve=approve, force=force
    )
    try:
        payload = json.loads(result.stdout) if result.stdout else {}
    except json.JSONDecodeError:
        payload = {"raw": result.stdout}
    return json.dumps(
        {
            "ok": True,
            "executed": result.executed,
            "signal": bool(payload.get("signal")),
            "reason": payload.get("reason") or "",
            "detail": payload,
            "message": result.message,
        }
    )


def _tool_second_order_xss(args: dict[str, Any], *, approve_fn: ApproveFn | None) -> str:
    target = _target_path(args["target_dir"])
    url = args["url"]
    trigger = str(args.get("trigger_url") or url)
    param = args.get("param") or "comment"
    method = str(args.get("method") or "POST")
    approve = parse_bool(args.get("approve"))
    force = _resolve_force_arg(args)
    if approve:
        refusal = _require_approval(
            approve_fn,
            f"Approve ACTIVE second_order_xss?\n  store={url}\n  trigger={trigger}\n  force={force}",
            kind="active_traffic",
            tool="second_order_xss",
            host=host_from_target(url),
            force_override=force,
            aggression=2,
        )
        if refusal:
            return refusal
    result = second_order_xss_runner.second_order_xss(
        target,
        url,
        trigger_url=trigger,
        param=param,
        method=method,
        approve=approve,
        force=force,
    )
    try:
        payload = json.loads(result.stdout) if result.stdout else {}
    except json.JSONDecodeError:
        payload = {"raw": result.stdout}
    return json.dumps(
        {
            "ok": True,
            "executed": result.executed,
            "signal": bool(payload.get("signal")),
            "reason": payload.get("reason") or "",
            "detail": payload,
            "message": result.message,
        }
    )


def _tool_map_surface(args: dict[str, Any], *, approve_fn: ApproveFn | None) -> str:
    from .surface import map_surface

    target = _target_path(args["target_dir"])
    seed = args["seed"]
    approve = parse_bool(args.get("approve"))
    force = _resolve_force_arg(args)
    if approve:
        refusal = _require_approval(
            approve_fn,
            f"Approve ACTIVE surface map?\n  seed={seed}\n  force={force}",
            kind="active_traffic",
            tool="map_surface",
            host=host_from_target(seed),
            force_override=force,
            aggression=1,
        )
        if refusal:
            return refusal
    result = map_surface(target, seed, approve=approve, force=force)
    return json.dumps(result)


def _tool_run_hunt(args: dict[str, Any], *, approve_fn: ApproveFn | None) -> str:
    from .hunt_controller import run_hunt

    target = _target_path(args["target_dir"])
    prompt = args["prompt"]
    approve = parse_bool(args.get("approve"))
    force = _resolve_force_arg(args)
    resume = parse_bool(args.get("resume"))
    budget = args.get("budget")
    budget_i = int(budget) if budget is not None else None
    result = run_hunt(
        target,
        prompt,
        host=args.get("host") or "",
        approve_session=approve,
        budget=budget_i,
        approve_fn=approve_fn,
        force=force,
        resume=resume,
    )
    return json.dumps(result)


def _tool_brute_login(args: dict[str, Any], *, approve_fn: ApproveFn | None) -> str:
    target = _target_path(args["target_dir"])
    url = args["url"]
    approve = parse_bool(args.get("approve"))
    force = _resolve_force_arg(args)
    if approve:
        refusal = _require_approval(
            approve_fn,
            f"Approve ACTIVE brute_login (capped)?\n  url={url}\n  force={force}",
            kind="active_traffic",
            tool="brute_login",
            host=host_from_target(url),
            force_override=force,
            aggression=3,
        )
        if refusal:
            return refusal
    result = brute_login_runner.brute_login(
        target,
        url,
        username=str(args.get("username") or "test"),
        approve=approve,
        force=force,
    )
    try:
        payload = json.loads(result.stdout) if result.stdout else {}
    except json.JSONDecodeError:
        payload = {"raw": result.stdout}
    return json.dumps(
        {
            "ok": True,
            "executed": result.executed,
            "success": bool(payload.get("success")),
            "tried": payload.get("tried"),
            "message": result.message,
            "detail": payload,
        }
    )


def _run_campaign(args: dict[str, Any], *, approve_fn: ApproveFn | None) -> str:
    target = _target_path(args["target_dir"])
    host = args["host"]
    prompt = args["prompt"]
    approve = parse_bool(args.get("approve"))
    force = _resolve_force_arg(args)
    endpoint = args.get("endpoint") or host
    login_url = args.get("login_url") or ""
    if not login_url:
        path = extract_login_path(prompt)
        if path.startswith("http"):
            login_url = path
        else:
            base = host if "://" in host else f"https://{host}"
            login_url = base.rstrip("/") + (path if path.startswith("/") else "/" + path)

    modules, used_default = resolve_modules(prompt)
    if not modules:
        return json.dumps(
            {
                "ok": False,
                "error": "could not infer a hunt campaign from the prompt",
                "hint": (
                    "say what you want (attack / explore / DDoS / secrets / idor) "
                    "and include an in-scope host"
                ),
            }
        )

    policy = ScopePolicy.load(target)
    rows: list[dict[str, Any]] = []
    fallback_note = ""
    if used_default:
        fallback_note = (
            "Prompt did not name specific classes — ran the **default hunt pack** "
            "(recon, secrets, auth-bypass, brute, dos) so the task still completes."
        )
        ui.warn(fallback_note)

    if approve:
        names = ", ".join(m.id for m in modules)
        refusal = _require_approval(
            approve_fn,
            f"Approve ACTIVE campaign?\n  host={host}\n  modules={names}\n  force={force}",
            kind="active_traffic",
            tool="run_campaign",
            host=host_from_target(host),
            force_override=force,
            aggression=max(m.aggression for m in modules),
        )
        if refusal:
            return refusal

    def _auto(_d: str) -> bool:
        return True

    for mod in modules:
        row: dict[str, Any] = {
            "id": mod.id,
            "label": mod.label,
            "status": "NOT_FOUND",
            "summary": "",
        }
        if mod.aggression >= 3 and not policy.allows_level3() and not force:
            row["status"] = "BLOCKED"
            row["summary"] = "level-3 not in SCOPE Allowed — use /force or update SCOPE"
            rows.append(row)
            continue
        if mod.needs_sessions:
            ident = load_identity(target)
            ready = set(ident.ready_sessions())
            if not ({"A", "B"} <= ready or len(ready) >= 2):
                row["status"] = "NEEDS_SETUP"
                row["summary"] = "load A/B sessions first (/session set A --bearer …)"
                rows.append(row)
                continue

        try:
            if mod.kind == "playbook":
                ep = login_url if mod.id in {"brute", "auth-bypass"} else endpoint
                raw = execute_tool(
                    "run_playbook",
                    {
                        "target_dir": args["target_dir"],
                        "task": mod.task,
                        "host": host,
                        "endpoint": ep,
                        "approve": approve,
                        "force": force,
                    },
                    approve_fn=_auto if approve else approve_fn,
                )
                data = json.loads(raw)
                if not approve:
                    row["status"] = "DRY_RUN"
                    row["summary"] = (
                        f"would run playbook `{mod.task}` "
                        f"({len(data.get('steps') or [])} steps)"
                    )
                elif data.get("ok") is False:
                    row["status"] = "ERROR"
                    row["summary"] = str(data.get("error") or "playbook failed")
                else:
                    verdict = (data.get("verdict") or "").lower()
                    if verdict in {"confirmed", "likely"}:
                        row["status"] = "FOUND"
                        row["summary"] = f"verdict={verdict}"
                    elif verdict == "negative":
                        row["status"] = "NOT_FOUND"
                        row["summary"] = "controls held (negative)"
                    else:
                        row["status"] = "NOT_FOUND"
                        row["summary"] = f"executed; verdict={verdict or 'none'}"
            elif mod.task == "secrets_scan":
                raw = execute_tool(
                    "secrets_scan",
                    {
                        "target_dir": args["target_dir"],
                        "host": host,
                        "approve": approve,
                        "force": force,
                    },
                    approve_fn=_auto if approve else approve_fn,
                )
                data = json.loads(raw)
                if not approve:
                    row["status"] = "DRY_RUN"
                    row["summary"] = "would scan common paths for tokens/creds"
                elif int(data.get("hit_count") or 0) > 0:
                    row["status"] = "FOUND"
                    kinds = ", ".join(data.get("kinds") or [])
                    row["summary"] = f"hits={data['hit_count']} kinds={kinds}"
                else:
                    row["status"] = "NOT_FOUND"
                    row["summary"] = "no token/credential patterns in scanned paths"
            elif mod.task == "brute_login":
                raw = execute_tool(
                    "brute_login",
                    {
                        "target_dir": args["target_dir"],
                        "url": login_url,
                        "username": "test",
                        "approve": approve,
                        "force": force,
                    },
                    approve_fn=_auto if approve else approve_fn,
                )
                data = json.loads(raw)
                if not approve:
                    row["status"] = "DRY_RUN"
                    row["summary"] = f"would spray capped wordlist at {login_url}"
                elif data.get("success"):
                    row["status"] = "FOUND"
                    row["summary"] = f"login accepted within {data.get('tried')} attempts"
                else:
                    row["status"] = "NOT_FOUND"
                    row["summary"] = f"no hit in {data.get('tried')} capped attempts"
            else:
                row["status"] = "ERROR"
                row["summary"] = f"unknown module task {mod.task}"
        except Exception as exc:  # noqa: BLE001
            row["status"] = "ERROR"
            row["summary"] = f"{type(exc).__name__}: {exc}"
        rows.append(row)

    md = report_markdown(host, rows, fallback_note=fallback_note)
    ui.markdown_panel(md, title="campaign results")
    try:
        EvidenceStore(target).save("campaign_results.md", md)
    except StrictRedactError:
        pass

    found = [r for r in rows if r["status"] == "FOUND"]
    finding_ids: list[str] = []
    if approve and found:
        from .hunt_controller import promote_campaign_findings

        finding_ids = promote_campaign_findings(
            target,
            {"host": host, "modules": found},
        )

    return json.dumps(
        {
            "ok": True,
            "executed": approve,
            "host": host,
            "modules": rows,
            "found_count": len(found),
            "finding_ids": finding_ids,
            "used_default_pack": used_default,
            "report_md": md,
            "force": force,
        }
    )
