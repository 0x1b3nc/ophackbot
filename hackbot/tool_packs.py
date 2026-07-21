"""Tool packs — send fewer tools to the model, grouped by hunt phase."""

from __future__ import annotations

import os
from typing import Any

# Phase → tool names. Unknown packs fall back to "core"+"recon".
PACKS: dict[str, tuple[str, ...]] = {
    "core": (
        "list_targets",
        "set_target",
        "session_status",
        "capabilities",
        "show_identity",
        "set_session",
        "set_account",
        "show_accounts",
        "detect_login",
        "session_smoke",
        "load_sessions_from_file",
        "scope_check",
        "read_file",
        "read_image",
        "list_dir",
        "write_file",
        "edit_file",
        "append_file",
        "open_knowledge",
        "make_plan",
        "open_playbook",
        "run_playbook",
        "hunt_status",
        "run_hunt",
        "run_campaign",
        "hunt_checklist",
        "hunt_pause",
        "hunt_resume_flag",
        "hunt_telemetry",
        "submit_ready",
        "import_policy",
        "delete_path",
        "make_dir",
        "move_path",
        "extract_page",
    ),
    "recon": (
        "map_surface",
        "analyze_js",
        "mine_params",
        "analyze_headers",
        "extract_page",
        "crt_subdomains",
        "wayback_urls",
        "import_har",
        "import_burp_xml",
        "burp_rest_health",
        "burp_proxy_history",
        "burp_issue_list",
        "burp_replay",
        "burp_replay_history",
        "secrets_scan",
        "analyze_jwt",
        "discover_paths",
        # External recon CLIs + HexStrike (operator sees via /tools + capabilities)
        "run_tool",
    ),
    "inject": (
        "http_request",
        "assert_diff",
        "idor_probe",
        "session_bootstrap",
        "detect_login",
        "session_smoke",
        "browser_capture_session",
        "set_account",
        "show_accounts",
        "sqli_probe",
        "xss_probe",
        "second_order_xss",
        "lfi_probe",
        "ssti_probe",
        "xxe_probe",
        "ssrf_probe",
        "oob_mint",
        "oob_poll",
        "interactsh_status",
        "interactsh_register",
        "interactsh_poll",
        "mass_assignment_probe",
        "method_override_probe",
        "hpp_probe",
        "race_probe",
        "websocket_probe",
        "cors_probe",
        "open_redirect_probe",
        "graphql_probe",
        "jwt_active_probe",
        "oauth_probe",
        "brute_login",
        "run_tool",
    ),
    "browser": (
        "browser_navigate",
        "browser_screenshot",
        "browser_eval",
        "browser_cookies",
        "browser_storage",
        "browser_network",
        "browser_with_session",
        "browser_capture_session",
        "browser_diff_sessions",
        "browser_console",
        "browser_set_cookie",
        "browser_hint",
        "cdp_attach",
    ),
    "mobile": (
        "mobile_status",
        "mobile_hint",
        "adb_devices",
        "inspect_apk",
        "mobile_bridge",
        "mobsf_health",
        "mobsf_upload",
        "mobsf_scan",
        "frida_status",
        "frida_list_apps",
        "frida_run_script",
        "objection_explore",
    ),
    "report": (
        "log_finding",
        "update_resume",
        "save_evidence",
        "redact",
        "write_report_draft",
        "build_chains",
        "learn_record",
        "learn_suggest",
        "learn_stats",
        "write_file",
        "edit_file",
        "append_file",
    ),
}

PHASE_KEYWORDS: dict[str, tuple[str, ...]] = {
    "browser": ("browser", "playwright", "screenshot", "cookie", "sessao", "sessão", "cdp"),
    "mobile": ("apk", "frida", "mobsf", "objection", "adb", "mobile"),
    "inject": (
        "sqli",
        "xss",
        "lfi",
        "ssti",
        "xxe",
        "ssrf",
        "race",
        "websocket",
        "idor",
        "oob",
        "jwt",
        "oauth",
        "cors",
        "inject",
    ),
    "recon": (
        "recon",
        "subdomain",
        "wayback",
        "har",
        "burp",
        "js",
        "surface",
        "headers",
        "discover",
        "fuzz",
    ),
    "report": ("report", "write-up", "writeup", "finding", "draft", "severity", "chain"),
}


def resolve_packs(prompt: str = "", *, explicit: str = "") -> list[str]:
    """Return pack names to load. Env HACKBOT_TOOL_PACK=all|auto|core,recon,..."""
    env = (explicit or os.environ.get("HACKBOT_TOOL_PACK") or "auto").strip().lower()
    if env in {"all", "*"}:
        return ["all"]
    if env != "auto":
        return [p.strip() for p in env.split(",") if p.strip()]

    packs = ["core"]
    low = (prompt or "").lower()
    for pack, words in PHASE_KEYWORDS.items():
        if any(w in low for w in words):
            packs.append(pack)
    # Default hunt surface: include recon + inject lightly
    if "run_hunt" in low or "explora" in low or "hunt" in low or len(packs) == 1:
        for p in ("recon", "inject", "report"):
            if p not in packs:
                packs.append(p)
    return packs


def filter_tool_specs(all_specs: list[dict[str, Any]], packs: list[str]) -> list[dict[str, Any]]:
    if "all" in packs:
        return all_specs
    names: set[str] = set()
    for pack in packs:
        names.update(PACKS.get(pack, ()))
    if not names:
        names.update(PACKS["core"])
        names.update(PACKS["recon"])
    filtered = [s for s in all_specs if s.get("name") in names]
    return filtered or all_specs
