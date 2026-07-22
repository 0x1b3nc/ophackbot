"""Tool packs — send fewer tools to the model, grouped by hunt phase.

Elite tools and extreme study notes are **global**: they live inside the normal
phase packs (core/recon/inject/browser/report). Setting ``advanced`` or
``study-extreme`` never strips the existing surface — those names expand to the
full kit (same as ``all``).
"""

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
        "lab_exec",
        "stack_prepare",
        "burp_ensure",
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
        # Study is always on (including extreme notes via open_knowledge routes)
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
        "hunt_cockpit",
        "submit_ready",
        "import_policy",
        "delete_path",
        "make_dir",
        "move_path",
        "extract_page",
        "coverage_map",
        "workflow_load",
        "workflow_run",
        "workflow_assert",
        "finding_score",
        "dedupe_findings",
        "chain_validate",
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
        "import_openapi",
        "import_postman",
        "import_burp_xml",
        "burp_rest_health",
        "burp_proxy_history",
        "burp_issue_list",
        "burp_replay",
        "burp_replay_history",
        "burp_watch",
        "proxy_correlate",
        "cdn_origin_hint",
        "takeover_probe",
        "asset_graph_build",
        "secrets_scan",
        "analyze_jwt",
        "discover_paths",
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
        "ssrf_protocol_matrix",
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
        "websocket_authz_probe",
        "cors_probe",
        "open_redirect_probe",
        "graphql_probe",
        "graphql_batch_probe",
        "graphql_authz_probe",
        "jwt_active_probe",
        "oauth_probe",
        "saml_probe",
        "oidc_probe",
        "session_fixation_probe",
        "token_binding_check",
        "cache_poison_probe",
        "http_smuggle_probe",
        "host_header_probe",
        "absolute_url_probe",
        "brute_login",
        "api_authz_matrix",
        "api_mass_assignment_probe",
        "api_method_override_probe",
        "api_hpp_probe",
        "api_content_type_probe",
        "api_version_diff_probe",
        "api_error_schema_probe",
        "api_cors_probe",
        "api_cache_detect_probe",
        "api_graphql_variable_authz",
        "api_graphql_batch_alias_probe",
        "api_jwt_claim_diff",
        "api_oauth_oidc_probe",
        "llm_prompt_probe",
        "llm_indirect_prompt_probe",
        "llm_rag_probe",
        "llm_tool_abuse_probe",
        "llm_tenant_isolation_probe",
        "mcp_agent_probe",
        "ai_eval_run",
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
        "browser_map_spa",
        "dom_xss_probe",
        "postmessage_probe",
        "prototype_pollution_probe",
        "browser_har_seed",
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
        "chain_validate",
        "finding_score",
        "dedupe_findings",
        "learn_record",
        "learn_suggest",
        "learn_stats",
        "write_file",
        "edit_file",
        "append_file",
    ),
    # Aliases kept for operators / docs — resolve_packs expands them to "all".
    "advanced": (),
    "study-extreme": (),
}

# Avoid tiny substrings that false-positive in PT/EN ("achar"→"har", "objeto"→…).
PHASE_KEYWORDS: dict[str, tuple[str, ...]] = {
    "browser": (
        "browser",
        "playwright",
        "screenshot",
        "cookie",
        "sessao",
        "sessão",
        "cdp",
        "dom xss",
        "postmessage",
        "spa",
    ),
    "mobile": ("apk", "frida", "mobsf", "objection", "adb", "mobile"),
    "inject": (
        "sqli",
        "xss",
        "lfi",
        "ssti",
        "xxe",
        "ssrf",
        "race condition",
        "websocket",
        "idor",
        "oob",
        "jwt",
        "oauth",
        "saml",
        "oidc",
        "cors",
        "smuggle",
        "cache poison",
        "inject",
        "vulnerab",
        "vuln",
        "unauth",
        "sem conta",
        "without account",
        "no account",
        "bola",
        "broken access",
        "workflow",
        "business logic",
        "llm",
        "prompt injection",
        "rag",
        "mcp",
        "agentic",
        "chatbot",
        "openapi",
        "postman",
    ),
    "recon": (
        "recon",
        "subdomain",
        "wayback",
        "import_har",
        "import_openapi",
        "import_postman",
        " .har",
        "burp",
        "openapi",
        "postman",
        "swagger",
        "javascript",
        ".js ",
        "analyze_js",
        "surface",
        "headers",
        "discover",
        "fuzz",
        "nuclei",
        "httpx",
        "katana",
        "ffuf",
        "takeover",
        "cdn",
    ),
    "report": ("report", "write-up", "writeup", "finding", "draft", "graphql", "chain"),
}

# Open-ended hunt language (PT/EN) → full recon+inject+report surface
_HUNT_HINTS: tuple[str, ...] = (
    "run_hunt",
    "explora",
    "explore",
    "hunt",
    "hunting",
    "vulnerab",
    "vuln",
    "achad",
    "finding",
    "próximo passo",
    "proximo passo",
    "next step",
    "sem conta",
    "without account",
    "no account",
    "unauth",
    "achar vulnerab",
    "extreme",
    "estudo",
    "study",
)

# Names that mean "give the agent everything" (never a knowledge-only jail).
_FULL_ALIASES = frozenset({"advanced", "study-extreme", "study_extreme", "elite"})


def resolve_packs(prompt: str = "", *, explicit: str = "") -> list[str]:
    """Return pack names to load. Env HACKBOT_TOOL_PACK=all|auto|core,recon,...

    ``advanced`` / ``study-extreme`` expand to ``all`` so study + elite tools
    never replace the normal kit surface.
    """
    env = (explicit or os.environ.get("HACKBOT_TOOL_PACK") or "auto").strip().lower()
    if env in {"all", "*"} or env in _FULL_ALIASES:
        return ["all"]
    if env != "auto":
        parts = [p.strip() for p in env.split(",") if p.strip()]
        # Any full-alias in a comma list → full kit
        if any(p in _FULL_ALIASES for p in parts):
            return ["all"]
        return parts

    packs = ["core"]
    low = (prompt or "").lower()
    for pack, words in PHASE_KEYWORDS.items():
        if any(w in low for w in words):
            packs.append(pack)
    # Open-ended hunt / vuln / study language → recon + inject + report (+ browser on SPA cues)
    if any(h in low for h in _HUNT_HINTS) or len(packs) == 1:
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
