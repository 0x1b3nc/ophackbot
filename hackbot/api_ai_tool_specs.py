"""TOOL_SPECS fragments for API + AI security upgrade (merged into tools.TOOL_SPECS)."""

from __future__ import annotations

from typing import Any

_APPROVE_FALSE = {"type": "boolean", "default": False}
_FORCE = {"type": "boolean", "default": False}


def _url_tool(name: str, description: str, extra: dict[str, Any] | None = None) -> dict[str, Any]:
    props: dict[str, Any] = {
        "target_dir": {"type": "string"},
        "url": {"type": "string"},
        "approve": _APPROVE_FALSE,
        "force": _FORCE,
    }
    if extra:
        props.update(extra)
    return {
        "name": name,
        "description": description,
        "parameters": {
            "type": "object",
            "properties": props,
            "required": ["target_dir", "url"],
            "additionalProperties": False,
        },
    }


def _ai_tool(name: str, description: str) -> dict[str, Any]:
    return _url_tool(
        name,
        description,
        {
            "canary": {"type": "string", "default": ""},
            "session": {"type": "string", "default": ""},
            "prompt_field": {"type": "string", "default": "message"},
            "session_field": {"type": "string", "default": "conversation_id"},
            "method": {"type": "string", "default": "POST"},
            "max_payloads": {"type": "integer", "default": 3},
        },
    )


API_AI_TOOL_SPECS: list[dict[str, Any]] = [
    {
        "name": "import_openapi",
        "description": (
            "Ingest OpenAPI/Swagger JSON or YAML; seed HuntMemory endpoints + coverage cells "
            "(servers, params, requestBody, security, risk scores)."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "target_dir": {"type": "string"},
                "path": {"type": "string"},
                "base_url": {"type": "string", "default": ""},
            },
            "required": ["target_dir", "path"],
            "additionalProperties": False,
        },
    },
    {
        "name": "import_postman",
        "description": (
            "Ingest Postman Collection v2.0/v2.1 JSON (+ optional environment); seed HuntMemory."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "target_dir": {"type": "string"},
                "path": {"type": "string"},
                "environment_path": {"type": "string", "default": ""},
                "base_url": {"type": "string", "default": ""},
            },
            "required": ["target_dir", "path"],
            "additionalProperties": False,
        },
    },
    _url_tool(
        "api_authz_matrix",
        "Compare A/B/anon responses for an API endpoint (BOLA/BFLA matrix). Dry-run default.",
        {
            "method": {"type": "string", "default": "GET"},
            "session_a": {"type": "string", "default": "A"},
            "session_b": {"type": "string", "default": "B"},
        },
    ),
    _url_tool(
        "api_mass_assignment_probe",
        "Inject canary privilege fields (role/plan/tenant_id). Never destructive. Dry-run default.",
        {"session": {"type": "string", "default": "A"}},
    ),
    _url_tool(
        "api_method_override_probe",
        "Test X-HTTP-Method-Override / alternate verbs safely. Dry-run default.",
        {"session": {"type": "string", "default": "A"}},
    ),
    _url_tool(
        "api_hpp_probe",
        "Duplicate query params (id=owned&id=other) with safe IDs. Dry-run default.",
        {
            "param": {"type": "string", "default": "id"},
            "owned_id": {"type": "string", "default": "owned"},
            "other_id": {"type": "string", "default": "other"},
            "session": {"type": "string", "default": "A"},
        },
    ),
    _url_tool(
        "api_content_type_probe",
        "Compare JSON vs form vs multipart parsing with canary body. Dry-run default.",
        {"session": {"type": "string", "default": "A"}},
    ),
    _url_tool(
        "api_version_diff_probe",
        "Compare /v1 vs /v2 /api /internal variants when discovered. Dry-run default.",
        {"session": {"type": "string", "default": "A"}},
    ),
    _url_tool(
        "api_error_schema_probe",
        "Trigger harmless validation errors to learn schema/auth boundary. Dry-run default.",
        {"session": {"type": "string", "default": "A"}},
    ),
    _url_tool(
        "api_cors_probe",
        "Controlled Origin header CORS tests (canary origin). Dry-run default.",
        {"origin": {"type": "string", "default": "https://hb-canary.example"}},
    ),
    _url_tool(
        "api_cache_detect_probe",
        "Detection-only cache key/header variance. Dry-run default.",
    ),
    _url_tool(
        "api_graphql_variable_authz",
        "GraphQL A/B variable/ID swap authz check. Dry-run default.",
        {
            "query": {"type": "string", "default": ""},
            "session_a": {"type": "string", "default": "A"},
            "session_b": {"type": "string", "default": "B"},
        },
    ),
    _url_tool(
        "api_graphql_batch_alias_probe",
        "GraphQL batching/alias probe (capped, detection-only). Dry-run default.",
    ),
    _url_tool(
        "api_jwt_claim_diff",
        "Offline JWT decode + optional safe active check with test-account token. Dry-run default.",
        {
            "token": {"type": "string", "default": ""},
            "session": {"type": "string", "default": "A"},
        },
    ),
    _url_tool(
        "api_oauth_oidc_probe",
        "OIDC discovery / redirect_uri / state checks without token theft. Dry-run default.",
    ),
    _ai_tool(
        "llm_prompt_probe",
        "Prompt-injection canary probes against a chat/completions endpoint. Dry-run default.",
    ),
    _ai_tool(
        "llm_indirect_prompt_probe",
        "Indirect prompt-injection canaries (untrusted content). Dry-run default.",
    ),
    _ai_tool(
        "llm_rag_probe",
        "RAG cross-tenant / source confusion canaries. Dry-run default.",
    ),
    _ai_tool(
        "llm_tool_abuse_probe",
        "Tool-use / excessive agency canaries (dry-run tool intent). Dry-run default.",
    ),
    _ai_tool(
        "llm_tenant_isolation_probe",
        "AI tenant isolation canary (DENIED expected). Dry-run default.",
    ),
    _url_tool(
        "mcp_agent_probe",
        "MCP/JSON-RPC tools/list + resources/list exposure probe. Dry-run default.",
        {
            "canary": {"type": "string", "default": "hb-canary"},
            "session": {"type": "string", "default": ""},
            "max_payloads": {"type": "integer", "default": 2},
        },
    ),
    _url_tool(
        "ai_eval_run",
        "Run a capped multi-family AI security eval (prompt/rag/tool/…). Dry-run default.",
        {
            "families": {
                "type": "string",
                "default": "prompt-injection,rag,tool-abuse",
            },
            "canary": {"type": "string", "default": ""},
            "session": {"type": "string", "default": ""},
            "prompt_field": {"type": "string", "default": "message"},
            "session_field": {"type": "string", "default": "conversation_id"},
            "method": {"type": "string", "default": "POST"},
            "max_payloads": {"type": "integer", "default": 1},
        },
    ),
]
