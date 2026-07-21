"""LLM transport. OpenAI-wire or Anthropic-wire, driven by providers.Config.

Provider selection, models and reasoning-effort normalization live in
providers.py. This module only speaks HTTP (stdlib) and injects the right
reasoning knob for the active wire.
"""

from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any, Callable

from .providers import Config, ConfigError, resolve_config

DeltaFn = Callable[[str], None]


@dataclass
class LLMMessage:
    role: str  # user | assistant | tool
    content: str | list[dict[str, Any]]
    tool_call_id: str | None = None
    name: str | None = None


@dataclass
class ToolCall:
    id: str
    name: str
    arguments: dict[str, Any]


@dataclass
class LLMResponse:
    text: str
    tool_calls: list[ToolCall]
    raw: dict[str, Any]


class LLMError(RuntimeError):
    pass


def detect_provider() -> tuple[str, str]:
    """Return (provider, model). Raises LLMError if nothing configured."""
    try:
        cfg = resolve_config()
    except ConfigError as exc:
        raise LLMError(str(exc)) from exc
    return cfg.provider, cfg.model


_ANTHROPIC_EFFORT_BUDGET = {
    "minimal": 0,
    "low": 2048,
    "medium": 6000,
    "high": 12000,
    "xhigh": 24000,
}


def _is_openai_reasoning_model(model: str) -> bool:
    m = model.lower()
    if re.match(r"^o\d", m):  # o1, o3, o4, o5...
        return True
    return "gpt-5" in m or "reason" in m


def _is_anthropic_thinking_model(model: str) -> bool:
    m = model.lower()
    return "-4" in m or "3-7" in m or "opus-4" in m or "sonnet-4" in m


def _apply_openai_effort(body: dict[str, Any], cfg: Config) -> None:
    if not cfg.effort:
        return
    level = "high" if cfg.effort == "xhigh" else cfg.effort
    style = cfg.effort_style
    if style == "openai":
        if _is_openai_reasoning_model(cfg.model):
            body["reasoning_effort"] = level
    elif style == "openrouter":
        body["reasoning"] = {"effort": level}
    elif style == "glm":
        enabled = cfg.effort in ("medium", "high", "xhigh")
        body["thinking"] = {"type": "enabled" if enabled else "disabled"}


def _streaming_enabled() -> bool:
    return os.environ.get("HACKBOT_STREAM", "1").strip().lower() not in {"0", "false", "no", "off"}


def streaming_enabled() -> bool:
    """Public: is live streaming turned on? (HACKBOT_STREAM=0 disables)."""
    return _streaming_enabled()


def chat(
    *,
    system: str,
    messages: list[dict[str, Any]],
    tools: list[dict[str, Any]],
    on_reasoning: DeltaFn | None = None,
    on_text: DeltaFn | None = None,
) -> LLMResponse:
    try:
        cfg = resolve_config()
    except ConfigError as exc:
        raise LLMError(str(exc)) from exc
    if cfg.wire == "codex":
        raise LLMError("codex provider runs through the codex CLI, not the HTTP client.")

    stream = _streaming_enabled() and (on_reasoning is not None or on_text is not None)
    if cfg.wire == "anthropic":
        if stream:
            return _anthropic_stream(
                system=system, messages=messages, tools=tools, cfg=cfg,
                on_reasoning=on_reasoning, on_text=on_text,
            )
        return _anthropic(system=system, messages=messages, tools=tools, cfg=cfg)
    if stream:
        return _openai_stream(
            system=system, messages=messages, tools=tools, cfg=cfg,
            on_reasoning=on_reasoning, on_text=on_text,
        )
    return _openai(system=system, messages=messages, tools=tools, cfg=cfg)


def _http_json(url: str, headers: dict[str, str], body: dict[str, Any]) -> dict[str, Any]:
    data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise LLMError(f"HTTP {exc.code}: {detail[:800]}") from exc
    except urllib.error.URLError as exc:
        raise LLMError(f"network error: {exc}") from exc


def _http_stream(url: str, headers: dict[str, str], body: dict[str, Any]):
    """POST with stream=true and yield decoded SSE lines."""
    data = json.dumps({**body, "stream": True}).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    try:
        resp = urllib.request.urlopen(req, timeout=300)
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise LLMError(f"HTTP {exc.code}: {detail[:800]}") from exc
    except urllib.error.URLError as exc:
        raise LLMError(f"network error: {exc}") from exc
    with resp:
        for raw in resp:
            yield raw.decode("utf-8", errors="replace").rstrip("\r\n")


# --- Anthropic wire --------------------------------------------------------

def _anthropic_build(
    system: str,
    messages: list[dict[str, Any]],
    tools: list[dict[str, Any]],
    cfg: Config,
) -> tuple[str, dict[str, str], dict[str, Any]]:
    model = cfg.model
    anth_messages: list[dict[str, Any]] = []
    pending_tools: list[dict[str, Any]] = []

    def flush_tools() -> None:
        nonlocal pending_tools
        if pending_tools:
            anth_messages.append({"role": "user", "content": pending_tools})
            pending_tools = []

    for msg in messages:
        role = msg["role"]
        if role == "tool":
            pending_tools.append(
                {
                    "type": "tool_result",
                    "tool_use_id": msg["tool_call_id"],
                    "content": msg["content"],
                }
            )
            continue
        flush_tools()
        if role == "assistant" and msg.get("tool_calls"):
            content: list[dict[str, Any]] = []
            if msg.get("content"):
                content.append({"type": "text", "text": msg["content"]})
            for tc in msg["tool_calls"]:
                content.append(
                    {
                        "type": "tool_use",
                        "id": tc["id"],
                        "name": tc["name"],
                        "input": tc["arguments"],
                    }
                )
            anth_messages.append({"role": "assistant", "content": content})
            continue
        anth_messages.append({"role": role, "content": msg["content"]})
    flush_tools()

    anth_tools = [
        {
            "name": t["name"],
            "description": t["description"],
            "input_schema": t["parameters"],
        }
        for t in tools
    ]
    body: dict[str, Any] = {
        "model": model,
        "max_tokens": 4096,
        "system": system,
        "messages": anth_messages,
        "tools": anth_tools,
    }
    if cfg.effort and cfg.effort_style == "anthropic" and _is_anthropic_thinking_model(model):
        budget = _ANTHROPIC_EFFORT_BUDGET.get(cfg.effort, 0)
        if budget > 0:
            body["thinking"] = {"type": "enabled", "budget_tokens": budget}
            body["max_tokens"] = budget + 4096
    base_url = cfg.base_url or "https://api.anthropic.com"
    url = f"{base_url}/v1/messages"
    headers = {
        "Content-Type": "application/json",
        "x-api-key": cfg.api_key,
        "anthropic-version": "2023-06-01",
    }
    return url, headers, body


def _anthropic(
    *,
    system: str,
    messages: list[dict[str, Any]],
    tools: list[dict[str, Any]],
    cfg: Config,
) -> LLMResponse:
    url, headers, body = _anthropic_build(system, messages, tools, cfg)
    raw = _http_json(url, headers, body)
    text_parts: list[str] = []
    tool_calls: list[ToolCall] = []
    for block in raw.get("content", []):
        if block.get("type") == "text":
            text_parts.append(block.get("text", ""))
        elif block.get("type") == "tool_use":
            tool_calls.append(
                ToolCall(
                    id=block["id"],
                    name=block["name"],
                    arguments=block.get("input") or {},
                )
            )
    return LLMResponse(text="\n".join(text_parts).strip(), tool_calls=tool_calls, raw=raw)


def _anthropic_stream(
    *,
    system: str,
    messages: list[dict[str, Any]],
    tools: list[dict[str, Any]],
    cfg: Config,
    on_reasoning: DeltaFn | None,
    on_text: DeltaFn | None,
) -> LLMResponse:
    url, headers, body = _anthropic_build(system, messages, tools, cfg)
    text_parts: list[str] = []
    tool_calls: list[ToolCall] = []
    blocks: dict[int, dict[str, Any]] = {}
    for line in _http_stream(url, headers, body):
        if not line.startswith("data:"):
            continue
        payload = line[5:].strip()
        if not payload:
            continue
        try:
            evt = json.loads(payload)
        except json.JSONDecodeError:
            continue
        etype = evt.get("type")
        if etype == "content_block_start":
            idx = evt.get("index", 0)
            cb = evt.get("content_block") or {}
            blocks[idx] = {"type": cb.get("type"), "id": cb.get("id"), "name": cb.get("name"), "input": ""}
        elif etype == "content_block_delta":
            idx = evt.get("index", 0)
            d = evt.get("delta") or {}
            dt = d.get("type")
            if dt == "text_delta":
                txt = d.get("text", "")
                text_parts.append(txt)
                if on_text:
                    on_text(txt)
            elif dt == "thinking_delta":
                if on_reasoning:
                    on_reasoning(d.get("thinking", ""))
            elif dt == "input_json_delta":
                blk = blocks.get(idx)
                if blk is not None:
                    blk["input"] += d.get("partial_json", "")
        elif etype == "content_block_stop":
            blk = blocks.get(evt.get("index", 0))
            if blk and blk.get("type") == "tool_use":
                try:
                    args = json.loads(blk["input"] or "{}")
                except json.JSONDecodeError:
                    args = {"_raw": blk["input"]}
                tool_calls.append(ToolCall(id=blk["id"], name=blk["name"], arguments=args))
        elif etype == "message_stop":
            break
    return LLMResponse(text="".join(text_parts).strip(), tool_calls=tool_calls, raw={})


# --- OpenAI wire -----------------------------------------------------------

def _openai_build(
    system: str,
    messages: list[dict[str, Any]],
    tools: list[dict[str, Any]],
    cfg: Config,
) -> tuple[str, dict[str, str], dict[str, Any]]:
    oai_messages = [{"role": "system", "content": system}]
    for msg in messages:
        if msg["role"] == "tool":
            oai_messages.append(
                {
                    "role": "tool",
                    "tool_call_id": msg["tool_call_id"],
                    "content": msg["content"],
                }
            )
        elif msg["role"] == "assistant" and msg.get("tool_calls"):
            oai_messages.append(
                {
                    "role": "assistant",
                    "content": msg.get("content") or None,
                    "tool_calls": [
                        {
                            "id": tc["id"],
                            "type": "function",
                            "function": {
                                "name": tc["name"],
                                "arguments": json.dumps(tc["arguments"]),
                            },
                        }
                        for tc in msg["tool_calls"]
                    ],
                }
            )
        else:
            oai_messages.append({"role": msg["role"], "content": msg["content"]})

    oai_tools = [
        {
            "type": "function",
            "function": {
                "name": t["name"],
                "description": t["description"],
                "parameters": t["parameters"],
            },
        }
        for t in tools
    ]
    base_url = cfg.base_url or "https://api.openai.com/v1"
    body: dict[str, Any] = {
        "model": cfg.model,
        "messages": oai_messages,
        "tools": oai_tools,
        "tool_choice": "auto",
    }
    _apply_openai_effort(body, cfg)
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {cfg.api_key}",
    }
    if cfg.provider == "openrouter":
        headers["HTTP-Referer"] = "https://github.com/hackbot-kit"
        headers["X-Title"] = "hackbot"
    return f"{base_url}/chat/completions", headers, body


def _openai(
    *,
    system: str,
    messages: list[dict[str, Any]],
    tools: list[dict[str, Any]],
    cfg: Config,
) -> LLMResponse:
    url, headers, body = _openai_build(system, messages, tools, cfg)
    raw = _http_json(url, headers, body)
    choice = raw["choices"][0]["message"]
    text = choice.get("content") or ""
    tool_calls: list[ToolCall] = []
    for tc in choice.get("tool_calls") or []:
        args_raw = tc["function"].get("arguments") or "{}"
        try:
            args = json.loads(args_raw)
        except json.JSONDecodeError:
            args = {"_raw": args_raw}
        tool_calls.append(
            ToolCall(id=tc["id"], name=tc["function"]["name"], arguments=args)
        )
    return LLMResponse(text=text.strip(), tool_calls=tool_calls, raw=raw)


def _reasoning_delta_text(delta: dict[str, Any]) -> str:
    """Pull reasoning text from the many shapes providers use."""
    for key in ("reasoning_content", "reasoning"):
        val = delta.get(key)
        if isinstance(val, str):
            return val
        if isinstance(val, dict):
            return val.get("text") or val.get("content") or ""
        if isinstance(val, list):
            return "".join(
                (p.get("text") or "") if isinstance(p, dict) else str(p) for p in val
            )
    return ""


def _openai_stream(
    *,
    system: str,
    messages: list[dict[str, Any]],
    tools: list[dict[str, Any]],
    cfg: Config,
    on_reasoning: DeltaFn | None,
    on_text: DeltaFn | None,
) -> LLMResponse:
    url, headers, body = _openai_build(system, messages, tools, cfg)
    text_parts: list[str] = []
    tool_map: dict[int, dict[str, str]] = {}
    for line in _http_stream(url, headers, body):
        if not line.startswith("data:"):
            continue
        payload = line[5:].strip()
        if not payload or payload == "[DONE]":
            if payload == "[DONE]":
                break
            continue
        try:
            chunk = json.loads(payload)
        except json.JSONDecodeError:
            continue
        choices = chunk.get("choices") or []
        if not choices:
            continue
        delta = choices[0].get("delta") or {}
        r = _reasoning_delta_text(delta)
        if r and on_reasoning:
            on_reasoning(r)
        c = delta.get("content")
        if c:
            text_parts.append(c)
            if on_text:
                on_text(c)
        for tcd in delta.get("tool_calls") or []:
            idx = tcd.get("index", 0)
            slot = tool_map.setdefault(idx, {"id": "", "name": "", "args": ""})
            if tcd.get("id"):
                slot["id"] = tcd["id"]
            fn = tcd.get("function") or {}
            if fn.get("name"):
                slot["name"] += fn["name"]
            if fn.get("arguments"):
                slot["args"] += fn["arguments"]
    tool_calls: list[ToolCall] = []
    for idx in sorted(tool_map):
        slot = tool_map[idx]
        if not slot["name"]:
            continue
        try:
            args = json.loads(slot["args"] or "{}")
        except json.JSONDecodeError:
            args = {"_raw": slot["args"]}
        tool_calls.append(
            ToolCall(id=slot["id"] or f"call_{idx}", name=slot["name"], arguments=args)
        )
    return LLMResponse(text="".join(text_parts).strip(), tool_calls=tool_calls, raw={})
