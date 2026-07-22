"""ACP (Agent Client Protocol) stdio agent for Toad / Zed / other ACP clients.

Stdout is reserved for JSON-RPC. Rich logs go to stderr. Approvals use YOLO
(OOS still blocked). Launch via::

    toad acp "python -m hackbot acp" .
    # or: python -m hackbot acp
"""

from __future__ import annotations

import asyncio
import logging
import os
import sys
from typing import Any
from uuid import uuid4

from . import ui
from .tui_commands import handle_slash
from .turn_bridge import clear_bridge_histories, resolve_mode, run_bridged_turn
from .yolo import enable_yolo, is_yolo

_LOG = logging.getLogger("hackbot.acp")


def _redirect_console_to_stderr() -> None:
    """Keep ACP stdout clean (newline-delimited JSON-RPC only)."""
    try:
        ui.console.file = sys.stderr  # type: ignore[misc]
    except Exception:  # noqa: BLE001
        pass
    os.environ.setdefault("HACKBOT_PLAIN", "1")


def _block_text(block: Any) -> str:
    if isinstance(block, dict):
        text = block.get("text")
        if text:
            return str(text)
        # resource / link hints
        uri = block.get("uri") or block.get("path")
        if uri:
            return f"@{uri}"
        return ""
    text = getattr(block, "text", None)
    if text:
        return str(text)
    uri = getattr(block, "uri", None) or getattr(block, "path", None)
    if uri:
        return f"@{uri}"
    return ""


def prompt_blocks_to_text(prompt: list[Any]) -> str:
    parts = [_block_text(b) for b in prompt]
    return "\n".join(p for p in parts if p).strip()


def start_acp_agent() -> int:
    """Run the ACP agent until the client closes stdin. Returns exit code."""
    try:
        from acp import (
            PROTOCOL_VERSION,
            Agent,
            InitializeResponse,
            NewSessionResponse,
            PromptResponse,
            run_agent,
            text_block,
            update_agent_message,
        )
        from acp.interfaces import Client
        from acp.schema import AgentCapabilities, Implementation
    except ImportError:
        print(
            "ACP SDK missing. Install with:\n"
            "  pip install 'hackbot-kit[acp]'\n"
            "  # or: pip install agent-client-protocol",
            file=sys.stderr,
        )
        return 1

    _redirect_console_to_stderr()
    logging.basicConfig(
        level=logging.INFO,
        stream=sys.stderr,
        format="%(levelname)s %(name)s: %(message)s",
    )
    if not is_yolo():
        enable_yolo(quiet=True)
        _LOG.info("YOLO enabled for ACP session (OOS still blocked)")

    mode, label = resolve_mode()
    _LOG.info("hackbot ACP ready · %s", label)

    class HackbotAgent(Agent):
        _conn: Client

        def __init__(self) -> None:
            self._sessions: set[str] = set()

        def on_connect(self, conn: Client) -> None:
            self._conn = conn

        async def initialize(
            self,
            protocol_version: int,
            client_capabilities: Any = None,
            client_info: Any = None,
            **kwargs: Any,
        ) -> InitializeResponse:
            del client_capabilities, client_info, kwargs
            return InitializeResponse(
                protocol_version=min(protocol_version, PROTOCOL_VERSION),
                agent_capabilities=AgentCapabilities(),
                agent_info=Implementation(
                    name="hackbot",
                    title="hackbot",
                    version="0.1.0",
                ),
            )

        async def new_session(
            self,
            cwd: str,
            additional_directories: list[str] | None = None,
            mcp_servers: list[Any] | None = None,
            **kwargs: Any,
        ) -> NewSessionResponse:
            del additional_directories, mcp_servers, kwargs
            if cwd:
                try:
                    os.chdir(cwd)
                except OSError as exc:
                    _LOG.warning("chdir(%s) failed: %s", cwd, exc)
            session_id = uuid4().hex
            self._sessions.add(session_id)
            clear_bridge_histories()
            return NewSessionResponse(session_id=session_id)

        async def prompt(
            self,
            session_id: str,
            prompt: list[Any],
            **kwargs: Any,
        ) -> PromptResponse:
            del kwargs
            self._sessions.add(session_id)
            text = prompt_blocks_to_text(prompt)
            if not text:
                await self._conn.session_update(
                    session_id=session_id,
                    update=update_agent_message(text_block("(empty prompt)")),
                )
                return PromptResponse(stop_reason="end_turn")

            # Operator slash commands stay local — never go to the model.
            if text.startswith("/"):
                result = await asyncio.to_thread(handle_slash, text)
                if result.handled:
                    body = "\n\n".join(result.messages) or "(ok)"
                    await self._conn.session_update(
                        session_id=session_id,
                        update=update_agent_message(text_block(body)),
                    )
                    return PromptResponse(stop_reason="end_turn")

            _, label_now = resolve_mode()
            await self._conn.session_update(
                session_id=session_id,
                update=update_agent_message(
                    text_block(f"_working · {label_now}_\n\n")
                ),
            )
            try:
                answer = await asyncio.to_thread(run_bridged_turn, text)
            except Exception as exc:  # noqa: BLE001
                answer = f"Error: {type(exc).__name__}: {exc}"
            await self._conn.session_update(
                session_id=session_id,
                update=update_agent_message(text_block(answer or "(empty)")),
            )
            return PromptResponse(stop_reason="end_turn")

        async def cancel(self, session_id: str, **kwargs: Any) -> None:
            del session_id, kwargs
            try:
                from .turn_bus import get_bus

                bus = get_bus()
                if bus is not None:
                    bus.request_interrupt()
                    return
            except Exception:  # noqa: BLE001
                pass
            try:
                from .codex_backend import request_codex_cancel

                request_codex_cancel()
            except Exception:  # noqa: BLE001
                pass

    try:
        asyncio.run(run_agent(HackbotAgent()))
    except KeyboardInterrupt:
        return 130
    except Exception as exc:  # noqa: BLE001
        print(f"ACP agent failed: {exc}", file=sys.stderr)
        return 1
    return 0
