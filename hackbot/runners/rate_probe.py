"""Controlled rate-limit / concurrency probe (aggression level 3).

Bounded totals and concurrency — not an unbounded flood. Operator must approve
active traffic; SCOPE or /force must allow level 3.
"""

from __future__ import annotations

import concurrent.futures
import time
import urllib.error
import urllib.request
from collections import Counter
from pathlib import Path

from .. import ui
from ..config import get_config
from .base import RunnerResult, require_in_scope

# Hard caps — never exceed even if caller asks higher.
MAX_CONCURRENCY = 20
MAX_TOTAL = 100
DEFAULT_CONCURRENCY = 5
DEFAULT_TOTAL = 25
DEFAULT_TIMEOUT = 5.0


def rate_probe(
    target_dir: Path,
    host_or_url: str,
    *,
    concurrency: int = DEFAULT_CONCURRENCY,
    total: int = DEFAULT_TOTAL,
    timeout: float = DEFAULT_TIMEOUT,
    method: str = "GET",
    approve: bool = False,
    force: bool = False,
) -> RunnerResult:
    # Honor configs/hackbot*.yaml safety.default_max_rps (and HACKBOT_MAX_RPS).
    cfg_rps = max(1, int(get_config().safety.default_max_rps))
    concurrency = max(1, min(int(concurrency), MAX_CONCURRENCY, cfg_rps))
    total = max(1, min(int(total), MAX_TOTAL))
    timeout = max(0.5, min(float(timeout), 30.0))
    method = (method or "GET").upper()

    require_in_scope(
        target_dir,
        host_or_url,
        action="rate-limit testing dos stress",
        force=force,
    )
    url = host_or_url if "://" in host_or_url else f"https://{host_or_url}"

    plan = (
        f"rate_probe method={method} url={url} "
        f"concurrency={concurrency} total={total} timeout={timeout}s"
    )
    ui.code_panel(plan, title="command", lexer="text")

    if not approve:
        ui.dry_run_banner()
        return RunnerResult(
            command=["rate_probe", method, url, str(concurrency), str(total)],
            executed=False,
            returncode=None,
            stdout="",
            stderr="",
            message="dry-run",
        )

    statuses: list[int] = []
    errors: list[str] = []
    latencies: list[float] = []

    def one(_i: int) -> tuple[int | None, float, str | None]:
        req = urllib.request.Request(url, method=method)
        started = time.perf_counter()
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                code = int(getattr(resp, "status", None) or resp.getcode())
                _ = resp.read(64)
            return code, time.perf_counter() - started, None
        except urllib.error.HTTPError as exc:
            return int(exc.code), time.perf_counter() - started, None
        except Exception as exc:  # noqa: BLE001 — report, don't crash the probe
            return None, time.perf_counter() - started, f"{type(exc).__name__}: {exc}"

    with ui.console.status("[cyan]rate_probe running...[/]", spinner="dots"):
        with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as pool:
            futs = [pool.submit(one, i) for i in range(total)]
            for fut in concurrent.futures.as_completed(futs):
                code, elapsed, err = fut.result()
                latencies.append(elapsed)
                if err:
                    errors.append(err)
                elif code is not None:
                    statuses.append(code)

    counts = Counter(statuses)
    avg_ms = (sum(latencies) / len(latencies) * 1000) if latencies else 0.0
    summary_lines = [
        f"sent={total} concurrency={concurrency}",
        f"status_counts={dict(sorted(counts.items()))}",
        f"errors={len(errors)} avg_latency_ms={avg_ms:.1f}",
    ]
    if errors:
        summary_lines.append("first_errors=" + "; ".join(errors[:5]))
    stdout = "\n".join(summary_lines)
    ui.code_panel(stdout, title="stdout", lexer="text")
    ui.success("rate_probe finished")
    return RunnerResult(
        command=["rate_probe", method, url, str(concurrency), str(total)],
        executed=True,
        returncode=0,
        stdout=stdout,
        stderr="\n".join(errors[:20]),
        message="executed",
    )
