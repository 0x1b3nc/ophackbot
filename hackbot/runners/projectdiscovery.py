"""ProjectDiscovery stack: httpx, katana, nuclei, plus ffuf."""

from __future__ import annotations

from pathlib import Path

from .base import RunnerResult, require_in_scope, run_command


def httpx_probe(
    target_dir: Path,
    host: str,
    *,
    approve: bool = False,
    force: bool = False,
) -> RunnerResult:
    require_in_scope(target_dir, host, action="httpx fingerprint", force=force)
    url = host if "://" in host else f"https://{host}"
    return run_command(
        ["httpx", "-u", url, "-title", "-tech-detect", "-status-code", "-silent"],
        approve=approve,
    )


def katana_crawl(
    target_dir: Path,
    host: str,
    *,
    depth: int = 2,
    approve: bool = False,
    force: bool = False,
) -> RunnerResult:
    require_in_scope(target_dir, host, action="katana crawl", force=force)
    url = host if "://" in host else f"https://{host}"
    return run_command(
        ["katana", "-u", url, "-d", str(depth), "-silent"],
        approve=approve,
    )


def nuclei_scan(
    target_dir: Path,
    host: str,
    *,
    templates: str | None = None,
    rate_limit: int = 10,
    concurrency: int = 5,
    approve: bool = False,
    force: bool = False,
) -> RunnerResult:
    require_in_scope(target_dir, host, action="nuclei templates", force=force)
    url = host if "://" in host else f"https://{host}"
    cmd = [
        "nuclei",
        "-u",
        url,
        "-rl",
        str(rate_limit),
        "-c",
        str(concurrency),
        "-silent",
    ]
    if templates:
        cmd.extend(["-t", templates])
    return run_command(cmd, approve=approve)


def ffuf_dir(
    target_dir: Path,
    url: str,
    wordlist: str,
    *,
    approve: bool = False,
    force: bool = False,
) -> RunnerResult:
    require_in_scope(target_dir, url, action="ffuf fuzz", force=force)
    if "FUZZ" not in url:
        url = url.rstrip("/") + "/FUZZ"
    return run_command(
        ["ffuf", "-u", url, "-w", wordlist, "-mc", "200,204,301,302,307,401,403"],
        approve=approve,
    )
