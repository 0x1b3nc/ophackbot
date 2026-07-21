# Hackbot CLI reference

Day-to-day use (install, brains, hunt, approve UX, `/tools`) lives in the
**[README](../README.md)**. This page is the deeper reference: env knobs,
low-level commands, and the full NL → tool map.

## Agent entrypoints

```powershell
.\.venv\Scripts\python.exe -m hackbot
.\.venv\Scripts\python.exe -m hackbot check if example.com is in scope for targets/demo
.\.venv\Scripts\python.exe -m hackbot demo
```

Linux: `source .venv/bin/activate` then `python -m hackbot`.

## Provider env (optional pin)

Prefer `/provider <name>` in the REPL. Pin for one shell only if needed:

```powershell
$env:HACKBOT_PROVIDER="openai"          # Windows PowerShell
# export HACKBOT_PROVIDER=openai       # Linux
```

Legacy alias: `HACKBOT_BACKEND` (same values). Clear both if the REPL keeps
opening on the wrong brain:

```powershell
[Environment]::SetEnvironmentVariable("HACKBOT_BACKEND",$null,"User")
[Environment]::SetEnvironmentVariable("HACKBOT_PROVIDER",$null,"User")
```

Known names: `openai`, `anthropic`, `codex`, `cursor`, `deepseek`, `glm`,
`openrouter`, `ollama`, `lmstudio`, `custom`, `offline`.

### Models

`/model` is strict: only catalog ids (`/models`, `/models refresh`). Live lists
are TTL-cached under `.hackbot/model_cache/`.

```powershell
setx HACKBOT_MODEL "o4-mini"
setx HACKBOT_EFFORT "auto"    # auto | minimal | low | medium | high | xhigh
```

Cursor: `/effort high fast` or `/fast on`. Each Cursor turn prints `used model …`.
`HACKBOT_CURSOR_TOOLS=1` (default) registers CustomTools; override mode with
`HACKBOT_CURSOR_MODE=plan|agent`.

### Streaming / verbose / Codex files

```text
/stream on|off
/verbose on|off
/codex-write          # toggle Codex-proposed file ops (still asks per edit)
```

### Strict redaction

```powershell
setx HACKBOT_STRICT_REDACT "1"
```

Save refuses if evidence/report text still looks sensitive after regex redact.

## SCOPE.md & config

Prefer YAML front-matter on `SCOPE.md` for `in_scope`, `out_of_scope`, `allowed`,
`prohibited`. URL/CIDR rules and Playwright re-gating: see
[SAFETY_MODEL.md](SAFETY_MODEL.md).

```powershell
copy configs\hackbot.example.yaml configs\hackbot.yaml
.\.venv\Scripts\python.exe -m hackbot show-config
.\.venv\Scripts\python.exe -m hackbot policy-import targets/demo --file policy.md --write
```

Knobs: `safety.default_max_rps` / `HACKBOT_MAX_RPS`,
`safety.subprocess_timeout_sec` / `HACKBOT_SUBPROCESS_TIMEOUT`.

## Hunt knobs

| Env | Meaning |
| --- | --- |
| `HACKBOT_HUNT_BUDGET` | Act budget (default ~28) |
| `HACKBOT_HUNT_PHASE_BUDGETS` | e.g. `recon:30,authz:35,inject:35` |
| `HACKBOT_HUNT_RESUME=1` | Resume from `hunt/state.yaml` |
| `HACKBOT_TOOL_PACK` | `auto\|all\|core,recon,inject,browser,mobile,report` |
| `HACKBOT_REPORT_PLATFORM` | e.g. `bugcrowd` / `generic` |
| `HACKBOT_AUTO_ROUTE=0` | Disable offline→model JSON router |
| `HACKBOT_ROUTE_THRESHOLD` | Default `0.68` |

State: `targets/<name>/hunt/` (`surface.yaml`, `attempts.jsonl`, `state.yaml`, …).

IdP: headed `browser_capture_session` (operator finishes login); resume with
“resume hunt” / `run_hunt resume=true`. Never bypass MFA.

## Full NL → tool map

| Ask in natural language | Tool |
| --- | --- |
| Account A/B email/password / `accounts.yaml` | `set_account` |
| Sessions from a file | `load_sessions_from_file` |
| Extract / summarize page | `extract_page` |
| Create/edit/delete file or folder | `write_file` / `edit_file` / `delete_path` / `make_dir` |
| Read image / screenshot | `read_image` |
| HAR / Burp export | `import_har` / `import_burp_xml` |
| Analyze `app.js` / bundle URL | `analyze_js` |
| Decode JWT | `analyze_jwt` |
| GraphQL introspection | `graphql_probe` |
| CORS / open redirect | `cors_probe` / `open_redirect_probe` |
| Hidden params | `mine_params` |
| LFI / SSTI / XXE | `lfi_probe` / `ssti_probe` / `xxe_probe` |
| JWT active (alg=none / claim flip) | `jwt_active_probe` |
| OAuth authorize checks | `oauth_probe` |
| Exploit chains A→B | `build_chains` |
| Subdomains / wayback | `crt_subdomains` / `wayback_urls` |
| Security headers | `analyze_headers` |
| What’s in folder X | `list_dir` |
| Playwright navigate / screenshot | `browser_navigate` / `browser_screenshot` |
| Cookies / storage (redacted) | `browser_cookies` / `browser_storage` |
| Capture XHR → surface | `browser_network` |
| Open as session A/B | `browser_with_session` |
| Diff URL as A vs B | `browser_diff_sessions` |
| IdP capture (headed) | `browser_capture_session` |
| Burp REST up? | `burp_rest_health` |
| Burp history / issues / replay | `burp_proxy_history` / `burp_issue_list` / `burp_replay` |
| What worked before? | `learn_suggest` / `learn_stats` |
| Mobile / adb / APK | `mobile_status` / `adb_devices` / `inspect_apk` / `mobile_bridge` |
| MobSF / Frida / Objection | `mobsf_*` / `frida_*` / `objection_explore` |
| Draft bounty report | `write_report_draft` |
| SSRF / race / websocket | `ssrf_probe` / `race_probe` / `websocket_probe` |
| IDOR A/B | `idor_probe` |
| Session bootstrap / detect login | `session_bootstrap` / `detect_login` / `session_smoke` |
| Content discovery (capped) | `discover_paths` |
| OOB / Interactsh | `oob_mint` / `interactsh_*` |
| Stack health | `capabilities` |
| Hunt checklist / pause | `hunt_checklist` / `hunt_pause` / `hunt_telemetry` |

Playwright ships with `pip install -e .`; run `playwright install chromium`.
Frida hooks are allowlisted lab templates only — never silent.

## OOB / Interactsh

```powershell
setx HACKBOT_INTERACTSH "1"
# optional: HACKBOT_INTERACTSH_SERVER / HACKBOT_INTERACTSH_TOKEN
pip install cryptography

# Legacy Collaborator-style:
setx HACKBOT_OOB_BASE "https://YOUR.oast.fun"
setx HACKBOT_OOB_POLL_URL "https://YOUR/poll?id=TOKEN"
setx HACKBOT_OOB_AUTH "Bearer ..."
```

## Burp control plane (local)

```powershell
setx HACKBOT_BURP_BASE "http://127.0.0.1:1337"
setx HACKBOT_BURP_API_KEY "..."
setx HACKBOT_BURP_MCP_CMD "path\to\burp-mcp-server.exe"
```

NL: `burp replay https://example.com/api` → dry-run until approve.

## Campaign / playbooks (named classes)

Named classes (DDoS, bruteforce, secrets, …) still use `run_campaign`. Open-ended
prompts prefer `/hunt`. Offline low confidence may ask a configured model to
route (`HACKBOT_AUTO_ROUTE=1`).

```powershell
.\.venv\Scripts\python.exe -m hackbot playbook idor --endpoint https://example.com/api/orders/1
.\.venv\Scripts\python.exe -m hackbot playbook rate-limit --run --host example.com --target-dir targets/demo
.\.venv\Scripts\python.exe -m hackbot run targets/demo --tool rate_probe --host example.com
```

## HexStrike

Separate venv or Docker — not the kit `.venv`. See
[integrations/hexstrike/PROVENANCE.md](../integrations/hexstrike/PROVENANCE.md).

```powershell
.\.venv\Scripts\python.exe -m hackbot run targets/demo --tool hexstrike --approve
# docker:
.\.venv\Scripts\python.exe -m hackbot run targets/demo --tool hexstrike --docker --approve
```

## Low-level commands

```powershell
.\.venv\Scripts\python.exe -m hackbot cmd
.\.venv\Scripts\python.exe -m hackbot scope-check targets/demo --host example.com
.\.venv\Scripts\python.exe -m hackbot run targets/demo --tool httpx --host example.com
.\.venv\Scripts\python.exe -m hackbot run targets/demo --tool katana --host example.com --approve
.\.venv\Scripts\python.exe -m hackbot run targets/demo --tool nuclei --host example.com --approve
```
