# Hackbot CLI reference

Normal day-to-day stuff is in the **[README](../README.md)**. This page is the
nerdy pocket: env knobs, low-level commands, full "I said X → tool Y" map.

## Open it

```powershell
.\.venv\Scripts\python.exe -m hackbot
.\.venv\Scripts\python.exe -m hackbot check if example.com is in scope for targets/demo
.\.venv\Scripts\python.exe -m hackbot demo
```

Linux: `source .venv/bin/activate` then `python -m hackbot`.

## YOLO + lab tools

```text
/yolo on|off          # skip y/n; force on; OOS still blocked
stack_prepare         # fix Go/gau PATH for this process
burp_ensure           # start Burp Community + wait for local REST
lab_exec              # local shell; sudo via HACKBOT_SUDO_PASS or .hackbot/sudo_pass
```

Boot already in YOLO: `HACKBOT_YOLO=1`.

YOLO skips approve prompts. It does **not** mean run forever. Default step mode
(`HACKBOT_STEP_MODE=1` / `/step on`) pauses the hunt after each act so you can say
continue / resume. Full-budget unattended loop until finding/budget/blocker:

```text
/step off
# or: export HACKBOT_STEP_MODE=0
# or say: "não pausa, executa até achar a vulnerabilidade"
```

Codex sandbox (curl/httpx need this — old default was read-only and broke hunt):

```text
# default: workspace-write + network
# /yolo on  →  danger-full-access
export HACKBOT_CODEX_SANDBOX=danger-full-access   # or workspace-write | read-only
```

## Pinning a provider (optional)

I prefer `/provider <name>` in the REPL. If you insist on pinning a shell:

```powershell
$env:HACKBOT_PROVIDER="openai"          # Windows PowerShell
# export HACKBOT_PROVIDER=openai       # Linux
```

Old alias: `HACKBOT_BACKEND`. If the REPL keeps waking up on the wrong brain,
clear both and open a new terminal:

```powershell
[Environment]::SetEnvironmentVariable("HACKBOT_BACKEND",$null,"User")
[Environment]::SetEnvironmentVariable("HACKBOT_PROVIDER",$null,"User")
```

Names I know: `openai`, `anthropic`, `codex`, `cursor`, `deepseek`, `glm`,
`openrouter`, `ollama`, `lmstudio`, `custom`, `offline`.

### Models

`/model` is picky. Only real catalog ids. `/models` and `/models refresh` exist.
Cache lives under `.hackbot/model_cache/`.

```powershell
setx HACKBOT_MODEL "o4-mini"
setx HACKBOT_EFFORT "auto"    # auto | minimal | low | medium | high | xhigh
```

Cursor: `/effort high fast` or `/fast on`. Look for `used model …` after a turn.
`HACKBOT_CURSOR_TOOLS=1` (default) registers my CustomTools.
`HACKBOT_CURSOR_MODE=plan|agent` if you need to override.

### Streaming / noise / Codex files

```text
/stream on|off
/verbose on|off
/codex-write          # Codex file proposals on/off (still asks per edit)
```

### Strict redaction

```powershell
setx HACKBOT_STRICT_REDACT "1"
```

Saves bail if evidence/report still looks juicy after the soft regex pass.

## SCOPE.md and config

Put YAML front-matter on `SCOPE.md` for `in_scope`, `out_of_scope`, `allowed`,
`prohibited`. URL/CIDR rules and Playwright re-gating: [SAFETY_MODEL.md](SAFETY_MODEL.md).

```powershell
copy configs\hackbot.example.yaml configs\hackbot.yaml
.\.venv\Scripts\python.exe -m hackbot show-config
.\.venv\Scripts\python.exe -m hackbot policy-import targets/demo --file policy.md --write
```

Knobs I actually honor: `safety.default_max_rps` / `HACKBOT_MAX_RPS`,
`safety.subprocess_timeout_sec` / `HACKBOT_SUBPROCESS_TIMEOUT`.

## Hunt knobs

| Env | What |
| --- | --- |
| `HACKBOT_HUNT_BUDGET` | Act budget (default ~28) |
| `HACKBOT_HUNT_PHASE_BUDGETS` | e.g. `recon:30,authz:35,inject:35` |
| `HACKBOT_HUNT_RESUME=1` | Resume from `hunt/state.yaml` |
| `HACKBOT_TOOL_PACK` | `auto\|all\|core,recon,…` — elite tools are inside normal packs; `advanced`/`study-extreme` = `all` |
| `HACKBOT_REPORT_PLATFORM` | e.g. `bugcrowd` / `generic` |
| `HACKBOT_AUTO_ROUTE=0` | Kill offline→model JSON router |
| `HACKBOT_ROUTE_THRESHOLD` | Default `0.68` |

State: `targets/<name>/hunt/`. IdP: headed `browser_capture_session` (you finish
login). Resume with "resume hunt" / `run_hunt resume=true`. I don't bypass MFA.

## Full NL → tool map

| You say roughly | Tool |
| --- | --- |
| Account A/B email/password / `accounts.yaml` | `set_account` |
| Sessions from a file | `load_sessions_from_file` |
| Extract / summarize page | `extract_page` |
| Create/edit/delete file or folder | `write_file` / `edit_file` / `delete_path` / `make_dir` |
| Read image / screenshot | `read_image` |
| HAR / Burp export | `import_har` / `import_burp_xml` |
| OpenAPI / Swagger | `import_openapi` |
| Postman collection | `import_postman` |
| AI / LLM / MCP | `llm_prompt_probe`, `llm_rag_probe`, `mcp_agent_probe`, `ai_eval_run` |
| API authz / canary probes | `api_authz_matrix`, `api_mass_assignment_probe`, … |
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
| What's in folder X | `list_dir` |
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

Playwright comes with `pip install -e .`. Then `playwright install chromium`.
Frida hooks are allowlisted lab templates. I don't silent-hook your phone.

## OOB / Interactsh

```powershell
setx HACKBOT_INTERACTSH "1"
# optional: HACKBOT_INTERACTSH_SERVER / HACKBOT_INTERACTSH_TOKEN
pip install cryptography

# Old Collaborator-style:
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

NL: `burp replay https://example.com/api` (dry-run until you approve).

## Campaign / playbooks

Named classes (DDoS, bruteforce, secrets, …) still go through `run_campaign`.
Vague prompts prefer `/hunt`. Low offline confidence can ask a configured model
to route (`HACKBOT_AUTO_ROUTE=1`).

```powershell
.\.venv\Scripts\python.exe -m hackbot playbook idor --endpoint https://example.com/api/orders/1
.\.venv\Scripts\python.exe -m hackbot playbook rate-limit --run --host example.com --target-dir targets/demo
.\.venv\Scripts\python.exe -m hackbot run targets/demo --tool rate_probe --host example.com
```

Extreme playbooks (study + capped tools): `invite-idor`, `dom-xss`, `cache-detect`, `prohibited-stop`.

## Workflows / coverage (always available)

YAML under `targets/<name>/hunt/workflows/`. See [WORKFLOW_HARNESS.md](WORKFLOW_HARNESS.md).

In the agent / REPL tools (no special pack required):

- `workflow_load` → preview
- `workflow_run` (`approve=false` dry-run; `approve=true` ACTIVE)
- `coverage_map` / `hunt_cockpit`
- Extreme notes: `open_knowledge` (task keywords like `extreme`, `saml`, `prohibited`)
- Optional: `HACKBOT_TOOL_PACK=all` if you want every tool every turn

## HexStrike

Own venv or Docker. Not the kit `.venv`. See
[integrations/hexstrike/PROVENANCE.md](../integrations/hexstrike/PROVENANCE.md).

```powershell
.\.venv\Scripts\python.exe -m hackbot run targets/demo --tool hexstrike --approve
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
