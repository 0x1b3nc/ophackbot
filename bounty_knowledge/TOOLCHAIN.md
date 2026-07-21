# Toolchain I Use

Tools I already have on the VM. I don't reinstall them unless something's actually broken.

| Tool | Phase | Persona I lean on |
|------|-------|-------------------|
| `subfinder`, `amass`, `dnsx` | Subdomains | `recon-advisor` |
| `httpx` | Live hosts | `recon-advisor` |
| `katana`, `waybackurls`, `gau` | Crawl / history | `recon-advisor`, `web-hunter` |
| `ffuf` | Dir/param fuzz | `web-hunter`, `vuln-scanner` |
| `arjun` | Params | `web-hunter`, `api-security` |
| `nuclei` | Official + community templates | `vuln-scanner` |
| `cent` (`~/go/bin/cent`) | Aggregate community templates | `vuln-scanner` |
| HexStrike + Burp | Validation | `poc-validator`, `bizlogic-hunter` |

## Local paths (don't reinvent)

| Resource | Path |
|----------|------|
| Official nuclei (PD) | `~/.local/nuclei-templates` (~13k YAML, incl. `dast/`) |
| Community nuclei (`cent`) | `bounty_knowledge/nuclei-community/cent-templates` |
| PayloadsAllTheThings | `bounty_knowledge/PayloadsAllTheThings/` |
| HexStrike | calls `nuclei` from PATH (doesn't ship its own templates) |

How I usually run nuclei:

```bash
# official, selective
nuclei -u URL -tags kev,exposure,misconfig -severity critical,high,medium

# DAST/fuzz (old fuzzing-templates, now under dast/)
nuclei -u URL -dast -severity medium,high,critical

# community (noisy — filter tags/severity; validate FPs)
nuclei -u URL -t bounty_knowledge/nuclei-community/cent-templates -severity critical,high
```

## Persona routing (Bug-Bounty-Agents)

| Situation | Agent (`.cursor/rules/`) |
|-----------|---------------------------|
| New program / scope | `engagement-planner` + `bug-bounty` |
| Wide recon | `recon-advisor` → `osint-collector` |
| SPA / REST APIs | `web-hunter` + `api-security` |
| GraphQL | `graphql-hunter` |
| JWT / OAuth | `jwt-cracker` |
| SSRF | `ssrf-hunter` |
| Biz logic / payment | `bizlogic-hunter` |
| IDOR / cross-account | `bizlogic-hunter` + `poc-validator` |
| Cloud (AWS/GCP/Azure) | `cloud-security` |
| Subdomain takeover | `subdomain-takeover` |
| LLM / chatbot in scope | `llm-redteam` |
| Coordinate everything | `swarm-orchestrator` |
| Bugcrowd report (VRT) | `report-generator` |

Full index: `Bug-Bounty-Agents/AGENTS.md`

## Stuff from awesome-bugbounty-tools (install on demand)

I check `awesome-bugbounty-tools/README.md` before installing. Priority when I'm missing something:

- **Secrets/JS:** `nuclei` (`~/.local/nuclei-templates`) + `katana` + grep
- **GraphQL:** `clairvoyance`, `graphql-cop` (if GraphQL is in scope)
- **JWT:** `jwt_tool` (`jwt-cracker` persona)
- **SSRF / payloads:** `bounty_knowledge/PayloadsAllTheThings/` (cloned; not just an awesome link)
- **Community templates:** `cent` → `bounty_knowledge/nuclei-community/`; prefer official+tags before blasting the whole community set
- **H1/BC scopes:** `bounty-targets-data`

I don't install Docker-heavy stacks (Ars0n, full Darkmoon) on this VM.

## Agent security (reference)

`awesome-agent-skills-security/` — when I add external skills/MCP, I check supply chain and I don't pipe target output into `| bash`.
