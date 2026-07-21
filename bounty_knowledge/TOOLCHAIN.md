# Toolchain — VM + Agentes

Ferramentas **já presentes** nesta VM (não reinstalar sem bloqueio real):

| Ferramenta | Fase | Agente sugerido |
|------------|------|-----------------|
| `subfinder`, `amass`, `dnsx` | Subdomains | `recon-advisor` |
| `httpx` | Hosts vivos | `recon-advisor` |
| `katana`, `waybackurls`, `gau` | Crawl / histórico | `recon-advisor`, `web-hunter` |
| `ffuf` | Dir/param fuzz | `web-hunter`, `vuln-scanner` |
| `arjun` | Parâmetros | `web-hunter`, `api-security` |
| `nuclei` | Templates oficiais + community | `vuln-scanner` |
| `cent` (`~/go/bin/cent`) | Agrega templates community | `vuln-scanner` |
| HexStrike + Burp | Validação | `poc-validator`, `bizlogic-hunter` |

## Paths locais (não reinventar)

| Recurso | Path |
|---------|------|
| Nuclei oficiais (PD) | `~/.local/nuclei-templates` (~13k YAML, incl. `dast/`) |
| Nuclei community (`cent`) | `bounty_knowledge/nuclei-community/cent-templates` |
| PayloadsAllTheThings | `bounty_knowledge/PayloadsAllTheThings/` |
| HexStrike | chama `nuclei` do PATH (não traz templates próprios) |

Uso típico:

```bash
# oficiais, seletivo
nuclei -u URL -tags kev,exposure,misconfig -severity critical,high,medium

# DAST/fuzz (ex-fuzzing-templates, agora em dast/)
nuclei -u URL -dast -severity medium,high,critical

# community (barulhento — filtrar tags/severity; validar FP)
nuclei -u URL -t bounty_knowledge/nuclei-community/cent-templates -severity critical,high
```

## Roteamento de agentes (Bug-Bounty-Agents)

| Situação | Agente (`.cursor/rules/`) |
|----------|---------------------------|
| Novo programa / escopo | `engagement-planner` + `bug-bounty` |
| Recon amplo | `recon-advisor` → `osint-collector` |
| SPA / APIs REST | `web-hunter` + `api-security` |
| GraphQL | `graphql-hunter` |
| JWT / OAuth | `jwt-cracker` |
| SSRF | `ssrf-hunter` |
| Lógica de negócio / pagamento | `bizlogic-hunter` |
| IDOR / cross-account | `bizlogic-hunter` + `poc-validator` |
| Cloud (AWS/GCP/Azure) | `cloud-security` |
| Subdomain takeover | `subdomain-takeover` |
| LLM / chatbot no escopo | `llm-redteam` |
| Coordenar tudo | `swarm-orchestrator` |
| Report Bugcrowd (VRT) | `report-generator` |

Índice completo: `Bug-Bounty-Agents/AGENTS.md`

## Ferramentas do awesome-bugbounty-tools (instalar sob demanda)

Consultar `awesome-bugbounty-tools/README.md` antes de instalar. Prioridade quando faltar:

- **Secrets/JS:** `nuclei` (`~/.local/nuclei-templates`) + `katana` + grep
- **GraphQL:** `clairvoyance`, `graphql-cop` (se no escopo API GraphQL)
- **JWT:** `jwt_tool` (agente `jwt-cracker`)
- **SSRF / payloads:** `bounty_knowledge/PayloadsAllTheThings/` (clonado; não só link do awesome)
- **Templates community:** `cent` → `bounty_knowledge/nuclei-community/`; preferir oficiais+tags antes de varrer community inteiro
- **Scopes H1/BC:** `bounty-targets-data` (dados públicos de programas)

Não instalar Docker-heavy stacks (Ars0n, Darkmoon full) nesta VM.

## Segurança do agente (referência)

`awesome-agent-skills-security/` — ao adicionar skills/MCP externos, validar supply chain e não executar output de alvo com `| bash`.
