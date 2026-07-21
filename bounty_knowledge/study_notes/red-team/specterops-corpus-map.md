# SpecterOps corpus map

Status: **mapeado 2026-07-15**, nao DEEP por artigo ainda.

Base local:
- `bounty_knowledge/study_notes/red-team/source-crawls/specterops-post-manifest.tsv`
- `bounty_knowledge/study_notes/red-team/source-crawls/specterops-resource-manifest.tsv`

Escopo desta nota:
- fechar o inventario inteiro do corpus aberto da SpecterOps;
- identificar os temas dominantes;
- definir o que vale puxar primeiro para leitura profunda futura.

## O que foi fechado

- `197` posts do blog com titulo resolvido.
- `32` resources/reports/datasheets com titulo ou nome de arquivo resolvido.

Distribuicao por ano no manifesto de posts:
- `2026`: 68
- `2025`: 72
- `2022`: 3
- `2021`: 11
- `2020`: 15
- `2019`: 15
- `2018`: 8
- `2017`: 4
- `2024`: 1

## Temas dominantes

Contagens simples por palavra-chave no manifesto de posts:
- `BloodHound`: 32
- `Azure|Entra|AAD`: 14
- `AI|LLM|prompt`: 12
- `trust`: 4
- `token`: 6

Leitura correta disso:
- o corpus recente da SpecterOps gira fortemente em torno de **identity attack paths**;
- `BloodHound` nao aparece como ferramenta isolada, mas como eixo de modelagem de relacoes e caminhos de abuso;
- a trilha `Azure/Entra/AAD` concentra material de token abuse, privilege escalation, trusts e hybrid identity;
- a trilha `AI/LLM` aparece mais forte em `2025-2026`, conectando prompt injection, jailbreaks, agent workflows e pesquisa assistida por LLM.

## O que a SpecterOps parece ensinar melhor

### 1. Identity as graph, not as checklist

O padrao recorrente do corpus nao e "achar um unico misconfig". E:
- modelar relacoes entre identidades, trusts, roles, apps, collectors, SCCM, GitHub, Okta e cloud;
- transformar isso em **attack path**;
- provar reachability e impacto de forma encadeada.

Para nos, isso importa porque eleva a qualidade de PoC:
- parar de reportar permissao solta sem contexto;
- conectar permissao -> caminho -> dado/acao critica;
- usar controle negativo e caminho minimo provavel.

### 2. Azure/Entra continua candidato forte para high/critical

Titulos do corpus apontam para:
- request tokens;
- SSO cookies;
- service principal abuse;
- API permissions abuse;
- hybrid movement de Azure para on-prem AD;
- conditional access e trust issues.

Licao pratica:
- em escopos enterprise/cloud, endpoints e grants de identidade valem mais que superficie web generica;
- permissao aparentemente pequena em app registration, service principal, sync, trust ou token flow pode ser o inicio do caminho relevante.

### 3. AI security na visao deles e seguranca de identidade + fluxo

Os titulos recentes de AI nao apontam so para "prompt hacking" generico. Eles misturam:
- indirect prompt injection;
- jailbreak testing;
- prompt engineering para agentes;
- abuso de features AI em banco/plataforma;
- risco de identidade e contexto em pipelines automatizados.

Uso pratico para bounty:
- procurar LLM/app agent com conectores, memoria, contexto e acoes;
- procurar se o modelo consegue puxar segredo, atravessar boundary de tenant, chamar tool errada ou operar com contexto nao autorizado;
- sempre amarrar impacto ao fluxo real, nao ao "modelo falou algo estranho".

## Resources que valem leitura profunda primeiro

Com base no titulo e na utilidade pratica, os melhores candidatos para proxima rodada sao:

1. `Identity Risk and Attack Path Management Trends for 2026`
2. `State of Attack Path Management`
3. `The CISO's Guide to Modern Identity Security`
4. `AdminSDHolder Misconceptions & Misconfigurations`
5. `Trends in Identity Attack Path Management 2025`

Motivo:
- parecem materiais mais densos e conceituais que datasheets comerciais;
- ajudam a montar linguagem de impacto e priorizacao;
- servem tanto para escopo enterprise quanto para interpretar falhas de authz/graph/role em bounty.

## Posts que merecem leitura profunda primeiro

Rotas de maior valor, pelo proprio corpus:

### Linha identity / trust / tokens
- `Good Fences Make Good Neighbors: New AD Trusts Attack Paths in BloodHound`
- `Untrustworthy Trust Builders: Account Operators Replicating Trust Attack (AORTA)`
- `Requesting Entra ID Tokens with Entra ID SSO Cookies`
- `Azure Privilege Escalation via Azure API Permissions Abuse`
- `Azure Privilege Escalation via Service Principal Abuse`
- `Azure Seamless SSO: When Cookie Theft Doesn't Cut It`
- `SCCM Hierarchy Takeover via Entra Integration`

### Linha graph / OpenGraph / collectors
- `Introducing the BloodHound Query Library`
- `Chatting with Your Attack Paths: An MCP for BloodHound`
- `BloodHound Community Edition v8 Launches with OpenGraph`
- `Adding MSSQL to BloodHound with OpenGraph`
- `Introducing ConfigManBearPig`
- `Introducing TailscaleHound`

### Linha AI / offensive research
- `Building an Indirect Prompt Injection Workflow`
- `Prompt Engineering for Security Agents with GEPA`
- `GhostWorks: AI-Enabled Cybersecurity Research`
- `LLM Jailbreak Testing with Jailbreaker`
- `Abusing AI Features in SQL Server 2025`

## Como isso entra no workspace

Quando estivermos em programa enterprise, cloud ou SaaS com RBAC/grafo/tokens:
- consultar esta nota antes de improvisar heuristica;
- puxar a nota tecnica relevante ja estudada ou o artigo profundo correspondente;
- traduzir qualquer achado para caminho de ataque, nao apenas para "permissao estranha".

Quando estivermos em bounty web comum:
- usar esse corpus como linguagem de impacto e modelo mental;
- nao importar tecnicas fora do escopo.

## Status honesto

Esta nota fecha o **mapa do corpus**, nao a leitura profunda dos `197` posts.

Pode receber **DEEP** no futuro somente apos leitura real dos artigos prioritarios por trilha:
- identity/trust/tokens;
- BloodHound/OpenGraph/attack paths;
- AI security/offensive agent workflows.
