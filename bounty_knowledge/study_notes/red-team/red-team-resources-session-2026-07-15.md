# Red Team / Offensive Security - sessao 2026-07-15

Status: **em andamento**.

Motivo desta nota:
- O lote passado pelo operador inclui repos pequenos, agregadores enormes, blogs com dezenas/centenas de paginas e arquivos de tecnicas sensiveis.
- Regra aplicada: fonte so recebe **DEEP** quando o conteudo relevante foi lido/inventariado de verdade. Home/README sozinho nao basta quando o site/repo tem subpastas/artigos relevantes.
- Regra adicional do operador: nao mitigar aprendizado. Em estudo, ler e registrar tudo o que for pedido; separar o que pode ou nao ser usado apenas na fase de aplicacao contra alvo real.

## Fontes locais clonadas

Diretorio base: `bounty_knowledge/red-team/`.

| Fonte | Estado local | Cobertura desta sessao |
|-------|--------------|------------------------|
| `Active-Directory-Exploitation-Cheat-Sheet` | 6.3M | **DEEP** em nota propria; README inteiro lido |
| `Red-Teaming-Toolkit` | 324K | README completo lido; catalogo de ferramentas por fase |
| `RedTeam-Tools` | 432K | README grande inventariado por headings; ainda nao DEEP linha-a-linha |
| `nishang` | 9.2M | README completo + arvore de scripts inventariada |
| `Penetration-Testing-Tools` | 50M | README principal + READMEs de web, networks, red-teaming, phishing, windows, linux e file-formats lidos; scripts inventariados |
| `Red-Team-Infrastructure-Wiki` | 5.7M | README completo lido; foco em design/seguranca de infra, redirectors e limites |
| `Pentest-Resources-Cheat-Sheets` | 276K | README completo lido; agregador de links |
| `SecSheets` | 248K | README completo lido; site externo ainda pendente |
| `atomic-red-team` | 417M | README lido; 354 YAMLs/técnicas locais inventariados por caminho; leitura por tecnica ainda pendente |

## Principais aprendizados aplicaveis

### 1. Separar aprendizado de aplicacao

O operador pediu explicitamente para nao reduzir o aprendizado com base em "talvez nao vamos precisar". Isso passa a valer como regra do workspace:

- Em estudo: aprender, inventariar e registrar o maximo possivel da fonte pedida.
- Em operacao real: aplicar apenas o que o escopo permitir.

### 2. Separar bounty web de red team interno

Muitos recursos sao para red team com autorizacao formal: phishing, C2, payloads, AMSI/EDR evasion, credential dumping, persistence, lateral movement e exfiltration.

Regra para o workspace:
- Em bug bounty web/API comum, usar esse material apenas para entender impacto, nao para executar tecnica.
- Em programa enterprise/internal, so aplicar se o escopo permitir explicitamente.
- Em lab proprio, pode servir para validacao e estudo.

### 3. Ferramentas úteis para bounty sem virar red team indevido

Do `Red-Teaming-Toolkit` e `Pentest-Resources`:
- Recon/ASM: Amass, BBOT, Recon-ng, SpiderFoot, RustScan, AttackSurfaceMapper.
- Secrets/cloud OSINT: gitleaks, cloud_enum, S3Scanner.
- Screenshots/inventory: WitnessMe/gowitness equivalents.
- API/web: awesome-api-security, APISec University, PortSwigger, PayloadsAllTheThings, SecLists.
- Cloud/Azure/AWS: CloudMapper, Pacu, ROADtools, MicroBurst, Stormspotter, AADInternals, GraphRunner.
- AI red team: promptfoo, garak, PyRIT, FuzzyAI.

Uso no hunting:
- Priorizar essas categorias quando o alvo for web/API/cloud/LLM.
- Evitar automaticamente categorias de phishing, malware, C2, persistence e dumping.

### 4. Enterprise/AD quando o escopo permitir

Do repo AD + Nishang + Atomic:
- Enumeracao de AD, usuarios, grupos, GPOs, ACLs, shares e trusts.
- BloodHound/Adalanche para grafo de caminho de ataque.
- ADCS/templates como candidato forte para High/Critical.
- Kerberos/delegation/ACL abuse como impacto de dominio.
- GPO delegated users, LAPS handling, PowerView export/import e contagem de grupos privilegiados como provas seguras.

Prova preferida:
- Grafo ou diff de permissao.
- Conta baixa vs controle negativo.
- Caminho ate role/host/dado critico.
- Sem dump de credenciais reais, sem persistencia, sem lateral destrutivo.

### 5. Web/API aproveitavel do `Penetration-Testing-Tools`

Itens lidos no README de `web/` que podem ajudar bounty:
- `ajax_crawl.js`: aumentar cobertura de URLs acessiveis via browser/Burp.
- `burp-curl-beautifier.py`: limpar cURL de Burp para replay/report.
- `reencode.py`: decodificar/recodificar parametros em camadas, util em SAML, 3DS, XML, JWT-like ou blobs.
- `padding-oracle-tests.py`: gerar casos manuais para padding oracle.
- `xml-attacks.md`, `blindxxe.py`, `XXE_payloads`: apoio para XXE quando endpoint XML estiver em escopo.
- `sqlmap-tamper-scripts-evaluation.md`: referencia para WAF/tamper, com limite de rate/policy.
- `ysoserial-generator.py`, `java-XMLDecoder-RCE.md`, `pickle-payload.py`, `struts-cheatsheet.md`: apenas em endpoints/labs explicitamente vulneraveis e autorizados.

Uso pratico:
- Antes de inventar payload manual, consultar esta pasta para encoding, XML/XXE, deserialization e padding oracle.

### 6. Infra / OPSEC

Do `Red-Team-Infrastructure-Wiki`:
- Segregacao funcional: SMTP, payload hosting, C2 longo/curto, redirectors.
- Redirectors para SMTP, DNS, HTTP(S), C2.
- Hardening e logging de infra de teste.
- Risco de infraestrutura ofensiva ser atacada.

Uso no nosso caso:
- Mais relevante para laboratorio/OAST/infra propria e para entender egress/redirector reports.
- Phishing e C2 ficam fora de bounty salvo autorizacao escrita.
- Bom aprendizado para manter infraestrutura de PoC limpa, logs separados, rotacao e destruicao de dados sensiveis.

### 7. Atomic Red Team / MITRE ATT&CK

Atomic Red Team local:
- 354 YAMLs de tecnicas inventariados.
- Inclui Windows, Linux, macOS, cloud, SaaS, containers, ESXi, O365/Google Workspace, Azure/AWS/GCP.
- Exemplos relevantes para impacto: account manipulation, cloud roles, service accounts, web shell, credential access, discovery, lateral movement, exfiltration, impact.

MITRE ATT&CK site:
- Matriz Enterprise inclui taticas de Reconnaissance a Impact, com linhas para discovery, credential access, lateral movement, collection, exfiltration e impact.
- Para report, usar ATT&CK como linguagem de consequencia e cobertura, nao como severidade isolada.

Uso no hunting:
- Transformar achado em impacto: "esta falha permitiria T1098 Account Manipulation" ou "T1552 Unsecured Credentials" quando realmente provado.
- Validar em lab, nao em alvo real sem escopo.

## Fontes web abertas nesta sessao

- SpecterOps blog: pagina de blog aberta; o site mostra categorias Research & Tradecraft, AI & Security, BloodHound, Industry Insights e pagina 1/60. Depois foram consolidadas duas trilhas identity/trust/token.
- Bishop Fox Labs/blog: paginas abertas e depois consolidadas em tres blocos: metodo moderno, cloud attack paths e advisories + AI/MCP.
- Cobalt Strike blog: pagina aberta e corpus mapeado; trilhas prioritarias consolidadas, mas DEEP por post ficou bloqueado por Cloudflare em `curl`.
- MITRE ATT&CK: pagina principal/matriz Enterprise aberta; depois foi usado dump estruturado local e familias prioritarias foram consolidadas.
- Atomic Red Team site: pagina principal aberta; repo local usado como base para familias prioritarias.

## Manifests coletados nesta sessao

Arquivos salvos em `bounty_knowledge/study_notes/red-team/source-crawls/`:

- `specterops-sitemap.xml`
- `specterops-post-sitemap.xml`
- `specterops-resource-sitemap.xml`
- `specterops-post-urls.txt`
- `specterops-resource-urls.txt`
- `specterops-resource-manifest.tsv`
- `bishopfox-sitemap.xml`
- `bishopfox-research-sitemap.xml`
- `bishopfox-research-urls.txt`
- `bishopfox-blog-sitemap.xml` (retornou 504 HTML; precisa retentar)
- `cobaltstrike-blog.html` (pagina protegida por Cloudflare no `curl`; usar browser/web para continuar)
- `cobaltstrike-blog-pages.txt`
- `mitre-enterprise-attack.json` (dump STIX oficial; 45 MB)
- `mitre-techniques.csv`
- `mitre-platform-counts.csv`
- `mitre-tactic-counts.csv`
- `mitre-enterprise-topline.txt`
- `blackhat-archives.html`
- `blackhat-sitemap.xml`
- `defcon-archives.html`
- `defcon-archive-urls.txt`

Contagens ja confirmadas:
- SpecterOps posts no sitemap local: `197`
- SpecterOps resources no sitemap local: `32`
- Bishop Fox research URLs no sitemap local: `14`
- DEF CON archive pages listadas no indice local: `37`
- Atomic Red Team YAMLs locais: `354`
- Cobalt Strike blog via browser: `28` paginas / `278` posts
- MITRE ATT&CK Enterprise local: `858` attack patterns totais = `365` tecnicas + `493` subtecnicas
- Atomic Red Team local: `341` diretorios de tecnica, `356` YAMLs e `740` IDs MITRE distintos referenciados

Observacoes:
- O sitemap de blog da Bishop Fox retornou pagina Cloudflare `504`, nao XML valido.
- O sitemap/blog do Cobalt Strike via `curl` cai em Cloudflare challenge; a continuacao precisa ser por browser/web ou fontes oficiais alternativas.
- O MITRE foi obtido em formato estruturado oficial (`enterprise-attack.json`), melhor que ler HTML solto.
- O `Black Hat` inicialmente parecia bloqueado, mas o hub real foi capturado depois via Chromium + CDP; `237` links confirmados.
- Amostras validadas nesta etapa:
  - primeiro post SpecterOps abriu via `curl` e retornou titulo `On Detection: Tactical to Functional`
  - primeiro item Bishop Fox research abriu via `curl` e retornou titulo `Home and Office Security System Hacking`
  - primeiro archive DEF CON abriu via `curl`; `DEF CON 1 Archive` retornou `107` links na pagina
- Cobalt Strike:
  - `curl` em HTML e `wp-json` seguem bloqueados por Cloudflare challenge
  - browser/web confirmou `278` posts e `28` paginas, e a navegacao para `/blog/page/2` funciona

Notas criadas nesta etapa:
- `specterops-corpus-map.md`: mapa tematico do corpus completo da SpecterOps com prioridades de leitura por trilha
- `specterops-identity-trust-token-track.md`: consolidacao tecnica da trilha trusts/tokens/app roles a partir de tres artigos prioritarios
- `specterops-identity-trust-token-track-2.md`: segunda metade da trilha com service principal abuse, Azure Seamless SSO, AORTA e SCCM/Entra
- `bishopfox-modern-method-track.md`: consolidacao tecnica da trilha moderna da Bishop Fox com exposure publico, favicon/ASM, LLM-assisted validation, MCP authz e patch diffing
- `bishopfox-cloud-attack-paths.md`: consolidacao do subbloco cloud com GCP IAM inheritance, attack paths, data plane, Cirro e reuse de identities entre ambientes
- `bishopfox-advisories-ai-mcp.md`: advisories tecnicos e posts AI/MCP restantes, incluindo confused deputy, SSRF/token passthrough, excessive agency e chains de impacto
- `mitre-attack-atomic-red-team.md`: uso operacional de ATT&CK + Atomic com contagens locais e regras de aplicacao
- `mitre-atomic-technique-families.md`: aprofundamento das familias `T1552`, `T1098`, `T1078`, `T1550`, `T1021`, `T1484` com YAMLs Atomic locais
- `bishopfox-research-map.md`: diferenca entre research legado do sitemap e o corpus moderno de Labs/Blog; prioridades de leitura
- `cobaltstrike-corpus-map.md`: mapa do blog oficial com contagens por tema/autor e prioridades de leitura
- `cobaltstrike-priority-posts.md`: consolidacao por trilha prioritaria de REST API, AI, Beacon instrumentation, BOF, scripting e integracoes, com limitacao honesta por Cloudflare
- `defcon-archives-map.md`: mapa estrutural do arquivo DEF CON e como usar por trilha
- `defcon-recent-tracks.md`: trilhas recentes DEF CON 31/32/33 por web, cloud, identity, AI, supply chain, hardware/mobile
- `blackhat-archives-map.md`: mapa real do hub de arquivos Black Hat obtido via navegador/CDP apos challenge
- `offsec-ai-threat-track.md`: OffSec consolidado em AI pentest, Shadow AI, web methodology, bug bounty, threat intel e supply chain
- `falconfeeds-threat-intel-track.md`: Falcon Feeds consolidado como fonte de threat intelligence, dark web/ransomware context, MCP e priorizacao

## Status honesto

Marcado como DEEP:
- `Active-Directory-Exploitation-Cheat-Sheet`.

Lido/inventariado, mas nao DEEP total:
- `Red-Teaming-Toolkit`.
- `Red-Team-Infrastructure-Wiki`.
- `Pentest-Resources-Cheat-Sheets`.
- `SecSheets`.
- `nishang`.
- `Penetration-Testing-Tools`.
- `atomic-red-team`.
- `RedTeam-Tools`.
- `SpecterOps` como corpus/index completo, porem ainda nao por artigo.
- `SpecterOps` com uma trilha prioritaria ja consolidada: trusts, Entra SSO cookies e Azure API permission abuse.
- `SpecterOps` com a segunda metade da trilha consolidada: service principal abuse, Seamless SSO, AORTA e SCCM/Entra.
- `Bishop Fox` com mapa de research/blog/labs e tres blocos tecnicos consolidados por artigo: trilha moderna inicial, cloud attack paths e advisories + AI/MCP.
- `Cobalt Strike` como mapa do blog e temas dominantes, com trilhas prioritarias consolidadas; ainda nao DEEP por post porque `curl` e posts individuais retornaram Cloudflare challenge.
- `MITRE/Atomic` com dump, nota operacional e familias prioritarias consolidadas.
- `DEF CON` como mapa estrutural e trilhas recentes 31/32/33 consolidadas.
- `OffSec` consolidado por trilhas AI/web/threat/supply chain.
- `Falcon Feeds` consolidado como threat intel/context/prioritization source.
- `Black Hat` como mapa de arquivo estrutural e historico por regiao/ano, porem ainda nao por schedule/talk.

Pendente para continuar:
- SpecterOps: trilha principal identity/trust/token ja bem consolidada; proximo bloco relevante passa a ser AI/LLM ou OpenGraph/collectors.
- Bishop Fox: trilhas modernas relevantes fechadas para esta sessao.
- Cobalt Strike: fechado por trilha prioritaria para esta sessao; DEEP post-a-post exige navegador com challenge resolvido.
- DEF CON: trilhas recentes fechadas; proximos aprofundamentos seriam leitura de slides individuais escolhidos.
- Black Hat: entrar em `USA/Europe/Asia` recentes e separar talks/ferramentas por trilha.
- MITRE/Atomic: familias prioritarias fechadas; proximos aprofundamentos seriam familias adicionais.
- RedTeam-Tools: leitura por blocos do README de 4795 linhas e filtragem segura.

## Fechamento do lote solicitado em 2026-07-15

O operador pediu para terminar:
- Bishop Fox advisories tecnicos e posts restantes de AI/MCP;
- Cobalt Strike por posts/trilhas prioritarias;
- MITRE/Atomic por familias;
- OffSec blog e Falcon Feeds;
- DEF CON por trilhas/talks recentes.

Resultado:
- Bishop Fox: fechado em nota propria.
- Cobalt Strike: fechado por trilhas prioritarias com limitacao tecnica registrada.
- MITRE/Atomic: fechado nas familias do backlog.
- OffSec: fechado em nota propria.
- Falcon Feeds: fechado em nota propria.
- DEF CON: fechado em nota propria com edicoes 31/32/33.

Estado final honesto:
- o lote operacionalmente util foi fechado;
- fontes enormes nao foram marcadas como **DEEP total** quando isso significaria ler centenas de posts/slides linha a linha;
- cada fonte agora tem nota aplicavel, status e limites claros.

## Regra operacional adicionada pela sessao

Quando o usuario passar um lote grande de estudo, nao parar apos uma fonte. Fazer:

1. Clonar/inventariar tudo que for repo.
2. Ler a fonte destacada primeiro se houver.
3. Ler READMEs/indices completos.
4. Para sites grandes, abrir indice/categorias e salvar lista de artigos pendentes.
5. Criar nota com status por fonte.
6. Marcar **DEEP** apenas quando a fonte relevante tiver sido realmente lida.
