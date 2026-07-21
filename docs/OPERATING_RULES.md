# Regra Operacional de Bug Bounty

## Plataforma preferida: Bugcrowd

Programas e reports via **Bugcrowd** por padrão. Referencia: `bounty_knowledge/BUGCROWD.md`.

- Iniciar programa: URL `bugcrowd.com/engagements/<slug>` ou domínio + brief
- Escopo: salvar em `targets/<slug>/SCOPE.md`
- Severidade em reports: **VRT** (Bugcrowd), nao CVSS generico
- Headers obrigatorios do programa: documentar e usar em todo teste
- HackerOne continua valido se o usuario/link apontar para la

## Objetivo

Manter um fluxo padrao para qualquer programa de bug bounty:

1. Usar reconFTW como orquestrador primario de reconhecimento, aproveitando ferramentas locais ja instaladas.
2. Selecionar alvos/promessas com base nos resultados.
3. Pular para HexStrike + Burp para validacao focada, replay, PoC e report.

## Filosofia

O estilo preferido e agressivo em cobertura e profundidade, sempre calibrado pelas regras do programa.
Nao operar em modo neutro/auditoria passiva: apos negativos no mesmo vetor, pivotar; usar `bounty_knowledge/` e a toolchain (reconFTW, PD stack, nuclei, ffuf, HexStrike/Burp) em vez de so replay manual repetitivo.

Feedback 2026-07-10 (obrigatorio): nao ser abstrato. Cada ciclo = hipotese falsificavel + ataque concreto com tool do stack + evidencia. Matrizes/inventarios sem impacto nao contam como caca. Subuso de repos/personas/toolchain e falha operacional — consultar e executar, nao so citar.

### Regra obrigatoria: evidencia local antes de conclusao

Codex, Cursor e qualquer outra IA/CLI neste workspace compartilham o mesmo disco,
mas nao a mesma memoria. Por isso, antes de afirmar qualquer conclusao sobre
escopo, categoria, severidade, exploitabilidade, estrategia de report ou proximo
plano de ataque, a IA deve checar o material local primeiro.

Ordem obrigatoria:

1. `WORKSPACE_STATE.md` ou estado privado equivalente.
2. Arquivos do alvo em `targets/<program>/`: `PLAN.md`, `SCOPE.md`,
   `FINDINGS.md`, `RESUME.md`, reports, anexos e recon.
3. `bounty_knowledge/study_notes/INDEX.md` e a nota tecnica relevante.
4. Reports anteriores, respostas de triage e licoes locais para padroes similares.

Se o material local nao confirmar a afirmacao, declarar como inferencia:
`isso e inferencia, nao confirmado ainda`.

Evitar recomendacao abstrata. Toda recomendacao importante deve apontar para
escopo/regra, endpoint/request, evidencia de conta, tecnica estudada ou impacto
provado/faltante.

### Regra obrigatoria: authz nao para em GET/read

Para Codex, Cursor e qualquer outra IA/CLI neste workspace:

- nao limitar IDOR/BOLA a `GET` ou leitura;
- priorizar tambem endpoints e operacoes de mudanca de estado:
  - `PATCH`
  - `PUT`
  - `POST` sensivel
  - `DELETE`
  - GraphQL `mutation`

Heuristica obrigatoria:
- devs costumam proteger melhor `read` do que `write`;
- procurar cadeia `BOLA` (objeto alheio) + `BFLA` (acao/role indevida) na mesma operacao;
- isso vale especialmente para GraphQL mutations e admin/account-management flows.

Matriz minima para toda mutation/write operation:
1. trocar o object ID (`BOLA`)
2. trocar a sessao/role (`BFLA`)
3. trocar ambos ao mesmo tempo

Prioridades:
- nao testar so `A le B`;
- testar se `A altera B`, `A apaga B`, `A desativa B`, `A trava B`, `A muda role de B`, `A mexe no lifecycle de B`.

Em GraphQL:
- olhar primeiro mutations com IDs e transicoes de estado;
- triagers frequentemente esperam introspection, nao cadeia authz em mutation;
- nossa vantagem e fechar o efeito real na escrita.

### Regra obrigatoria: estudo completo antes de marcar DEEP

Em sessoes de estudo, nao marcar fonte como **DEEP** sem ler a pagina principal,
subpastas, arquivos e artigos relevantes. Para repos, clonar ou inventariar a
arvore antes da sintese. Para blogs/sites grandes, criar backlog por artigo ou
categoria e manter como pendente ate a leitura real.

Se a fonte for grande demais para uma sessao, registrar progresso e dizer
claramente o que foi lido e o que falta. Nao fingir que "estudou tudo" so por
ter lido a home, README ou indice.

Nao mitigar aprendizado por suposta necessidade futura. Em estudo, a IA deve
aprender e registrar o conteudo integralmente quando o operador pedir. A
restricao de escopo entra apenas na fase de aplicacao operacional contra alvo
real, nao na fase de leitura, sintese e organizacao do conhecimento.

Isso significa:

- mapear bastante superficie;
- procurar rotas esquecidas, APIs, parametros, JS, fluxos autenticados e estados incompletos;
- priorizar endpoints com auth, conta, pagamento, organizacao, certificacao, arquivos, admin, integracoes e IDs;
- testar hipoteses rapidamente;
- documentar evidencia assim que houver sinal real;
- consultar TOOLCHAIN + personas Bug-Bounty-Agents + awesome-bugbounty-tools antes de alongar probes ad hoc.

O nivel permitido de agressividade nao e fixo. Cada bounty tem sua propria regra. Antes de rodar qualquer teste de alto impacto, ler o escopo e seguir exatamente o que o programa permite.

### Niveis de agressividade (0-3) — obrigatorio antes de comando ativo

Framework do estudo (`bounty_knowledge/study_notes/` + guia `bugbounty-study.md`). **Agressividade sobe com a policy, nunca por default.**

Antes de qualquer comando que envie trafego a um alvo de programa, declarar:
1. **Nivel 0-3** da acao
2. **Trecho** de `targets/<slug>/SCOPE.md` (ou policy) que autoriza
Sem trecho claro → usar o nivel mais conservador. Fora de SCOPE = nenhum nivel.

| Nivel | Nome | Exemplos | Quando |
|-------|------|----------|--------|
| **0** | Passivo | OSINT, crt.sh, Wayback, GitHub dork, ler JS ja publico, Shodan indexado | Sempre; achado so vira ativo apos asset em SCOPE |
| **1** | Ativo leve | `subfinder`, `dnsx`, `httpx`, `katana` raso, fingerprint | Default apos asset confirmado; rate baixo (~10-20 rps, c 5-10) |
| **2** | Ativo moderado | `ffuf` controlado, nuclei templates padrao (sem `dos`/`fuzz`), injecao manual 1 param, IDOR A/B | Asset in-scope + policy nao proibe scanning automatizado |
| **3** | Agressivo | Alta concorrencia, brute, race multi-req, `nuclei -itags dos` | So com autorizacao **explicita** na policy; releia antes |

Teto de hardware (VM) e independente: `nuclei -c 5-10 -rl 10-30` mesmo se policy permitir 3. Vale o menor entre teto de escopo e teto de hardware.

Notas de estudo (sintese, nao so links): `bounty_knowledge/study_notes/INDEX.md`.

Se o programa permitir explicitamente, podem entrar testes mais fortes como:

- brute force controlado;
- rate-limit stress;
- DoS;
- fuzzing de maior volume;
- scanners ativos em cadencia alta.

Se o programa nao permitir explicitamente, tratar como proibido.

Por padrao, sem autorizacao clara, nao fazer:

- DoS;
- brute force;
- credential stuffing;
- bypass de anti-abuse fora do permitido;
- spam de formularios;
- dados falsos de empresa/KYC/pagamento;
- tocar fora do escopo;
- explorar destrutivamente;
- submeter provas, compras, pagamentos ou acoes irreversiveis.

## Stack Padrao

### Regra obrigatoria para JADX / APKs grandes

Para Codex, Cursor e qualquer outra IA/CLI neste workspace:

- Nao abrir JADX GUI completo como fluxo padrao em APK grande ou obfuscado. Nesta VM isso ja congelou a sessao inteira.
- Primeiro usar busca em artefatos ja extraidos e caminhos escopados.
- Para classe especifica, usar `recon_tools/jadx_single_class.sh <Classe> <apk> <out>`.
- Para cobertura ampla pesquisavel, usar `recon_tools/jadx_full_safe.sh <apk> <out>`, que roda CLI com heap/thread limitados e modo `fallback` por padrao.
- Usar `jadx-gui` apenas como excecao, com `recon_tools/jadx_gui_light.sh <apk> --select-class <Classe>`.
- Se o modo readable/simple falhar ou ficar parcial, manter `fallback` como indice completo para `rg` e extrair classes pontuais depois.
- Nunca fazer busca repo-wide em dumps JADX grandes; sempre escopar para o diretorio do alvo/export.

### 1. reconFTW: superficie ampla

Usar reconFTW como radar inicial ate aparecer alvo/candidato real. O reconFTW deve ser tratado como orquestrador, nao como motivo para reinstalar a toolchain inteira.

Regra de instalacao:

- nao rodar instalador amplo sem necessidade;
- nao reinstalar Go, Python, nuclei, subfinder, httpx, katana, ffuf, arjun ou ferramentas ja funcionais;
- antes de instalar algo, checar `which`/`--version`;
- instalar somente dependencia ausente que bloqueia um modo especifico do reconFTW;
- nao usar Docker.

Ferramentas base que o reconFTW deve aproveitar:

- ProjectDiscovery:
  - `subfinder` para subdomains;
  - `httpx` para hosts vivos, titles, tech, status e fingerprints;
  - `katana` para crawling;
  - `nuclei` para templates apropriados ao escopo;
  - `naabu` apenas quando port scan estiver permitido.
- OWASP Amass:
  - usar quando o programa tiver dominio/empresa grande e asset discovery for relevante.
- Ferramentas complementares:
  - `ffuf` para discovery/fuzzing de rotas e parametros;
  - `arjun` para parametros;
  - `waybackurls`/gau equivalente para historico de URLs;
  - analise manual de JS quando houver SPA/API rica.

Saida esperada:

- lista de hosts vivos;
- endpoints interessantes;
- JS importantes;
- rotas autenticadas;
- APIs com parametros;
- candidatos para teste manual.

### 2. Selecao de alvo

Priorizar alvos com:

- login ou estado autenticado;
- workflows de conta/organizacao;
- IDs previsiveis;
- funcoes sensiveis;
- upload/download;
- convites, certificacoes, pagamentos, relatorios ou dados privados;
- APIs que retornam `code: 00`, `success: true`, dados ricos ou erros diferenciais.

Evitar perder tempo com:

- landing pages estaticas;
- docs publicas;
- marketing puro;
- endpoints que so retornam SPA shell;
- scanners gerando ruido sem hipotese.

### 3. HexStrike + Burp: Validacao focada

Quando houver um candidato:

- capturar fluxo no Burp;
- exportar XML se necessario;
- parsear requests/responses;
- redigir tokens/cookies antes de compartilhar;
- reproduzir com scripts controlados;
- comparar estados: sem login, login incompleto, conta A, conta B, roles diferentes;
- montar PoC minima;
- separar evidencia de controle e evidencia vulneravel.

### 4. Report

So reportar quando houver:

- precondicao clara;
- comportamento esperado;
- comportamento observado;
- impacto plausivel;
- reproducao em passos curtos;
- evidencia sem segredo de sessao;
- severidade defensavel.

## Padrao de Agressividade

O padrao de agressividade deve ser definido por programa:

- ler policy/scope antes;
- registrar o que e permitido;
- registrar o que e proibido;
- adaptar recon modular/HexStrike/Burp ao limite daquele programa;
- se DoS/bruteforce/rate-limit forem permitidos, documentar essa permissao antes de testar;
- se houver duvida, usar intensidade moderada ate confirmar.

Normalmente permitido em bounties comuns:

- crawling moderado;
- enum de parametros em endpoints proprios do app;
- nuclei em baixa/media taxa quando permitido pelo programa;
- testes A/B com contas proprias;
- replay de requests capturadas;
- variacao controlada de IDs nao destrutiva;
- validacao de leitura e autorizacao;
- testes A/B com contas proprias.

Testes de alto impacto, somente quando explicitamente autorizados:

- brute force;
- DoS;
- stress test;
- alto volume;
- criacao massiva de contas;
- exploracao agressiva de rate-limit;
- fuzzing pesado.

Mesmo quando autorizado, preservar evidencia, escopo e controle operacional. Nao usar credenciais de terceiros, nao alterar/deletar dados de terceiros sem permissao explicita e nao ultrapassar o escopo.

## Regra de Decisao

Se o alvo ainda e amplo:

- reconFTW primeiro, usando ferramentas locais ja existentes.

Se ja existe endpoint/fluxo suspeito:

- HexStrike + Burp.

Se precisa provar impacto:

- script controlado + evidencia redigida.

Se o teste exige empresa real, KYC, pagamento ou acao irreversivel:

- parar e trocar de alvo, salvo se o programa autorizar explicitamente.

## Padrao de Evidencia

Guardar:

- request redigida;
- response redigida;
- screenshot;
- controle negativo;
- estado da conta/role;
- PoC simples;
- resumo tecnico.

Nao guardar em report publico:

- cookies;
- bearer tokens;
- session IDs;
- CSRF tokens vivos;
- XML bruto do Burp com sessao;
- dados pessoais alem do minimo necessario.

## Base de Conhecimento e Agentes IA

Repositorios e personas instalados em `bounty_knowledge/` e `.cursor/rules/`:

- **Bug-Bounty-Agents** (`bounty_knowledge/Bug-Bounty-Agents/`): 43 personas (recon, web, API, report, etc.) instaladas em `.cursor/rules/`. Reinstalar com `./bounty_knowledge/Bug-Bounty-Agents/install.sh --target cursor` apos atualizar o repo.
- **awesome-bugbounty-tools**: catalogo de ferramentas por categoria; consultar antes de instalar algo novo.
- **awesome-ai-security** (+ variantes): referencia para alvos com LLM/chatbot no escopo.
- **awesome-agent-skills-security**: seguranca de agentes/skills (nao e playbook ofensivo).

Indice e toolchain local:

- `bounty_knowledge/README.md`
- `bounty_knowledge/TOOLCHAIN.md`
- `.cursor/skills/bug-bounty-workflow/SKILL.md`

Roteamento rapido de personas:

| Fase | Persona em `.cursor/rules/` |
|------|----------------------------|
| Escopo/plano | `engagement-planner`, `bug-bounty` |
| Recon | `recon-advisor` |
| Web/API | `web-hunter`, `api-security` |
| IDOR/logica | `bizlogic-hunter` |
| PoC | `poc-validator` |
| Report | `report-generator` |

As personas complementam este fluxo; `regra.md` continua mandatorio (reconFTW, HexStrike, Burp, portugues, limites do programa).

O agente deve seguir `.cursor/rules/01-bounty-autopilot.mdc`: rotear personas e executar sem o usuario nomear `engagement-planner`, `bizlogic-hunter`, etc.

## Licoes obrigatorias de comportamento (reutilizar)

Arquivo completo (detalhe + checklist): `bounty_knowledge/LESSONS_MOBILE_API_AUTH.md`.

**Ler esse arquivo** em qualquer programa com APK, Azure APIM, CIAM/identity, ForgeRock/Ping, ADFS/employee portal, Adobe Pass/TVE, ou WP legacy atras de Akamai. Resumo mandatorio:

### Cadeia mobile → gateway → config → terceiro
- Keys de APIM/`Subscription-Key` no APK (e as vezes no JS web) bypassam 403 de edge e abrem `clientconfig`.
- Impacto reportavel = cadeia ate secret de terceiro com write authz (provar 400/404 de schema, nao so 401/403).
- Separar secrets High (PAT employee) de N/A (player license, Storyteller id, analytics).
- Programas populares: esperar **duplicate** no jackpot obvio do APK; nao reabrir a mesma cadeia apos duplicate.

### CIAM / identity
- Envelope `status/data/errorCodes`; prefixes `/api/v1` vs `/dev` vs `/qa` por host.
- JSON 404 "Route GET:/x not found" + `/health` 200 = app vivo, path errado (outro produto pode ser `identity-server-*`).
- Enum: `registrationStatus` / `auth` / `otp` diferenciais; `password/forgot` generico = controle.
- Device pairing codes unauth = Low sem ATO/binding.

### ForgeRock / AM
- Metadata/JWKS/serverinfo publicos sozinhos = nao bounty.
- Grants/scopes "perigosos" no discovery **sem client_id** = sem impacto.
- Dynreg pode exigir access token (`access_denied`); password/CC grant falha com `invalid_client`.
- Nao gastar rate em authorize/token/PAR ate minerar `client_id` (JS/Burp/runtime).
- Consumer login pode ser CIAM; ForgeRock pode ser so employee/dev.

### ADFS / team portal
- "Authorization has been denied" + 302 discovery = **controller real** (diferente de 404 ASP.NET generico).
- `appid` (td/gn) + ReturnUrl: validar se wreply ADFS aceita externo; no caso estudado wreply ficou fixo no portal.
- Unauth = lead; bounty precisa sessao employee + authz/IDOR.

### Gates de cliente fracos
- Header diario `base64(uuid + "_" + data)` derivado de endpoint publico = bypass cosmetico se dados ja sao publicos (Low/Info).

### WP / Akamai / content edge
- users/draft locked; media `inherit` publico = nao reportar; XML-RPC 403/410; 418 content-unavailable = parar de repetir.

### Adobe Pass / ContentProvider exported
- Static (exported + openFile sem caller check) **nao basta**; PoC com adb pre/post login + impacto em authn/authz/entitlement.

### SSRF — DNS rebinding (feedback operador 2026-07-12)
Referencia: H1 [#1369312](https://hackerone.com/reports/1369312) + nota `bounty_knowledge/study_notes/web-vulns/ssrf.md`.

Quando existir sink de URL (fetch/import/webhook/preview/og/avatar/callback) **nao** parar em:
- so OAST “bateu DNS”;
- so `127.0.0.1` / metadata direto bloqueados.

**Obrigatorio tentar DNS rebinding TOCTOU** se o app valida host/IP e depois faz o request (segunda resolucao):
1. Dominio sob nosso controle com TTL baixo / rebind A: 1ª resposta = IP publico “safe”, 2ª = `127.0.0.1` / RFC1918 / `169.254.169.254`.
2. Ferramentas: `rbndr.us`, `1u.ms`, Singularity, ou DNS proprio (dois A com TTL 0–1s).
3. Hipotese falsificavel: filtro passa no check, fetch interno muda — evidencia = OAST interno, body, timing ou erro diferencial.
4. Paralelizar com: open redirect na allowlist, redirect 302 pos-check, bypass de IP (`127.1`, IPv6, dword, `@`, etc.).

Sem sink de URL mapeado → primeiro achar o sink (JS/`url=`/webhook); sem sink, rebind nao inventa SSRF.

### ROI / pivot
- Rate limit duro (ex. ≤3 rps) + escopo enorme + High gated (device/ADFS/KYC) → estacionar apos 2–3 rounds unauth sem Medium+.
- Preferir programa com 2 contas sem KYC, ou fechar draft ja existente, em vez de mais fuzz unauth.

Handshake dual-agente (quando usado): Codex offline zero HTTP no alvo; ao terminar: `CODEX_DONE::<task>::<file>` + `STATUS.md` DONE + `LANE_A_WAKE.md` + `NOTIFY_CURSOR.txt` com primeira linha `READY`. Cursor nao depende do usuario para acordar se o watcher estiver ativo.

## Regra obrigatoria: mini relatorio por etapa

Ao finalizar qualquer etapa de um programa de bounty, o agente deve enviar ao usuario um mini relatorio curto contendo:

- etapa concluida;
- ferramentas usadas;
- materiais/arquivos de estudo consultados;
- linha de raciocinio escolhida;
- resultados objetivos;
- decisao de continuar, pivotar ou pedir acao do usuario.

Tambem deve registrar o mesmo resumo em arquivo do alvo quando a etapa gerar contexto reutilizavel. O objetivo e manter o operador ciente de como o trabalho esta sendo conduzido, sem depender de memoria da conversa.
