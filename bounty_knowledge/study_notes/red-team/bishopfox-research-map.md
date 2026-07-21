# Bishop Fox research map

Status: **mapeado 2026-07-15**. Parte do corpus foi confirmada por manifesto local; a listagem moderna do blog/labs foi conferida no site oficial. Ainda nao e DEEP por artigo.

Base local:
- `bounty_knowledge/study_notes/red-team/source-crawls/bishopfox-research-manifest.tsv`
- `bounty_knowledge/study_notes/red-team/source-crawls/bishopfox-research-urls.txt`
- `bounty_knowledge/study_notes/red-team/source-crawls/bishopfox-sitemap.xml`

## O que foi confirmado

### Research sitemap acessivel

O sitemap local de `research` trouxe `14` URLs e, na pratica, ele aponta para um subconjunto pequeno de paginas historicas em `tools/`:

- `Home and Office Security System Hacking`
- `Google Hacking Diggity Project`
- `RFID Hacking`
- subpaginas de `Attack Tools`, `Defense Tools`, `Media Gallery`, `Presentation Slides` e `White Papers`

Leitura correta:
- esse sitemap nao representa o corpus inteiro moderno do blog;
- ele parece refletir material historico de pesquisa ferramental e apresentacoes;
- e util como indice de legados tecnicos, mas insuficiente para dizer que "Bishop Fox inteiro" foi coberto.

### Labs/blog moderno

Na leitura do site oficial atual:
- `Bishop Fox Labs` se apresenta como area de `vulnerability intelligence`, `open-source tools`, `training & workshops`, `security advisories`, `technical blog` e `guides & reports`.
- O bloco `A Hacker's Tool Kit` destaca ferramentas como `Sliver`, `CloudFox`, `Broken Hill` e `Swagger Jacker`.
- O blog atual mostra foco forte em `AI`, `attack surface intelligence`, `technical research`, advisories e estudos com reproducao segura.

## O que o corpus atual deles parece priorizar

### 1. Ferramenta primeiro, impacto depois

Tanto no research legado quanto no blog/labs moderno, o padrao e consistente:
- criam ou destacam uma ferramenta/flow;
- mostram metodologia;
- amarram isso a um caso tecnico concreto.

Isso e um bom modelo para nosso workspace:
- nao parar em ideia abstrata;
- gerar metodo reproduzivel;
- ligar ferramenta a superficie real e a impacto real.

### 2. AI como acelerador, nao substituto

O blog atual bate repetidamente em um ponto:
- IA ajuda a escalar descoberta, diffing, firmware work e triagem;
- o impacto real continua dependendo de criterio tecnico humano.

Esse padrao encaixa bem no que o operador cobrou aqui:
- usar IA para acelerar coleta, organizacao e hipoteses;
- nao chamar de achado algo que ainda nao fechou impacto e controle negativo;
- preferir workflow com evidencia em vez de explicacao bonita.

### 3. Attack surface intelligence com sinais pequenos

Os temas atuais sugerem valor alto em sinais que muita gente trata como detalhe:
- `favicons` como fingerprint duravel;
- superficies publicas "aparentemente trancadas" mas com backend exposto, como portais ServiceNow;
- advisories com foco em deteccao segura, nao so exploit.

Traducao para bounty:
- fingerprinting e discovery ainda importam quando ajudam a achar software exposto, widget publico, rota esquecida ou produto third-party mal integrado;
- a diferenca e sair de banner-grab vazio para `surface -> product -> endpoint -> exposure`.

## Ferramentas/projetos deles que valem mais para nos

### `CloudFox`

Motivo:
- casa diretamente com cloud attack paths e enum controlada;
- conversa bem com o que ja apareceu em SpecterOps sobre identidade, grafo e caminho de abuso;
- pode ser util em programas que autorizem cloud/IaaS ou em lab.

### `Swagger Jacker`

Motivo:
- conversa diretamente com API discovery e OpenAPI exposure;
- serve para transformar definicao exposta em superficie testavel;
- encaixa bem em bounty web/API sem sair do nosso perfil.

### `Broken Hill`

Motivo:
- entra no eixo AI/LLM offensive testing;
- serve mais para lab e para programas com escopo LLM explicito.

### `Sliver`

Motivo:
- importante para repertorio de red team;
- mas operacionalmente fica muito mais restrito por politica, entao aqui entra mais como estudo do que como ferramenta de bounty.

## Posts recentes que valem puxar primeiro

Pelo que apareceu na listagem atual do blog/labs, as rotas de maior valor sao:

1. `Introducing snowpick: Testing ServiceNow for Public Data Exposure`
2. `On Favicons: From Browser Icons to Attack Surface Intelligence`
3. `AI Finds Vulnerabilities. Security Experts Find Impact.`
4. `A Crash, Not a Shell: SolarWinds Serv-U CVE-2026-28318`
5. `Popping Root on UniFi OS Server: Unauthenticated RCE Chain Detection & Analysis`
6. `Otto Support - Testing MCP Servers`
7. `Vulnerability Discovery with LLM-Powered Patch Diffing`
8. `You're Pen Testing AI Wrong: Why Prompt Engineering Isn't Enough`

Motivo da prioridade:
- eles combinam superficie publica, metodologia, AI, descoberta de produto, autorizacao e cadeia de impacto;
- isso conversa direto com bounty moderno e com programas enterprise.

## Como usar isso no workspace

Quando estivermos montando fluxo de estudo ou teste:
- usar Bishop Fox como referencia de **metodo reproduzivel**;
- preferir discovery que termina em confirmacao tecnica;
- separar ferramenta de impacto, e impacto de severidade;
- usar o material deles para refinar nossa logica de ASM, API exposure, AI testing e advisory-style reporting.

## Status honesto

Esta nota fecha um mapa confiavel do que foi coletado e do que o site atual destaca.

Ainda falta para chamar de DEEP:
- leitura dos artigos prioritarios;
- percorrer a trilha moderna de `Technical Research`;
- expandir alem do sitemap historico de `tools/`.
