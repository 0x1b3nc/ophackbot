# Black Hat archives map

Status: **mapeado 2026-07-15**. A pagina real foi capturada via navegador/CDP depois do anti-bot; isso substitui o HTML antigo de Cloudflare salvo no crawl inicial.

Base local:
- Arquivo local de estudo Black Hat, quando importado pelo operador.
- `bounty_knowledge/study_notes/red-team/source-crawls/blackhat-archives.html` (estado antigo bloqueado por Cloudflare)

## O que foi confirmado

Na captura real de `https://blackhat.com/html/archives.html`:
- titulo: `Black Hat | Archives`
- `237` links na pagina
- `40` scripts
- `108` recursos carregados

O arquivo nao e uma pagina solta de legado. Ele funciona como hub historico por:
- regiao/evento
- ano
- tipo de trilha

## Trilhas historicas confirmadas

### Black Hat USA

Links de arquivo/schedule confirmados de:
- `1997` ate `2025`
- `2026` aparece como evento atual em `us-26/`

Padrao observado:
- anos recentes usam `briefings/schedule/`
- anos intermediarios usam `briefings.html` ou `archives.html`
- anos antigos caem em paginas `bh-usa-*` ou `bh-media-archives`

### Black Hat Europe

Links confirmados de:
- `2000` ate `2025`

Padrao semelhante:
- anos recentes em `eu-YY/briefings/schedule/`
- anos antigos em `bh-eu-*` e `bh-europe-*`

### Black Hat Asia

Links confirmados de:
- `2014` ate `2026`

Padrao:
- `2014-2015` em `archives.html`
- `2016-2017` em `briefings.html`
- recentes em `briefings/schedule/`

### Outras linhas visiveis

Tambem aparecem no hub:
- `Black Hat(HER)`
- `Cyber War Forum Series`
- `SecTor`
- `Arsenal`
- `Summits`
- `Webinars`
- `Executive Interviews`
- `Trainings`
- `On-Demand Training`

Isso importa porque o valor tecnico do arquivo nao esta so em talks de Briefings.
Tambem existe material historico espalhado em:
- `arsenal`
- `webcast`
- `training`
- `media archives`

## O que esse arquivo vale para nos

### 1. Black Hat e melhor que o indice cru sugeria

Antes do bypass do anti-bot, so sabiamos que a pagina existia.
Agora esta claro que o hub:
- preserva quase trinta anos de `USA`;
- preserva longas trilhas de `Europe` e `Asia`;
- aponta tanto para edicoes antigas quanto para estruturas modernas de `schedule`.

Isso faz do `Black Hat` uma biblioteca muito melhor que um simples blog.

### 2. A melhor unidade de estudo aqui e `schedule/briefings`, nao a home

Para estudo real, o caminho eficiente nao e reler o hub.
E:
1. escolher regiao
2. escolher ano
3. entrar no `schedule` ou `briefings`
4. puxar titulo/abstract/slides/material quando existir

### 3. Arsenal e webcast merecem trilha separada

Para nosso workspace:
- `Briefings` servem mais para pesquisa, tecnica e impacto
- `Arsenal` serve para ferramentas e workflows
- `Webcast` serve para talks gravadas/historico

## Como eu usaria isso no workspace

### Para estudo

Fluxo recomendado:
1. priorizar `USA`, `Europe` e `Asia` recentes
2. entrar por `schedule`
3. separar por trilha:
   - identity/auth
   - cloud
   - web/API
   - AI/LLM
   - firmware/hardware
   - detection/evasion
4. registrar notas curtas por talk ou por tema

### Para hunting

Uso indireto:
- repertorio de tecnicas e casos;
- linguagem de impacto;
- ideias de pivoteamento e modelagem de superficie.

Nao usar:
- como desculpa para importar tecnica fora do escopo;
- como prova de severidade sem reproducao no alvo.

## Proximos aprofundamentos de maior valor

1. `Black Hat USA 2025`
2. `Black Hat Europe 2025`
3. `Black Hat Asia 2026`
4. trilha `Arsenal`
5. trilha `Webcast`

## Status honesto

Agora o `Black Hat` saiu de "bloqueado/parcial" para **mapeado de verdade**.

Ainda falta para chamar de DEEP:
- entrar nos schedules por ano;
- selecionar talks/ferramentas;
- registrar notas tecnicas por trilha.
