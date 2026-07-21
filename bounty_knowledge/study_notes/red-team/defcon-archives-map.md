# DEF CON archives map

Status: **mapeado 2026-07-15**. O indice principal e as URLs de arquivo foram confirmados localmente; uma pagina de show recente foi amostrada para validar a estrutura.

Base local:
- `bounty_knowledge/study_notes/red-team/source-crawls/defcon-archives.html`
- `bounty_knowledge/study_notes/red-team/source-crawls/defcon-archive-urls.txt`

## O que foi confirmado

No indice de `DEF CON Archives`:
- existem `37` URLs de arquivo localmente extraidas;
- o indice lista edicoes principais de `DEF CON 1` a `DEF CON 32`;
- tambem aparecem eventos paralelos/especiais como `China`, `SAFE MODE` e `New Year's Eve`.

Na amostra da pagina `DEF CON 32 Archive`, a estrutura confirmada inclui:
- `Talk Sections`
- `Speaker Index`
- `Talks & Materials`
- `Presentation Slides and Extras`
- `Presentation Audio and Video`
- `Highlights`
- `Badge Files`
- `Music`
- `Program`
- `Photos and Video`
- `CTF`
- `Contest & Events Results`
- `Audio/Video RSS Feeds`
- `Press Coverage`

Leitura correta:
- o arquivo da DEF CON nao e so lista de talks;
- ele preserva muito material operacional e cultural de cada edicao;
- para estudo tecnico, ele serve como ponto de entrada para talks, slides, badge material, CTF e artefatos historicos.

## O que vale para nos

### 1. DEF CON e melhor tratada como biblioteca por trilha

Nao faz sentido ler "em ordem cronologica" sem filtro.

Faz sentido ler por trilha:
- API/web
- cloud
- hardware/firmware
- identity/auth
- AI/LLM
- recon/ASM
- mobile
- detection/evasion

### 2. Slides e materiais extras importam tanto quanto o video

Como o arquivo preserva `Presentation Slides and Extras`, ele e bom para:
- extrair checklist tecnico rapidamente;
- pegar payloads, diagramas e prerequisitos;
- transformar talks em notas operacionais mais depressa.

### 3. Badge/CTF/contest tambem sao fonte tecnica

Para nosso workspace, isso tem dois usos:
- repertorio de engenharia reversa, radio, hardware, puzzles e protocol abuse;
- ideias de laboratorio sem depender de programa real.

## Como eu usaria a DEF CON no workspace

### Para estudo

Usar o arquivo como indice de material por categoria.

Fluxo recomendado:
1. escolher uma trilha;
2. abrir as edicoes mais recentes;
3. puxar slides/extras antes do video quando houver;
4. registrar notas locais com tecnica, precondicao, evidencia e no-go de escopo.

### Para hunting

Uso indireto:
- ganhar repertorio;
- reconhecer padroes;
- transformar ideias de talk em hipoteses testaveis dentro do escopo.

Nao usar:
- como justificativa para aplicar tecnica fora da policy;
- como atalho para chamar algo de impacto sem prova no alvo.

## Proximos aprofundamentos de maior valor

1. Criar backlog por trilha, nao por ano.
2. Priorizar edicoes recentes primeiro.
3. Cruzar temas com o que ja apareceu em:
   - `specterops-corpus-map.md`
   - `bishopfox-research-map.md`
   - `mitre-attack-atomic-red-team.md`

## Status honesto

Esta nota fecha o mapa estrutural do arquivo DEF CON.

Ainda falta para chamar de DEEP:
- escolher trilhas;
- abrir talks/slides por tema;
- registrar estudo por edicao ou por topico.
