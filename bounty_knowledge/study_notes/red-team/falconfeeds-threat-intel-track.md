# Falcon Feeds threat intelligence track

Data: 2026-07-15.

Escopo desta nota:
- fechar Falcon Feeds como fonte de threat intelligence;
- registrar o que serve para bug bounty/red team autorizado;
- evitar uso como caca cega ou justificativa sem evidencia.

Fontes salvas localmente:
- `falconfeeds/home.html`
- `falconfeeds/blog.html`
- `falconfeeds/threat-intelligence-pipeline.html`
- `falconfeeds/mcp-falconfeeds.html`
- `falconfeeds/threat-intelligence-training-basics.html`
- `falconfeeds/threat-intelligence-training-advance.html`
- `falconfeeds/quickstart.html`

## O que a fonte e

FalconFeeds se apresenta como data layer para threat intelligence:
- dark web monitoring;
- ransomware/extortion tracking;
- dataset de sinais;
- enrichment;
- APIs/dashboard;
- MCP FalconFeeds;
- treinamento de threat intelligence.

## Como isso entra no workspace

Uso correto:
- priorizacao de alvo e risco;
- contexto de campanha;
- linguagem de impacto para leaked credentials, ransomware, extortion e exposed data;
- enriquecimento de IOC quando o escopo permitir.

Uso incorreto:
- usar feed como prova de vulnerabilidade sem reproduzir no alvo;
- perseguir dado vazado privado/pago;
- transformar inteligencia em acao contra terceiros fora de escopo.

## Conexao com bug bounty

Falcon Feeds ajuda principalmente em:
- reports de leaked credentials permitidos;
- validacao de impacto de exposicao publica;
- triagem de quais assets/tecnologias merecem prioridade;
- explicar por que determinado dado exposto tem risco operacional.

Mas bounty ainda exige:
- asset em escopo;
- evidencia propria;
- reproducibilidade;
- demonstracao minima e responsavel.

## MCP FalconFeeds

A existencia de MCP FalconFeeds reforca uma tendencia:
- threat intel tambem esta entrando em workflows agentic;
- qualquer MCP que consulte ou enriquece dados precisa de authz, audit e egress controls;
- isso conecta Falcon Feeds com as notas Bishop Fox sobre MCP.

## Status

Falcon Feeds deixa de estar pendente. Fica registrado como fonte de contexto e priorizacao, nao como fonte primaria de exploracao.
