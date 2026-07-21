# Promptfoo LM Security Database

Status: **backlog tecnico 2026-07-20**. Nao marcar DEEP ainda.

Fonte: https://www.promptfoo.dev/lm-security-db

## O que e

Base publica da Promptfoo para vulnerabilidades de LLMs e agentes. Snapshot observado via busca em 2026-07-20:
- 931 entries
- 931 research papers
- 803 affected models
- last updated 2026-04-11

## Por que importa para bounty

Essa fonte entra como mapa de hipoteses para alvos com:
- chatbot com tool access
- agentic workflows
- RAG sobre documentos externos
- MCP ou plugins
- assistentes que leem tickets, PRs, docs, emails ou paginas web
- features de prompt sharing, evals, datasets, traces, reports ou export

## Classes que parecem imediatamente uteis

### Agent goal reframing

Hipotese: o agente nao viola regras explicitamente, mas aceita uma nova moldura de tarefa como "CTF", "puzzle" ou "debug challenge" e passa a executar acoes que deveriam ficar fora do objetivo.

Teste bounty: tentar transformar uma acao proibida em objetivo legitimo dentro do fluxo do produto, observando se ferramentas, arquivos, conectores ou acoes sensiveis sao chamados.

### Agent implicit doc execution

Hipotese: agente de codigo ou automacao le documentacao, exemplos ou templates como fonte autoritativa e reproduz payload embutido sem o usuario pedir diretamente.

Teste bounty: supply-chain de docs/skills/templates controlados pelo atacante em sistemas que importam prompt packs, repos, tickets ou markdown externo.

### Indirect prompt injection em tool-calling

Hipotese: conteudo externo injeta comandos que acionam ferramentas com privilegio do usuario/agente.

Teste bounty: pagina, ticket, comentario, README, email ou documento controlado pelo atacante induzindo o agente a chamar ferramenta sensivel, exfiltrar dados ou alterar estado.

### Instruction serialization leak

Hipotese: o modelo bloqueia pedido direto de system prompt, mas vaza quando o pedido parece transformacao inocua, como YAML, TOML, base64, logs, schema, checklist ou export.

Teste bounty: export/format/diagnostic/debug modes que serializam contexto, mensagens internas, prompts, chaves ou tool config.

## Regra operacional

Quando o alvo tiver LLM/agent:
1. mapear entradas externas que o agente le
2. mapear ferramentas/acoes que o agente pode executar
3. testar se instrucao indireta de um recurso A controla acao em recurso B
4. procurar vazamento em exports/logs/traces/share links
5. sempre separar hardening local de quebra real de boundary multi-tenant ou destino nao configurado

## Proxima leitura

Priorizar entries ligadas a:
- indirect prompt injection
- tool access / excessive agency
- MCP confused deputy
- RAG data exfiltration
- prompt leakage via serialization
- cross-session leaks
- cloud/shared reports e trace exposure

