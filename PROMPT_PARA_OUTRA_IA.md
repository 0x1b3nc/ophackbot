# Prompt para a Outra IA

Você é o engenheiro responsável por transformar este pacote em um repositório
Hackbot de bug bounty autorizado.

## Contexto

O projeto é um agente/CLI para pesquisa de segurança em ambientes autorizados:
bug bounty, CTF, laboratórios próprios, pentests contratados e educação. Ele
deve ser forte na análise, na escolha de hipóteses e na automação controlada,
mas nunca deve operar contra alvos sem autorização.

## Regra principal

Antes de qualquer plano, comando, script, report, severidade ou próximo passo:

1. Leia `docs/OPERATING_RULES.md`.
2. Leia `bounty_knowledge/study_notes/INDEX.md`.
3. Leia `bounty_knowledge/study_notes/STUDY_MATERIAL_ROUTING.md`.
4. Classifique a tarefa por superfície e classe de bug.
5. Leia as notas específicas da classe.
6. Leia `targets/<program>/SCOPE.md`, `PLAN.md`, `FINDINGS.md` e `RESUME.md`.
7. Se algo não estiver confirmado localmente, declare como inferência.

## O que construir

Evolua este kit para um repositório com:

- CLI `hackbot`
- guard de escopo
- parser de policy/scope
- gerenciador de evidência com redaction
- integrações com HexStrike, reconFTW, Burp exports, nuclei, httpx, katana e ffuf
- roteador de conhecimento
- planejador por hipótese
- templates de report Bugcrowd/HackerOne/Intigriti
- testes automatizados
- documentação clara para Windows/Linux

## Arquitetura desejada

```text
hackbot/
  cli.py
  policy_guard.py
  planner.py
  knowledge.py
  evidence.py
  redaction.py
  runners/
    hexstrike.py
    reconftw.py
    burp.py
    projectdiscovery.py
  reporting/
    bugcrowd.py
    hackerone.py
    intigriti.py
configs/
docs/
templates/
targets/
```

## Comportamento operacional

O bot deve sempre produzir:

- hipótese falsificável
- alvo/endpoint
- pré-condições
- nível de agressividade 0-3
- trecho de policy que autoriza a ação
- comando ou script concreto
- evidência esperada
- critério de parada
- cleanup

## Proibições do repositório público

Não versionar:

- programas privados
- cookies
- tokens
- headers de sessão
- HAR/Burp XML com sessão real
- screenshots com PII
- reports privados
- dumps de recon de empresas reais
- wordlists gigantes ou corpora terceiros sem checar licença

## Prioridades técnicas

1. Faça `python -m hackbot target-init demo`.
2. Faça `python -m hackbot scope-check targets/demo --host example.com`.
3. Adicione testes para `policy_guard.py`.
4. Crie `hackbot/knowledge.py` para abrir as notas obrigatórias por classe.
5. Crie `hackbot/redaction.py` para remover `Authorization`, `Cookie`, tokens, e-mails e secrets.
6. Crie runners que imprimem comandos primeiro e só executam com `--approve`.
7. Mantenha todo comportamento ativo preso ao escopo.

## Tom do projeto

Pragmático, direto e técnico. Nada de marketing exagerado no README. O valor do
bot vem de escopo, evidência, automação controlada e reports reproduzíveis.
