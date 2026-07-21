# OffSec AI / threat / web track

Data: 2026-07-15.

Escopo desta nota:
- fechar OffSec blog para o que interessa ao workspace;
- priorizar AI security, web methodology, bug bounty, threat intelligence e supply chain;
- registrar aprendizado aplicavel sem transformar posts em checklist destrutivo.

Artigos salvos localmente:
- `ai-penetration-testing-vs-traditional-penetration-testing.html`
- `ai-vs-traditional-penetration-testing-tooling-and-outcomes.html`
- `ai-vs-traditional-penetration-testing-which-approach-is-right-for-your-organization.html`
- `top-ai-risks-every-security-team-should-be-testing-for.html`
- `shadow-ai-risks.html`
- `attacking-the-web-offsec-way.html`
- `bug-bounty-program-insights.html`
- `what-infosec-leaders-need-to-know-about-ai.html`
- `xz-backdoor.html`
- `threat-intelligence-in-cyber-defense.html`

## AI pentest vs traditional pentest

OffSec separa bem:
- pentest tradicional testa app, rede, cloud e infra;
- AI pentest testa modelos, prompts, retrieval, contexto, ferramentas e workflows;
- habilidades tradicionais ainda transferem: recon, modelagem de ataque, chaining, reporting e validacao.

Para nosso workspace:
- AI app nao e so prompt injection;
- precisa testar RAG, memoria, tool invocation, authz server-side e side effects.

## Riscos AI prioritarios

Categorias destacadas:
- prompt injection;
- system prompt leakage;
- data/model poisoning;
- excessive agency;
- agent goal hijacking;
- tool misuse;
- sensitive information disclosure.

Conexao com Bishop Fox:
- confirma a mesma regra: AI security e sistema inteiro, nao prompt isolado.

## Shadow AI

OffSec trata Shadow AI como uso de ferramentas nao sancionadas, integracoes invisiveis e vazamento por prompts/API keys.

Para hunting autorizado:
- procurar connectors, browser extensions, SaaS integrations, API keys e automations que movem dado para fora do boundary;
- em report, impacto forte vem de dado sensivel, credencial, compliance ou acao automatizada nao auditada.

## Web e bug bounty

Os posts de web/bounty reforcam:
- metodologia manual importa;
- ferramenta automatica nao substitui leitura de codigo/fluxo;
- report e reproducibilidade pesam tanto quanto descoberta.

Isso reforca o que ja esta nas nossas regras:
- evidence first;
- before/after real;
- diff de estado;
- cadeia de impacto.

## Threat intelligence e supply chain

Os posts de threat intel e XZ colocam foco em:
- contexto;
- cadeia de fornecimento;
- sinais de campanha;
- diferenca entre vulnerabilidade isolada e risco ecossistemico.

Uso no workspace:
- usar threat intel para priorizacao e contexto, nao para hunting cego;
- supply chain entra como fator de impacto quando o alvo depende do componente/integracao em escopo.

## Regras consolidadas

1. AI testing precisa cobrir modelo, contexto, tools, dados e backend.
2. Shadow AI e relevante quando ha dado real, credencial ou integracao nao governada.
3. Ferramenta automatica acelera, mas nao fecha prova.
4. Supply chain aumenta impacto quando a dependencia esta ligada ao produto/tenant/cliente em escopo.

## Status

OffSec deixa de estar pendente e fica consolidado para as trilhas uteis ao workspace.
