# Bishop Fox advisories + AI/MCP remaining track

Data: 2026-07-15.

Escopo desta nota:
- fechar o bloco pendente da Bishop Fox: advisories tecnicos e posts AI/MCP restantes;
- registrar padroes de impacto, nao payloads operacionais;
- transformar os artigos em heuristicas para hunting autorizado.

Artigos lidos/salvos localmente:
- `otto-support-supply-chain-risks-mcp-servers.html`
- `otto-support-confused-deputy.html`
- `otto-support-ssrf-token-passthrough-with-mcp.html`
- `otto-support-excessive-agency-and-tool-privileges.html`
- `cve-2026-42208-pre-authentication-sql-injection-in-litellm-proxy.html`
- `cve-2026-27886-unauthenticated-boolean-oracle-exfiltration-of-administrator-secrets-in-strapi.html`
- `api-authentication-bypass-in-forticlient-ems-7-4-5-7-4-6-cve-2026-35616.html`
- `popping-root-on-unifi-os-server-unauthenticated-rce-chain-detection-analysis.html`

## Padrao 1: MCP amplia superficie antiga

Os posts `otto-support` repetem uma ideia consistente:
- MCP nao cria uma fisica nova de seguranca;
- ele expande superficies classicas: SSRF, token passthrough, confused deputy, supply chain e excesso de privilegio;
- o risco nasce quando uma tool aceita chamada direta, recebe contexto nao confiavel ou roda com permissao maior que a tarefa.

Para nosso workspace:
- testar MCP/agentic como API stateful;
- enumerar tools/resources/prompts;
- separar permissao do usuario, permissao do agente e permissao da tool;
- procurar diferenca entre "via chat" e chamada direta ao servidor/tool.

## Padrao 2: Confused deputy em agentic systems

O post de confused deputy mostra o caso em que o agente executa a acao correta com permissao valida, mas a fonte da instrucao foi atacante-controlada.

Heuristica:
- tickets, emails, calendario, documentos e comentarios sao input nao confiavel;
- se o agente le esse input e depois usa tool privilegiada, existe uma borda critica;
- logs podem culpar o usuario/agente legitimo mesmo quando a instrucao veio de fora.

Teste seguro em escopo:
- provar que o agente distingue dado de instrucao;
- verificar se tools destructive/write exigem confirmacao humana;
- confirmar se egress e tool registration sao limitados por tarefa.

## Padrao 3: SSRF + token passthrough

O post de SSRF em MCP reforca um ponto que ja apareceu na nossa nota de SSRF:
- callback/reachability sozinho e fraco;
- impacto cresce quando o request carrega token, sessao ou acesso lateral;
- SSRF em ambiente agentic pode ser SSRF + credential forwarding.

Heuristica:
- sempre perguntar se o backend/agent esta passando headers, cookies, bearer tokens, client certs ou metadata para destino controlado;
- confirmar se o destino consegue causar acao ou ler dado, nao apenas receber ping.

## Padrao 4: Excessive agency

O artigo mostra excesso de agency como problema de composicao:
- cada tool isolada pode ser legitima;
- a combinacao de tools em uma sessao pode criar efeito destrutivo ou cross-boundary;
- permissao de producao em agente aumenta drasticamente blast radius.

Regra para hunting:
- em AI/MCP, procurar tool sets grandes demais;
- testar role-aware tool registration;
- priorizar tools de write/delete/export/admin/credential/token.

## Padrao 5: Advisories tecnicos fortes contam uma cadeia

Os advisories lidos nao param em "CVE existe". Eles mostram:
- precondicao;
- root cause;
- caminho ate sink;
- condicao de exposicao;
- deteccao segura;
- impacto pos-compromisso;
- patch/remediation.

Casos estudados:
- LiteLLM Proxy: pre-auth SQL injection como padrao de auth boundary em produto AI/inferencia.
- Strapi: boolean-oracle unauthenticated ate exfiltracao de segredo administrativo.
- FortiClient EMS: bypass por trust indevido em headers equivalentes a variaveis WSGI/TLS + validacao fraca de cadeia.
- UniFi OS Server: chain unauthenticated ate root e impacto no management plane.

O que isso muda nos reports:
- report forte nao e "endpoint vulneravel";
- report forte e "componente A cruza boundary B, chega no sink C, e isso permite efeito D".

## Checklist novo

Para AI/MCP:
1. O input do agente vem de fonte atacante-controlada?
2. A tool roda com permissao maior que o usuario?
3. A mesma tool aceita chamada direta?
4. Existe token/header passthrough?
5. Existem tools de write/delete/export/admin registradas sem escopo por tarefa?

Para advisories/nday:
1. Ler patch ou diff quando existir.
2. Identificar boundary real.
3. Provar condicao de exposicao.
4. Preferir deteccao segura a exploit destrutivo.
5. Documentar impacto pos-compromisso sem coletar dado sensivel alem do necessario.

## Status

Com esta nota, Bishop Fox fica coberto em tres blocos uteis:
- metodo moderno geral;
- cloud attack paths;
- advisories + AI/MCP.

Ainda nao significa "todos os posts historicos lidos linha a linha". Significa que as trilhas modernas relevantes para nosso workspace foram consolidadas.
