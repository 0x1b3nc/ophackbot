# Bishop Fox modern method track

Data: 2026-07-15.

Escopo desta nota:
- consolidar artigos modernos da Bishop Fox que mudam metodo de hunting, triagem e validacao;
- focar em exposicao publica, fingerprinting, LLM-assisted research e MCP/AI systems;
- registrar o que e operacionalmente reaproveitavel no workspace.

Artigos lidos nesta nota:
- `Introducing snowpick: Testing ServiceNow for Public Data Exposure`
- `On Favicons: From Browser Icons to Attack Surface Intelligence`
- `AI Finds Vulnerabilities. Security Experts Find Impact.`
- `Otto Support - Testing MCP Servers`
- `Vulnerability Discovery with LLM-Powered Patch Diffing`
- `You're Pen Testing AI Wrong: Why Prompt Engineering Isn't Enough`

Arquivos-fonte locais:
- `red-team/source-html/bishopfox/introducing-snowpick-testing-servicenow-for-public-data-exposure.html`
- `red-team/source-html/bishopfox/on-favicons-from-browser-icons-to-attack-surface-intelligence.html`
- `red-team/source-html/bishopfox/ai-finds-vulnerabilities-security-experts-find-impact.html`
- `red-team/source-html/bishopfox/otto-support-testing-mcp-servers.html`
- `red-team/source-html/bishopfox/vulnerability-discovery-with-llm-powered-patch-diffing.html`
- `red-team/source-html/bishopfox/youre-pen-testing-ai-wrong-why-prompt-engineering-isnt-enough.html`

## O que a Bishop Fox reforca

O padrao mais forte desses artigos e simples:

- automacao e LLM aceleram descoberta, triagem e ranking;
- impacto real ainda depende de verificacao no sistema vivo;
- superficie "nova" quase sempre cai em fundamentos antigos: authz, exposure, attribution, trust boundary e state handling.

Em outras palavras: IA ajuda a chegar mais rapido no lugar certo, mas nao substitui prova, chaining nem leitura de contexto.

## 1. Snowpick: exposure publico de ServiceNow

Pontos centrais do artigo:
- A abordagem testa duas superficies ao mesmo tempo: widgets do portal e `Table REST API`.
- O fluxo parte de sessao publica e trata widgets como se fossem APIs de dados.
- O objetivo nao e baixar massa de dados, e sim coletar evidencia suficiente sem bulk collection.
- Resultado observado pela Bishop Fox: `31%` de `166` instancias autorizadas tinham ao menos um achado.

O que importa para nos:
- Nao assumir que frontend/portal publico so vaza "conteudo". Ele pode ser proxy de tabela, fluxo ou objeto interno.
- Testar sempre por superficies paralelas: UI widget, endpoint JSON, table-like API, export/search/count endpoints.
- Em exposure publico, a prova forte nem sempre e exfiltrar massa. Contagem, metadata, attachment names, KB titles, ticket refs e estrutura organizacional ja bastam como evidencia segura.

Regra operacional:
- Para apps enterprise pesados e portais de suporte, partir de `public session -> widgets -> APIs paralelas -> count-only / metadata-only evidence`.

## 2. Favicons como attack surface intelligence

Pontos centrais do artigo:
- Favicon fingerprinting usa `MMH3` e ganha valor quando combinado com contexto de host, HTML, headers e certs.
- O valor nao esta no icone sozinho, mas na populacao de hosts que compartilham o mesmo hash.
- O pipeline descrito usa Shodan, agrupamento por assinatura HTML, browser controlado e verificacao humana.
- O proprio artigo insiste em dois freios: search e suplementar, e o agente nao deve promover conclusao sem evidencia de conteudo.
- Favicons tambem servem para detectar honeypots e parking pages quando ha inconsistencias entre produtos, portas, banners e infraestrutura.

O que importa para nos:
- Favicon nao e so recon decorativo. E um pivoteador de superficie e priorizacao.
- Hash igual em varios hosts pode revelar:
  - produto comum exposto em massa;
  - admin panels clonados;
  - staging/forgotten assets;
  - honeypots ou decoys que precisam ser retirados da fila.
- A melhor unidade de trabalho nao e "esse hash parece X", mas "esses hosts compartilham o mesmo template, titulo, headers e cert pattern".

Regra operacional:
- Quando formos fazer ASM/recon em programas grandes, combinar favicon hash com HTML grouping, server headers e paths nao padrao antes de concluir tecnologia.
- Nunca deixar busca web substituir a evidencia do host.

## 3. AI acha bug; humano acha impacto

Pontos centrais do artigo:
- A IA acelerou o "80% chato": rastrear fluxo, entrypoints, handlers e relacionamento entre repositorios.
- O achado de maior valor veio do chaining humano, nao da identificacao inicial.
- Um bypass de verificacao parecia limitado ate que a validacao manual revelou um segundo comportamento e a cadeia virou criacao ilimitada de contas.
- Em SSRF, a IA parou em "blind SSRF". O aprofundamento manual mudou o `mime_type`, forcou renderizacao util e converteu reachability em extracao de dados.
- O artigo mostra explicitamente que a IA deu explicacao confiante e impossivel sobre comportamento de frontend; a causa real era cache server-side.

O que importa para nos:
- LLM e bom para:
  - mapear codigo;
  - resumir handlers;
  - sugerir candidatos;
  - reduzir busca manual.
- LLM nao pode fechar:
  - impacto;
  - falsos positivos;
  - explicacao causal final;
  - chaining entre comportamentos.

Regra operacional:
- Toda vez que a IA disser "parece limitado", tratar isso como estado intermediario, nao conclusao.
- Para SSRF, authz, race, verification bypass e business logic, continuar ate responder: "qual e o dado/acao/estado real que isso me entrega?"

## 4. MCP servers sao web services com outro nome

Pontos centrais do artigo:
- O artigo usa `nmap`, template `Nuclei` e `MCP Inspector` para sair de discovery ate exploit.
- A serie fecha com uma falha de autorizacao em `delete_ticket`: usuario sem privilegio nao podia ler/editar tickets alheios, mas conseguia deletar.
- A mensagem central e correta: MCP introduz outra superficie, nao outra fisica de seguranca.

O que importa para nos:
- Em MCP/AI systems, nosso modelo deve ser:
  - discovery de endpoints (`/mcp`, `/sse`, JSON-RPC style);
  - enumeration de tools/resources;
  - authz por tool/action/tenant/object;
  - efeito state-changing acima de read-only;
  - diferenca entre "LLM pode chamar" e "API aceita chamada direta".
- Isso encaixa exatamente na regra nova do workspace: write-path first, nao so GET/read.

Regra operacional:
- Em qualquer alvo MCP ou agentic, testar matriz minima:
  - trocar objeto;
  - trocar sessao/papel;
  - trocar os dois;
  - chamar a tool diretamente, nao so via UI/chat.

## 5. Patch diffing com LLM: onde compensa e onde nao

Pontos centrais do artigo:
- A maioria dos casos produziu funcao vulneravel conhecida no Top 25 do ranking.
- Casos simples ou medianos foram fortes:
  - `INFO DISCLOSURE`: Top 25 `100%` em todos os modelos testados.
  - `FORMAT STRING`: modelos mais fortes chegaram a `100%`.
  - `AUTH BYPASS`: Sonnet 3.7 foi bem mesmo com `1424` funcoes alteradas, mas com custo alto.
- Casos de stack overflow foram fracos, mesmo apos ajuste de prompt.
- Conclusao do artigo: o ganho esta em abordagem direcionada, nao holistica.

O que importa para nos:
- Patch diffing com LLM vale muito para:
  - auth bypass;
  - info disclosure;
  - regressao de authz;
  - superficie grande demais para leitura manual rapida.
- Nao vale assumir que o ranking resolve tudo, principalmente quando:
  - advisory e pobre;
  - diff e barulhento;
  - classe depende de memoria/side effects/baixo nivel.

Regra operacional:
- Quando tivermos patch/advisory/diff em programa ou third-party component relevante, usar LLM como priorizador de funcoes e nao como laudo final.
- Confirmar no codigo e no comportamento vivo antes de promover candidato.

## 6. AI security testing nao e prompt engineering

Pontos centrais do artigo:
- O artigo rejeita a ideia de que testar LLM = mexer em prompt ou filtro.
- O modelo deve ser tratado como sistema conversacional, com memoria, ferramentas, fluxo e estado.
- Ataques podem nao repetir exatamente, entao metodo precisa aceitar variacao e focar impacto real.

O que importa para nos:
- Em alvo AI/LLM:
  - nao focar so em jailbreak e prompt leak;
  - mapear tools, connectors, file context, memory, approval boundary, tenant boundary e side effects;
  - avaliar o sistema inteiro, nao so a resposta textual.

Regra operacional:
- Para AI app, pensar em cinco camadas:
  1. input/prompt;
  2. retrieval/context;
  3. tool invocation;
  4. authz do lado servidor;
  5. side effect real.

## Como isso muda nosso workspace

### A. Confirmacao acima de abstracao

Esses artigos reforcam uma regra que o operador ja exigiu: confirmar com material e com sistema vivo. Nao basta "parece IDOR", "parece blind SSRF" ou "parece stack path sensivel".

### B. Write-path first continua correta

O caso MCP e o caso de chaining no artigo de AI validam diretamente nossa regra nova:
- nao parar em GET;
- priorizar write/delete/role/lifecycle/payment/approval actions;
- testar o encadeamento objeto + sessao/papel.

### C. Exposure publico precisa de metodo proprio

Snowpick mostra que exposure publico serio raramente e so "index listing". Muitas vezes e:
- widget que faz papel de API;
- count endpoint;
- metadata surface;
- parallel endpoint que o time nao protegeu igual ao principal.

### D. Recon com enrichment e melhor que lista bruta

O artigo de favicons reforca que descobrir mais hostnames nao basta. Precisamos agrupar, enriquecer e retirar ruido antes de gastar tempo manual.

### E. IA ajuda no funil; humano fecha o caso

Uso correto no workspace:
- IA para parsing, clustering, triagem e priorizacao;
- humano para causalidade, exploit chain, impacto e narrativa de report.

## Checklist que passa a valer

1. Se houver sistema grande/publico, procurar superficies paralelas e count/metadata evidence.
2. Se houver patch/diff/advisory, usar LLM para rankear funcoes candidatas.
3. Se houver AI/MCP, testar tools diretamente e focar efeitos state-changing.
4. Se houver candidate bug "limitado", insistir na pergunta de impacto real.
5. Se houver recon em massa, agrupar por evidencia tecnica antes de concluir tecnologia/produto.

## Status

Esta nota fecha uma primeira trilha realmente tecnica da Bishop Fox.

Ainda falta para considerar a fonte "completa":
- advisories tecnicos selecionados;
- mais artigos de cloud attack paths e ASM;
- trilha AI/MCP complementar do blog recente.
