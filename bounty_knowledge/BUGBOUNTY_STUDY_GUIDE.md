# Guia de Estudo — Hacking Web & Bug Bounty (HackerOne / Bugcrowd) — v2

> **O que mudou nessa versão:** conteúdo técnico bem mais denso nas classes de vulnerabilidade (seção 4, inteiramente nova), um framework explícito de **níveis de agressividade** amarrado ao escopo documentado (seção 0.1), e o AGENTS.md ajustado pra IA declarar o nível — e apontar o trecho da policy que autoriza — antes de rodar qualquer comando ativo contra um alvo. O resto da estrutura (seções 1, 2, 3, 5, 6, 8, 9) continua a mesma, só ficou mais robusta.

Lista curada de fontes legítimas para pesquisa em segurança ofensiva, com foco em programas oficiais de bug bounty, mais um plano de estudo pensado para ser executado por uma IA agente (Cursor CLI) rodando numa VM Oracle com Kali Linux de configuração modesta.

Seções 1–7 = **o quê** estudar (incluindo profundidade técnica por classe de vulnerabilidade). Seção 8 = **como** a IA deve estudar isso, dado o hardware — e **com que intensidade**, dado o escopo.

---

## 0. Antes de tudo: escopo é lei

Isso vale tanto pra você quanto para qualquer coisa que a IA sugerir ou automatizar:

- Ler a *security policy*/escopo do programa **antes** de qualquer teste ativo — o que está in scope, out of scope, e que tipos de teste são proibidos (DoS, engenharia social, etc.) variam muito de programa pra programa.
- Guardar o link da policy localmente (ver estrutura na seção 8.3) antes de começar a testar.
- Respeitar rate limits. Scan agressivo demais é o jeito mais rápido de ser banido de um programa — e, sem autorização, deixa de ser bug bounty e vira acesso não autorizado.
- Ao lidar com dados de terceiros encontrados incidentalmente, extrair o mínimo necessário pra provar impacto — nada de exfiltrar além disso.
- Só divulgar publicamente (blog, Twitter, etc.) depois de aprovação formal de disclosure na plataforma.

### 0.1 Regra de ouro: agressividade escala com o escopo — nunca por padrão

Esse é o ponto central desta versão do guia. "Ser mais agressivo tecnicamente" (mais concorrência, mais profundidade de fuzzing, brute-force, testes de race condition disparando dezenas de requisições simultâneas, templates de `nuclei` mais intrusivos) só é uma opção **depois** que o escopo documentado do programa confirma que aquele tipo de teste é permitido naquele asset. Fora isso, o padrão é sempre o nível mais conservador. Trate intensidade como algo que se conquista lendo a policy, não como configuração default de ferramenta.

Framework de 4 níveis pra classificar qualquer ação antes de executá-la:

- **Nível 0 — Passivo** (sempre permitido, nunca toca o alvo diretamente): OSINT, Google dorking, certificate transparency (crt.sh), Wayback Machine, GitHub dorking em busca de segredos vazados, Shodan/Censys (lendo dados já indexados), engenharia reversa client-side de um app já publicado. Pode ser feito mesmo antes de confirmar 100% o escopo — mas qualquer achado só vira teste ativo depois de confirmado em `scope.md`.

- **Nível 1 — Ativo leve** (default assim que `programs/<nome>/scope.md` confirma o asset): enumeração de subdomínios ativa (`subfinder`, resolução via `dnsx`), probing HTTP simples (`httpx`), crawling respeitoso (`katana` com profundidade limitada), fingerprint de tecnologia, checagem de headers de segurança. Rate baixo por padrão (algo como 10-20 req/s, concorrência 5-10).

- **Nível 2 — Ativo moderado** (requer escopo explícito autorizando o asset + ausência de proibição de scanning automatizado na policy): fuzzing de diretórios/parâmetros via `ffuf` com wordlists do SecLists, testes manuais de injeção (SQLi, XSS, SSTI, XXE) em campos identificados um de cada vez, `nuclei` com o conjunto de templates padrão (que já exclui por padrão tags como `dos` e `fuzz` — ver seção 8.6), testes de IDOR/BAC trocando IDs/tokens entre contas de teste próprias.

- **Nível 3 — Agressivo** (só quando a policy deixa explícito: sem proibição de "high volume"/scanning pesado, sem proibição de brute-force, aceita testes DoS-adjacent controlados): fuzzing de alta concorrência, brute-force em campos onde o programa permite (ex: cupom, bypass de rate limit), testes de race condition com múltiplas requisições paralelas, `nuclei` liberando explicitamente tags normalmente excluídas via `-itags dos` (só se a policy aceitar esse tipo de teste — releia duas vezes antes). "Agressivo" aqui significa **usar a intensidade máxima que o escopo autoriza**, nunca "sem regras" — o teto continua sendo a policy, não a capacidade técnica da ferramenta.

**Fora do escopo documentado = não existe nível.** Nenhum grau de agressividade se aplica a um asset que não está confirmado em `scope.md` — mesmo que "pareça" relacionado (subdomínio parecido, IP na mesma faixa, mesma empresa-mãe). Confirmação explícita, nunca inferência.

---

## 1. HackerOne — plataforma e recursos oficiais

- **Directory de programas** — https://hackerone.com/directory/programs
  Listagem pesquisável de todos os programas públicos, com filtros por tipo de asset (domain, API, mobile, IoT, smart contract etc.) e se paga bounty. Ponto de partida pra escolher onde caçar.

- **Hacktivity** — https://hackerone.com/hacktivity
  Feed de reports divulgados publicamente. É provavelmente a fonte de maior densidade de aprendizado real: dá pra ler o report completo — o que foi encontrado, como foi reproduzido, quanto pagou, e qual severidade foi atribuída — de milhares de vulnerabilidades reais, já classificadas por programa e tipo de bug. Filtre por "Disclosed" e ordene por severidade pra priorizar reports com cadeia de exploração mais rica.

- **Hacker101 + CTF** — https://www.hacker101.com/ e https://ctf.hacker101.com/
  Treinamento gratuito mantido pela própria HackerOne: vídeos, guias escritos e uma CTF com dezenas de níveis baseados em vulnerabilidades reais (SQLi, XSS, falhas de autenticação). Ao atingir 26 pontos na CTF você já fica elegível a convites de programas privados — é literalmente o funil de entrada oficial da plataforma. Com 500 de reputação, dá pra resgatar licença gratuita de 3 meses do Burp Suite Pro.

- **reddelexc/hackerone-reports** — https://github.com/reddelexc/hackerone-reports
  Repo que agrega e organiza os reports mais relevantes já divulgados no Hacktivity, agrupados por tipo de bug e por programa (inclusive por empresas específicas). Bom pra "estudo em lote" sem depender da UI do Hacktivity.

## 2. Bugcrowd — plataforma e recursos oficiais

- **Engagements (lista de programas)** — https://bugcrowd.com/engagements (precisa de conta) — ou a versão pública sem login: https://www.bugcrowd.com/bug-bounty-list/

- **CrowdStream** — https://bugcrowd.com/crowdstream
  Equivalente da Bugcrowd ao Hacktivity: feed público de submissions aceitas/divulgadas, com prioridade VRT, programa e (quando o pesquisador permite) valor pago.

- **Bugcrowd University** — https://github.com/bugcrowd/bugcrowd_university
  Treinamento oficial, gratuito e open source da Bugcrowd — módulos em Markdown puro cobrindo desde fundamentos até SSRF, XXE, recon de GitHub e exposição de dados sensíveis. Por ser Markdown direto no repo, é o material mais fácil de dar pra uma IA ler sem parsing extra.

- **Vulnerability Rating Taxonomy (VRT)** — https://github.com/bugcrowd/vulnerability-rating-taxonomy (versão navegável: https://bugcrowd.com/vulnerability-rating-taxonomy)
  Não é um tutorial, é uma taxonomia: como a Bugcrowd classifica severidade (**P1 Crítico** a **P5 Informativo**) pra cada classe de vulnerabilidade — incluindo categorias mais "avançadas" como cloud misconfig, IAM, decentralized apps/DeFi e firmware. Essencial pra calibrar o que realmente vale reportar. A seção 4 deste guia já referencia P1-P5 por classe de bug, mas a VRT completa tem muito mais granularidade (ex: SSRF "blind" e SSRF "full read/write" têm prioridades diferentes).

## 3. Fundamentos de segurança web (aplica às duas plataformas)

- **PortSwigger Web Security Academy** — https://portswigger.net/web-security
  Feito por quem faz o Burp Suite. Free, com labs interativos reais (não só teoria) e learning paths organizados por tema. É o material mais denso e mais atualizado que existe de graça — praticamente todo bug hunter sério passou por aqui. Os learning paths cobrem, entre outros, SQLi, XSS, CSRF, SSRF, XXE, deserialização insegura, request smuggling, prototype pollution, GraphQL e testes de API — a divisão da seção 4 deste guia segue a mesma lógica.

- **HackTricks** — https://book.hacktricks.wiki/
  Wiki comunitária gigantesca, organizada por serviço/tecnologia/classe de vulnerabilidade, com comandos e payloads prontos pra cada cenário — inclui uma seção dedicada a pentest de API. Mais "cheatsheet operacional" do que curso: bom complemento pro PortSwigger quando você já entende o conceito e só quer o comando/payload certo pra confirmar. Tem uma extensão focada em cloud (AWS/GCP/Azure) em https://cloud.hacktricks.wiki/.

- **OWASP WSTG (Web Security Testing Guide)** — https://github.com/OWASP/wstg
  Guia de metodologia de teste mais formal/completo que existe, com um checklist pronto para uso em https://github.com/OWASP/wstg/blob/master/checklists/checklist.md. Bom como "índice mestre" — cada item tem um ID (ex: WSTG-INFO-02) que serve de referência cruzada com as próprias notas.

- **OWASP Top 10** — https://owasp.org/www-project-top-ten/
  As categorias mais comuns de vulnerabilidade em apps web, direto da fonte. Ponto de entrada pra quem tá organizando conhecimento por categoria.

- **OWASP API Security Top 10 (edição 2023)** — https://owasp.org/API-Security/
  Boa parte do escopo moderno em HackerOne/Bugcrowd é API (REST/GraphQL), não só front-end tradicional. A lista atual, em ordem:
  1. API1:2023 – Broken Object Level Authorization (BOLA)
  2. API2:2023 – Broken Authentication
  3. API3:2023 – Broken Object Property Level Authorization (fusão do antigo "Excessive Data Exposure" com "Mass Assignment")
  4. API4:2023 – Unrestricted Resource Consumption
  5. API5:2023 – Broken Function Level Authorization (BFLA)
  6. API6:2023 – Unrestricted Access to Sensitive Business Flows
  7. API7:2023 – Server-Side Request Forgery (SSRF)
  8. API8:2023 – Security Misconfiguration
  9. API9:2023 – Improper Inventory Management
  10. API10:2023 – Unsafe Consumption of APIs

  BOLA (nº1) sozinho já responde por boa parte dos achados pagos em bug bounty de API — é o primeiro lugar pra procurar em qualquer endpoint novo.

## 4. Classes de vulnerabilidade — aprofundamento técnico (novo)

Isso não substitui PortSwigger/OWASP/HackTricks — é a camada de síntese que a seção 8.2 pede ("40-50 notas próprias, não 500 links salvos"). Cada bloco segue o formato pensado pra virar nota final: o que é, onde procurar, padrões de bypass comuns, nível de agressividade tipicamente necessário pra confirmar (seção 0.1), e severidade típica na VRT (P1 = crítico, P5 = informativo — seção 2).

### 4.1 Injeção (SQLi, NoSQLi, Command Injection, SSTI, XXE)

- **SQLi**: além do clássico erro/union-based, treine detecção **blind** (boolean-based e time-based) e **second-order** (payload gravado num campo e disparado em outro contexto, tipo relatório ou export). Pontos de entrada além do form óbvio: headers (`X-Forwarded-For`, `User-Agent`), parâmetros de ordenação/filtro em APIs REST, campos de busca com autocomplete.
- **NoSQLi (MongoDB e afins)**: operadores injetáveis em JSON (`$ne`, `$gt`, `$regex`) quando o backend faz parse direto do corpo sem sanitizar tipos — um campo que espera string recebendo um objeto `{"$ne": null}` já é sinal de alerta.
- **Command Injection**: qualquer funcionalidade que chama um binário externo (conversão de imagem/PDF, ping/traceroute embutido, geração de relatório) é candidata. Teste com separadores (`;`, `|`, `&&`, backtick) e, se bloqueado, com técnicas de bypass de filtro (concatenação, encoding, variáveis de ambiente).
- **SSTI (Server-Side Template Injection)**: aparece em campos que geram conteúdo dinâmico (nome exibido num template, geração de e-mail/PDF personalizado). Teste clássico é a expressão matemática (`{{7*7}}`, `${7*7}`, `#{7*7}`, dependendo da engine) — se o cálculo volta resolvido na resposta, o próximo passo é identificar a engine (Jinja2, Twig, FreeMarker etc.) pra entender até onde dá pra escalar, dependendo dos gadgets disponíveis.
- **XXE**: em qualquer endpoint que aceita XML (upload de arquivo, SOAP, às vezes SVG), teste entidade externa apontando pra um arquivo local como evidência e, se bloqueado, OOB via DTD externo com callback pro seu próprio servidor (OAST/Burp Collaborator) pra confirmar exfiltração blind.
- **Agressividade**: nível 2 cobre a maioria (um payload por vez, manual). Fuzzing automatizado de todos os parâmetros é nível 2 alto — controle concorrência.
- **Severidade típica**: SQLi/SSTI/Command Injection com execução de código comprovada → geralmente P1. XXE limitado a leitura de arquivo local sem OOB → P2-P3, dependendo da sensibilidade do arquivo.

### 4.2 Autenticação, sessão e tokens

- **JWT**: teste `alg: none` (remover assinatura e ver se o backend ainda aceita), confusão de algoritmo RS256→HS256 (só funciona se o backend não fixar o algoritmo esperado), injeção via campo `kid` (path traversal ou SQLi se o `kid` é usado pra montar caminho de arquivo ou query de busca da chave).
- **OAuth**: validação fraca de `redirect_uri` (aceita subdomínio arbitrário, aceita parâmetro extra depois da URL cadastrada, ou faz só `startswith` em vez de match exato), `state` ausente ou não validado (abre CSRF no fluxo de login), reuso de `authorization code`.
- **Reset de senha / magic link**: token previsível (sequencial, timestamp, hash sem salt de algo público como e-mail), token que não expira ou não é invalidado após uso, endpoint que aceita o token errado se o e-mail bater (falha de binding entre token e conta).
- **Fixação de sessão**: verifique se o session ID muda após login — se o mesmo ID de antes da autenticação continua válido depois, há fixação.
- **Agressividade**: nível 1-2 pra maioria dos testes manuais (um request de cada vez). Brute-force de tokens curtos de reset de senha é nível 3 — precisa de volume, só com escopo permitindo brute-force explicitamente.
- **Severidade típica**: bypass de autenticação completo (assumir conta de outro usuário sem interação) → P1. CSRF em fluxo OAuth sem 2FA → geralmente P2.

### 4.3 Autorização (IDOR/BAC, mass assignment, escalação de privilégio)

- **IDOR/BAC**: o teste base é trocar o identificador (numérico sequencial, UUID, hash) de um recurso pelo de outra conta de teste sua e ver se a resposta muda de "forbidden" pra "sucesso". Cubra três eixos: leitura (GET vazando dado de outro usuário), escrita (PUT/PATCH alterando recurso de outro usuário) e função (endpoint administrativo acessível por conta comum — isso é BFLA, API5:2023). Em GraphQL, o mesmo bug aparece como falta de checagem por campo/resolver, não só por endpoint.
- **Mass assignment**: envie campos extras no corpo JSON que o formulário normal não expõe (`"role": "admin"`, `"isVerified": true`, `"balance": 999999`) e veja se o backend faz bind cego do objeto inteiro sem allowlist de campos.
- **Privilege escalation horizontal vs vertical**: tenha sempre pelo menos duas contas de teste em níveis diferentes (ex: usuário free vs pago, membro vs admin) — sem isso boa parte de BAC/BFLA fica impossível de testar de forma confiável.
- **Agressividade**: nível 1-2 — trocar IDs manualmente entre contas próprias não é intrusivo nem precisa de volume.
- **Severidade típica**: IDOR que vaza PII de qualquer usuário sem interação → geralmente P1-P2. Vazamento de dado não-sensível (ex: contador interno) → P3-P4.

### 4.4 SSRF

- **Pontos de entrada clássicos**: webhooks, geração de PDF/thumbnail a partir de URL, "preview de link", qualquer integração que busca um recurso a partir de um campo de URL fornecido pelo usuário.
- **Alvos internos comuns**: metadata de cloud (`169.254.169.254` — path e headers exigidos variam entre AWS/GCP/Azure, vale confirmar qual cloud o alvo usa antes), serviços internos em portas não expostas publicamente, `localhost`/`127.0.0.1` disfarçado.
- **Bypass de filtro comuns**: encoding alternativo de IP (decimal, octal, hex — `http://2130706433/` equivale a `127.0.0.1`), redirect chain (URL externa que seu servidor controla redirecionando pra um alvo interno), DNS rebinding, uso de `@` na URL.
- **Blind SSRF**: quando não há reflexo direto da resposta, confirme via OOB — interactsh (`nuclei` já integra) ou Burp Collaborator; um callback DNS/HTTP pro seu próprio servidor prova a requisição mesmo sem ver o corpo da resposta.
- **Agressividade**: nível 2 pra testes manuais com payload único por campo. Nível 3 só se for necessário varrer uma faixa grande de portas/IPs internos — normalmente evitável testando primeiro os alvos internos mais prováveis.
- **Severidade típica**: SSRF que atinge metadata de cloud com leitura de credenciais → P1. SSRF blind sem leitura de dado sensível confirmada → P2-P3.

### 4.5 Race conditions e lógica de negócio

- **TOCTOU (time-of-check to time-of-use)**: qualquer fluxo que verifica um estado e depois age sobre ele (saldo antes de debitar, cupom antes de aplicar, limite de tentativas antes de permitir) é candidato. O teste é disparar múltiplas requisições no mesmo instante — não sequencialmente — pra ver se o servidor processa mais operações do que o estado permitiria.
- **Técnica de single-packet / last-byte sync**: em vez de só rodar requisições em paralelo (onde o jitter de rede já cria uma janela grande), agrupe os pacotes HTTP e libere o último byte de cada requisição no mesmo instante — é o que o Turbo Intruder (extensão do Burp) implementa, reduzindo a janela de corrida de dezenas de ms pra frações de ms.
- **Onde procurar primeiro**: resgate de cupom/voucher, aplicação de código de convite/referral, endpoints de "curtir"/"seguir" que deveriam ser idempotentes, criação de recurso com limite (ex: "1 conta grátis por CPF"), qualquer coisa envolvendo saldo ou crédito.
- **Agressividade**: nível 3 por definição — a técnica exige disparar várias requisições simultâneas. Comece com poucas (5-10) pra confirmar o comportamento antes de escalar, e desfaça/reverta o estado gerado (ex: cancele pedidos duplicados) se o programa não instruir o contrário.
- **Severidade típica**: race condition com impacto financeiro direto (duplicar saldo, comprar sem debitar) → geralmente P1-P2. Duplicação sem impacto financeiro → P4-P5.

### 4.6 Subdomain takeover e bugs orientados a recon

- **Mecânica**: um registro DNS (geralmente CNAME) aponta pra um serviço de terceiro (S3, Heroku, GitHub Pages, Azure, Fastly, Netlify...) que não existe mais ou nunca foi reclamado — quem registrar aquele recurso no provedor passa a controlar o conteúdo servido no subdomínio da vítima.
- **Como detectar em escala**: depois de enumerar subdomínios (`subfinder` → `dnsx` pra resolver CNAMEs), rode `nuclei -t takeovers/` (templates da comunidade já cobrem as assinaturas de "página não encontrada" de cada provedor) ou ferramentas dedicadas de takeover.
- **Confirmação sem causar dano**: registrar o recurso pra provar o takeover costuma ser aceito pelos programas, mas não publique conteúdo além do necessário pra evidência (um `index.html` simples de identificação, nunca nada que pareça phishing) e desfaça assim que o report for aceito.
- **Agressividade**: nível 1 — é essencialmente enumeração passiva + uma resolução DNS.
- **Severidade típica**: varia muito com o que o subdomínio "vale" — takeover de subdomínio principal com cookies/sessão compartilhada → P1-P2. Takeover de subdomínio esquecido sem tráfego real → P4.

### 4.7 API-specific: GraphQL, request smuggling, cache poisoning

- **GraphQL**: introspecção deixada ligada em produção (`__schema`) expõe o schema inteiro — mesmo desligada, "field suggestion" (erros que sugerem o nome certo do campo) pode vazar schema aos poucos. Abuso de batching (múltiplas queries num único request) pra contornar rate limit de auth ou de outras proteções por-request. Queries profundamente aninhadas ou com alias duplicado em excesso podem causar exaustão de recursos (API4/API6:2023).
- **HTTP Request Smuggling**: desincronização entre como o front-end (proxy/CDN/load balancer) e o back-end interpretam `Content-Length` vs `Transfer-Encoding` (CL.TE, TE.CL, TE.TE com ofuscação de header). Detecção é delicada, tipicamente por diferença de timing numa requisição de sondagem — vale estudar a fundo direto no PortSwigger (tem learning path dedicado) antes de tentar em programas reais; o risco de afetar outros usuários sem querer é real.
- **Cache poisoning**: quando um header não-chaveado pelo cache (`X-Forwarded-Host`, `X-Forwarded-Scheme`, `X-Original-URL`) é refletido na resposta e essa resposta é cacheada, qualquer usuário que acessar a URL depois recebe a resposta envenenada.
- **Agressividade**: introspecção/field suggestion é nível 1. Batching abuse e cache poisoning são nível 2. Request smuggling é nível 2-3 e **exige cuidado redobrado** — um teste malfeito pode afetar requisições de usuários reais alheios ao teste; releia a policy quanto a "testes que podem afetar outros usuários" antes de tentar.
- **Severidade típica**: request smuggling com sequestro de sessão de outro usuário → P1. Cache poisoning com XSS armazenado pra qualquer visitante → P1-P2. Introspecção GraphQL exposta sem mais nada → geralmente informativo/P4, a menos que o schema exponha algo sensível por si só.

### 4.8 Client-side: prototype pollution, DOM XSS, postMessage

- **Prototype pollution (JS)**: funções de merge/clone recursivas mal implementadas (`_.merge`, `$.extend`, merges caseiros) que aceitam `__proto__` ou `constructor.prototype` como chave permitem poluir o protótipo global — dependendo do que a aplicação faz com propriedades de objeto depois, isso pode virar de bypass de validação até XSS ou, em Node.js server-side, algo mais grave via gadgets específicos do framework.
- **DOM XSS**: fontes (`location.hash`, `location.search`, `postMessage`, `document.referrer`) que chegam em sinks perigosos (`innerHTML`, `eval`, `document.write`, atributos `on*`) sem sanitização. Ferramentas como Burp (DOM Invader) ou revisão manual do JS via `katana` + grep por sinks conhecidos ajudam a mapear isso em escala.
- **postMessage inseguro**: listener de `message` que não valida `event.origin` antes de confiar no conteúdo — permite que qualquer página (inclusive uma maliciosa aberta como iframe/popup) envie dados que a aplicação trata como confiáveis.
- **Agressividade**: nível 1-2 — é análise de código client-side (às vezes até nível 0, se o JS já está público) mais confirmação manual pontual.
- **Severidade típica**: DOM XSS explorável sem interação do usuário-vítima → P2-P3 (raramente chega a P1 sozinho, a menos que encadeie com outra coisa). Prototype pollution que vira execução de código server-side → P1.

## 5. Metodologia de reconhecimento e hunting

- **The Bug Hunter's Methodology (TBHM)** — https://github.com/jhaddix/tbhm
  Repositório com os slides/PDFs de todas as versões das talks de Jason Haddix (v1 a v4 + Recon + Application Analysis), referência histórica de metodologia de recon → discovery → exploração em bug bounty. Tudo texto/slide, gratuito.

- **Pentester Land — Writeups** — https://pentester.land/writeups/
  Base pesquisável com milhares de writeups de bug bounty/pentest/disclosure catalogados por tag, programa, autor e valor pago. Excelente pra buscar "todos os writeups de SSRF" ou "todos os de um programa específico" de uma vez.

- **Pensando em cadeia, não em bug isolado**: os reports que pagam mais quase sempre encadeiam 2-3 bugs "médios" em algo crítico — ex: um IDOR (nível 2) que vaza um token de reset de senha (baixa severidade sozinho) que permite assumir qualquer conta (severidade alta). Ao estudar um writeup, sempre pergunte "quais bugs individuais compõem essa cadeia, e cada um sozinho valeria o quê?" — isso ensina mais do que decorar payloads.

## 6. Bancos de writeups reais (aprender com casos concretos)

- **ngalongc/bug-bounty-reference** — https://github.com/ngalongc/bug-bounty-reference
  Um dos repos mais antigos e influentes do gênero: writeups reais organizados por natureza do bug (XSS, SQLi, RCE, subdomain takeover, OAuth, race condition etc.).

- **devanshbatham/Awesome-Bugbounty-Writeups** — https://github.com/devanshbatham/Awesome-Bugbounty-Writeups
  Curadoria mais recente no mesmo espírito, também organizada por tipo de bug, com centenas de links.

## 7. Repositórios técnicos: payloads, wordlists e ferramentas leves

- **PayloadsAllTheThings** — https://github.com/swisskyrepo/PayloadsAllTheThings
  A referência de payloads por classe de vulnerabilidade (cada pasta = um README com explicação + payloads + cheatsheet). **Já está empacotado no Kali**: `sudo apt install payloadsallthethings` — evita clonar o repo inteiro.

- **SecLists** — https://github.com/danielmiessler/SecLists
  Wordlists de tudo (subdomínios, diretórios, parâmetros, senhas, payloads de fuzzing). **Atenção**: clone completo tem ~1.4GB. **Também já está no Kali**: `sudo apt install seclists` — instala em `/usr/share/seclists`, sem duplicar espaço.

- **ProjectDiscovery (suite de recon)** — https://github.com/projectdiscovery
  Ferramentas em Go, binário único, sem dependência pesada — ideais pra VM fraca:
  - `subfinder` (enumeração de subdomínios), `dnsx` (resolução), `naabu` (port scan leve), `httpx` (probing HTTP + fingerprint), `katana` (crawling), `nuclei` (scanner baseado em templates YAML, comunidade atualiza constantemente).
  - Pipeline típico: `subfinder -d alvo.com -silent | dnsx -silent | httpx -silent | nuclei -silent`.
  - Instala tudo de uma vez com o gerenciador oficial: `pdtm -ia` (https://docs.projectdiscovery.io/quickstart).
  - **Sobre agressividade no `nuclei` especificamente**: por padrão a ferramenta já exclui templates com tag `dos` e `fuzz` da execução (mecanismo de segurança embutido) — só rodam se você liberar explicitamente com `-itags dos` (nível 3, e só com escopo permitindo). Pra controlar intensidade: `-rl`/`-rate-limit` (requisições/segundo, default 150 — alto demais pra VM fraca ou nível 1/2, considere 10-30), `-c`/`-concurrency` (templates em paralelo, default ~25, considere 5-10 numa VM fraca) e `-etags`/`-exclude-tags` pra remover categorias inteiras (ex: `-etags dos,fuzz,intrusive`).

- **HackTricks** (seção 3) também tem comandos prontos de `ffuf`/`nuclei`/etc. por cenário — bom pra copiar o ponto de partida e ajustar rate/concorrência conforme o nível de agressividade permitido.

- **ffuf** — https://github.com/ffuf/ffuf
  Fuzzer web rápido em Go (content discovery, parâmetros, vhosts). Mais leve que ferramentas equivalentes em Python.

---

## 8. Como a sua IA (Cursor CLI) deve estudar isso

### 8.1 O que roda onde
O raciocínio do Cursor CLI acontece na nuvem (no modelo que você escolher) — o que roda local na VM é só a camada de execução: `git`, `curl`, os binários Go, leitura/escrita de arquivo. Ou seja, o gargalo real numa VM de entrada não é "poder de IA", é disco, banda e RAM pra rodar ferramentas. Trate os dois como recursos separados: a IA pode "pensar" bastante sem pesar na VM, mas cada `git clone` e cada scan pesa.

### 8.2 Princípios de estudo
1. **Texto > vídeo.** O Cursor processa texto de forma muito mais eficiente do que tentar extrair sentido de vídeo. Praticamente tudo listado acima é texto ou tem versão em texto (os slides do TBHM, por exemplo) — priorize essas fontes na hora de "alimentar" a IA.
2. **Sintetizar, não acumular.** O objetivo não é ter 500 links salvos, é ter uma base própria de 40–50 notas, escritas com as palavras da IA, que dá pra reler em 30 segundos antes de testar um alvo. A instrução padrão devia ser sempre "resuma na base de conhecimento, não guarde só o link".
3. **Estudar em camadas, não em ordem aleatória:** fundamentos (PortSwigger/OWASP/HackTricks) → metodologia de recon (TBHM) → classes de vulnerabilidade específicas (seção 4 deste guia + PayloadsAllTheThings + WSTG) → reports reais (Hacktivity/CrowdStream/Pentester Land) pra ver a teoria aplicada.
4. **Toda nota termina em "como isso é reportado".** De nada adianta saber explorar um bug se o report não é aceito — referencie a VRT da Bugcrowd pra severidade em cada nota.
5. **Toda ação ativa declara o nível antes de rodar.** Antes de qualquer comando que toque um alvo real (não durante estudo de material — só durante teste de programa), a IA declara qual nível (0-3, seção 0.1) aquela ação corresponde e qual trecho da policy autoriza esse nível. Sem apontar a autorização, o nível cai automaticamente pro mais conservador possível.

### 8.3 Estrutura de pastas sugerida

```
~/bugbounty-study/
├── AGENTS.md                    # instruções persistentes (seção 8.4)
├── knowledge-base/
│   ├── INDEX.md                 # índice com 1 linha por nota
│   ├── recon/
│   │   ├── subdomain-enum.md
│   │   ├── subdomain-takeover.md
│   │   ├── content-discovery.md
│   │   └── fingerprinting.md
│   ├── web-vulns/
│   │   ├── injection.md          # SQLi, NoSQLi, command injection, SSTI, XXE
│   │   ├── auth-session.md       # JWT, OAuth, reset de senha, fixação
│   │   ├── idor-bac.md           # IDOR, mass assignment, BFLA
│   │   ├── ssrf.md
│   │   ├── race-conditions.md
│   │   └── client-side.md        # prototype pollution, DOM XSS, postMessage
│   ├── api-security/
│   │   ├── owasp-api-top10.md
│   │   └── graphql-smuggling-cache.md
│   └── reports-estudados/
│       └── AAAA-MM-DD-programa-tipo-bug.md
├── refs/                         # clones rasos de repos-referência
├── tools/                        # binários Go (subfinder, httpx, nuclei, ffuf…)
└── programs/
    └── <nome-do-programa>/
        ├── scope.md               # inclui o nível de agressividade (0-3) autorizado por asset
        ├── recon-notes.md
        └── findings.md
```

### 8.4 AGENTS.md sugerido
O Cursor CLI já lê automaticamente um `AGENTS.md` na raiz do workspace (e também `CLAUDE.md`, além de regras mais granulares em `.cursor/rules`) — é a forma mais direta de fixar essas instruções sem repetir tudo em cada prompt. Sugestão de conteúdo pra colar na raiz de `~/bugbounty-study/`:

```markdown
# Contexto do projeto

Base de conhecimento pessoal de segurança web e metodologia de bug bounty,
focada em programas legítimos do HackerOne e Bugcrowd. Não é um repo de
código — é uma base de estudo que você (agente) ajuda a manter.

# Como processar uma fonte nova (artigo, repo, writeup)

1. Leia a fonte inteira antes de escrever qualquer coisa.
2. Nunca copie parágrafos inteiros para as notas — reescreva com suas
   próprias palavras. Payloads/comandos de exemplo podem ser citados
   literalmente, desde que curtos.
3. Salve o resumo em knowledge-base/<categoria>/<tema>.md usando o template:
   ## O que é / ## Onde aparece / ## Padrões de bypass comuns
   ## Como confirmar (PoC) / ## Nível de agressividade necessário (0-3)
   ## Severidade típica (VRT) / ## Fontes
4. Se o tema já tiver nota, atualize a existente em vez de criar uma nova.
5. Ao final, adicione uma linha em knowledge-base/INDEX.md linkando a nota.

# Antes de rodar qualquer comando ativo contra um alvo real

Isso NÃO se aplica a estudar material (ler PortSwigger, resumir um writeup)
— só a comandos que efetivamente enviam tráfego pra um alvo de um programa.

1. Confirme que o asset está listado em programs/<nome>/scope.md.
2. Declare o nível de agressividade (0-3, ver seção "Níveis" abaixo) que
   aquele comando específico representa.
3. Aponte qual trecho da policy (salva em scope.md) autoriza esse nível.
   Sem trecho claro, use o nível mais conservador disponível — nunca
   assuma permissão implícita.
4. Só depois disso, execute.

# Níveis de agressividade (use sempre o mais baixo que resolve o objetivo)

- Nível 0 — passivo, nunca toca o alvo (OSINT, certificate transparency,
  Wayback, GitHub dorking). Sempre permitido.
- Nível 1 — ativo leve (subfinder, httpx, dnsx, crawling raso). Default
  assim que o asset está confirmado em scope.md.
- Nível 2 — ativo moderado (ffuf, testes manuais de injeção, nuclei com
  templates padrão). Requer escopo explícito + ausência de proibição de
  scanning automatizado na policy.
- Nível 3 — agressivo (fuzzing de alta concorrência, brute-force, race
  condition, nuclei com tags normalmente excluídas via -itags). Só com
  autorização explícita na policy — releia antes de escalar pra esse nível.
- Fora de scope.md = nenhum nível se aplica. Nunca.

# Restrições de hardware (VM Oracle de entrada, Kali Linux)

- git clone --depth 1 sempre que for só consulta.
- Prefira pacotes apt do Kali (seclists, payloadsallthethings) a clonar os repos.
- Não instale nem rode modelos locais (embeddings, LLM local) — desnecessário,
  o raciocínio já roda na nuvem via Cursor.
- Nunca rode mais de um scanner de rede/recon em paralelo.
- Ferramentas de recon (nuclei, ffuf) sempre com rate limit e concorrência
  baixos por padrão (ex: nuclei -c 10 -rate-limit 20), mesmo quando o
  escopo permitiria nível 3 — o teto de hardware é uma restrição separada
  do teto de escopo, e vale sempre o menor dos dois.

# Escopo e ética — inegociável

- Antes de qualquer teste ativo contra um alvo, confirme que ele está no
  escopo documentado em programs/<nome>/scope.md.
- Nunca sugira testes contra ativos fora de escopo, mesmo "só pra checar",
  mesmo que pareça relacionado (subdomínio parecido, mesma empresa-mãe).
- Sempre lembre de checar rate limits e regras de engajamento do programa
  antes de rodar qualquer scan automatizado.
- Ao encontrar um bug real durante teste, o objetivo é reportar pela
  plataforma — nunca explorar além do necessário pra provar impacto,
  nunca reter acesso "pra confirmar depois", nunca testar em conta de
  terceiro sem ser a própria conta de teste.
```

### 8.5 Loop de estudo, na prática
Prompt-tipo pra cada fonte nova (cole no Cursor CLI, trocando o link):

> Leia [URL ou path do repo clonado em refs/]. Resuma em `knowledge-base/<categoria>/<tema>.md` seguindo o template do AGENTS.md (inclui nível de agressividade necessário e severidade VRT). Não copie blocos grandes de texto — reescreva com suas palavras. Inclua no máximo 2–3 exemplos de payload/comando como referência rápida. Depois, adicione a entrada em `knowledge-base/INDEX.md`.

Pra estudar um report real do Hacktivity/CrowdStream, o prompt muda um pouco — o objetivo aí não é o template de vulnerabilidade, é entender a cadeia de raciocínio:

> Leia este report divulgado: [URL]. Em `knowledge-base/reports-estudados/`, registre: qual foi a hipótese inicial do pesquisador, que passo de recon levou à descoberta, quais bugs individuais foram encadeados (se houver mais de um — ver seção 5 sobre "pensar em cadeia"), e o que teria sido diferente se o alvo tivesse uma proteção X.

### 8.6 Cuidados específicos pra VM de entrada
- `git clone --depth 1` sempre que só for consultar (não precisa do histórico).
- Prefira `apt install seclists` e `apt install payloadsallthethings` a clonar — evita duplicar ~1.4GB do SecLists sozinho.
- Pras ferramentas Go da ProjectDiscovery, `pdtm -ia` instala tudo de uma vez; rode `go clean -cache` depois pra não deixar lixo de build acumulando.
- Nunca rode `nuclei` sem `-rl`/`-c` ajustados pra baixo — o default da ferramenta é 150 req/s e ~25 templates em paralelo, pesado demais pra VM fraca mesmo quando o escopo permitiria nível 3. Por padrão o `nuclei` já exclui tags `dos`/`fuzz`; só libere com `-itags` se o nível 3 estiver confirmado.
- Se for só ler/estudar um repo grande (sem contribuir de volta), pode `rm -rf .git` depois do clone raso pra liberar espaço — só lembre que aí a atualização é via re-clone, não `git pull`.
- Evite manter wordlists redundantes: o SecLists já cobre a maior parte do que PayloadsAllTheThings referencia.

### 8.7 Cadência sugerida
Uma categoria de vulnerabilidade por sessão de estudo (ex: só SSRF — seção 4.4 deste guia como ponto de partida), seguida de 2–3 writeups reais daquela categoria no Hacktivity/CrowdStream/Pentester Land pra ver a teoria aplicada antes de passar pra próxima. Isso evita o padrão comum de "ler 10 artigos e não lembrar de nenhum" — cada sessão fecha com uma nota nova ou atualizada na base.

---
