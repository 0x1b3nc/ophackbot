# SpecterOps identity, trust and token track II

Status: **2026-07-15**. Continuação da trilha priorizada da SpecterOps com foco em:
- `Azure Privilege Escalation via Service Principal Abuse`
- `Azure Seamless SSO: When Cookie Theft Doesn't Cut It`
- `Untrustworthy Trust Builders: Account Operators Replicating Trust Attack (AORTA)`
- `SCCM Hierarchy Takeover via Entra Integration`

Base local:
- `bounty_knowledge/study_notes/red-team/source-html/specterops/azure-service-principal-abuse.html`
- `bounty_knowledge/study_notes/red-team/source-html/specterops/azure-seamless-sso.html`
- `bounty_knowledge/study_notes/red-team/source-html/specterops/aorta.html`
- `bounty_knowledge/study_notes/red-team/source-html/specterops/sccm-entra-integration.html`

## O que essa segunda metade adiciona

Se a primeira nota da trilha mostrou que:
- trusts
- cookies/tokens
- app roles

viram caminho de ataque,

esta segunda metade mostra algo mais importante:
- o atacante quase nunca precisa do privilégio final logo no começo;
- basta controlar um ponto intermediário que emite, valida, representa ou replica identidade.

Esse e o fio comum dos quatro artigos:
- `service principal`
- `Azure Seamless SSO`
- `Incoming Forest Trust Builders`
- `AdminService` do SCCM

Todos parecem "detalhes de integração". Na prática, viram ponte até Tier 0 ou tenant compromise.

## 1. Service principal abuse: controlar o principal vale mais que controlar o usuário

Do artigo `Azure Privilege Escalation via Service Principal Abuse`:

### O encadeamento central

Eles mostram que o "freio de emergência" embutido do Azure para password reset de `Global Admin` não resolve o problema quando o caminho passa por `service principal`.

O caminho resumido:
1. um principal com `Application Administrator` ou papel equivalente ganha controle sobre o app
2. esse principal adiciona novo segredo ao `service principal`
3. autentica como o `service principal`
4. herda os privilégios já atribuídos a ele
5. usa isso para promover a si mesmo ou outro usuário até `Global Admin`

### O ponto crítico

O problema não é "usuário virou admin" de forma direta.
O problema é:
- controle sobre credencial do app
- app com role alta
- abuso da identidade não-humana como ponte de escalation

### O que isso muda no nosso raciocínio

Quando estivermos vendo Azure/Entra:
- não perguntar só "quem é admin?"
- perguntar:
  - quem pode adicionar segredo?
  - quem é owner do app?
  - que roles o `service principal` já tem?
  - que papel tenant-level permite gerenciar credenciais de apps?

Essa é uma boa tradução de attack path:
- `identity with app-control` -> `service principal auth` -> `privileged role already attached`

### Lição forte

`role on service principal` sem análise de `who controls the service principal` é meia verdade.

## 2. Azure Seamless SSO: quando o cookie falha, o fluxo de identidade continua valendo

Do artigo `Azure Seamless SSO: When Cookie Theft Doesn't Cut It`:

### O ponto central

O post parte de um cenário em que o cookie interessante expirou.
Mesmo assim, o caminho de ataque continuou porque havia um mecanismo legítimo de autenticação híbrida a explorar:
- `Azure Seamless SSO`

Eles pivotam a partir da existência de:
- `AZUREADSSOACC$`
- browser configurável para SSO
- device-code auth
- caminhos posteriores de role/PIM/app abuse

### O valor operacional disso

Isso reforça uma regra excelente:
- material roubado pode falhar;
- o mecanismo legítimo que emite novo material pode ser ainda mais valioso.

Ou seja:
- não focar só em `steal token`
- focar também em `what valid identity flow can I still trigger?`

### Pontos que importam

- `Conditional Access Policies` continuam relevantes
- o browser/host precisa reproduzir a experiência de login do usuário
- `AZUREADSSOACC$` é sinal arquitetural útil
- device-code flow e autenticação real podem ser combinados com pivôs posteriores

### O que fica para nós

Em enterprise auth:
- mapear artefatos de sessão é bom
- mapear fluxos legítimos de reemissão é melhor ainda

Isso vale para:
- SSO
- OAuth device flow
- refresh paths
- PIM activations
- app bootstrap flows

## 3. AORTA: grupo aparentemente não-Tier0 que compromete floresta vanilla

Do artigo `AORTA`:

### O que eles provaram

Eles mostram que `Account Operators`, combinando:
- `Incoming Forest Trust Builders`
- `DnsAdmins`

pode comprometer o domínio/floresta num ambiente AD vanilla, sem depender de customização exótica.

### A cadeia de abuso

Em alto nível:
1. preparar domínio controlado pelo atacante
2. criar `inbound forest trust` com `TGT delegation enabled`
3. criar `DNS conditional forwarder`
4. coagir o DC alvo a autenticar via Kerberos contra host com unconstrained delegation
5. capturar o TGT do DC
6. fazer `DCSync`

### O ponto mais forte

Esse artigo mata uma intuição ruim:
- "esse grupo não é protegido por AdminSDHolder, então deve ser menos crítico"

Não necessariamente.

O grupo pode:
- não ser formalmente Tier 0
- mas ainda abrir um caminho padrão até Tier 0

### O que isso ensina

Não avaliar grupo só por rótulo.
Avaliar por:
- direitos efetivos
- integrações adjacentes
- o que consegue criar
- o que consegue replicar
- o que consegue fazer o DC acreditar

### Lição estrutural

`create trust` + `delegation` + `DNS` parece trio administrativo inocente.
Na prática, vira:
- emissão de confiança
- roteamento
- autenticação transferida

Essa composição é o ataque.

## 4. SCCM + Entra: validar token não basta se o UPN vira identidade local

Do artigo `SCCM Hierarchy Takeover via Entra Integration`:

### O coração do bug

O `AdminService` do SCCM aceitava autenticação Entra e:
1. validava o token
2. extraía o `UPN`
3. construía `WindowsIdentity` com esse valor
4. fazia `s4u` / impersonation da identidade AD correspondente

O problema:
- a validação do token estava boa
- a autorização sobre *quem aquele UPN podia representar localmente* era o buraco

### O abuso

Com manipulação criativa de `UPN`, o atacante consegue:
- ter token Entra válido
- com `UPN` que resolve para identidade privilegiada local
- e o `AdminService` executa em nome dessa identidade

O post destaca especialmente o caso do `site server`:
- máquina com `implicit UPN`
- sincronização híbrida
- criação de usuário em Entra/AD com o UPN certo
- alteração posterior do UPN para forçar a resolução cair na conta certa

### O que isso ensina

Validação criptográfica do token não resolve sozinha.

Perguntas certas:
- o `claim` autenticado mapeia para quem localmente?
- existe ambiguidade em `UPN`, `implicit UPN`, `explicit UPN`, `sAMAccountName`?
- o serviço valida "token válido" e depois assume "identidade autorizada" sem amarração extra?

Esse é um padrão forte para enterprise integrations:
- cloud identity validated
- local identity derived
- derivação vira a vulnerabilidade

### Lição forte

`validated token` != `safe impersonation target`

Esse é um raciocínio muito reaproveitável fora de SCCM.

## 5. O padrão comum dos quatro artigos

Todos eles são variantes da mesma fórmula:

### a) Integração é boundary, não detalhe

- app registration
- service principal
- Seamless SSO
- trust creation
- DNS forwarder
- UPN mapping
- AdminService

Nada disso é "só plumbing".
Isso é superfície de segurança.

### b) O objeto mais perigoso às vezes não é humano

Exemplos:
- `service principal`
- `AZUREADSSOACC$`
- `site server machine account`
- trust account / TDO-related objects

Para nossa caça, isso é ótimo:
- olhar só para usuário humano deixa metade do ataque path passar.

### c) O melhor achado não é "privilégio alto visível"

É:
- permissão intermediária
- fluxo legítimo
- mapeamento implícito
- replicação de confiança
- emissão de nova identidade

Esse tipo de cadeia é o que mais parece "baixo nível operacional"
e o que mais vira `high/critical` quando você fecha até o fim.

## 6. Como isso muda o workspace na prática

### Em cloud / enterprise

Antes de encerrar uma investigação, forçar estas perguntas:
1. quem controla credenciais de apps?
2. quem consegue emitir ou renovar identidade?
3. quem consegue criar trust/integração?
4. quem decide o mapeamento local de uma identidade validada?
5. qual identidade não-humana está no meio do fluxo?

### Em report

O jeito forte de escrever a cadeia é:
- `Principal A` controla `integration object B`
- `B` representa ou autentica como `identity C`
- `C` já possui ou pode ganhar `privilege D`
- `D` concede `tenant/domain/hierarchy compromise`

### Em hunting

Isso amplia os alvos prioritários:
- app registrations
- service principals
- sync/connectors
- trust builders
- admin APIs que convertem cloud identity em local execution
- UPN / claim / principal mapping

## 7. Fechamento da trilha SpecterOps

Depois desta segunda nota, a trilha SpecterOps já está boa em:
- trusts
- trust attributes
- SID filtering
- TGT delegation
- SSO cookies
- OAuth/device flows
- service principal abuse
- app role abuse
- UPN mapping abuse
- cloud-to-local identity bridging

Ainda falta, se quisermos fechar mais:
- aprofundar a trilha `AI/LLM`
- puxar artigos mais recentes de OpenGraph/collectors

Mas a parte `identity/trust/token/app-control-plane` já está bem acima de simples mapeamento.
