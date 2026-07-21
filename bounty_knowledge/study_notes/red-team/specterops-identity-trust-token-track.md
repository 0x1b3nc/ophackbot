# SpecterOps identity, trust and token track

Status: **2026-07-15**. Leitura focada de tres artigos prioritarios da trilha SpecterOps:
- `Good Fences Make Good Neighbors: New AD Trusts Attack Paths in BloodHound`
- `Requesting Entra ID Tokens with Entra ID SSO Cookies`
- `Azure Privilege Escalation via Azure API Permissions Abuse`

Base local:
- `bounty_knowledge/study_notes/red-team/source-html/specterops/good-fences.html`
- `bounty_knowledge/study_notes/red-team/source-html/specterops/entra-sso-cookies.html`
- `bounty_knowledge/study_notes/red-team/source-html/specterops/azure-api-permissions-abuse.html`

## Leitura agregada

Os tres artigos batem no mesmo ponto central:
- identidade nao e um atributo isolado;
- ela vira caminho de ataque quando entra em relacoes de `trust`, `token`, `role` e `control plane`;
- modelar a direcao correta dessas relacoes importa mais do que decorar uma unica tecnica.

Para o workspace, essa trilha melhora duas coisas:
1. como pensar impacto em escopo enterprise/cloud;
2. como descrever caminhos de abuso sem virar abstrato.

## 1. Trusts de AD: modelar a relacao certa importa

Do artigo `Good Fences Make Good Neighbors`:

### O problema que eles resolveram

O edge antigo `TrustedBy` em BloodHound era util, mas ruim para pathfinding preciso porque:
- nem toda relacao de trust e sempre abusavel;
- trusts entre florestas diferentes podem nao ser exploraveis por default;
- a direcao da relacao confundia o operador.

### A solucao deles

Eles quebraram esse modelo em edges mais precisos:
- `SameForestTrust`
- `CrossForestTrust`
- `AbuseTGTDelegation`
- `SpoofSIDHistory`

Licao forte:
- em vez de tratar trust como um binario `tem/nao tem`, eles separam:
  - a existencia da relacao;
  - o tipo de trust;
  - a direcao do abuso;
  - a configuracao que efetivamente libera o ataque.

### O que isso nos ensina

Quando estivermos olhando authz/graph/tenant/role:
- nao basta ver que existe relacao entre A e B;
- precisamos perguntar qual lado controla a configuracao;
- qual lado e fonte da verdade;
- qual lado realmente ganha acesso/abuso.

Isso e muito melhor do que escrever report do tipo:
- "existe trust entre sistemas"

O formato correto e mais perto de:
- "o trust existe, e esta configurado com a combinacao X/Y que destrava o abuso Z na direcao A -> B"

### Pontos tecnicos que merecem ficar na memoria

- `SameForestTrust` nao e igual a `CrossForestTrust`
- `SID filtering` muda a realidade do abuso
- `TGT delegation` muda a realidade do abuso
- `trustAttributes` pode divergir entre os dois lados do trust
- `Get-ADTrust` pode devolver leitura enganosa; valor bruto e direcao importam

Em termos de raciocinio, isso reforca uma regra:
- o controle real quase nunca esta no nome simpatico da feature; ele esta no atributo cru, na direcao e no boundary.

## 2. Cookie SSO da Entra como material de autenticacao

Do artigo `Requesting Entra ID Tokens with Entra ID SSO Cookies`:

### O ponto principal

Mesmo sem PRT, um host nao cloud-joined ainda pode render material util se o usuario estiver logado em recursos da Entra no browser.

O cookie destacado foi:
- `ESTSAUTHPERSISTENT`

Uso descrito:
- usar o cookie como prova de autenticacao dentro do fluxo OAuth 2.0 Authorization Code;
- pedir `authorization code`;
- trocar por `access token` e `refresh token`;
- usar isso para enumerar tenant e acessar recursos autorizados no contexto do usuario.

### Por que isso importa

Esse artigo ajuda a tirar o raciocinio de "token theft" do abstrato.
Ele mostra um encadeamento claro:
- browser SSO state
- cookie reutilizavel
- OAuth code flow
- tokens
- enumeracao do tenant

### O que fica de mais forte para nos

1. `session material` nao e so bearer token.
2. Cookie de SSO pode ser ponte para token real.
3. O boundary pratico pode depender do tipo de dispositivo:
   - cloud-joined / hybrid-joined
   - non cloud-joined
4. `Conditional Access Policies` ainda entram no jogo; o fluxo nao ignora CAP por magia.

### Traducao para hunting

Quando estivermos em programa enterprise com superfícies Entra/OAuth:
- procurar material de sessao reutilizavel;
- entender qual fluxo ele ainda alimenta;
- validar se isso atravessa restricao de dispositivo, IP ou CA;
- sempre separar:
  - material presente
  - material reaproveitavel
  - token efetivamente emitido
  - recurso efetivamente acessado

Essa separacao evita report inflado.

## 3. Azure API permissions abuse: caminho de escalation via service principal

Do artigo `Azure Privilege Escalation via Azure API Permissions Abuse`:

### O encadeamento central

O artigo mostra como uma combinacao de app roles pode virar escalation real.

Exemplo de cadeia descrita:
1. um service principal recebe `AppRoleAssignment.ReadWrite.All`
2. isso permite conceder a si mesmo outras API permissions
3. ele se concede `RoleManagement.ReadWrite.Directory`
4. com isso passa a gerir RBAC do tenant
5. e consegue se elevar ate `Global Admin`

### O ponto mais importante

O problema nao e uma unica permissao isolada fora de contexto.
O problema e a composicao:
- permissao de grant
- permissao de RBAC
- controle sobre o principal

Isso conversa diretamente com a nossa regra de workspace:
- nao tratar permissao solta como achado pronto;
- buscar caminho completo ate acao critica.

### O que fica para o nosso modelo mental

Quando estivermos auditando cloud/admin plane:
- perguntar quem consegue adicionar credencial a app/service principal;
- quem consegue conceder app roles;
- quem consegue manipular RBAC;
- quem controla ownership;
- onde PIM muda o estado real.

O artigo tambem reforca que:
- auditoria defensiva boa nao e so "quem e admin agora"
- mas tambem "quem consegue se tornar admin por relacao indireta"

## 4. O fio comum entre os tres artigos

Apesar de tratarem AD trust, Entra SSO cookie e Azure app roles, os tres artigos dizem a mesma coisa em niveis diferentes:

### a) O grafo manda mais que o objeto isolado

- trust sozinho nao basta
- cookie sozinho nao basta
- role sozinha nao basta

O que importa e a cadeia:
- qual objeto controla outro
- por qual fluxo
- em qual direcao
- sob quais condicoes

### b) A direcao do abuso e parte do achado

Nos trusts:
- quem confia em quem
- de qual lado o atributo vale

Nos tokens:
- quem emite
- quem aceita
- sob qual contexto de dispositivo/sessao

Nas app roles:
- quem consegue conceder
- quem recebe
- quem se torna administrador no final

### c) O boundary verdadeiro costuma estar escondido nos detalhes

Exemplos:
- `trustAttributes`
- `SID filtering`
- `TGT delegation`
- `ESTSAUTHPERSISTENT`
- `Authorization Code flow`
- `AppRoleAssignment.ReadWrite.All`
- `RoleManagement.ReadWrite.Directory`

Para o nosso trabalho, isso reforca:
- procurar o mecanismo concreto, nao a narrativa genérica.

## 5. Como aplicar isso no workspace

### Em programas enterprise/cloud

Antes de classificar algo como high/critical, tentar fechar:
1. objeto inicial controlado
2. relacao exata que ele possui
3. fluxo de abuso
4. objeto final atingido
5. acao final sensivel

### Em reports

Preferir escrever assim:
- `A controla B`
- `B permite conceder/emitir/assumir C`
- `C destrava D`
- `D leva a privilegio/tenant access/role assignment/token issuance`

Em vez de:
- `esta permissao pode talvez levar a mais acesso`

### Em estudos futuros

Esta trilha deve ser cruzada com:
- `active-directory-exploitation-cheatsheet.md`
- `mitre-attack-atomic-red-team.md`
- `bishopfox-research-map.md`

Especialmente para:
- `T1098 Account Manipulation`
- `T1552 Unsecured Credentials`
- token abuse
- trust abuse
- service principal abuse

## 6. O que vale aprofundar depois

Daqui, os proximos artigos da mesma linha que valem leitura profunda sao:
- `Azure Privilege Escalation via Service Principal Abuse`
- `Azure Seamless SSO: When Cookie Theft Doesn't Cut It`
- `Untrustworthy Trust Builders: Account Operators Replicating Trust Attack (AORTA)`
- `SCCM Hierarchy Takeover via Entra Integration`

## Status honesto

Esta nota ja sai do nivel de simples corpus map.
Ela consolida uma trilha tecnica real da SpecterOps e melhora o modelo mental do workspace para:
- trusts
- session material
- OAuth token abuse
- app-role-driven escalation

Ainda nao marca `DEEP` da SpecterOps inteira.
Mas marca uma leitura util e concreta de um bloco prioritario.
