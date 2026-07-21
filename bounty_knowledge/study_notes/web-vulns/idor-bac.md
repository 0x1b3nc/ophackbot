# IDOR / BAC / BOLA / BFLA / Mass Assignment (DEEP STUDY)

Status: **deep study 2026-07-12** (nao esqueleto).  
Nivel tipico de teste: **2**.

## Log do que foi lido nesta sessao

| Fonte | O que absorvi |
|-------|----------------|
| PortSwigger Access control (pagina principal) | Vertical vs horizontal vs context-dependent; parameter-based role; X-Original-URL; Referer ACL; multi-step; IDOR como subclasse |
| PortSwigger IDOR | IDOR = input aponta objeto direto sem authz; DB index; static files (`/static/12144.txt`) |
| Lab: IDOR (chat transcripts) | Transcripts em arquivos incrementais; `1.txt` vaza password do carlos |
| Lab: User ID in request param | Conta `wiener` → troca `id=carlos` → API key |
| Lab: Multi-step no ACL on one step | Admin promote tem step sem authz; replay com cookie de user comum promove a si |
| OWASP API1:2023 BOLA | Endpoint autorizado por design; falha e no **objeto**; so comparar session.userId com param e insuficiente; vs BFLA |
| OWASP API3:2023 | Excess exposure + mass assignment no nivel de **property** |
| WSTG-APIT-02 BOLA | A/B accounts; GET/PUT/PATCH/DELETE; GraphQL args; bulk list |
| WSTG-APIT-04 BFLA | Admin functions com user comum; metodos HTTP alternativos |
| WSTG-ATHZ-04 IDOR | Quatro cenarios: DB record, operacao (changepassword?user=), file, menu/functionality |
| WSTG-ATHZ-02 Bypass authz schema | Forced browse; horizontal A/B session swap; admin functions |
| HackTricks IDOR | Params em path/query/body/header; enum seq; oracle de erro; cases McHire (64M PII) e wristband QR (ID=bearer) |
| Vickie Li "How to find more IDORs" | Encoded/hash IDs; leak ID via outro endpoint; oferecer ID mesmo sem pedir; HPP; blind IDOR; trocar metodo/file type; priorizar reset/DM; chain write-IDOR+self-XSS |
| Bugcrowd University BAC PDF (33p, Haddix) | IDOR vs MFLAC; numeric/POST/UUID/hash/encoded; UUID leak via email→UUID ou mobile API; PUT updateEmail; Autorize/AuthMatrix/AutoRepeater; VRT depende do impacto da funcao |
| PAT Mass Assignment + OWASP Mass Assign CS | Bind ORM cego (`isAdmin`); Rails/Django/Laravel/Spring |
| VRT local JSON | IDOR sensitive iterable modify/view ate P1; UUID complex tipico P4; view non-sensitive P5 |
| Caso padrao read-only bypass | Nao e IDOR cego de UUID; e BAC de **nivel** (READ executa WRITE). `isReadonly:true` mentiroso |

## O que e (modelo mental unico)

Tres eixos que misturam na pratica:

1. **BOLA / IDOR (objeto):** voce pode chamar a funcao, mas troca o ID e mexe no objeto alheio.
2. **BFLA / MFLAC (funcao):** voce nao deveria poder chamar a funcao (admin/promote/deleteUser).
3. **Property-level (API3):** le campo sensivel demais na response **ou** escreve campo que o form nao expoe (mass assign).

PortSwigger ainda soma:
- **Vertical** (privilegio)
- **Horizontal** (mesmo papel, outro dono)
- **Context-dependent** (ordem do fluxo / multi-step)

OWASP API1 deixa claro: se o user **nao deveria** ter o endpoint, e BFLA; se deveria ter o endpoint mas nao aquele objeto, e BOLA.

## Onde procurar (checklist operacional)

### Identificadores
- Path/query/body/GraphQL: `id`, `user_id`, `order_id`, `workspaceId`, `lead_id`, `vin`, `reportKeys`
- Headers/cookies: `X-Client-ID`, IDs em JWT claims usados como "prova de ownership"
- Arquivos estaticos / transcripts / downloads (`?id=`, `/static/N.txt`)
- Encoded/hash/UUID: decode; checar se so parte e random; achar oracle que traduz email→UUID (Haddix)

### Funcoes
- Reset/change password, change email, delete, promote, export, download
- Admin so escondido na UI (forced browse / JS leak de URL)
- GraphQL mutations com IDs

### Properties
- Response com PII extra (location, tokens)
- Body extra: `isAdmin`, `role`, `price`, `accessLevel`, `approved`

## Tecnicas (alem de "decrementar ID")

Da Vickie Li + Haddix + HackTricks + labs:

1. **Dois usuarios A/B** (WSTG): criar objeto na A, atacar com sessao B. Mais barato que adivinhar.
2. **Metodo HTTP:** GET↔POST↔PUT↔PATCH↔DELETE (ACL muitas vezes so em um).
3. **File type:** acrescentar `.json` / Accept diferente.
4. **Oferecer ID sem o app pedir:** `GET /messages?user_id=`
5. **HPP:** duplicar param / arrays.
6. **Blind IDOR:** efeito em email, export, job async (nao no body).
7. **Multi-step:** ACL no step 1, falha no confirm (lab PortSwigger).
8. **Referer / platform ACL:** forjar Referer; `X-Original-URL` se proxy filtra path.
9. **UUID nao e mitigacao:** se o UUID vaza (share link, list endpoint, mobile verbose), vira bearer. Encoding hex/base64 **nao** adiciona entropia (caso wristband).
10. **Nivel de permissao vs objeto:** UI/API diz READ/`isReadonly`; mutate ainda 200. Testar **upload/PATCH** sempre que share for "view".
11. **GraphQL batch/multi-object BOLA:** em mutations que recebem `ids`, `items`, `nodes` ou `input[]`, misturar objetos autorizados e nao autorizados no mesmo request. Falha comum: resolver valida ownership do primeiro ID e aplica a operacao no lote inteiro.

### Regra fixa nova: write-path first, nao so read-path

Observacao operacional que passa a valer sempre:
- parar de tratar IDOR/BOLA como teste de `GET` apenas;
- o dinheiro costuma estar em mutacoes de estado:
  - `PATCH`
  - `PUT`
  - `DELETE`
  - `POST` sensivel
  - GraphQL `mutation`

Racional:
- times costumam proteger melhor `read access`;
- esquecem o mesmo check de objeto ou de role nos endpoints de `write/update/delete`.

Matriz minima por operacao:
1. trocar o ID do objeto (`BOLA`)
2. trocar a sessao/role (`BFLA`)
3. trocar os dois juntos
4. em arrays/lotes: `A_owned + B_owned` e `B_owned + A_owned` para ver se a ordem muda o resultado

Prioridade pratica:
- nao perguntar so `A consegue ler B?`
- perguntar tambem:
  - `A consegue alterar B?`
  - `A consegue apagar B?`
  - `A consegue travar B?`
  - `A consegue subir/rebaixar role de B?`
  - `A consegue mudar lifecycle, recovery, ownership ou settings de B?`

Esse encadeamento `BOLA + BFLA` numa mutation unica e especialmente forte.

## Como confirmar (PoC minimo)

1. Contas proprias A (owner) e B (attacker).
2. A cria recurso; anota ID.
3. B tenta read **e** write no mesmo ID (e metodos alternativos).
4. Controle: recurso privado / ACCESS_NONE → 401/403/404.
5. Evidencia: body ou side-effect na conta A (arquivo sobrescrito, email mudado, etc.).
6. Nao precisa Intruder de milhoes em bounty com rate-limit OOS; A/B basta para authz.

Ferramentas (nivel 2): Burp Repeater + **Autorize** / AuthMatrix / AutoRepeater (Haddix). Intruder/ffuf so se IDs previsiveis **e** policy permitir enum (cuidado nivel 2 alto / 3).

## Impacto e severidade

### VRT (Bugcrowd, JSON local)
- Modify/view sensitive, IDs **iteraveis**: ate **P1**
- View sensitive iterable: **P3**
- Modify/view sensitive, GUID/UUID complexo: baseline **P4** (triage sobe com impacto claro / write)
- View non-sensitive: **P5**
- Haddix: payout segue **o que a funcao faz** (financeiro > chato)

### H1 / CVSS
- Weakness: Improper Access Control - Generic (ou IDOR)
- Write sob "Can view": I:High, PR:Low → ~6.5–7.1

### Encadear (Vickie)
- Write-IDOR em campo XSS-able → stored XSS dirigido
- IDOR reset/password/email → ATO (pior que IDOR de settings)

## Padrao read-only bypass

| Modelo classico | Caso read-only bypass |
|-----------------|-------|
| Trocar ID sequencial | UUID do share (intencional para viewers) |
| BOLA puro | Parcial: B acessa objeto da A |
| Diferenca real | Enforcement de **ACCESS_LEVEL_READ** falha em `files/upload` apesar de `isReadonly:true` |
| Licao | Sempre testar mutate quando o produto declara read-only / Can view / clone-to-edit |

## Nivel de agressividade

- A/B puntual: **2**
- Enum sequencial larga / Intruder 100k+: so com policy clara.
- Brute de UUID v4 full space: inutil; precisa leak do UUID

## Remediation (para report)

- Check de ownership **e** de capability (READ vs WRITE) em todo handler
- Nao confiar em UI / `isReadonly` client-side
- UUID ajuda contra enum, nao substitui authz
- Allowlist de properties no bind (mass assign)
- Testes automatizados A/B por endpoint novo (OWASP API1)

## Fontes (lidas de verdade nesta deep session)

- https://portswigger.net/web-security/access-control
- https://portswigger.net/web-security/access-control/idor
- https://portswigger.net/web-security/access-control/lab-insecure-direct-object-references
- https://portswigger.net/web-security/access-control/lab-user-id-controlled-by-request-parameter
- https://portswigger.net/web-security/access-control/lab-multi-step-process-with-no-access-control-on-one-step
- https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/
- `API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization.md`
- WSTG APIT-02, APIT-04, ATHZ-02, ATHZ-04 (paths locais)
- `hacktricks/src/pentesting-web/idor.md`
- https://medium.com/@vickieli/how-to-find-more-idors-ae2db67c9489
- Bugcrowd University BAC PDF → extract em `study_notes/_raw/bugcrowd_univ_bac_extract.txt`
- `PayloadsAllTheThings/Mass Assignment/README.md`
- `CheatSheetSeries/cheatsheets/Mass_Assignment_Cheat_Sheet.md`
- `vulnerability-rating-taxonomy/vulnerability-rating-taxonomy.json` (nos BAC/IDOR)
- Casos internos privados nao devem ser versionados no repositorio publico.

## Proxima deep session sugerida

**SSRF** (PortSwigger full + bypasses + lab solutions + PAT SSRF + Bugcrowd University SSRF PDF) — uma classe, mesmo rigor.
