# Bugcrowd — notas operacionais (workspace)

**Plataforma preferida** deste workspace (em vez de HackerOne como padrão).

## URLs e escopo

- Programa público: `https://bugcrowd.com/engagements/<slug>`
- Pesquisa: `https://bugcrowd.com/engagements?category=bug_bounty`
- Escopo: brief do programa + targets (domínios, apps, APIs, código-fonte se aplicável)
- Agregar escopos (com API token do usuário): [bbscope](https://github.com/sw33tLie/bbscope) — `bbscope bugcrowd ...`
- Dumps públicos de escopo: [bounty-targets-data](https://github.com/arkadiyt/bounty-targets-data) (Bugcrowd incluído)

## Ao iniciar programa Bugcrowd

1. Salvar policy/brief em `targets/<slug>/PROGRAM.md` ou `SCOPE.md`
2. Extrair in/out of scope, recompensas, tipos excluídos, headers obrigatórios
3. Registrar slug Bugcrowd em `WORKSPACE_STATE.md` ou no estado privado do operador

## Headers e identificação

Alguns programas exigem header de pesquisador (equivalente ao `X-HackerOne-*`).

- Ler o brief; se houver header obrigatório, documentar em `targets/<slug>/HEADERS.md`
- Usar em **todas** as requests de teste quando exigido

## Severidade e report

- Classificar com **Bugcrowd VRT** (Vulnerability Rating Taxonomy), não CVSS genérico
- Draft local: `targets/<slug>/report/BUGCROWD_REPORT_DRAFT.md`
- Campos típicos: título, VRT category, descrição, passos, impacto, PoC redigido, remediação
- Templates: [bountyplz](https://github.com/fransr/bountyplz) (suporta Bugcrowd)

## Diferenças vs HackerOne (lembrar)

| | Bugcrowd | HackerOne |
|---|----------|-----------|
| Escopo | Brief + targets no engagement | Policy + structured scope |
| Severidade | VRT | CVSS + weakness types |
| Duplicatas | Disclosures do programa | Hacktivity |
| API escopo | bbscope + token BC | H1 API / bbscope |

HackerOne continua válido se o usuário passar link `hackerone.com` — tratar como plataforma secundária.
