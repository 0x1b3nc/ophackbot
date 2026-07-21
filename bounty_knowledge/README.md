# Base de Conhecimento do Hackbot

Este pacote inclui apenas notas e sínteses próprias reutilizáveis. Os corpora
terceiros grandes devem ser instalados como dependências de conhecimento, não
versionados diretamente neste repositório.

## Incluído no kit

- `study_notes/`: sínteses por classe de bug e roteamento obrigatório.
- `BUGBOUNTY_STUDY_GUIDE.md`: currículo e metodologia de estudo.
- `BUGCROWD.md`: fluxo operacional para programas Bugcrowd.
- `TOOLCHAIN.md`: mapeamento de ferramentas por fase.
- `LESSONS_MOBILE_API_AUTH.md`: padrões reutilizáveis para mobile/API/auth.
- `techniques/`: técnicas próprias e checklists curtos.

## Fontes recomendadas para importar fora do Git

Use `scripts/import_knowledge_sources.sh` para clonar localmente, quando quiser:

- OWASP WSTG
- OWASP API Security
- OWASP ASVS
- OWASP MASTG
- OWASP Cheat Sheet Series
- PayloadsAllTheThings
- SecLists
- nuclei-templates
- Bugcrowd University
- Vulnerability Rating Taxonomy
- The Bug Hunter's Methodology
- CloudGoat
- ClaudeBrain

Essas fontes têm licenças e tamanhos próprios. Mantenha-as em
`external_knowledge/`, fora do pacote público, ou documente as licenças se
decidir versionar alguma delas.

## Regra de uso

Antes de plano, script, report, severidade ou próximo passo de hunting, leia:

1. `docs/OPERATING_RULES.md`
2. `bounty_knowledge/study_notes/INDEX.md`
3. `bounty_knowledge/study_notes/STUDY_MATERIAL_ROUTING.md`
4. As notas específicas da classe de bug
5. O `SCOPE.md` do alvo autorizado

O bot deve ser agressivo em raciocínio e cobertura, mas conservador em execução
ativa quando a policy não autorizar explicitamente tráfego pesado, brute force,
DoS, stress test, spam ou ações destrutivas.
