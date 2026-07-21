# MITRE ATT&CK + Atomic Red Team

Status: **mapeado 2026-07-15** com base em dados locais estruturados; nao e leitura completa de cada tecnica.

Base local:
- `bounty_knowledge/study_notes/red-team/source-crawls/mitre-enterprise-attack.json`
- `bounty_knowledge/study_notes/red-team/source-crawls/mitre-techniques.csv`
- `bounty_knowledge/study_notes/red-team/source-crawls/mitre-platform-counts.csv`
- `bounty_knowledge/study_notes/red-team/source-crawls/mitre-tactic-counts.csv`
- `bounty_knowledge/study_notes/red-team/source-crawls/mitre-family-summary.tsv`
- `bounty_knowledge/red-team/atomic-red-team/`

## O que foi confirmado localmente

MITRE ATT&CK Enterprise:
- `858` attack patterns totais
- `365` tecnicas top-level
- `493` subtecnicas
- `15` taticas
- `729` malwares
- `95` tools
- `268` mitigations

Atomic Red Team local:
- `341` diretorios de tecnica em `atomics/`
- `356` arquivos YAML
- `740` IDs MITRE distintos referenciados nos YAMLs

Top plataformas do dump Enterprise:
- `Windows`: 591
- `macOS`: 441
- `Linux`: 419
- `ESXi`: 121
- `IaaS`: 112
- `Network Devices`: 105
- `PRE`: 96
- `Office Suite`: 83
- `SaaS`: 76
- `Identity Provider`: 51
- `Containers`: 50

Top taticas por volume:
- `stealth`: 212
- `persistence`: 167
- `privilege-escalation`: 126
- `execution`: 89
- `credential-access`: 80
- `defense-impairment`: 56
- `command-and-control`: 55
- `discovery`: 50
- `resource-development`: 50
- `reconnaissance`: 46

## O que isso significa de verdade

### 1. ATT&CK e linguagem de comportamento, nao checklist de severidade

Erro comum:
- achar que citar um `Txxxx` automaticamente eleva o report.

Uso correto:
- mostrar que a falha provada suporta uma tecnica ou subtecnica real;
- usar isso para explicar cadeia de impacto, cobertura defensiva e prioridade.

Exemplo mental:
- segredo exposto -> `T1552 Unsecured Credentials`
- manipulacao de conta/role -> `T1098 Account Manipulation`
- abuso de token -> familia de roubo/uso indevido de credenciais e autenticacao
- relay ou pivot para outro ambiente -> lateral movement ou valid accounts, se realmente provado

### 2. Atomic Red Team vale como ponte entre abstracao e reproducao

O valor do Atomic nao e "rodar em alvo". O valor e:
- transformar tecnica ATT&CK em acao observavel;
- entender prerequisitos, entradas, artefatos e impacto esperado;
- montar lab proprio para validar como uma tecnica se parece.

Para nosso workspace:
- ATT&CK explica **o que** uma falha habilita;
- Atomic ajuda a visualizar **como** isso se manifesta num ambiente controlado;
- bounty report continua preso ao que o escopo permite e ao que foi provado no alvo.

### 3. O dump mostra para onde o ecossistema se expandiu

O ATT&CK Enterprise local nao esta concentrado so em Windows/AD.
Os campos de plataforma deixam claro que hoje o modelo cobre:
- cloud/IaaS;
- SaaS;
- identity provider;
- containers;
- ESXi;
- network devices;
- O365/office-like surfaces.

Conclusao pratica:
- quando pegarmos programa enterprise moderno, authz/token/SCIM/SSO/API/admin plane merecem o mesmo peso que "host vuln" tradicional.

## Familias que mais interessam para bounty/enterprise

Para nosso tipo de caca, as familias abaixo costumam ter melhor traducao para falhas reais:

### Credenciais e identidade
- `T1552` Unsecured Credentials
- `T1550` Use Alternate Authentication Material
- `T1078` Valid Accounts
- `T1098` Account Manipulation
- `T1110` Brute Force, quando explicitamente permitido

### Escalacao e persistencia de privilegio
- `T1068` Exploitation for Privilege Escalation
- `T1484` Domain or Tenant Policy Modification
- ACL, role, delegation e trust abuse quando encaixarem nas tecnicas correspondentes

### Descoberta e movimento lateral
- `T1016` System Network Configuration Discovery
- `T1018` Remote System Discovery
- `T1021` Remote Services
- tecnicas de trusts, sync, connector, graph, collector e admin-plane quando provadas

### Coleta, exfiltracao e impacto
- `T1005` Data from Local System
- `T1020` Automated Exfiltration
- `T1537` Transfer Data to Cloud Account
- `T1499` e afins so quando o escopo permitir testes desse tipo

## Como usar isso no nosso fluxo

### Durante a caca

Usar ATT&CK para responder:
- se eu provar essa falha, qual tecnica ela realmente suporta?
- isso da leitura, alteracao, pivoteamento, persistencia ou coleta?
- qual e o passo minimo seguinte que ainda cabe no escopo?

### Durante o report

Usar ATT&CK para fortalecer:
- linguagem de impacto;
- cadeia de abuso;
- prioridade para triage tecnica.

Nao usar ATT&CK para:
- inflar severidade sem prova;
- substituir PoC;
- chamar de `critical` algo que continua hipotetico.

### Durante estudo/lab

Usar Atomic Red Team para:
- reproduzir a tecnica com seguranca;
- entender telemetria e artefatos;
- ganhar repertorio de pos-exploit sem improviso.

## Regras operacionais para o workspace

- ATT&CK/Atomic entram como **material de raciocinio e lab**.
- Em alvo real, aplicar apenas o que a policy permitir.
- Se a tecnica exigir phishing, malware, persistence, credential dumping ou movimento lateral agressivo fora de escopo, fica restrita ao estudo.
- Em programas enterprise com permissao explicita, essa base vira referencia prioritaria.

## Proximos aprofundamentos de maior valor

1. Ler por familias relevantes ao nosso uso, nao por ordem numerica:
   - `T1552`, `T1098`, `T1078`, `T1550`, `T1021`, `T1484`
2. Cruzar essas familias com:
   - a nota de AD ja profunda;
   - BloodHound/SpecterOps;
   - roles/tokens/trusts em SaaS e cloud.
3. Criar mini-matrizes locais:
   - tecnica -> tipo de bug bounty que pode provar aquilo
   - tecnica -> evidencia minima necessaria
   - tecnica -> o que fica proibido sem autorizacao de escopo

## Status honesto

Esta nota fecha o uso operacional do corpus local de ATT&CK/Atomic.

Ainda falta:
- leitura profunda de familias selecionadas;
- leitura de YAMLs Atomics de maior valor;
- criar mapas locais por `token`, `role`, `trust`, `credential`, `SaaS` e `identity provider`.
