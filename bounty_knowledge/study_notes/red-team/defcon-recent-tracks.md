# DEF CON recent tracks

Data: 2026-07-15.

Escopo desta nota:
- aprofundar DEF CON alem do mapa estrutural;
- usar edicoes recentes `31`, `32` e `33`;
- classificar materiais por trilha util ao workspace.

Base local:
- `source-html/defcon/dc-31-archive.html`
- `source-html/defcon/dc-32-archive.html`
- `source-html/defcon/dc-33-archive.html`
- `source-html/defcon/dc-31-presentations.html`
- `source-html/defcon/dc-32-presentations.html`
- `source-html/defcon/dc-33-presentations.html`
- `source-html/defcon/dc-31-villages.html`
- `source-html/defcon/dc-32-villages.html`
- `source-html/defcon/dc-33-villages.html`
- `source-html/defcon/dc-31-workshops.html`
- `source-html/defcon/dc-32-workshops.html`
- `source-html/defcon/dc-33-workshops.html`

## Estrutura confirmada

As edicoes recentes preservam:
- archive principal;
- presentations;
- villages;
- workshops;
- program;
- CTF/materials quando disponivel;
- slides, videos e extras.

DEF CON 33 ainda tinha algumas seções de video/CTF comentadas no archive principal, mas presentations/workshops estavam listaveis.

## Trilhas de maior valor encontradas

### Web / AppSec / race / parsing

Materiais relevantes vistos:
- James Kettle sobre race conditions e state machines;
- Gareth Heyes sobre parser/email access-control bypass;
- talks sobre browser/local network scanning;
- PHP/glibc/iconv/RCE research.

Conexao com nossas notas:
- reforca `race-conditions.md`;
- reforca parser differential e input normalization;
- reforca que impacto vem de estado real, nao payload isolado.

### Cloud / CI/CD / identity

Materiais relevantes vistos:
- GitHub Actions runner abuse;
- OIDC ate cloud;
- AWS public AMI secrets;
- Cloud REST API workshop;
- Kubernetes workshop;
- Teams/SharePoint integrity;
- NTLM, Windows Hello e AD/GPO talks.

Conexao:
- cruza com SpecterOps, Bishop Fox cloud e MITRE `T1098/T1484/T1552`.
- em bounty, priorizar CI/CD, OIDC, service identities, runners e artifact stores quando em escopo.

### AI / LLM / agentic

Materiais relevantes vistos:
- Llama 3 red team process;
- LLM extracting IoCs;
- secure coding with personal LLM assistant;
- adversarial simulation com voice cloning.

Conexao:
- valida que AI security precisa de workflow, dados e toolchain;
- confirma OffSec/Bishop Fox: nao e so prompt.

### Supply chain / secrets / public artifacts

Materiais relevantes vistos:
- GitHub Actions dependency tree;
- public AMI secrets;
- supply chain em surveillance systems;
- XZ-like supply-chain relevance via OffSec.

Uso:
- quando programa permite leaked credentials/public artifacts, olhar repos, images, AMIs, packages, CI logs e build artifacts.

### Hardware / firmware / mobile

Materiais relevantes vistos:
- Android source/runtime;
- prepaid Android carrier devices;
- Pixel modem;
- iOS/macOS ecosystem;
- firmware/BMC/SoC/EMMC;
- RF/Bluetooth/OSDP/IoT.

Uso:
- bom para programas mobile/hardware;
- em web bounty comum, serve como repertorio e nao prioridade.

## Regra de uso

DEF CON deve ser usado como biblioteca por trilha:
1. escolher tema;
2. pegar slides/extras primeiro;
3. transformar em hipotese testavel;
4. validar em lab ou escopo permitido;
5. registrar no report apenas o que foi comprovado no alvo.

## Status

DEF CON deixa de estar apenas mapeado e passa a ter trilhas recentes consolidadas.
