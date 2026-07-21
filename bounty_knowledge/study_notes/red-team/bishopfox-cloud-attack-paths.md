# Bishop Fox cloud attack paths

Data: 2026-07-15.

Escopo desta nota:
- consolidar o subbloco Bishop Fox sobre cloud attack paths;
- focar em como eles modelam relacoes, heranca, data plane e caminho transitive de abuso;
- registrar o que muda nosso raciocinio para cloud/enterprise.

Artigos lidos nesta nota:
- `Introducing CloudFox GCP: Attack Path Identification for Google Cloud`
- `Inside Cirro: Attack Paths, Cloud Graphs, and Extensible Schemas`
- `Azure Hacking: New Cloudfoxable Challenges`

Arquivos-fonte locais:
- `red-team/source-html/bishopfox/introducing-cloudfox-gcp-attack-path-identification-for-google-cloud.html`
- `red-team/source-html/bishopfox/inside-cirro-attack-paths-cloud-graphs-and-extensible-schemas.html`
- `red-team/source-html/bishopfox/azure-hacking-new-cloudfoxable-challenges.html`

## Ideia central

O ponto comum dos tres textos e:

- risco em cloud quase nunca mora num objeto isolado;
- ele aparece na cadeia entre identidade, escopo, heranca, recurso, secret, token, rede e data plane;
- por isso, inventario sem grafo ou sem path analysis enxerga menos do que deveria.

## 1. CloudFox GCP

Pontos centrais do artigo:
- GCP tem uma heranca forte de IAM: `Organization -> Folders -> Projects -> Resources`.
- Um binding permissivo alto pode se propagar para muito mais superficie do que parece.
- O artigo destaca riscos que importam mesmo para bounty/enterprise:
  - service account proliferation;
  - cross-project trust;
  - metadata service em `169.254.169.254`;
  - domain-wide delegation;
  - buckets publicos;
  - workload identity mal configurada.
- O foco declarado da ferramenta nao e compliance, e sim pergunta ofensiva:
  - o que essa identidade faz;
  - onde existe escalacao;
  - onde existe lateral;
  - onde ha exfiltracao plausivel.

Chains exemplificados no proprio artigo:
- `compute compromise -> metadata token -> service account impersonation -> privileged account`
- `dev project access -> shared VPC / cross-project permissions -> production pivot`
- `temporary bucket -> allUsers -> unauthenticated sensitive data exposure`

O que muda no nosso metodo:
- Em cloud, nao parar em "tem permissao X". Perguntar sempre:
  - em qual escopo;
  - herdada de onde;
  - com qual identidade intermediaria;
  - levando a qual recurso final.
- Public bucket e metadata service nao sao issues soltas. Sao vertices de cadeia.

## 2. Cirro

Pontos centrais do artigo:
- Cirro parte da tese de que attack path = relacao, nao objeto.
- Ele junta management plane com data plane.
- O exemplo-chave e forte:
  - usuario -> grupo -> RBAC -> recurso/VM -> managed identity -> Key Vault role -> Key Vault -> secret -> app downstream.
- O artigo mostra que isso vai alem de "quem administra o recurso":
  - inclui segredo, certificado, relacionamento com app, e possibilidade de ambientes dev/QA/staging/prod reutilizarem a mesma identidade.
- Outro ponto importante: o grafo nao precisa modelar perfeitamente todo recurso para preservar reachability e scope.

O que muda no nosso metodo:
- Em Azure/Entra, path valido pode incluir:
  - RBAC management plane;
  - data plane access;
  - secret correlation;
  - workload identity;
  - reutilizacao indevida da mesma app identity entre ambientes.
- Isso conversa diretamente com o que ja vimos na SpecterOps:
  - problema nao e so permissao "alta";
  - problema e permissao encaixada numa cadeia de trust e mapeamento.

## 3. Azure Hacking: New Cloudfoxable Challenges

Valor real deste artigo no estudo:
- menos tecnico que os outros dois;
- funciona mais como hub para treino/lab da linha CloudFoxable.

Mesmo assim, serve para uma regra util:
- antes de aplicar heuristica agressiva em ambiente real, validar o raciocinio de attack path em lab controlado.

## Regras que entram no workspace

### A. Cloud = path first

Nao tratar cloud finding como lista de misconfigs soltas.

Perguntas minimas:
- qual identidade inicial?
- qual heranca/escopo faz a permissao valer?
- qual token/secret/metadata pode ser obtido?
- qual recurso seguinte essa identidade alcanca?
- o caminho termina em dado, role alta ou execucao?

### B. Management plane sem data plane e visao parcial

Se so enxergarmos RBAC e ARM/API administrativa, perdemos:
- secrets;
- certificates;
- app credentials;
- storage data exposure;
- service-to-service reachability.

### C. Ambiente baixo pode matar ambiente alto

O exemplo de Key Vault/App identity e o chain de dev -> prod do CloudFox GCP reforcam uma regra importante:
- menor ambiente nao significa menor impacto se ele compartilha identidade, rede ou trusted path com producao.

### D. Metadata service e impersonation sao pivots, nao curiosidades

Sempre que aparecer:
- metadata endpoint;
- managed identity;
- service account impersonation;
- domain-wide delegation;
- workload identity binding;

tratar como potencial inicio de attack path, nao como finding isolado.

## Como isso se conecta ao que ja estudamos

- Com SpecterOps:
  - bate forte em trust boundaries, app identities e abuse de objeto nao-humano.
- Com a regra nova de authz em writes:
  - cloud tambem exige teste state-changing, so que em roles, grants, bindings, secrets e token issuance.
- Com MITRE/Atomic:
  - ajuda a mapear melhor `T1078`, `T1098`, `T1550`, `T1552` e movimentos entre identidade e recurso.

## Uso pratico no workspace

Quando o escopo permitir cloud/enterprise:

1. enumerar identidade, escopo e heranca;
2. mapear recursos com secret/token/metadata/value;
3. procurar chains entre ambiente fraco e ambiente forte;
4. procurar reuse de identities entre dev/qa/staging/prod;
5. provar impacto no menor passo seguro possivel.

## Status

Com esta nota, Bishop Fox deixa de estar so "mapeado" e passa a ter dois blocos consolidados:
- metodo moderno geral;
- cloud attack paths.

Ainda falta para ampliar a fonte:
- advisories tecnicos selecionados;
- posts adicionais de AI/MCP;
- cloud tooling especifico por provider em maior profundidade.
