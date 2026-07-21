# MITRE ATT&CK + Atomic families

Data: 2026-07-15.

Escopo desta nota:
- aprofundar as familias pedidas no backlog;
- cruzar MITRE Enterprise local com YAMLs Atomic locais;
- registrar uso como linguagem de impacto e validacao em lab.

Base local:
- `red-team/source-crawls/mitre-enterprise-attack.json`
- `bounty_knowledge/red-team/atomic-red-team/atomics/`

Familias consolidadas:
- `T1552` Unsecured Credentials
- `T1098` Account Manipulation
- `T1078` Valid Accounts
- `T1550` Use Alternate Authentication Material
- `T1021` Remote Services
- `T1484` Domain or Tenant Policy Modification

## T1552 - Unsecured Credentials

MITRE: credenciais inseguras em arquivos, registros, historico, chaves privadas, metadata cloud, GPP, Kubernetes secrets.

Atomic local confirmou subtecnicas:
- `T1552.001` Credentials in Files
- `T1552.002` Credentials in Registry
- `T1552.003` Bash History
- `T1552.004` Private Keys
- `T1552.005` Cloud Instance Metadata API
- `T1552.006` Group Policy Preferences
- `T1552.007` Kubernetes List Secrets

Uso em report:
- bom para explicar impacto de leaked secret, metadata exposure, bucket/artefato com chave, kube token ou historico sensivel;
- nao precisa executar lateral movement para provar risco se a credencial tem escopo alto demonstravel.

## T1098 - Account Manipulation

MITRE: modificar contas, roles, credenciais adicionais, delegacoes ou permissoes para manter/elevate acesso.

Atomic local confirmou:
- additional cloud credentials;
- additional email delegate permissions;
- additional cloud roles;
- SSH authorized keys;
- user/service principal em roles Azure/AWS/GCP.

Uso em bounty/enterprise:
- role assignment indevido;
- API token criado por papel baixo;
- owner/admin lockout;
- service principal adicionado a role;
- mailbox delegation ou org-wide delegate.

Conecta diretamente com nossa regra de write-path first.

## T1078 - Valid Accounts

MITRE: abuso de contas validas para acesso inicial, persistencia, privilegio ou evasao.

Atomic local confirmou:
- default accounts;
- local accounts;
- cloud accounts.

Uso em report:
- conta valida nao reduz impacto automaticamente;
- se uma falha permite usar conta legitima fora do boundary esperado, isso ainda e impacto;
- mapear sempre role, tenant, projeto, org e recursos alcancados.

## T1550 - Use Alternate Authentication Material

MITRE: uso de hashes, tickets, tokens ou material alternativo de autenticacao.

Atomic local confirmou:
- pass the hash;
- pass the ticket.

Uso seguro:
- em bounty web/cloud, traduzir para tokens, session material, API keys, refresh tokens e signed cookies;
- foco em provar que material alternativo bypassa controle esperado, sem roubar token real de terceiros.

## T1021 - Remote Services

MITRE: uso de servicos remotos com contas validas.

Atomic local confirmou:
- RDP;
- SMB/Admin Shares;
- DCOM;
- SSH;
- VNC;
- WinRM.

Uso em report:
- bom para consequencia de credencial/role comprometida em programa enterprise;
- nao usar como severidade isolada em web bounty se nao houver alcance real a servico remoto em escopo.

## T1484 - Domain or Tenant Policy Modification

MITRE: modificacao de politica de dominio/tenant, GPO, trust, federation.

Atomic local confirmou:
- Group Policy Modification;
- Domain Trust Modification;
- Federation em Azure AD.

Uso em report:
- categoria forte para High/Critical quando falha permite alterar policy central, federation, trust, tenant-wide controls ou GPO;
- conecta com SpecterOps AORTA, SCCM/Entra e service principal abuse.

## Matriz de uso no workspace

Para cada finding enterprise/cloud:
1. Identificar tecnica MITRE aplicavel.
2. Confirmar se ha Atomic local para validar em lab.
3. Usar MITRE como linguagem de consequencia, nao como substituto de prova.
4. Em alvo real, provar menor efeito seguro possivel.

## Regras novas/reforcadas

- `T1098` e `T1484` sao as familias mais fortes para authz write-path.
- `T1552` e `T1550` explicam impacto de tokens/secrets melhor que "info disclosure" generico.
- `T1078` e `T1021` so elevam severidade quando o alcance real foi demonstrado por boundary autorizado.

## Status

MITRE/Atomic deixa de ser so dump/indice e passa a ter familias prioritarias consolidadas.
