# Mobile MAUI banking API hunting

Origem: estudo operacional de um programa financeiro Intigriti em 2026-07-14. Nota generica; nao manter escopo, evidencias ou dados do alvo.

## Quando vale

Use esta nota quando o alvo tiver app Android/iOS bancario, Xamarin/.NET MAUI, APIs mobile com certificado cliente embarcado, login por PIN/Digipass/itsme, XS2A/PSD2, documentos, assinatura ou pagamentos.

Barra de report neste tipo de programa costuma ser alta: breach de dados confidenciais ou executar/alterar estado financeiro. Erro generico, stack trace, endpoint bootstrap e certificado publico no APK raramente bastam.

## Extracao util

1. Baixar APK/XAPK por fonte legitima.
2. Separar splits, principalmente `config.arm64_v8a.apk`.
3. Procurar `libassemblies.arm64-v8a.blob.so`.
4. Extrair assemblies .NET com ferramenta propria ou scripts MAUI.
5. Decompilar DLL principal com `ilspycmd`.
6. Mapear service clients e contratos antes de qualquer request.

Sinais importantes:

- `ServiceManager` ou equivalente define hosts/base paths.
- `BaseRestServiceAgent` revela convencao de rota, headers, retries, certificado cliente e tratamento de redirects.
- Classes `*.Contracts` revelam nomes reais de endpoints e propriedades JSON.
- `Security` pode carregar PFX/cer embarcado. Isso e material cliente publico por design ate provar uso indevido.

## Matriz de ataque

Prioridade de endpoints:

- account/list/balance/transaction;
- document/documentContent/paymentProof/archivedDocuments;
- payment create/start/sign/delete;
- payment limits, card limits, card replacement/status;
- signing/documentPackage/connective/itsme;
- onboarding/reidentification/contact info;
- XS2A session, consent, PIS/AIS payment instruction;
- Wero/Payconiq/wallet provisioning quando em escopo.

Para cada endpoint:

- no-auth;
- certificado publico de registro;
- sessao anonima legitima, se o programa permitir;
- A/B com contas proprias, quando houver conta;
- IDs aleatorios primeiro;
- IDs proprios depois;
- nunca enumerar IDs reais.

Stop imediato se retornar IBAN, conta, saldo, documento, telefone, email, endereco, session token, cookie de auth, consent ID, payment ID ou instrucao de pagamento que nao seja propria.

## Pre-auth que parece bug mas geralmente nao e

Respostas como estas normalmente sao erro funcional, nao finding:

- `wrongPincode: true`;
- `succeeded: false`;
- `locked: null`;
- `disabled: null`;
- `cookie: null`;
- validation problem sem dado de usuario;
- bootstrap app status/info publico.

Elas so viram lead se:

- diferenciam usuario existente vs inexistente;
- retornam cookie/token/chave;
- permitem lockout/estado em conta de terceiro;
- conectam com conta propria ate dados financeiros.

## XS2A/PSD2

XS2A sem sessao legitima costuma parar em gateway antes da validacao de negocio. Testes uteis e seguros:

- URL parser confusion apenas com hosts em escopo;
- userinfo, slash/backslash encoded, no-scheme, schemeless;
- follow redirect control;
- metodos auxiliares com GUID proprio/aleatorio;
- discovery publica de well-known/openapi somente low-rate.

Nao reportar se tudo volta `302` para gateway, `403` vazio, timeout ou body zero. Procurar apenas retorno de `xs2aSession`, `sessionToken`, `tppName`, consent scope, payment instruction, account list, IBAN, balance, transaction, consent ID ou payment ID.

## WebView/native bridge em apps bancarios

Ponto de alto valor se houver conversa/documentos/assinatura:

- JavaScript habilitado;
- file access ou universal access from file URLs;
- `addJavascriptInterface` ou bridge MAUI;
- `LoadDataWithBaseURL`;
- HTML gerado com `HtmlDecode` ou texto de usuario sem encoding;
- bridge com acoes `att#id`, `doc#id`, `documentPackage#id`;
- fluxo de signing ou abrir documento no contexto do usuario.

Isso ainda precisa de prova dinamica:

- servidor aceita HTML/JS bruto;
- mensagem/documento renderiza em app de outra conta propria;
- bridge executa acao no contexto da vitima;
- impacto chega a dado confidencial ou signing state.

Sem essa prova, e lead estatico, nao High/Critical.

## No-go honesto

Encerrar o programa se:

- nao ha conta/sessao legitima;
- app nao permite registro anonimo na pratica;
- endpoints de impacto alto retornam `403` vazio antes da validacao;
- XS2A depende de sessao/gateway indisponivel;
- o unico material restante e stack trace, header, TLS, CORS ou bootstrap publico.

Antes de apagar, salvar no workspace apenas o metodo reutilizavel e remover artefatos do alvo.
