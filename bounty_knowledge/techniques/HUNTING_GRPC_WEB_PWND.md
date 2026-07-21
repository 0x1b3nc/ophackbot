# Hunting gRPC-Web endpoints — estudo

- Fonte: https://pwnd.blog/article/hunting-grpc-web-endpoints
- Autor: @reeshasx (bolhasec)
- Data: 2026-07-12

## Por que importa neste workspace

- Técnica High: IDOR em APIs binárias que Burp/FFUF não enxergam.
- `grpcurl` / `grpcui` **não** servem para gRPC-Web (HTTP/1.1 encapsulado); usar **curl --data-binary**.
- Checklist operacional abaixo + texto completo do artigo.

## Checklist operacional (resumo)

1. Miner JS: `Service/Method` → `POST /api.{Service}/{Method}`
2. APK: jadx + `application/grpc`
3. Frame vazio: `printf '\x00\x00\x00\x00\x00' > empty.bin`
4. `Content-Type: application/grpc` + cookie sessão
5. Ler `grpc-status` (0 ok, 3 invalid, 5 not found, 7 permission, 16 unauth)
6. Body → `strings`
7. Protobuf manual: field string = `(n<<3)|2` + varint len + bytes; wrap frame 1+4+payload
8. IDOR: injetar UUID alheio em fields 1/2/3; comparar size/strings vs baseline
9. Distinguir NOT_FOUND vs PERMISSION_DENIED
10. CORS `*` sem `Allow-Credentials` → sem cookie cross-origin (não é finding sozinho)

## Texto do artigo

[ 0x00 ] INTRO

Quase todo bug bounty hunter sabe testar REST. FFUF, Burp, GraphQL introspection. Mas tem um tipo de API que ninguém testa: gRPC-Web.

gRPC-Web deixa browsers falarem com backends gRPC via HTTP. Em vez de JSON, usa Protocol Buffers — serialização binária. Isso assusta geral porque não dá pra ler no Burp. Mas a real é que gRPC-Web é trivial de testar com curl. Não precisa de .proto, não precisa de protoc, não precisa de client compilado.

Pra quem não conhece a diferença: gRPC puro roda sobre HTTP/2 com Protobuf nativo. gRPC-Web é uma adaptação pra browsers, normalmente via proxy Envoy, que encapsula o framing gRPC num HTTP/1.1 comum. É por isso que ferramentas como grpcurl não funcionam — elas esperam gRPC nativo (HTTP/2), não o encapsulamento HTTP/1.1 do gRPC-Web. Curl resolve porque pra ele é só um POST com Content-Type especial e body binário.

Vou mostrar como eu mapeei endpoints gRPC escondidos numa SPA Next.js, fiz requests com protobuf construído a mão, e testei IDOR injetando UUIDs de outros usuários no payload binário. Tudo com curl e Python.

[ 0x01 ] O ALVO

Uma SPA Next.js. O frontend fala com uma API que não é REST — é gRPC-Web. No DevTools os requests tem `Content-Type: application/grpc` e respostas binárias que o Burp não decodifica.

A primeira pergunta que me fiz: como mapear todos os endpoints se eles não aparecem em scan nenhum?

[ 0x02 ] DESCOBRINDO OS ENDPOINTS

JS Bundle Mining

SPAs carregam tudo no JavaScript. Os endpoints gRPC seguem um padrão: `POST https://target.com/api.{Service}/{Method}`. O Service e o Method ficam hardcoded no JS bundle.

```
`# Baixar todos os JS chunks da pagina
curl -s "https://target.com/" | grep -oP 'https://cdn\.target\.com/_next/static/chunks/[^"]+\.js' | sort -u > chunks.txt

# Procurar por padroes gRPC nos chunks
for chunk in $(cat chunks.txt); do
    curl -s "$chunk" | grep -oP '[a-z_]+\.[A-Z][a-z]+/[A-Z][a-z]+' | sort -u
done
`
```

Poucos minutos depois eu tinha 30+ endpoints: `api.Chat/GetUserSettings`, `api.Media/ListMediaPosts`, `api.Settings/GetUserConfig`, etc.

APK Decompile

O alvo tem app mobile também. Decompilando com jadx:

```
`jadx -d output/ app.apk
grep -r "application/grpc\|\.Service/\|grpc" output/sources/ --include="*.java" | head -20
`
```

O APK revelou 625 tipos de serviços — muito mais que o web. O app mobile tem superficie de ataque bem maior.

[ 0x03 ] O PRIMEIRO REQUEST

O body do gRPC é binário (protobuf). Mas um protobuf vazio é só 5 bytes: 1 byte de flag (0 = sem compressão) + 4 bytes de length (0 = payload vazio).

```
`# Criar payload vazio
printf '\x00\x00\x00\x00\x00' > /tmp/empty.bin

# Fazer o request
curl -s -X POST \
  -H "Content-Type: application/grpc" \
  -H "Cookie: session=YOUR_COOKIE" \
  --data-binary @/tmp/empty.bin \
  -D - \
  "https://target.com/api.Chat/GetUserSettings"
`
```

A resposta tem duas partes. O header `grpc-status` e o body binário.

```
`grpc-status: 0    → sucesso
grpc-status: 3    → invalid argument (precisa de parametros)
grpc-status: 16   → unauthenticated (cookie invalido)
`
```

Quando o status é 0, o body tem dados reais. Mas é binário. Pra ler:

```
`curl -s -X POST \
  -H "Content-Type: application/grpc" \
  -H "Cookie: session=YOUR_COOKIE" \
  --data-binary @/tmp/empty.bin \
  "https://target.com/api.Chat/GetUserSettings" | strings
`
```

O `strings` extrai todo texto legivel do binario. Nomes, valores, URLs, configurações. Qualquer string que o server serializou no protobuf aparece. No meu teste, o primeiro endpoint que funcionou retornou o system prompt customizado do usuário, configurações de personalidade, e preferências de idioma.

[ 0x04 ] O PROBLEMA DO PROTOBUF

Aqui é onde geral desiste. Pra testar IDOR em REST, você troca um `user_id` na URL ou no JSON. Em gRPC, o `user_id` viaja dentro do protobuf binário. Você não sabe em qual field ele está, não sabe o tipo, e não tem o .proto.

Mas protobuf wire format é simples. Cada campo é tag + valor. A tag é `(field_number << 3) | wire_type`. Para strings (wire type 2), depois da tag vem o length como varint, depois os bytes.

Isso significa que dá pra construir protobuf a mao sem saber o schema:

```
`import struct

def encode_string_field(field_num, value):
    """Encode a string field in protobuf wire format"""
    tag = (field_num << 3) | 2  # wire type 2 = length-delimited
    value_bytes = value.encode()
    length = len(value_bytes)
    varint = b""
    while length > 0:
        b = length & 0x7F
        length >>= 7
        if length > 0:
            b |= 0x80
        varint += bytes([b])
    if not varint:
        varint = bytes([0])
    return bytes([tag]) + varint + value_bytes

def make_grpc_frame(payload):
    """Wrap protobuf in gRPC frame (5-byte prefix)"""
    return bytes([0]) + struct.pack(">I", len(payload)) + payload
`
```

[ 0x05 ] TESTANDO IDOR

A ideia: pegar um userId público (de uma API que não precisa de auth), injetar nos fields 1, 2, e 3 do protobuf, e comparar a resposta com o baseline (sem userId injetado).

O userId público

O alvo tem uma wiki pública onde usuários fazem edit requests. A API da wiki expõe o `userId` de qualquer um sem autenticação:

```
`curl -s "https://wiki.target.com/api/list-edits?slug=PopularArticle&limit=1"
# Retorna: {"userId":"abc123-def456-789...","summary":"..."}
`
```

Esses UUIDs são a identidade do usuário na plataforma inteira. Saber o userId de alguém é trivial.

O teste

```
`import struct, subprocess

def encode_string_field(field_num, value):
    tag = (field_num << 3) | 2
    value_bytes = value.encode()
    length = len(value_bytes)
    varint = b""
    while length > 0:
        b = length & 0x7F
        length >>= 7
        if length > 0: b |= 0x80
        varint += bytes([b])
    if not varint: varint = bytes([0])
    return bytes([tag]) + varint + value_bytes

def make_grpc_frame(payload):
    return bytes([0]) + struct.pack(">I", len(payload)) + payload

def grpc_call(endpoint, payload_file, cookie):
    r = subprocess.run([
        "curl", "-s", "-X", "POST",
        "-H", "Content-Type: application/grpc",
        "-H", f"Cookie: {cookie}",
        "--data-binary", f"@{payload_file}",
        f"https://target.com/api.{endpoint}"
    ], capture_output=True, timeout=15)
    # Extrair strings
    strings = []
    cur = b""
    for b in r.stdout:
        if 32 <= b < 127: cur += bytes([b])
        else:
            if len(cur) >= 8: strings.append(cur.decode())
            cur = b""
    return len(r.stdout), strings

# userId de OUTRO usuario (publico na wiki)
target_uid = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"

# Injetar nos fields 1, 2, 3 (nao sabemos qual o server usa)
payload = b""
for field_num in [1, 2, 3]:
    payload += encode_string_field(field_num, target_uid)
frame = make_grpc_frame(payload)
with open("/tmp/grpc_idor.bin", "wb") as f:
    f.write(frame)

# Baseline: request vazio (server usa session_id)
base_size, base_str = grpc_call("Chat/GetUserProfile", "/tmp/empty.bin", "session=YOUR_COOKIE")

# Injetado: request com target userId
tgt_size, tgt_str = grpc_call("Chat/GetUserProfile", "/tmp/grpc_idor.bin", "session=YOUR_COOKIE")

print(f"Baseline: {base_size} bytes")
print(f"Target:   {tgt_size} bytes")

if target_uid in " ".join(tgt_str):
    print("[!!!] IDOR CONFIRMADO — target userId na resposta")
elif tgt_size != base_size:
    print("[!] Response size diferente — investigar")
else:
    print("[x] Mesma resposta — server ignora o campo injetado")
`
```

[ 0x06 ] O RESULTADO

Testei 30+ endpoints com 5 UUIDs diferentes de outros usuários. Todos os casos:

- O server ignorou o userId injetado no protobuf

- A resposta foi idêntica ao baseline (meu próprio perfil)

- O server autentica pelo `session_id` do cookie SSO, não pelo protobuf

O server faz auth right. Não confia no client pra dizer quem é o usuário. Usa o session cookie. Injetar userId no protobuf não muda nada.

Mas não foi inútil. Os endpoints que funcionaram revelaram coisa interessante:

- GetUserMemoryBlurb: retorna um perfil gerado por IA sobre o usuário. Identidade online, localização, características físicas, padrões comportamentais. Tudo baseado em conversas privadas.

- GetUserSettings: retorna o system prompt customizado do usuário

- ListConversations: retorna IDs e títulos de todas as conversas

- ListResponses: retorna o histórico completo de chat de uma conversa (aceita conversation_id no field 1)

[ 0x07 ] LISTRESPONSES — ENGENHARIA REVERSA DO FIELD 1

O endpoint `Chat/ListResponses` aceita um `conversation_id` como protobuf field 1 e retorna o histórico completo daquela conversa. Mas como eu descobri que era o field 1 sem ter o .proto?

A resposta é tentativa e erro. Primeiro mandei um protobuf vazio. O server respondeu com `grpc-status: 3` (INVALID_ARGUMENT) e a mensagem `"Invalid uuid"`. Isso me disse duas coisas: o endpoint espera um UUID, e o field que recebe esse UUID não está sendo preenchido.

Aí injetei o UUID nos fields 1, 2, e 3 separadamente. Field 1 retornou `grpc-status: 0` com 50KB de dados. Fields 2 e 3 retornaram o mesmo `INVALID_ARGUMENT`. O field 1 é o conversation_id.

```
`cid = b"conv-uuid-here"
payload = bytes([0x0a, len(cid)]) + cid  # field 1, wire type 2
frame = bytes([0]) + struct.pack(">I", len(payload)) + payload
with open("/tmp/conv.bin", "wb") as f:
    f.write(frame)
`
```

```
`curl -s -X POST -H "Content-Type: application/grpc" \
  -H "Cookie: session=YOUR_COOKIE" \
  --data-binary @/tmp/conv.bin \
  "https://target.com/api.Chat/ListResponses" | strings
`
```

A resposta tem: texto das mensagens (user e AI), nome do modelo, citações com URLs de fontes, timestamps, response IDs.

Agora a parte interessante. Testando com um conversation_id aleatório que não existe no banco: `grpc-status: 5` (NOT_FOUND). Testando com um ID sequencial (incrementando 1 byte do meu UUID real): também NOT_FOUND.

Por que isso importa: `NOT_FOUND` é diferente de `PERMISSION_DENIED`. Se o server respondesse `PERMISSION_DENIED` (grpc-status: 7) pra UUIDs de outros usuários, significaria que o ID existe mas você não tem acesso. `NOT_FOUND` (grpc-status: 5) não diferencia — pode ser que o ID não existe OU que existe mas o server esconde a existencia pra evitar enumeração. De qualquer forma, o server está checando ownership no backend antes de retornar dados. Não dá pra acessar conversas de outros usuários.

Mas se alguém vazar um conversation_id (screenshot, log, share link), qualquer sessão autenticada pode recuperar o histórico completo.

[ 0x08 ] CORS — O DETALHE QUE IMPORTA

Todos os endpoints gRPC retornaram:

```
`access-control-allow-origin: *
access-control-expose-headers: *
`
```

Preflight OPTIONS:

```
`access-control-allow-methods: *
access-control-allow-headers: *
access-control-allow-origin: *
`
```

À primeira vista parece grave. MAS: não tem `Access-Control-Allow-Credentials: true`. Sem esse header, o browser não envia cookies cross-origin. Um site malicioso não consegue fazer requests autenticados.

O detalhe técnico: o cabeçalho `ACAO: *` não cria impacto sozinho. Num cenário de XSS same-origin, o atacante já tem acesso às respostas porque o código executa no mesmo origin. CORS só restringe cross-origin. O que a configuração permissiva faz é ampliar cenários envolvendo outros recursos expostos cross-origin — por exemplo, se um subdomínio vulnerável pudesse fazer requests autenticados pra esses endpoints. O risco principal continua sendo o XSS. O CORS permissivo é um multiplicador, não a raiz.

[ 0x09 ] FERRAMENTAS

Ferramenta
Uso
Nota

curl
Requests gRPC-Web
Funciona perfeito com --data-binary

strings
Extrair texto do protobuf binário
Já vem no sistema

Python struct
Construir protobuf manual
15 linhas, sem dependências

jadx
Decompile APK
Para achar endpoints no mobile

grpcurl
Client gRPC nativo
Não funciona com gRPC-Web (HTTP/1.1)

grpcui
Interface web gRPC
Precisa de reflection ou .proto

[ 0x0A ] CHECKLIST

- [ ] Mapear endpoints gRPC no JS bundle: `grep -oP '[a-z_]+\.[A-Z][a-z]+/[A-Z][a-z]+'`

- [ ] Se tem app mobile, decompilar APK com jadx e procurar por `application/grpc`

- [ ] Criar protobuf vazio: `printf '\x00\x00\x00\x00\x00' > empty.bin`

- [ ] Testar cada endpoint com curl + `--data-binary @empty.bin`

- [ ] Ler `grpc-status` nos headers de resposta

- [ ] Extrair strings do body: `| strings`

- [ ] Para endpoints que aceitam IDs, construir protobuf com Python (wire format manual)

- [ ] Injetar ID de outro user nos fields 1, 2, 3 e comparar response

- [ ] Verificar se o target ID aparece nas strings da resposta

- [ ] Checar CORS: `curl -X OPTIONS -H "Origin: https://evil.com" ...`

- [ ] Decodificar `grpc-message` em erros (URL-encoded)

- [ ] Testar sem cookie (grpc-status 16 = auth necessário, 0 = acesso anônimo)





            SHARE

                 POST_ON_X


                 COPY_LINK








                    R



                    WRITTEN BY

                    @reeshasx








                    #grpc

                    #protobuf

                    #api

                    #recon

                    #idor

                    #access-control

                    #web

                    #bughunting




                    ID: hunting-grpc-web-endpoints
