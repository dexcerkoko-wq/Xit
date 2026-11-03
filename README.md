# KeyAuth API

Backend Node.js + Express para validar keys de acesso de um app Android.

## Deploy no Render

1. Envie esta pasta para um repositório GitHub.
2. No Render, escolha **New > Blueprint** e conecte o repositório.
3. O Render lê `render.yaml` e cria o Web Service e o PostgreSQL.
4. Em Environment do serviço, configure `SUPPORT_URL` e `UPDATE_URL` (podem ficar vazios).
5. O `ADMIN_SECRET` é gerado pelo Blueprint. Copie-o da página Environment do serviço e guarde-o em local seguro.
6. Aguarde o deploy e teste `https://SEU-SERVICO.onrender.com/health`.

> O Blueprint usa o plano `free` para o Web Service e `basic-256mb` para PostgreSQL. O banco é um recurso pago. Confira os preços atuais no Render antes de confirmar a criação.

## Rodar localmente

Requer Node.js 20+ e PostgreSQL.

```bash
cp .env.example .env
# Edite DATABASE_URL e ADMIN_SECRET
npm install
npm start
```

## Endpoints

### Obter sessão

```http
GET /api/session/
```

Resposta `200`:
```json
{ "csrfToken": "token_aleatorio" }
```

### Validar key

```http
POST /api/client/access/
Content-Type: application/json
```

Body:
```json
{ "key": "TOKEN_DO_USUARIO" }
```

Sucesso `200`:
```json
{
  "csrfToken": "token_aleatorio",
  "expires": "2027-01-01T00:00:00.000+00:00",
  "watermark": {
    "enabled": false,
    "position": "top_center",
    "fontSize": 24
  }
}
```

Para keys ilimitadas, `expires` é `null`. Erro `401`:
```json
{
  "error": "Key inválida ou expirada.",
  "supportUrl": "",
  "updateUrl": ""
}
```

### Criar key (admin)

```http
POST /api/admin/keys
x-admin-secret: SEU_ADMIN_SECRET
Content-Type: application/json
```

Body:
```json
{ "duration": "30d", "label": "Cliente 001" }
```

`duration`: `7d`, `30d`, `90d` ou `unlimited`.

A resposta `201` contém a key em texto puro **uma única vez**. Salve-a: o banco armazena apenas seu hash SHA-256 e não há como recuperá-la depois.

Exemplo:
```bash
curl -X POST "https://SEU-SERVICO.onrender.com/api/admin/keys" \
  -H "x-admin-secret: SEU_ADMIN_SECRET" \
  -H "Content-Type: application/json" \
  -d '{"duration":"30d","label":"Cliente 001"}'
```

### Listar keys

```http
GET /api/admin/keys
x-admin-secret: SEU_ADMIN_SECRET
```

Lista metadados, sem revelar tokens.

### Revogar key

```http
DELETE /api/admin/keys/ID
x-admin-secret: SEU_ADMIN_SECRET
```

## Configuração

| Variável | Uso |
|---|---|
| `DATABASE_URL` | URL PostgreSQL |
| `ADMIN_SECRET` | Segredo para rotas administrativas |
| `SUPPORT_URL` | Link de suporte retornado no 401 |
| `UPDATE_URL` | Link de atualização retornado no 401 |
| `WATERMARK_ENABLED` | `true` ou `false` |
| `WATERMARK_POSITION` | Posição da watermark |
| `WATERMARK_FONT_SIZE` | Tamanho de 8 a 96 |

## Notas de segurança

- Nunca coloque `ADMIN_SECRET` dentro do APK.
- Não versione `.env` nem compartilhe a key administrativa.
- Use HTTPS no app Android.
- O CSRF retornado é um token aleatório para a camada cliente; para proteger futuras rotas mutáveis autenticadas por sessão, implemente validação e vínculo de sessão no servidor. O endpoint de validação de key não depende do CSRF.
- A API não consegue impedir que alguém modifique um APK sob seu controle; validação no servidor reduz falsificação simples, mas não substitui medidas anti-tamper.
