# Remote MCP server starter for Railway

A Model Context Protocol server your agent connects to over the network, with a
working OAuth 2.1 authorization server in front of it. Deploy it, add the URL to
your client, type a password once — the client registers itself and gets a token.

## Why this exists

The catalogue has plenty of MCP servers, and almost all of them wrap somebody
else's SaaS: a server for Whoop, one for Meta Ads, one for a CRM. If what you
want is to expose *your own* data — an internal API, a database, a document
store — there is nothing to start from.

The hard part was never the tools. It is everything around them:

- **Transport.** Streamable HTTP replaced SSE, and stateless is the shape that
  survives more than one replica. Sessions in memory mean sticky routing.
- **Authorization.** The MCP spec puts OAuth 2.1 in the required path: PKCE,
  dynamic client registration, protected-resource metadata under RFC 9728,
  resource indicators under RFC 8707. Clients will not connect without it.
- **Storage.** Codes and tokens have to outlive the process that issued them, or
  every deploy logs everyone out and a second replica rejects the first one's
  tokens.

This starter does all three, and leaves you three example tools to replace.

## What you get

| Path | What it is |
|------|-----------|
| `/mcp` | The MCP endpoint. Streamable HTTP, stateless, bearer-protected |
| `/.well-known/oauth-protected-resource` | RFC 9728 metadata, so clients can find the authorization server |
| `/.well-known/oauth-authorization-server` | RFC 8414 metadata: endpoints, PKCE method, scopes |
| `/register` | Dynamic client registration (RFC 7591) — no pre-shared credentials |
| `/authorize`, `/token`, `/revoke` | The authorization code flow with PKCE, plus refresh and revocation |
| `/login` | The one human step: your password, once per client |
| `/health` | Checks Postgres, so a broken database shows up as unhealthy |

Three example tools — `add_note`, `search_notes`, `whoami` — are backed by a real
table. They exist so a fresh deployment can be proven end to end, and so you have
a working handler to copy.

## Deploy

Two services: this repository and a Postgres. The template wires them together
and generates the password for you.

After the first deploy, open the service URL — the page shows the exact URL to
paste into your client.

## Add it to a client

Use `https://<your-domain>/mcp`. The client discovers the authorization server,
registers itself, opens the login page in a browser, and stores the token it
gets back. There is nothing to configure on the client side and no API key to
copy around.

For clients that speak stdio only, `npx mcp-remote https://<your-domain>/mcp`
bridges the two.

## Prove it works

```bash
npx tsx scripts/verify-oauth-flow.ts https://<your-domain> '<the password>'
```

The script walks the whole path a real client walks — discovery, registration,
PKCE, login, token exchange, `tools/call` — and also checks the parts that are
supposed to fail: an unauthenticated call, a wrong password, a replayed
authorization code.

## Write your own tools

`src/tools.ts` is the whole surface. Add a `registerTool` call with a Zod input
schema and a handler; the token that authorized the call arrives as `auth`, so
you can key data by `auth.clientId` or check `auth.scopes` per tool.

The example tools are deliberately backed by Postgres rather than returning
canned strings — that is what makes a first deploy prove the write path.

## How the security is set up

- **Tokens are stored hashed** (SHA-256). A database dump does not hand anyone a
  working token.
- **Authorization codes are single-use**, enforced by marking them consumed in
  the same statement that reads them, so a replay finds nothing to update — not
  by a check-then-write that two concurrent requests can both pass.
- **PKCE is required** (S256); the code challenge is bound to the code.
- **Login is rate limited** — 10 attempts per address per 15 minutes, counted in
  Postgres so the limit holds across replicas rather than per process.
- **Passwords are compared in constant time**, over hashes, so neither content
  nor length leaks through timing.
- **Refresh rotates**: using a refresh token revokes it and issues a new pair. A
  refresh can narrow its scopes, never widen them.

One honest note: client secrets issued by dynamic registration are stored as
issued, because the SDK's client authentication compares them directly. MCP
clients normally register as public clients and rely on PKCE, which is the path
this server expects.

## Configuration

| Variable | Required | Purpose |
|----------|----------|---------|
| `DATABASE_URL` | yes | Postgres for clients, codes, tokens |
| `MCP_ADMIN_PASSWORD` | yes | The password on the login page; at least 12 characters |
| `PUBLIC_URL` | on Railway, filled in | The origin clients reach — becomes the OAuth issuer |
| `PORT` | no | Defaults to 8080 |
| `MCP_SERVER_NAME` | no | Name reported to clients |
| `ACCESS_TOKEN_TTL_SECONDS` | no | Default 3600 |
| `REFRESH_TOKEN_TTL_SECONDS` | no | Default 2592000 (30 days) |

## Run locally

```bash
npm ci
cp .env.example .env
npm run dev
```

The SDK refuses a plain-HTTP issuer except on localhost, which is exactly where
you will be running it.

## Using an external identity provider

This server is its own authorization server, which is what makes it deploy in
one click. If you already run Keycloak, Auth0 or Zitadel, replace `mcpAuthRouter`
with `mcpAuthMetadataRouter` and point it at your issuer; the tools and transport
stay as they are.

## A note on versions

Built on `@modelcontextprotocol/sdk` 1.29.0, the current stable line. The v2 SDK
splits into `@modelcontextprotocol/server` and friends and is still in beta at
the time of writing; this starter will move when it stabilises.

## License

MIT
