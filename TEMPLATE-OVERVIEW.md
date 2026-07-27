# Deploy and Host a Remote MCP Server on Railway

The Model Context Protocol is how an AI assistant reaches tools and data it does not ship with. A **remote** MCP server is one your assistant connects to over the network instead of launching on your laptop — which means it needs a public address, a transport that survives more than one replica, and an authorization story, because anything reachable on the internet will be reached.

This template deploys a working one: a Streamable HTTP MCP endpoint, an OAuth 2.1 authorization server in front of it, and Postgres behind it. Add the URL to your client, type the generated password once, and the client is connected.

## About Hosting a Remote MCP Server

Most MCP templates wrap somebody else's SaaS — a server for one fitness tracker, one ad platform, one CRM. Useful if you want that product. Useless if what you want is to expose your own database, your internal API, or your document store.

The tools are the easy part. What takes the time is everything around them:

- **The transport.** Streamable HTTP replaced SSE as the recommended transport. Keeping sessions in memory forces sticky routing, so this server runs stateless: any replica can answer any request.
- **The authorization.** The spec puts OAuth 2.1 in the required path — PKCE, dynamic client registration (RFC 7591), protected-resource metadata (RFC 9728), resource indicators (RFC 8707). Clients like Claude and ChatGPT will not connect without it, and they register themselves, so there is no API key for you to copy around.
- **The storage.** Codes and tokens have to outlive the process that issued them. Hold them in memory and every deploy signs everyone out, while a second replica rejects tokens the first one issued.

## Common Use Cases

- **Give an assistant your own data.** Point tools at an internal API or a private database and let the model query it, with a token you can revoke.
- **Share one server with a team.** Every client registers separately and gets its own token; `whoami` shows which client is behind a call, so tools can scope data per client.
- **Start a product.** If you are shipping an MCP server to customers, this is the boilerplate — auth, storage, deployment — with your tools left to write.

## Dependencies for MCP Server Hosting

### Deployment Dependencies

- [MCP TypeScript SDK](https://github.com/modelcontextprotocol/typescript-sdk) 1.29.0 — server, Streamable HTTP transport, OAuth endpoints
- Node 24 and Express 5
- Postgres — OAuth clients, authorization codes, tokens, and the example table
- [Source repository](https://github.com/ak40u/mcp-server-railway-starter)

### Implementation Details

Every version is pinned, and the choices below are the ones that took a deployment to get right:

- **Stateless transport.** A new server and transport per request, torn down when the client disconnects. No session map, so scaling to several replicas needs no sticky routing — and a dropped connection cannot leak a live instance.
- **Tokens are stored hashed** (SHA-256). A database dump does not hand anyone a working token.
- **Authorization codes are single-use**, enforced by marking a code consumed in the same statement that reads it. A replay finds nothing to update — unlike a check-then-write, which two concurrent requests can both pass.
- **Refresh rotates.** Using a refresh token revokes it and issues a new pair; a refresh may narrow its scopes, never widen them.
- **Login is rate limited** — ten attempts per address per fifteen minutes, counted in Postgres so the limit holds across replicas instead of per process. The password is compared in constant time, over hashes, so neither its content nor its length leaks through timing.
- **`trust proxy` is on.** Railway terminates TLS at its edge; without it Express builds `http://` redirect URLs and OAuth clients reject the mismatch.
- **The issuer comes from `RAILWAY_PUBLIC_DOMAIN`.** OAuth metadata has to name the exact origin clients reach, so the template derives it rather than asking you to type it twice.
- **The server refuses to start on a bad configuration** — a missing password, a short one, no database — instead of failing later inside a request.
- **A health check that means something.** `/health` queries Postgres, so a broken database surfaces as an unhealthy deployment rather than a server that answers cheerfully and fails on every tool call.

Three example tools ship with it — `add_note`, `search_notes`, `whoami` — backed by a real table rather than canned strings, so a fresh deployment proves the whole path works: token, transport, handler, database write. Replace them in `src/tools.ts`.

The repository also carries `scripts/verify-oauth-flow.ts`, which walks the entire flow against a running deployment — discovery, registration, PKCE, login, token exchange, `tools/call` — and checks the parts that are supposed to fail. This template was published only after that script passed against a deployment created from the template itself.

## Why Deploy a Remote MCP Server on Railway?

Railway is a singular platform to deploy your infrastructure stack. Railway will host your infrastructure so you don't have to deal with configuration, while allowing you to vertically and horizontally scale it.

By deploying a Remote MCP Server on Railway, you are one step closer to supporting a complete full-stack application with minimal burden. Host your servers, databases, AI agents, and more on Railway.
