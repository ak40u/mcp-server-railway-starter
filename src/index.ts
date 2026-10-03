/**
 * Remote MCP server over Streamable HTTP, protected by its own OAuth 2.1
 * authorization server.
 *
 * The transport is stateless on purpose: no session is kept in memory, so any
 * replica can answer any request and the service scales horizontally without
 * sticky routing.
 */
import express from "express"

import { getOAuthProtectedResourceMetadataUrl, mcpAuthMetadataRouter, requireBearerAuth } from "@modelcontextprotocol/express"
import { toNodeHandler } from "@modelcontextprotocol/node"
import { createMcpHandler } from "@modelcontextprotocol/server"

import { authorizationServerRouter, buildOAuthMetadata } from "./authorization-server.js"
import { migrate, pool, sweepExpired } from "./db.js"
import { env } from "./env.js"
import { loginRouter } from "./login.js"
import { PostgresOAuthProvider } from "./oauth-provider.js"
import { buildServer } from "./tools.js"

const provider = new PostgresOAuthProvider()
const app = express()
const issuerUrl = new URL(env.issuer)

app.disable("x-powered-by")
// Railway terminates TLS at its edge, through exactly one proxy. A hop count of 1
// makes Express take the protocol and the client address from what that proxy
// appended and ignore anything a client put into X-Forwarded-* itself. Without it
// Express builds redirect URLs as http:// and OAuth clients reject the mismatch.
app.set("trust proxy", 1)

// The authorization-server routes bring their own body parsers and CORS, so they
// go first and nothing global is allowed to consume a request body ahead of them.
app.use(authorizationServerRouter(provider))
app.use(
  mcpAuthMetadataRouter({
    oauthMetadata: buildOAuthMetadata(issuerUrl, env.scopes),
    resourceServerUrl: issuerUrl,
    resourceName: env.serverName,
    scopesSupported: env.scopes,
  }),
)

app.use(express.urlencoded({ extended: false }), loginRouter(provider))

const bearer = requireBearerAuth({
  verifier: provider,
  requiredScopes: [],
  resourceMetadataUrl: getOAuthProtectedResourceMetadataUrl(issuerUrl),
})

app.use("/mcp", (req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", req.headers.origin ?? "*")
  res.setHeader("Access-Control-Allow-Headers", "authorization, content-type, mcp-protocol-version, mcp-session-id")
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS")
  if (req.method === "OPTIONS") {
    res.sendStatus(204)
    return
  }
  next()
})

// The factory runs once per request, so a fresh server answers every call and
// nothing is held between requests; the caller's token reaches the tools as authInfo.
const mcp = createMcpHandler(({ authInfo }) => buildServer(authInfo))
const serveMcp = toNodeHandler(mcp)

app.post("/mcp", express.json({ limit: "4mb" }), bearer, (req, res) => {
  void serveMcp(req, res, req.body).catch((error: unknown) => {
    console.error("mcp request failed", error)
    if (!res.headersSent) res.status(500).json({ error: "internal_error" })
  })
})

// Stateless mode has no stream to resume and no session to end, so the other
// two verbs of the transport are answered honestly instead of hanging.
app.all("/mcp", (_req, res) => {
  res.status(405).json({ error: "method_not_allowed", detail: "This server is stateless; use POST." })
})

app.get("/health", async (_req, res) => {
  try {
    await pool.query("select 1")
    res.json({ status: "ok" })
  } catch {
    res.status(503).json({ status: "degraded" })
  }
})

app.get("/", (_req, res) => {
  res.type("html").send(`<!doctype html>
<meta charset="utf-8"><title>${env.serverName}</title>
<style>body{font:16px/1.6 system-ui,sans-serif;max-width:44rem;margin:4rem auto;padding:0 1rem;color-scheme:light dark}code{background:#8882;padding:2px 5px;border-radius:4px}</style>
<h1>${env.serverName}</h1>
<p>A remote MCP server. Add it to your client with this URL:</p>
<p><code>${env.issuer}/mcp</code></p>
<p>The client will register itself, send you here to sign in with the server
password, and receive a token. Nothing else needs configuring.</p>`)
})

async function main() {
  await migrate()
  await sweepExpired()
  const sweeper = setInterval(() => void sweepExpired().catch((e) => console.error("sweep failed", e)), 60 * 60 * 1000)

  const server = app.listen(env.port, () => console.log(`listening on ${env.port}, issuer ${env.issuer}`))

  for (const signal of ["SIGTERM", "SIGINT"] as const) {
    process.on(signal, () => {
      clearInterval(sweeper)
      void mcp.close().finally(() => server.close(() => void pool.end().then(() => process.exit(0))))
    })
  }
}

main().catch((error) => {
  console.error("failed to start", error)
  process.exit(1)
})
