/**
 * Remote MCP server over Streamable HTTP, protected by its own OAuth 2.1
 * authorization server.
 *
 * The transport is stateless on purpose: no session is kept in memory, so any
 * replica can answer any request and the service scales horizontally without
 * sticky routing.
 */
import express from "express"

import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js"
import { mcpAuthRouter } from "@modelcontextprotocol/sdk/server/auth/router.js"
import { requireBearerAuth } from "@modelcontextprotocol/sdk/server/auth/middleware/bearerAuth.js"

import { migrate, pool, sweepExpired } from "./db.js"
import { env } from "./env.js"
import { loginRouter } from "./login.js"
import { PostgresOAuthProvider } from "./oauth-provider.js"
import { buildServer } from "./tools.js"

const provider = new PostgresOAuthProvider()
const app = express()

app.disable("x-powered-by")
// Railway terminates TLS at its edge; without this Express builds redirect URLs
// as http:// and OAuth clients reject the mismatch.
app.set("trust proxy", true)

// The SDK's routers bring their own body parsers and CORS, so they go first and
// nothing global is allowed to consume a request body ahead of them.
app.use(
  mcpAuthRouter({
    provider,
    issuerUrl: new URL(env.issuer),
    resourceServerUrl: new URL(env.issuer),
    resourceName: env.serverName,
    scopesSupported: env.scopes,
  }),
)

app.use(express.urlencoded({ extended: false }), loginRouter(provider))

const bearer = requireBearerAuth({
  verifier: provider,
  requiredScopes: [],
  resourceMetadataUrl: `${env.issuer}/.well-known/oauth-protected-resource`,
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

app.post("/mcp", express.json({ limit: "4mb" }), bearer, async (req, res) => {
  const server = buildServer(req.auth)
  const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined })

  // One server and one transport per request; both are torn down when the
  // client disconnects, otherwise a dropped connection leaks a live instance.
  res.on("close", () => {
    void transport.close()
    void server.close()
  })

  try {
    await server.connect(transport)
    await transport.handleRequest(req, res, req.body)
  } catch (error) {
    console.error("mcp request failed", error)
    if (!res.headersSent) res.status(500).json({ error: "internal_error" })
  }
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
      server.close(() => void pool.end().then(() => process.exit(0)))
    })
  }
}

main().catch((error) => {
  console.error("failed to start", error)
  process.exit(1)
})
