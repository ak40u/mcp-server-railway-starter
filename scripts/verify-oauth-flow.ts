/**
 * End-to-end check of the whole authorization flow against a running server.
 *
 * Walks the path a real MCP client walks - discovery, dynamic registration,
 * PKCE, login, token exchange - and then speaks MCP over the token. Run it
 * after deploying to prove the deployment works, not just that it responds.
 *
 *   npx tsx scripts/verify-oauth-flow.ts https://your-server.up.railway.app 'the-password'
 */
import { createHash, randomBytes } from "node:crypto"

import { Client } from "@modelcontextprotocol/sdk/client/index.js"
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js"

const base = (process.argv[2] ?? "http://127.0.0.1:8123").replace(/\/$/, "")
const password = process.argv[3] ?? "local-test-password-1"
const redirectUri = "http://localhost:9999/callback"

const ok = (label: string, detail = "") => console.log(`  ok   ${label}${detail ? ` - ${detail}` : ""}`)
const fail = (label: string, detail: string): never => {
  console.error(`  FAIL ${label} - ${detail}`)
  process.exit(1)
}

async function main() {
  console.log(`checking ${base}`)

  // 1. Discovery: an unauthenticated call must point the client at the metadata.
  const unauthorized = await fetch(`${base}/mcp`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" }),
  })
  if (unauthorized.status !== 401) fail("unauthenticated call is rejected", `got ${unauthorized.status}`)
  const challenge = unauthorized.headers.get("www-authenticate") ?? ""
  if (!challenge.includes("resource_metadata")) fail("challenge points at resource metadata", challenge)
  ok("unauthenticated call is rejected", "401 with resource_metadata")

  const prm = await (await fetch(`${base}/.well-known/oauth-protected-resource`)).json()
  const asUrl = String(prm.authorization_servers[0]).replace(/\/$/, "")
  const meta = await (await fetch(`${asUrl}/.well-known/oauth-authorization-server`)).json()
  ok("discovery", `authorization server at ${meta.issuer}`)

  // 2. Dynamic client registration - no pre-shared credentials anywhere.
  const registration = await fetch(meta.registration_endpoint, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      client_name: "verification script",
      redirect_uris: [redirectUri],
      grant_types: ["authorization_code", "refresh_token"],
      response_types: ["code"],
      token_endpoint_auth_method: "none",
    }),
  })
  if (!registration.ok) fail("dynamic client registration", `${registration.status} ${await registration.text()}`)
  const client = await registration.json()
  ok("dynamic client registration", `client_id ${client.client_id}`)

  // 3. Authorization with PKCE.
  const verifier = randomBytes(32).toString("base64url")
  const codeChallenge = createHash("sha256").update(verifier).digest("base64url")
  const authorizeUrl = new URL(meta.authorization_endpoint)
  authorizeUrl.search = new URLSearchParams({
    response_type: "code",
    client_id: client.client_id,
    redirect_uri: redirectUri,
    code_challenge: codeChallenge,
    code_challenge_method: "S256",
    state: "verification-state",
    resource: `${base}/mcp`,
  }).toString()

  const authorize = await fetch(authorizeUrl, { redirect: "manual" })
  const loginLocation = authorize.headers.get("location") ?? ""
  if (!loginLocation.startsWith("/login")) fail("authorize redirects to login", `${authorize.status} ${loginLocation}`)
  const requestId = new URL(loginLocation, base).searchParams.get("request") ?? ""
  ok("authorize parks the request", `request ${requestId.slice(0, 8)}...`)

  // 4. A wrong password must not produce a code.
  const badLogin = await fetch(`${base}/login`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ request: requestId, password: "definitely-not-it" }),
    redirect: "manual",
  })
  if (badLogin.status !== 401) fail("wrong password is rejected", `got ${badLogin.status}`)
  ok("wrong password is rejected")

  const login = await fetch(`${base}/login`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ request: requestId, password }),
    redirect: "manual",
  })
  const callback = login.headers.get("location") ?? ""
  if (!callback.startsWith(redirectUri)) fail("login redirects back to the client", `${login.status} ${callback}`)
  const code = new URL(callback).searchParams.get("code") ?? ""
  if (new URL(callback).searchParams.get("state") !== "verification-state") fail("state is echoed back", callback)
  ok("login issues an authorization code")

  // 5. Token exchange.
  const tokenBody = new URLSearchParams({
    grant_type: "authorization_code",
    code,
    code_verifier: verifier,
    client_id: client.client_id,
    redirect_uri: redirectUri,
    resource: `${base}/mcp`,
  })
  const tokenResponse = await fetch(meta.token_endpoint, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: tokenBody,
  })
  if (!tokenResponse.ok) fail("token exchange", `${tokenResponse.status} ${await tokenResponse.text()}`)
  const tokens = await tokenResponse.json()
  ok("token exchange", `expires in ${tokens.expires_in}s`)

  // 6. The same code must not work twice.
  const replay = await fetch(meta.token_endpoint, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: tokenBody,
  })
  if (replay.ok) fail("authorization code cannot be replayed", "second exchange succeeded")
  ok("authorization code cannot be replayed")

  // 7. Speak MCP over the token, using the real client transport.
  const transport = new StreamableHTTPClientTransport(new URL(`${base}/mcp`), {
    requestInit: { headers: { authorization: `Bearer ${tokens.access_token}` } },
  })
  const mcp = new Client({ name: "verification-script", version: "1.0.0" })
  await mcp.connect(transport)
  ok("mcp initialize")

  const { tools } = await mcp.listTools()
  const names = tools.map((t) => t.name).sort()
  if (!names.includes("add_note")) fail("tools/list", `got ${names.join(", ")}`)
  ok("tools/list", names.join(", "))

  const marker = `verified-${randomBytes(4).toString("hex")}`
  const added = await mcp.callTool({ name: "add_note", arguments: { title: marker, body: `written by the check ${marker}` } })
  ok("tools/call add_note", JSON.stringify(added.content).slice(0, 60))

  const found = await mcp.callTool({ name: "search_notes", arguments: { query: marker } })
  const foundText = JSON.stringify(found.content)
  if (!foundText.includes(marker)) fail("the write is readable back", foundText.slice(0, 120))
  ok("tools/call search_notes", "the note written a moment ago comes back")

  const who = await mcp.callTool({ name: "whoami", arguments: {} })
  if (!JSON.stringify(who.content).includes(client.client_id)) fail("whoami reports the caller", JSON.stringify(who.content))
  ok("tools/call whoami", "token is bound to the registered client")

  // 8. Refresh, so a client that outlives the access token keeps working.
  const refreshed = await fetch(meta.token_endpoint, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "refresh_token",
      refresh_token: tokens.refresh_token,
      client_id: client.client_id,
      resource: `${base}/mcp`,
    }),
  })
  if (!refreshed.ok) fail("refresh token exchange", `${refreshed.status} ${await refreshed.text()}`)
  ok("refresh token exchange")

  await transport.close()
  console.log("\nall checks passed")
}

main().catch((error) => {
  console.error("\nverification failed:", error)
  process.exit(1)
})
