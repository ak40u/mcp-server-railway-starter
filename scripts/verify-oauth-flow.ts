/**
 * End-to-end check of the whole authorization flow against a running server.
 *
 * Walks the path a real MCP client walks - discovery, dynamic registration,
 * PKCE, login, token exchange - and then speaks MCP over the token. Run it
 * after deploying to prove the deployment works, not just that it responds.
 *
 *   npx tsx scripts/verify-oauth-flow.ts https://your-server.up.railway.app 'the-password'
 *
 * The second half tries the attacks the server is built to refuse: script
 * injection into the login page, a spent refresh token or code used again,
 * weak PKCE, unsafe redirect URIs, unknown scopes. It registers about five
 * clients (registration allows 20 per hour per address).
 *
 * The brute-force check floods the login endpoint and leaves the addresses it
 * used locked out for 15 minutes. Against a local server it forges client
 * addresses with X-Forwarded-For, so your own address is untouched. It does
 * not run against a remote server unless you set VERIFY_LOCKOUT=1, because
 * there the forged header does not apply and the lockout would hit you.
 */
import { createHash, randomBytes } from "node:crypto"

import { Client, StreamableHTTPClientTransport } from "@modelcontextprotocol/client"

const base = (process.argv[2] ?? "http://127.0.0.1:8123").replace(/\/$/, "")
const password = process.argv[3] ?? "local-test-password-1"
const redirectUri = "http://localhost:9999/callback"
const isLocal = ["localhost", "127.0.0.1", "[::1]"].includes(new URL(base).hostname)

const ok = (label: string, detail = "") => console.log(`  ok   ${label}${detail ? ` - ${detail}` : ""}`)
const fail = (label: string, detail: string): never => {
  console.error(`  FAIL ${label} - ${detail}`)
  process.exit(1)
}

const form = (fields: Record<string, string>) => new URLSearchParams(fields)
const formHeaders = { "content-type": "application/x-www-form-urlencoded" }

async function postForm(url: string, fields: Record<string, string>, headers: Record<string, string> = {}) {
  return fetch(url, { method: "POST", headers: { ...formHeaders, ...headers }, body: form(fields), redirect: "manual" })
}

function pkce() {
  const verifier = randomBytes(32).toString("base64url")
  return { verifier, challenge: createHash("sha256").update(verifier).digest("base64url") }
}

interface Meta {
  issuer: string
  authorization_endpoint: string
  token_endpoint: string
  registration_endpoint: string
  revocation_endpoint: string
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
  const meta: Meta = await (await fetch(`${asUrl}/.well-known/oauth-authorization-server`)).json()
  ok("discovery", `authorization server at ${meta.issuer}`)

  const register = (body: Record<string, unknown>) =>
    fetch(meta.registration_endpoint, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) })

  // 2. Dynamic client registration - no pre-shared credentials anywhere.
  const registration = await register({
    client_name: "verification script",
    redirect_uris: [redirectUri],
    grant_types: ["authorization_code", "refresh_token"],
    response_types: ["code"],
    token_endpoint_auth_method: "none",
  })
  if (!registration.ok) fail("dynamic client registration", `${registration.status} ${await registration.text()}`)
  const client = await registration.json()
  ok("dynamic client registration", `client_id ${client.client_id}`)

  /** Starts /authorize for the public client; returns the raw response so callers can inspect redirects. */
  const authorize = (params: Record<string, string>, clientId = client.client_id, redirect = redirectUri) => {
    const url = new URL(meta.authorization_endpoint)
    url.search = new URLSearchParams({
      response_type: "code",
      client_id: clientId,
      redirect_uri: redirect,
      state: "verification-state",
      resource: `${base}/mcp`,
      ...params,
    }).toString()
    return fetch(url, { redirect: "manual" })
  }

  /** authorize + login for the public client, ending with a code. */
  async function obtainCode(extra: Record<string, string> = {}) {
    const { verifier, challenge: codeChallenge } = pkce()
    const response = await authorize({ code_challenge: codeChallenge, code_challenge_method: "S256", ...extra })
    const location = response.headers.get("location") ?? ""
    if (!location.startsWith("/login")) fail("authorize redirects to login", `${response.status} ${location}`)
    const id = new URL(location, base).searchParams.get("request") ?? ""
    const login = await postForm(`${base}/login`, { request: id, password })
    const callback = login.headers.get("location") ?? ""
    if (!callback.startsWith(redirectUri)) fail("login redirects back to the client", `${login.status} ${callback}`)
    return { code: new URL(callback).searchParams.get("code") ?? "", verifier }
  }

  const exchangeCode = (code: string, verifier: string, clientId = client.client_id) =>
    postForm(meta.token_endpoint, { grant_type: "authorization_code", code, code_verifier: verifier, client_id: clientId, redirect_uri: redirectUri })

  const refresh = (refreshToken: string, extra: Record<string, string> = {}) =>
    postForm(meta.token_endpoint, { grant_type: "refresh_token", refresh_token: refreshToken, client_id: client.client_id, ...extra })

  const mcpStatus = async (accessToken: string) =>
    (
      await fetch(`${base}/mcp`, {
        method: "POST",
        headers: { "content-type": "application/json", authorization: `Bearer ${accessToken}` },
        body: JSON.stringify({ jsonrpc: "2.0", id: 2, method: "tools/list" }),
      })
    ).status

  // 3. Authorization with PKCE.
  const { verifier, challenge: codeChallenge } = pkce()
  const authorizeResponse = await authorize({ code_challenge: codeChallenge, code_challenge_method: "S256" })
  const loginLocation = authorizeResponse.headers.get("location") ?? ""
  if (!loginLocation.startsWith("/login")) fail("authorize redirects to login", `${authorizeResponse.status} ${loginLocation}`)
  const requestId = new URL(loginLocation, base).searchParams.get("request") ?? ""
  ok("authorize parks the request", `request ${requestId.slice(0, 8)}...`)

  // 4. A wrong password must not produce a code.
  const badLogin = await postForm(`${base}/login`, { request: requestId, password: "definitely-not-it" })
  if (badLogin.status !== 401) fail("wrong password is rejected", `got ${badLogin.status}`)
  ok("wrong password is rejected")

  const login = await postForm(`${base}/login`, { request: requestId, password })
  const callback = login.headers.get("location") ?? ""
  if (!callback.startsWith(redirectUri)) fail("login redirects back to the client", `${login.status} ${callback}`)
  const code = new URL(callback).searchParams.get("code") ?? ""
  if (new URL(callback).searchParams.get("state") !== "verification-state") fail("state is echoed back", callback)
  ok("login issues an authorization code")

  // 5. Token exchange.
  const tokenResponse = await exchangeCode(code, verifier)
  if (!tokenResponse.ok) fail("token exchange", `${tokenResponse.status} ${await tokenResponse.text()}`)
  const tokens = await tokenResponse.json()
  ok("token exchange", `expires in ${tokens.expires_in}s`)

  // 6. The same code must not work twice, and the replay burns what it produced.
  const replay = await exchangeCode(code, verifier)
  if (replay.ok) fail("authorization code cannot be replayed", "second exchange succeeded")
  ok("authorization code cannot be replayed")
  if ((await mcpStatus(tokens.access_token)) !== 401) fail("code replay revokes the tokens it produced", "access token still works")
  if ((await refresh(tokens.refresh_token)).ok) fail("code replay revokes the tokens it produced", "refresh token still works")
  ok("code replay revokes the tokens issued from that code")

  // 7. Speak MCP over a fresh token, using the real client transport.
  const fresh = await obtainCode()
  const freshTokens = await (await exchangeCode(fresh.code, fresh.verifier)).json()
  const transport = new StreamableHTTPClientTransport(new URL(`${base}/mcp`), {
    requestInit: { headers: { authorization: `Bearer ${freshTokens.access_token}` } },
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
  await transport.close()

  // 8. Refresh rotates, and reusing the spent token burns the whole family.
  const refreshed = await refresh(freshTokens.refresh_token, { resource: `${base}/mcp` })
  if (!refreshed.ok) fail("refresh token exchange", `${refreshed.status} ${await refreshed.text()}`)
  const rotated = await refreshed.json()
  ok("refresh token exchange")

  if ((await refresh(freshTokens.refresh_token)).ok) fail("a used refresh token is rejected", "second refresh succeeded")
  ok("a used refresh token is rejected")
  if ((await refresh(rotated.refresh_token)).ok) fail("reuse revokes the family", "the newer refresh token still works")
  if ((await mcpStatus(rotated.access_token)) !== 401) fail("reuse revokes the family", "the newer access token still works")
  ok("refresh token reuse revokes the whole family", "descendant refresh and access tokens are dead")

  // 9. Revoking a refresh token takes its access token with it.
  const pair = await obtainCode()
  const pairTokens = await (await exchangeCode(pair.code, pair.verifier)).json()
  if ((await mcpStatus(pairTokens.access_token)) === 401) fail("fresh access token works", "401")
  const revokeRefresh = await postForm(meta.revocation_endpoint, { token: pairTokens.refresh_token, client_id: client.client_id })
  if (!revokeRefresh.ok) fail("token revocation", `${revokeRefresh.status} ${await revokeRefresh.text()}`)
  if ((await mcpStatus(pairTokens.access_token)) !== 401) fail("revoking a refresh token revokes its access token", "access token still works")
  ok("revoking a refresh token revokes its access token")

  // 10. Revoking an access token stops it at once.
  const third = await obtainCode()
  const thirdTokens = await (await exchangeCode(third.code, third.verifier)).json()
  const revoke = await postForm(meta.revocation_endpoint, { token: thirdTokens.access_token, client_id: client.client_id })
  if (!revoke.ok) fail("token revocation", `${revoke.status} ${await revoke.text()}`)
  if ((await mcpStatus(thirdTokens.access_token)) !== 401) fail("revoked token is rejected", "still accepted")
  ok("token revocation", "the revoked access token gets 401")

  console.log("\nnegative checks")

  // PKCE: plain, empty and malformed challenges never reach the login page; a wrong verifier gets no tokens.
  for (const [label, params] of [
    ["plain PKCE", { code_challenge: "a".repeat(43), code_challenge_method: "plain" }],
    ["empty code_challenge", { code_challenge: "", code_challenge_method: "S256" }],
    ["malformed code_challenge", { code_challenge: "too-short", code_challenge_method: "S256" }],
    ["missing PKCE", {}],
  ] as const) {
    const response = await authorize(params)
    const location = response.headers.get("location") ?? ""
    if (!location.startsWith(redirectUri) || new URL(location).searchParams.get("error") !== "invalid_request") {
      fail(`${label} is rejected`, `${response.status} ${location}`)
    }
  }
  ok("plain, empty, malformed and missing PKCE are rejected")

  const wrong = await obtainCode()
  const wrongVerifier = await exchangeCode(wrong.code, pkce().verifier)
  if (wrongVerifier.ok) fail("wrong code_verifier is rejected", "tokens issued")
  ok("wrong code_verifier is rejected")

  const unregistered = await authorize(
    { code_challenge: pkce().challenge, code_challenge_method: "S256" },
    client.client_id,
    "http://localhost:9999/elsewhere",
  )
  if (unregistered.status !== 400 || unregistered.headers.get("location")) fail("unregistered redirect_uri is not followed", `${unregistered.status}`)
  ok("unregistered redirect_uri is shown as an error, never redirected to")

  // Scopes: unknown ones are refused at authorize and on refresh.
  const badScope = await authorize({ code_challenge: pkce().challenge, code_challenge_method: "S256", scope: "admin root" })
  const badScopeLocation = badScope.headers.get("location") ?? ""
  if (!badScopeLocation.startsWith(redirectUri) || new URL(badScopeLocation).searchParams.get("error") !== "invalid_scope") {
    fail("unknown scope is rejected at authorize", `${badScope.status} ${badScopeLocation}`)
  }
  const scoped = await obtainCode()
  const scopedTokens = await (await exchangeCode(scoped.code, scoped.verifier)).json()
  const widened = await refresh(scopedTokens.refresh_token, { scope: "mcp:tools admin" })
  if (widened.ok || (await widened.json()).error !== "invalid_scope") fail("refresh cannot widen scope", "request was not refused with invalid_scope")
  const stillGood = await refresh(scopedTokens.refresh_token, { scope: "mcp:tools" })
  if (!stillGood.ok) fail("a refused scope request does not spend the refresh token", `${stillGood.status}`)
  ok("unknown scopes are rejected at authorize and refresh; a refused refresh keeps its token")

  // Registration: plain http to a remote host is refused; so is a credentialed or fragment URI.
  for (const uri of ["http://attacker.example/cb", "https://client.example/cb#frag", "ftp://client.example/cb", "myapp://callback"]) {
    const response = await register({ client_name: "bad redirect", redirect_uris: [uri], token_endpoint_auth_method: "none" })
    const body = await response.json().catch(() => ({}))
    if (response.status !== 400 || body.error !== "invalid_redirect_uri") fail(`redirect_uri ${uri} is rejected`, `${response.status} ${JSON.stringify(body)}`)
  }
  ok("registration refuses non-https remote, fragment and unqualified-scheme redirect URIs")

  // Registration without an auth method yields a client that can actually use its secret.
  const secretClientResponse = await register({ client_name: "secret client", redirect_uris: ["https://client.example/cb"] })
  const secretClient = await secretClientResponse.json()
  if (secretClient.token_endpoint_auth_method !== "client_secret_post" || !secretClient.client_secret) {
    fail("default registration is usable", JSON.stringify(secretClient))
  }
  const noSecret = await postForm(meta.token_endpoint, { grant_type: "refresh_token", refresh_token: "x", client_id: secretClient.client_id })
  if (noSecret.status !== 400 || (await noSecret.json()).error !== "invalid_client") fail("confidential client needs its secret", `${noSecret.status}`)
  ok("a client registered without an auth method gets client_secret_post, and its secret is enforced")

  // OPTIONS must not run the authorize handler.
  const options = await fetch(`${meta.authorization_endpoint}?client_id=${client.client_id}&response_type=code`, { method: "OPTIONS", redirect: "manual" })
  if (options.status !== 405) fail("OPTIONS /authorize does not run the handler", `got ${options.status}`)
  ok("OPTIONS /authorize is refused")

  // Login page: injected markup is inert, the client is named, remote redirects need confirmation.
  const evilName = `<img src=x onerror=alert(1)>"'`
  const remoteResponse = await register({ client_name: evilName, redirect_uris: ["https://client.example/cb"], token_endpoint_auth_method: "none" })
  const remote = await remoteResponse.json()
  const remoteAuthorize = await authorize(
    { code_challenge: pkce().challenge, code_challenge_method: "S256" },
    remote.client_id,
    "https://client.example/cb",
  )
  const remoteId = new URL(remoteAuthorize.headers.get("location") ?? "", base).searchParams.get("request") ?? ""
  const remotePage = await fetch(`${base}/login?request=${encodeURIComponent(remoteId)}`)
  const remoteHtml = await remotePage.text()
  const csp = remotePage.headers.get("content-security-policy") ?? ""
  if (remoteHtml.includes("<img")) fail("client name is escaped", "raw <img> in the login page")
  if (!remoteHtml.includes("&lt;img")) fail("client name is shown, escaped", remoteHtml.slice(0, 200))
  if (!remoteHtml.includes("client.example")) fail("login page shows the redirect host", "client.example missing")
  if (!csp.includes("default-src 'none'") || !csp.includes("frame-ancestors 'none'")) fail("login page sends a strict CSP", csp)
  ok("login page names the client (escaped), shows the redirect host, sends CSP with frame-ancestors")

  for (const payload of [`"><script>alert(1)</script>`, `' onfocus='alert(1)`, "short"]) {
    const response = await fetch(`${base}/login?request=${encodeURIComponent(payload)}`)
    const text = await response.text()
    if (response.status !== 400 || text.includes("<script") || text.includes(payload.slice(0, 3) + "<")) fail("malformed request id is refused", `${response.status} ${text.slice(0, 80)}`)
    const post = await postForm(`${base}/login`, { request: payload, password: "wrong-password-here" })
    if (post.status !== 400 || (await post.text()).includes("<script")) fail("malformed request id is refused on POST", `${post.status}`)
  }
  ok("script payloads in the request parameter are refused, never echoed")

  const unconfirmed = await postForm(`${base}/login`, { request: remoteId, password })
  if (unconfirmed.status !== 400 || unconfirmed.headers.get("location")) fail("remote redirect needs confirmation", `${unconfirmed.status}`)
  const confirmed = await postForm(`${base}/login`, { request: remoteId, password, confirm: "yes" })
  if (!(confirmed.headers.get("location") ?? "").startsWith("https://client.example/cb?code=")) fail("confirmed login redirects", `${confirmed.status}`)
  ok("a non-loopback redirect is refused without the confirmation box and issued with it")

  // Brute force: a burst of parallel guesses is capped exactly, and an IPv6 /64 shares one budget.
  if (isLocal || process.env.VERIFY_LOCKOUT === "1") {
    const dummy = randomBytes(18).toString("base64url")
    const guess = (ip: string) => postForm(`${base}/login`, { request: dummy, password: "wrong-password-here" }, { "x-forwarded-for": ip })
    const v4 = await Promise.all(Array.from({ length: 40 }, () => guess("198.51.100.77")))
    const evaluated = v4.filter((r) => r.status !== 429).length
    if (evaluated !== 10 || v4.filter((r) => r.status === 429).length !== 30) fail("parallel guesses are capped", `${evaluated} evaluated of 40`)
    const v6 = await Promise.all(Array.from({ length: 40 }, (_, i) => guess(`2001:db8:aaaa:bbbb:${i}::${i + 1}`)))
    const evaluated6 = v6.filter((r) => r.status !== 429).length
    if (evaluated6 !== 10) fail("an IPv6 /64 shares one budget", `${evaluated6} evaluated of 40`)
    ok("40 parallel wrong passwords: exactly 10 evaluated, the rest 429; one IPv6 /64 gets the same 10")
  } else {
    console.log("  skip parallel login cap (remote server; set VERIFY_LOCKOUT=1 to run it and accept a 15-minute lockout of your address)")
  }

  console.log("\nall checks passed")
}

main().catch((error) => {
  console.error("\nverification failed:", error)
  process.exit(1)
})
