/**
 * The human step of the authorization flow.
 *
 * An MCP client can register itself and ask for a token without anyone
 * watching. This page is the one point where a person has to prove they are
 * there, so it is also the one point worth rate limiting.
 */
import { Router, type RequestHandler } from "express"
import { ipKeyGenerator } from "express-rate-limit"

import { inTransaction, pool } from "./db.js"
import { isLoopbackRedirect } from "./authorization-server.js"
import { env } from "./env.js"
import { comparePassword, type PostgresOAuthProvider } from "./oauth-provider.js"

const MAX_ATTEMPTS = 10
const WINDOW_MINUTES = 15
// The shape `authorize` generates: 18 random bytes, base64url. Anything else is
// not a request id and is never echoed back.
const REQUEST_ID = /^[A-Za-z0-9_-]{24}$/

/**
 * Takes one attempt from the address's budget, or refuses. The attempt is
 * recorded before the password is checked, under a per-key lock, so parallel
 * requests queue up and each sees the ones before it; counting first and
 * recording later would let a burst all pass the same stale count. IPv6
 * addresses share a budget per /64, the smallest block a single subscriber
 * normally controls, so rotating inside one buys nothing.
 */
async function takeAttempt(key: string): Promise<boolean> {
  return inTransaction(async (db) => {
    await db.query(`select pg_advisory_xact_lock(hashtext($1))`, [`login:${key}`])
    const { rows } = await db.query<{ count: string }>(
      `select count(*)::text as count from login_attempts
       where ip = $1 and attempted_at > now() - ($2 || ' minutes')::interval`,
      [key, String(WINDOW_MINUTES)],
    )
    if (Number(rows[0].count) >= MAX_ATTEMPTS) return false
    await db.query(`insert into login_attempts (ip) values ($1)`, [key])
    return true
  })
}

function escapeHtml(value: string): string {
  return value.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c] as string)
}

/** Client-supplied text is untrusted: drop control and bidi-override characters, bound the length. */
function displayText(value: string, max: number): string {
  const cleaned = value.replace(/[\p{C}\u202a-\u202e\u2066-\u2069]/gu, "").trim()
  return cleaned.length > max ? `${cleaned.slice(0, max)}...` : cleaned
}

interface Requester {
  clientName: string | null
  redirectUri: string
}

/**
 * The CSP forbids scripts and every subresource, so even a markup-injection bug
 * could not run code. `form-action` is left out on purpose: Chromium applies it
 * to the redirect that follows the form post, which would block the redirect
 * back to the client.
 */
const securityHeaders: RequestHandler = (_req, res, next) => {
  res.setHeader("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'")
  res.setHeader("X-Frame-Options", "DENY")
  res.setHeader("X-Content-Type-Options", "nosniff")
  res.setHeader("Referrer-Policy", "no-referrer")
  res.setHeader("Cache-Control", "no-store")
  next()
}

function requesterBlock(requester: Requester): { html: string; needsConfirm: boolean } {
  const name = requester.clientName ? displayText(requester.clientName, 80) : ""
  const uri = displayText(requester.redirectUri, 200)
  let where = uri
  try {
    const url = new URL(requester.redirectUri)
    where = url.host || `${url.protocol}//`
  } catch {
    // Parked requests were validated at /authorize; fall back to the raw text.
  }
  const needsConfirm = !isLoopbackRedirect(requester.redirectUri)
  const html = `<div class="who">
    <p>Application: <strong>${name ? escapeHtml(name) : "(no name given)"}</strong></p>
    <p class="hint">Anyone can register an application under any name, so the name is not verified.</p>
    <p>After you sign in, an access code is sent to: <strong>${escapeHtml(displayText(where, 120))}</strong></p>
    <p class="hint"><code>${escapeHtml(uri)}</code></p>
    ${
      needsConfirm
        ? `<p class="warn">This address is not on your own computer. Continue only if you started this connection and recognise the address.</p>
    <label><input type="checkbox" name="confirm" value="yes" required> I recognise <strong>${escapeHtml(displayText(where, 120))}</strong> and want to give it access</label>`
        : `<p class="hint">This address is on your own computer.</p>`
    }
  </div>`
  return { html, needsConfirm }
}

function page(requestId: string, requester: Requester | undefined, error?: string): string {
  const message = error ? `<p class="error">${escapeHtml(error)}</p>` : ""
  const body = requester
    ? `${requesterBlock(requester).html}
  <p class="hint">Use the password from the <code>MCP_ADMIN_PASSWORD</code> variable of this service.</p>
  <input type="hidden" name="request" value="${escapeHtml(requestId)}">
  <input type="password" name="password" placeholder="Server password" autofocus required autocomplete="current-password">
  <button type="submit">Authorize</button>`
    : ""
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Authorize MCP client</title>
<style>
  :root { color-scheme: light dark; }
  body { font: 16px/1.5 system-ui, sans-serif; display: grid; place-items: center; min-height: 100vh; margin: 0; }
  form { width: min(400px, 90vw); display: grid; gap: 12px; }
  h1 { font-size: 20px; margin: 0; }
  p { margin: 0; overflow-wrap: anywhere; }
  input, button { font: inherit; padding: 10px 12px; border-radius: 8px; border: 1px solid #8884; }
  input[type=checkbox] { padding: 0; margin-right: 6px; }
  button { cursor: pointer; border-color: transparent; background: #6c5ce7; color: #fff; }
  .hint, .error { font-size: 14px; }
  .who { display: grid; gap: 8px; border: 1px solid #8884; border-radius: 8px; padding: 12px; }
  .error { color: #d63031; }
  .warn { color: #b35c00; font-weight: 600; }
  code { background: #8882; padding: 1px 4px; border-radius: 4px; }
</style>
</head>
<body>
<form method="post" action="/login">
  <h1>Authorize MCP client</h1>
  ${message}
  ${body}
</form>
</body>
</html>`
}

export function loginRouter(provider: PostgresOAuthProvider): Router {
  const router = Router()
  router.use("/login", securityHeaders)

  router.get("/login", async (req, res) => {
    const requestId = typeof req.query.request === "string" ? req.query.request : ""
    if (!REQUEST_ID.test(requestId)) {
      res.status(400).type("text/plain").send("Missing or malformed authorization request.")
      return
    }
    try {
      const requester = await provider.describePendingAuthorization(requestId)
      if (!requester) {
        res.status(400).type("html").send(page(requestId, undefined, "This authorization request expired. Start again from your client."))
        return
      }
      res.type("html").send(page(requestId, requester))
    } catch (error) {
      console.error("login page failed", error)
      res.status(500).type("text/plain").send("Internal Server Error")
    }
  })

  router.post("/login", async (req, res) => {
    const requestId = typeof req.body?.request === "string" ? req.body.request : ""
    const password = typeof req.body?.password === "string" ? req.body.password : ""
    if (!REQUEST_ID.test(requestId)) {
      res.status(400).type("text/plain").send("Missing or malformed authorization request.")
      return
    }
    // Behind the platform proxy the socket address is always internal. `req.ip`
    // is resolved through `trust proxy`, which counts exactly the proxy hops we
    // trust, so a client cannot choose its own address with an X-Forwarded-For header.
    const key = ipKeyGenerator(req.ip ?? "unknown", 64)

    try {
      const requester = await provider.describePendingAuthorization(requestId)

      if (!(await takeAttempt(key))) {
        res.status(429).type("html").send(page(requestId, requester, "Too many attempts. Try again later."))
        return
      }
      if (!comparePassword(password, env.adminPassword)) {
        res.status(401).type("html").send(page(requestId, requester, "Wrong password."))
        return
      }
      if (!requester) {
        res.status(400).type("html").send(page(requestId, undefined, "This authorization request expired. Start again from your client."))
        return
      }
      if (!isLoopbackRedirect(requester.redirectUri) && req.body?.confirm !== "yes") {
        res.status(400).type("html").send(page(requestId, requester, "Confirm that you recognise the address above."))
        return
      }

      const { redirectUri, code, state } = await provider.issueCodeForPendingAuthorization(requestId)
      const target = new URL(redirectUri)
      target.searchParams.set("code", code)
      if (state) target.searchParams.set("state", state)
      // Clear the attempt history for this address on success, so a person who
      // mistyped a few times is not locked out of their own server.
      await pool.query(`delete from login_attempts where ip = $1`, [key])
      res.redirect(target.href)
    } catch (error) {
      // The only expected failure is a request that expired or was used between
      // the lookup and the exchange; a database error looks the same to the user.
      console.error("login failed", error)
      res.status(400).type("html").send(page(requestId, undefined, "This authorization request expired. Start again from your client."))
    }
  })

  return router
}
