/**
 * The human step of the authorization flow.
 *
 * An MCP client can register itself and ask for a token without anyone
 * watching. This page is the one point where a person has to prove they are
 * there, so it is also the one point worth rate limiting.
 */
import { Router, type Request } from "express"

import { pool } from "./db.js"
import { env } from "./env.js"
import { comparePassword, type PostgresOAuthProvider } from "./oauth-provider.js"

const MAX_ATTEMPTS = 10
const WINDOW_MINUTES = 15

/**
 * The client IP as Railway sees it. Behind the platform proxy the socket
 * address is always internal, so a limiter keyed on it would be a limiter on
 * the whole world at once.
 */
function clientIp(req: Request): string {
  const forwarded = req.headers["x-forwarded-for"]
  const first = Array.isArray(forwarded) ? forwarded[0] : forwarded?.split(",")[0]
  return (first || req.socket.remoteAddress || "unknown").trim()
}

async function tooManyAttempts(ip: string): Promise<boolean> {
  const { rows } = await pool.query<{ count: string }>(
    `select count(*)::text as count from login_attempts
     where ip = $1 and attempted_at > now() - ($2 || ' minutes')::interval`,
    [ip, String(WINDOW_MINUTES)],
  )
  return Number(rows[0].count) >= MAX_ATTEMPTS
}

function page(requestId: string, error?: string): string {
  const message = error
    ? `<p class="error">${error}</p>`
    : `<p class="hint">This is the password from the <code>MCP_ADMIN_PASSWORD</code> variable of this service.</p>`
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Authorize MCP client</title>
<style>
  :root { color-scheme: light dark; }
  body { font: 16px/1.5 system-ui, sans-serif; display: grid; place-items: center; min-height: 100vh; margin: 0; }
  form { width: min(360px, 90vw); display: grid; gap: 12px; }
  h1 { font-size: 20px; margin: 0; }
  input, button { font: inherit; padding: 10px 12px; border-radius: 8px; border: 1px solid #8884; }
  button { cursor: pointer; border-color: transparent; background: #6c5ce7; color: #fff; }
  .hint, .error { font-size: 14px; margin: 0; }
  .error { color: #d63031; }
  code { background: #8882; padding: 1px 4px; border-radius: 4px; }
</style>
</head>
<body>
<form method="post" action="/login">
  <h1>Authorize MCP client</h1>
  ${message}
  <input type="hidden" name="request" value="${requestId}">
  <input type="password" name="password" placeholder="Server password" autofocus required autocomplete="current-password">
  <button type="submit">Authorize</button>
</form>
</body>
</html>`
}

export function loginRouter(provider: PostgresOAuthProvider): Router {
  const router = Router()

  router.get("/login", (req, res) => {
    const requestId = String(req.query.request ?? "")
    if (!requestId) {
      res.status(400).send("Missing authorization request.")
      return
    }
    res.type("html").send(page(requestId))
  })

  router.post("/login", async (req, res) => {
    const requestId = String(req.body?.request ?? "")
    const password = String(req.body?.password ?? "")
    const ip = clientIp(req)

    if (await tooManyAttempts(ip)) {
      res.status(429).type("html").send(page(requestId, "Too many attempts. Try again later."))
      return
    }

    if (!comparePassword(password, env.adminPassword)) {
      await pool.query(`insert into login_attempts (ip) values ($1)`, [ip])
      res.status(401).type("html").send(page(requestId, "Wrong password."))
      return
    }

    try {
      const { redirectUri, code, state } = await provider.issueCodeForPendingAuthorization(requestId)
      const target = new URL(redirectUri)
      target.searchParams.set("code", code)
      if (state) target.searchParams.set("state", state)
      // Clear the attempt history for this address on success, so a person who
      // mistyped a few times is not locked out of their own server.
      await pool.query(`delete from login_attempts where ip = $1`, [ip])
      res.redirect(target.href)
    } catch {
      res.status(400).type("html").send(page(requestId, "This authorization request expired. Start again from your client."))
    }
  })

  return router
}
