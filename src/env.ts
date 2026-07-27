/**
 * Configuration, read once and validated at boot.
 *
 * The server refuses to start on a bad value rather than failing later inside a
 * request: a half-configured OAuth server is worse than one that is plainly down.
 */

function required(name: string): string {
  const value = process.env[name]
  if (!value) {
    console.error(`${name} is not set. The server cannot start without it.`)
    process.exit(1)
  }
  return value
}

const publicUrl = process.env.PUBLIC_URL || (process.env.RAILWAY_PUBLIC_DOMAIN ? `https://${process.env.RAILWAY_PUBLIC_DOMAIN}` : "")

if (!publicUrl) {
  console.error("PUBLIC_URL is not set and no public domain was found. OAuth needs to know its own address.")
  process.exit(1)
}

// The issuer identifier goes into signed metadata and into every token audience
// check, so it has to be the exact origin clients reach us on - no trailing
// slash, no path.
const issuer = new URL(publicUrl).origin

const adminPassword = required("MCP_ADMIN_PASSWORD")

if (adminPassword.length < 12) {
  console.error("MCP_ADMIN_PASSWORD is shorter than 12 characters. Pick a longer one.")
  process.exit(1)
}

export const env = {
  port: Number(process.env.PORT ?? 8080),
  databaseUrl: required("DATABASE_URL"),
  issuer,
  adminPassword,
  serverName: process.env.MCP_SERVER_NAME || "mcp-starter",
  // Access tokens stay short because there is a refresh token behind them; an
  // hour bounds the damage from a leaked one without making clients reconnect.
  accessTokenTtlSeconds: Number(process.env.ACCESS_TOKEN_TTL_SECONDS ?? 3600),
  refreshTokenTtlSeconds: Number(process.env.REFRESH_TOKEN_TTL_SECONDS ?? 60 * 60 * 24 * 30),
  authorizationCodeTtlSeconds: 60,
  scopes: ["mcp:tools"],
}

export type Env = typeof env
