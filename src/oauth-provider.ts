/**
 * OAuth 2.1 authorization server, backed by Postgres.
 *
 * The MCP SDK supplies the endpoints (discovery, dynamic registration, token,
 * revocation); this file supplies the decisions behind them. Everything is
 * stored server-side and hashed, so no replica has to remember anything and a
 * database dump does not hand over working credentials.
 */
import { createHash, randomBytes, timingSafeEqual } from "node:crypto"
import type { Response } from "express"

import type { OAuthRegisteredClientsStore } from "@modelcontextprotocol/sdk/server/auth/clients.js"
import type { AuthorizationParams, OAuthServerProvider } from "@modelcontextprotocol/sdk/server/auth/provider.js"
import type { AuthInfo } from "@modelcontextprotocol/sdk/server/auth/types.js"
import type {
  OAuthClientInformationFull,
  OAuthTokenRevocationRequest,
  OAuthTokens,
} from "@modelcontextprotocol/sdk/shared/auth.js"
import { InvalidGrantError, InvalidTokenError } from "@modelcontextprotocol/sdk/server/auth/errors.js"

import { pool } from "./db.js"
import { env } from "./env.js"

const secret = () => randomBytes(32).toString("base64url")
const hash = (value: string) => createHash("sha256").update(value).digest("hex")

export function comparePassword(candidate: string, expected: string): boolean {
  // Both sides are hashed first so the comparison runs over equal-length buffers
  // and cannot leak the password's length through timing.
  const a = createHash("sha256").update(candidate).digest()
  const b = createHash("sha256").update(expected).digest()
  return timingSafeEqual(a, b)
}

class PostgresClientsStore implements OAuthRegisteredClientsStore {
  async getClient(clientId: string): Promise<OAuthClientInformationFull | undefined> {
    const { rows } = await pool.query<{ client_info: OAuthClientInformationFull }>(
      `select client_info from oauth_clients where client_id = $1`,
      [clientId],
    )
    return rows[0]?.client_info
  }

  async registerClient(client: OAuthClientInformationFull): Promise<OAuthClientInformationFull> {
    await pool.query(
      `insert into oauth_clients (client_id, client_name, client_info) values ($1, $2, $3)
       on conflict (client_id) do update set client_info = excluded.client_info`,
      [client.client_id, client.client_name ?? null, client],
    )
    return client
  }
}

export class PostgresOAuthProvider implements OAuthServerProvider {
  readonly clientsStore = new PostgresClientsStore()

  /**
   * The SDK has already validated the request against the registered client by
   * the time we get here. What is left is proving the human is present, so the
   * flow parks the request and hands the browser to the login page.
   */
  async authorize(client: OAuthClientInformationFull, params: AuthorizationParams, res: Response): Promise<void> {
    const id = randomBytes(18).toString("base64url")
    await pool.query(
      `insert into oauth_pending_authorizations (id, client_id, redirect_uri, code_challenge, state, scopes, resource)
       values ($1, $2, $3, $4, $5, $6, $7)`,
      [
        id,
        client.client_id,
        params.redirectUri,
        params.codeChallenge,
        params.state ?? null,
        params.scopes ?? [],
        params.resource?.href ?? null,
      ],
    )
    res.redirect(`/login?request=${encodeURIComponent(id)}`)
  }

  /** Called after the password check; turns a parked request into a real code. */
  async issueCodeForPendingAuthorization(pendingId: string): Promise<{ redirectUri: string; code: string; state?: string }> {
    const { rows } = await pool.query(
      `delete from oauth_pending_authorizations
       where id = $1 and created_at > now() - interval '15 minutes'
       returning client_id, redirect_uri, code_challenge, state, scopes, resource`,
      [pendingId],
    )
    const pending = rows[0]
    if (!pending) throw new Error("authorization request expired")

    const code = secret()
    await pool.query(
      `insert into oauth_codes (code_hash, client_id, redirect_uri, code_challenge, scopes, resource, expires_at)
       values ($1, $2, $3, $4, $5, $6, now() + ($7 || ' seconds')::interval)`,
      [
        hash(code),
        pending.client_id,
        pending.redirect_uri,
        pending.code_challenge,
        pending.scopes,
        pending.resource,
        String(env.authorizationCodeTtlSeconds),
      ],
    )
    return { redirectUri: pending.redirect_uri, code, state: pending.state ?? undefined }
  }

  async challengeForAuthorizationCode(_client: OAuthClientInformationFull, authorizationCode: string): Promise<string> {
    const { rows } = await pool.query<{ code_challenge: string }>(
      `select code_challenge from oauth_codes where code_hash = $1 and consumed_at is null and expires_at > now()`,
      [hash(authorizationCode)],
    )
    if (!rows[0]) throw new InvalidGrantError("Authorization code is invalid or expired")
    return rows[0].code_challenge
  }

  async exchangeAuthorizationCode(
    client: OAuthClientInformationFull,
    authorizationCode: string,
    _codeVerifier?: string,
    redirectUri?: string,
    resource?: URL,
  ): Promise<OAuthTokens> {
    // Marking the code consumed in the same statement that reads it is what
    // makes replay impossible: a second exchange finds nothing to update.
    const { rows } = await pool.query(
      `update oauth_codes set consumed_at = now()
       where code_hash = $1 and client_id = $2 and consumed_at is null and expires_at > now()
       returning redirect_uri, scopes, resource`,
      [hash(authorizationCode), client.client_id],
    )
    const code = rows[0]
    if (!code) throw new InvalidGrantError("Authorization code is invalid, expired or already used")
    if (redirectUri && redirectUri !== code.redirect_uri) throw new InvalidGrantError("redirect_uri does not match")

    return this.issueTokens(client.client_id, code.scopes, resource?.href ?? code.resource)
  }

  async exchangeRefreshToken(
    client: OAuthClientInformationFull,
    refreshToken: string,
    scopes?: string[],
    resource?: URL,
  ): Promise<OAuthTokens> {
    const { rows } = await pool.query(
      `update oauth_tokens set revoked_at = now()
       where token_hash = $1 and kind = 'refresh' and client_id = $2 and revoked_at is null and expires_at > now()
       returning scopes, resource`,
      [hash(refreshToken), client.client_id],
    )
    const token = rows[0]
    if (!token) throw new InvalidGrantError("Refresh token is invalid, expired or already used")

    // A refresh may narrow the scopes it was granted, never widen them.
    const granted: string[] = token.scopes
    const requested = scopes?.filter((s) => granted.includes(s))
    return this.issueTokens(client.client_id, requested?.length ? requested : granted, resource?.href ?? token.resource)
  }

  async verifyAccessToken(token: string): Promise<AuthInfo> {
    const { rows } = await pool.query(
      `select client_id, scopes, resource, extract(epoch from expires_at) as expires_at
       from oauth_tokens
       where token_hash = $1 and kind = 'access' and revoked_at is null and expires_at > now()`,
      [hash(token)],
    )
    const found = rows[0]
    if (!found) throw new InvalidTokenError("Token is invalid or expired")

    return {
      token,
      clientId: found.client_id,
      scopes: found.scopes,
      expiresAt: Number(found.expires_at),
      resource: found.resource ? new URL(found.resource) : undefined,
    }
  }

  async revokeToken(client: OAuthClientInformationFull, request: OAuthTokenRevocationRequest): Promise<void> {
    await pool.query(`update oauth_tokens set revoked_at = now() where token_hash = $1 and client_id = $2`, [
      hash(request.token),
      client.client_id,
    ])
  }

  private async issueTokens(clientId: string, scopes: string[], resource: string | null | undefined): Promise<OAuthTokens> {
    const accessToken = secret()
    const refreshToken = secret()
    await pool.query(
      `insert into oauth_tokens (token_hash, kind, client_id, scopes, resource, expires_at)
       values ($1, 'access',  $3, $4, $5, now() + ($6 || ' seconds')::interval),
              ($2, 'refresh', $3, $4, $5, now() + ($7 || ' seconds')::interval)`,
      [
        hash(accessToken),
        hash(refreshToken),
        clientId,
        scopes,
        resource ?? null,
        String(env.accessTokenTtlSeconds),
        String(env.refreshTokenTtlSeconds),
      ],
    )
    return {
      access_token: accessToken,
      token_type: "Bearer",
      expires_in: env.accessTokenTtlSeconds,
      scope: scopes.join(" "),
      refresh_token: refreshToken,
    }
  }
}
