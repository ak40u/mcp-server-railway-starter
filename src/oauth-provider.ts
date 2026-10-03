/**
 * OAuth 2.1 authorization server, backed by Postgres.
 *
 * `authorization-server.ts` supplies the HTTP endpoints (discovery, dynamic
 * registration, token, revocation); this file supplies the decisions behind
 * them. Everything is stored server-side, so no replica has to remember
 * anything. Codes and tokens are stored only as SHA-256 hashes, so a database
 * dump hands over no working token. Client secrets are the exception: they are
 * kept as issued, because client authentication compares them directly.
 *
 * Every code and token carries a `grant_id`: one id per authorization. Reusing
 * a spent code or a rotated refresh token is evidence that a credential leaked,
 * so it revokes everything issued under that grant.
 */
import { createHash, randomBytes, randomUUID, timingSafeEqual } from "node:crypto"
import type { PoolClient } from "pg"
import type { Response } from "express"

import {
  OAuthError,
  OAuthErrorCode,
  type AuthInfo,
  type OAuthClientInformationFull,
  type OAuthTokenRevocationRequest,
  type OAuthTokens,
  type OAuthTokenVerifier,
} from "@modelcontextprotocol/server"

import { inTransaction, pool } from "./db.js"
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

/** What /authorize hands over once the client and redirect URI are validated. */
export interface AuthorizationParams {
  state?: string
  scopes?: string[]
  codeChallenge: string
  redirectUri: string
  resource?: URL
}

const invalidGrant = (message: string) => new OAuthError(OAuthErrorCode.InvalidGrant, message)

class PostgresClientsStore {
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

export class PostgresOAuthProvider implements OAuthTokenVerifier {
  readonly clientsStore = new PostgresClientsStore()

  /**
   * The endpoint has already validated the request against the registered
   * client by the time we get here. What is left is proving the human is present, so the
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

  /** What the login page shows the person about to consent: who is asking and where the code will go. */
  async describePendingAuthorization(pendingId: string): Promise<{ clientName: string | null; redirectUri: string } | undefined> {
    const { rows } = await pool.query<{ client_name: string | null; redirect_uri: string }>(
      `select c.client_name, p.redirect_uri
       from oauth_pending_authorizations p join oauth_clients c on c.client_id = p.client_id
       where p.id = $1 and p.created_at > now() - interval '15 minutes'`,
      [pendingId],
    )
    return rows[0] ? { clientName: rows[0].client_name, redirectUri: rows[0].redirect_uri } : undefined
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
      `insert into oauth_codes (code_hash, client_id, redirect_uri, code_challenge, scopes, resource, grant_id, expires_at)
       values ($1, $2, $3, $4, $5, $6, $7, now() + ($8 || ' seconds')::interval)`,
      [
        hash(code),
        pending.client_id,
        pending.redirect_uri,
        pending.code_challenge,
        pending.scopes,
        pending.resource,
        randomUUID(),
        String(env.authorizationCodeTtlSeconds),
      ],
    )
    return { redirectUri: pending.redirect_uri, code, state: pending.state ?? undefined }
  }

  /** Revokes every token issued under the grant. A null grant (a row from before grants existed) has no family to find. */
  private async revokeGrant(grantId: string | null | undefined): Promise<void> {
    if (!grantId) return
    await pool.query(`update oauth_tokens set revoked_at = now() where grant_id = $1 and revoked_at is null`, [grantId])
  }

  async challengeForAuthorizationCode(client: OAuthClientInformationFull, authorizationCode: string): Promise<string> {
    const { rows } = await pool.query<{ code_challenge: string; consumed: boolean; live: boolean; grant_id: string | null }>(
      `select code_challenge, consumed_at is not null as consumed, expires_at > now() as live, grant_id
       from oauth_codes where code_hash = $1 and client_id = $2`,
      [hash(authorizationCode), client.client_id],
    )
    const code = rows[0]
    if (!code) throw invalidGrant("Authorization code is invalid or expired")
    if (code.consumed) {
      // A second presentation means the code was copied: whoever redeemed it
      // first holds tokens that should not survive this.
      await this.revokeGrant(code.grant_id)
      throw invalidGrant("Authorization code is invalid, expired or already used")
    }
    if (!code.live) throw invalidGrant("Authorization code is invalid or expired")
    return code.code_challenge
  }

  async exchangeAuthorizationCode(
    client: OAuthClientInformationFull,
    authorizationCode: string,
    redirectUri?: string,
    resource?: URL,
  ): Promise<OAuthTokens> {
    // Marking the code consumed in the same statement that reads it is what
    // makes replay impossible: a second exchange finds nothing to update.
    const outcome = await inTransaction(async (db) => {
      const { rows } = await db.query(
        `update oauth_codes set consumed_at = now(), grant_id = coalesce(grant_id, $3)
         where code_hash = $1 and client_id = $2 and consumed_at is null and expires_at > now()
         returning redirect_uri, scopes, resource, grant_id`,
        [hash(authorizationCode), client.client_id, randomUUID()],
      )
      const code = rows[0]
      if (!code) return undefined
      if (redirectUri && redirectUri !== code.redirect_uri) throw invalidGrant("redirect_uri does not match")
      return this.issueTokens(db, client.client_id, code.grant_id, code.scopes, resource?.href ?? code.resource)
    })
    if (outcome) return outcome

    // Lost a race with another exchange of the same code: treat it as a replay.
    const { rows } = await pool.query(`select grant_id from oauth_codes where code_hash = $1 and client_id = $2`, [
      hash(authorizationCode),
      client.client_id,
    ])
    await this.revokeGrant(rows[0]?.grant_id)
    throw invalidGrant("Authorization code is invalid, expired or already used")
  }

  async exchangeRefreshToken(
    client: OAuthClientInformationFull,
    refreshToken: string,
    scopes?: string[],
    resource?: URL,
  ): Promise<OAuthTokens> {
    const outcome = await inTransaction(async (db) => {
      const { rows } = await db.query(
        `update oauth_tokens set revoked_at = now(), rotated_at = now(), grant_id = coalesce(grant_id, $3)
         where token_hash = $1 and kind = 'refresh' and client_id = $2 and revoked_at is null and expires_at > now()
         returning scopes, resource, grant_id`,
        [hash(refreshToken), client.client_id, randomUUID()],
      )
      const token = rows[0]
      if (!token) return undefined

      // A refresh may narrow the scopes it was granted, never widen them. The
      // check throws before commit, so a bad request does not spend the token.
      const granted: string[] = token.scopes
      if (scopes?.length && !scopes.every((s) => granted.includes(s))) {
        throw new OAuthError(OAuthErrorCode.InvalidScope, "Requested scope exceeds the scope originally granted")
      }
      // A token from before grants existed was given its family id by the update above.
      return this.issueTokens(db, client.client_id, token.grant_id, scopes?.length ? scopes : granted, resource?.href ?? token.resource)
    })
    if (outcome) return outcome

    // Not usable. If it was spent by rotation, someone is presenting a copy of
    // a token that has already been replaced: revoke the family, including the
    // current descendant, so a thief and the owner both have to start over.
    const { rows } = await pool.query(
      `select grant_id from oauth_tokens where token_hash = $1 and kind = 'refresh' and client_id = $2 and rotated_at is not null`,
      [hash(refreshToken), client.client_id],
    )
    await this.revokeGrant(rows[0]?.grant_id)
    throw invalidGrant("Refresh token is invalid, expired or already used")
  }

  async verifyAccessToken(token: string): Promise<AuthInfo> {
    const { rows } = await pool.query(
      `select client_id, scopes, resource, extract(epoch from expires_at) as expires_at
       from oauth_tokens
       where token_hash = $1 and kind = 'access' and revoked_at is null and expires_at > now()`,
      [hash(token)],
    )
    const found = rows[0]
    if (!found) throw new OAuthError(OAuthErrorCode.InvalidToken, "Token is invalid or expired")

    return {
      token,
      clientId: found.client_id,
      scopes: found.scopes,
      expiresAt: Number(found.expires_at),
      resource: found.resource ? new URL(found.resource) : undefined,
    }
  }

  /** Revoking a refresh token ends its whole grant, access tokens included; an access token revokes only itself. */
  async revokeToken(client: OAuthClientInformationFull, request: OAuthTokenRevocationRequest): Promise<void> {
    await pool.query(
      `update oauth_tokens set revoked_at = now()
       where client_id = $2 and revoked_at is null
         and (token_hash = $1
              or grant_id = (select grant_id from oauth_tokens where token_hash = $1 and client_id = $2 and kind = 'refresh'))`,
      [hash(request.token), client.client_id],
    )
  }

  private async issueTokens(
    db: PoolClient,
    clientId: string,
    grantId: string,
    scopes: string[],
    resource: string | null | undefined,
  ): Promise<OAuthTokens> {
    const accessToken = secret()
    const refreshToken = secret()
    await db.query(
      `insert into oauth_tokens (token_hash, kind, client_id, scopes, resource, grant_id, expires_at)
       values ($1, 'access',  $3, $4, $5, $8, now() + ($6 || ' seconds')::interval),
              ($2, 'refresh', $3, $4, $5, $8, now() + ($7 || ' seconds')::interval)`,
      [
        hash(accessToken),
        hash(refreshToken),
        clientId,
        scopes,
        resource ?? null,
        String(env.accessTokenTtlSeconds),
        String(env.refreshTokenTtlSeconds),
        grantId,
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
