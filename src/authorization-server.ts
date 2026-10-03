/**
 * The OAuth 2.1 authorization-server endpoints: metadata, dynamic client
 * registration (RFC 7591), authorize, token and revocation (RFC 7009).
 *
 * The MCP v2 SDK is a resource-server library; it verifies tokens and publishes
 * metadata but does not issue them, and the frozen v1 helpers were moved to a
 * deprecated package. So the HTTP surface lives here and the decisions behind it
 * (what a code is, when a token is valid) live in `oauth-provider.ts`. The
 * endpoints, request shapes and error bodies are the ones the v1 SDK served, so
 * clients registered against an older deployment keep working.
 */
import { createHash, randomBytes, randomUUID, timingSafeEqual } from "node:crypto"
import express, { Router, type NextFunction, type Request, type RequestHandler, type Response } from "express"
import { rateLimit } from "express-rate-limit"
import { z } from "zod"

import { OAuthClientMetadataSchema, OAuthTokenRevocationRequestSchema } from "@modelcontextprotocol/core"
import { OAuthError, OAuthErrorCode, type OAuthClientInformationFull, type OAuthMetadata } from "@modelcontextprotocol/server"

import type { PostgresOAuthProvider } from "./oauth-provider.js"

const CLIENT_SECRET_EXPIRY_SECONDS = 30 * 24 * 60 * 60
const LOOPBACK_HOSTS = new Set(["localhost", "127.0.0.1", "[::1]"])

export function buildOAuthMetadata(issuer: URL, scopes: string[]): OAuthMetadata {
  return {
    issuer: issuer.href,
    authorization_endpoint: new URL("/authorize", issuer).href,
    token_endpoint: new URL("/token", issuer).href,
    registration_endpoint: new URL("/register", issuer).href,
    revocation_endpoint: new URL("/revoke", issuer).href,
    response_types_supported: ["code"],
    code_challenge_methods_supported: ["S256"],
    token_endpoint_auth_methods_supported: ["client_secret_post", "none"],
    grant_types_supported: ["authorization_code", "refresh_token"],
    revocation_endpoint_auth_methods_supported: ["client_secret_post"],
    scopes_supported: scopes,
  }
}

/** RFC 8252: a loopback redirect may differ from the registered one only in its port. */
export function redirectUriMatches(requested: string, registered: string): boolean {
  if (requested === registered) return true
  let req: URL
  let reg: URL
  try {
    req = new URL(requested)
    reg = new URL(registered)
  } catch {
    return false
  }
  if (!LOOPBACK_HOSTS.has(req.hostname) || !LOOPBACK_HOSTS.has(reg.hostname)) return false
  return req.protocol === reg.protocol && req.hostname === reg.hostname && req.pathname === reg.pathname && req.search === reg.search
}

function sendOAuthError(res: Response, error: unknown): void {
  if (error instanceof OAuthError) {
    res.status(error.code === OAuthErrorCode.ServerError ? 500 : 400).json(error.toResponseObject())
    return
  }
  console.error("oauth endpoint failed", error)
  res.status(500).json(new OAuthError(OAuthErrorCode.ServerError, "Internal Server Error").toResponseObject())
}

function allowedMethods(methods: string[]): RequestHandler {
  return (req, res, next) => {
    if (req.method === "OPTIONS" || methods.includes(req.method)) return next()
    res
      .status(405)
      .set("Allow", methods.join(", "))
      .json(new OAuthError(OAuthErrorCode.MethodNotAllowed, `The method ${req.method} is not allowed for this endpoint`).toResponseObject())
  }
}

/** Token, registration and revocation are called by browser-based clients, so they answer cross-origin requests. */
function cors(methods: string[]): RequestHandler {
  return (req, res, next) => {
    res.setHeader("Access-Control-Allow-Origin", "*")
    if (req.method === "OPTIONS") {
      res.setHeader("Access-Control-Allow-Methods", methods.join(", "))
      res.setHeader("Access-Control-Allow-Headers", req.headers["access-control-request-headers"] ?? "content-type")
      res.sendStatus(204)
      return
    }
    next()
  }
}

/** Keyed on `req.ip`, which Express resolves through `trust proxy`, so each client has its own budget. */
function limiter(windowMinutes: number, max: number, what: string): RequestHandler {
  return rateLimit({
    windowMs: windowMinutes * 60 * 1000,
    limit: max,
    standardHeaders: true,
    legacyHeaders: false,
    message: new OAuthError(OAuthErrorCode.TooManyRequests, `You have exceeded the rate limit for ${what}`).toResponseObject(),
  })
}

const sameSecret = (a: string, b: string) =>
  timingSafeEqual(createHash("sha256").update(a).digest(), createHash("sha256").update(b).digest())

/** Client authentication for the token and revocation endpoints (`client_secret_post` or a public client). */
function authenticateClient(provider: PostgresOAuthProvider): RequestHandler {
  const Body = z.object({ client_id: z.string(), client_secret: z.string().optional() })
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      const parsed = Body.safeParse(req.body)
      if (!parsed.success) throw new OAuthError(OAuthErrorCode.InvalidRequest, parsed.error.message)
      const { client_id, client_secret } = parsed.data

      const client = await provider.clientsStore.getClient(client_id)
      if (!client) throw new OAuthError(OAuthErrorCode.InvalidClient, "Invalid client_id")

      if (client.client_secret) {
        if (!client_secret) throw new OAuthError(OAuthErrorCode.InvalidClient, "Client secret is required")
        if (!sameSecret(client.client_secret, client_secret)) throw new OAuthError(OAuthErrorCode.InvalidClient, "Invalid client_secret")
        if (client.client_secret_expires_at && client.client_secret_expires_at < Math.floor(Date.now() / 1000)) {
          throw new OAuthError(OAuthErrorCode.InvalidClient, "Client secret has expired")
        }
      }
      res.locals.client = client
      next()
    } catch (error) {
      sendOAuthError(res, error)
    }
  }
}

/** PKCE S256 (RFC 7636): the verifier hashes to the challenge stored with the code. */
function verifierMatches(codeVerifier: string, codeChallenge: string): boolean {
  if (!/^[A-Za-z0-9._~-]{43,128}$/.test(codeVerifier)) return false
  const expected = Buffer.from(createHash("sha256").update(codeVerifier).digest("base64url"))
  const actual = Buffer.from(codeChallenge)
  return expected.length === actual.length && timingSafeEqual(expected, actual)
}

const AuthorizeClientParams = z.object({
  client_id: z.string(),
  redirect_uri: z.string().refine((v) => URL.canParse(v), { message: "redirect_uri must be a valid URL" }).optional(),
})

const AuthorizeRequestParams = z.object({
  response_type: z.literal("code"),
  code_challenge: z.string(),
  code_challenge_method: z.literal("S256"),
  scope: z.string().optional(),
  state: z.string().optional(),
  resource: z.url().optional(),
})

const TokenRequest = z.object({ grant_type: z.string() })
const AuthorizationCodeGrant = z.object({
  code: z.string(),
  code_verifier: z.string(),
  redirect_uri: z.string().optional(),
  resource: z.url().optional(),
})
const RefreshTokenGrant = z.object({
  refresh_token: z.string(),
  scope: z.string().optional(),
  resource: z.url().optional(),
})

function errorRedirect(redirectUri: string, error: OAuthError, state?: string): string {
  const target = new URL(redirectUri)
  target.searchParams.set("error", error.code)
  target.searchParams.set("error_description", error.message)
  if (state) target.searchParams.set("state", state)
  return target.href
}

export function authorizationServerRouter(provider: PostgresOAuthProvider): Router {
  const router = Router()
  const form = express.urlencoded({ extended: false })

  // Registration: any client may register itself, which is the point of RFC 7591,
  // so the budget is tight.
  router.use(
    "/register",
    cors(["POST"]),
    allowedMethods(["POST"]),
    express.json(),
    limiter(60, 20, "client registration requests"),
    async (req, res) => {
      res.setHeader("Cache-Control", "no-store")
      try {
        const parsed = OAuthClientMetadataSchema.safeParse(req.body)
        if (!parsed.success) throw new OAuthError(OAuthErrorCode.InvalidClientMetadata, parsed.error.message)

        const isPublic = parsed.data.token_endpoint_auth_method === "none"
        const issuedAt = Math.floor(Date.now() / 1000)
        const client: OAuthClientInformationFull = {
          ...parsed.data,
          client_id: randomUUID(),
          client_id_issued_at: issuedAt,
          client_secret: isPublic ? undefined : randomBytes(32).toString("hex"),
          client_secret_expires_at: isPublic ? undefined : issuedAt + CLIENT_SECRET_EXPIRY_SECONDS,
        }
        res.status(201).json(await provider.clientsStore.registerClient(client))
      } catch (error) {
        sendOAuthError(res, error)
      }
    },
  )

  router.use("/authorize", allowedMethods(["GET", "POST"]), form, limiter(15, 100, "authorization requests"), async (req, res) => {
    res.setHeader("Cache-Control", "no-store")
    const params = req.method === "POST" ? req.body : req.query

    // Until the client and redirect URI are proven, errors are shown to the user;
    // redirecting to an unverified address would turn this into an open redirector.
    let client: OAuthClientInformationFull
    let redirectUri: string
    try {
      const clientParams = AuthorizeClientParams.safeParse(params)
      if (!clientParams.success) throw new OAuthError(OAuthErrorCode.InvalidRequest, clientParams.error.message)

      const found = await provider.clientsStore.getClient(clientParams.data.client_id)
      if (!found) throw new OAuthError(OAuthErrorCode.InvalidClient, "Invalid client_id")
      client = found

      const requested = clientParams.data.redirect_uri
      if (requested !== undefined) {
        if (!client.redirect_uris.some((registered) => redirectUriMatches(requested, registered))) {
          throw new OAuthError(OAuthErrorCode.InvalidRequest, "Unregistered redirect_uri")
        }
        redirectUri = requested
      } else if (client.redirect_uris.length === 1) {
        redirectUri = client.redirect_uris[0]
      } else {
        throw new OAuthError(OAuthErrorCode.InvalidRequest, "redirect_uri must be specified when client has multiple registered URIs")
      }
    } catch (error) {
      sendOAuthError(res, error)
      return
    }

    let state: string | undefined
    try {
      const request = AuthorizeRequestParams.safeParse(params)
      if (!request.success) {
        state = typeof params.state === "string" ? params.state : undefined
        throw new OAuthError(OAuthErrorCode.InvalidRequest, request.error.message)
      }
      state = request.data.state
      await provider.authorize(
        client,
        {
          state,
          scopes: request.data.scope === undefined ? [] : request.data.scope.split(" "),
          redirectUri,
          codeChallenge: request.data.code_challenge,
          resource: request.data.resource ? new URL(request.data.resource) : undefined,
        },
        res,
      )
    } catch (error) {
      const oauthError = error instanceof OAuthError ? error : new OAuthError(OAuthErrorCode.ServerError, "Internal Server Error")
      if (!(error instanceof OAuthError)) console.error("authorize failed", error)
      res.redirect(302, errorRedirect(redirectUri, oauthError, state))
    }
  })

  router.use(
    "/token",
    cors(["POST"]),
    allowedMethods(["POST"]),
    form,
    limiter(15, 50, "token requests"),
    authenticateClient(provider),
    async (req, res) => {
      res.setHeader("Cache-Control", "no-store")
      try {
        const client = res.locals.client as OAuthClientInformationFull
        const base = TokenRequest.safeParse(req.body)
        if (!base.success) throw new OAuthError(OAuthErrorCode.InvalidRequest, base.error.message)

        switch (base.data.grant_type) {
          case "authorization_code": {
            const grant = AuthorizationCodeGrant.safeParse(req.body)
            if (!grant.success) throw new OAuthError(OAuthErrorCode.InvalidRequest, grant.error.message)
            const { code, code_verifier, redirect_uri, resource } = grant.data

            const challenge = await provider.challengeForAuthorizationCode(client, code)
            if (!verifierMatches(code_verifier, challenge)) {
              throw new OAuthError(OAuthErrorCode.InvalidGrant, "code_verifier does not match the challenge")
            }
            res.json(await provider.exchangeAuthorizationCode(client, code, redirect_uri, resource ? new URL(resource) : undefined))
            return
          }
          case "refresh_token": {
            const grant = RefreshTokenGrant.safeParse(req.body)
            if (!grant.success) throw new OAuthError(OAuthErrorCode.InvalidRequest, grant.error.message)
            const { refresh_token, scope, resource } = grant.data
            res.json(await provider.exchangeRefreshToken(client, refresh_token, scope?.split(" "), resource ? new URL(resource) : undefined))
            return
          }
          default:
            throw new OAuthError(OAuthErrorCode.UnsupportedGrantType, "The grant type is not supported by this authorization server.")
        }
      } catch (error) {
        sendOAuthError(res, error)
      }
    },
  )

  router.use(
    "/revoke",
    cors(["POST"]),
    allowedMethods(["POST"]),
    form,
    limiter(15, 50, "token revocation requests"),
    authenticateClient(provider),
    async (req, res) => {
      res.setHeader("Cache-Control", "no-store")
      try {
        const parsed = OAuthTokenRevocationRequestSchema.safeParse(req.body)
        if (!parsed.success) throw new OAuthError(OAuthErrorCode.InvalidRequest, parsed.error.message)
        await provider.revokeToken(res.locals.client as OAuthClientInformationFull, parsed.data)
        res.status(200).json({})
      } catch (error) {
        sendOAuthError(res, error)
      }
    },
  )

  return router
}
