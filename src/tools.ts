/**
 * The tools this server exposes.
 *
 * These three are deliberately backed by a real table rather than returning
 * canned strings: they prove the whole path works - token, transport, handler,
 * database write - and they are the place to replace with your own.
 */
import { z } from "zod"
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js"
import type { AuthInfo } from "@modelcontextprotocol/sdk/server/auth/types.js"

import { pool } from "./db.js"
import { env } from "./env.js"

const text = (value: string) => ({ content: [{ type: "text" as const, text: value }] })

export function buildServer(auth: AuthInfo | undefined): McpServer {
  const server = new McpServer(
    { name: env.serverName, version: "1.0.0" },
    { capabilities: { tools: {} }, instructions: "Example notes server. Replace these tools with your own." },
  )

  server.registerTool(
    "add_note",
    {
      title: "Add note",
      description: "Store a note with a title and a body.",
      inputSchema: { title: z.string().min(1).max(200), body: z.string().min(1).max(20_000) },
    },
    async ({ title, body }) => {
      const { rows } = await pool.query<{ id: string }>(
        `insert into notes (title, body) values ($1, $2) returning id::text`,
        [title, body],
      )
      return text(`Saved note ${rows[0].id}.`)
    },
  )

  server.registerTool(
    "search_notes",
    {
      title: "Search notes",
      description: "Find notes whose title or body contains the query.",
      inputSchema: { query: z.string().min(1).max(200), limit: z.number().int().min(1).max(50).optional() },
    },
    async ({ query, limit }) => {
      const { rows } = await pool.query<{ id: string; title: string; body: string }>(
        `select id::text, title, body from notes
         where title ilike '%' || $1 || '%' or body ilike '%' || $1 || '%'
         order by created_at desc limit $2`,
        [query, limit ?? 10],
      )
      if (rows.length === 0) return text(`No notes match "${query}".`)
      return text(rows.map((r) => `#${r.id} ${r.title}\n${r.body}`).join("\n\n"))
    },
  )

  server.registerTool(
    "whoami",
    {
      title: "Who am I",
      description: "Report the OAuth client and scopes behind the current call.",
      inputSchema: {},
    },
    async () => {
      if (!auth) return text("No token was presented.")
      return text(`client_id: ${auth.clientId}\nscopes: ${auth.scopes.join(", ") || "(none)"}`)
    },
  )

  return server
}
