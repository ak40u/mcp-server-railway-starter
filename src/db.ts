/**
 * Postgres access and schema.
 *
 * Everything that outlives a request lives here - OAuth clients, codes and
 * tokens - because the server is stateless: any replica has to be able to
 * verify a token issued by any other one.
 */
import { Pool, type PoolClient } from "pg"

import { env } from "./env.js"

export const pool = new Pool({
  connectionString: env.databaseUrl,
  max: Number(process.env.PG_POOL_MAX ?? 10),
  // Railway's Postgres is reached over the private network; a connection that
  // hangs on connect should fail fast rather than stall a request.
  connectionTimeoutMillis: 10_000,
})

const SCHEMA = `
create table if not exists oauth_clients (
  client_id           text primary key,
  client_name         text,
  registered_at       timestamptz not null default now(),
  client_info         jsonb not null
);

create table if not exists oauth_pending_authorizations (
  id                  text primary key,
  client_id           text not null references oauth_clients(client_id) on delete cascade,
  redirect_uri        text not null,
  code_challenge      text not null,
  state               text,
  scopes              text[] not null default '{}',
  resource            text,
  created_at          timestamptz not null default now()
);

create table if not exists oauth_codes (
  code_hash           text primary key,
  client_id           text not null references oauth_clients(client_id) on delete cascade,
  redirect_uri        text not null,
  code_challenge      text not null,
  scopes              text[] not null default '{}',
  resource            text,
  expires_at          timestamptz not null,
  consumed_at         timestamptz
);

create table if not exists oauth_tokens (
  token_hash          text primary key,
  kind                text not null check (kind in ('access', 'refresh')),
  client_id           text not null references oauth_clients(client_id) on delete cascade,
  scopes              text[] not null default '{}',
  resource            text,
  expires_at          timestamptz not null,
  revoked_at          timestamptz
);

create index if not exists oauth_tokens_client_idx on oauth_tokens (client_id);

-- Additive columns, nullable so rows written by an earlier version stay valid.
-- grant_id ties a code and every token descended from it into one family, so
-- reuse of a spent credential can revoke the whole family. rotated_at marks a
-- refresh token that was spent by rotation, as opposed to revoked on request.
-- Rows without a grant_id (issued before these columns) keep working; they join
-- a family the first time they are used.
alter table oauth_codes  add column if not exists grant_id text;
alter table oauth_tokens add column if not exists grant_id text;
alter table oauth_tokens add column if not exists rotated_at timestamptz;
create index if not exists oauth_tokens_grant_idx on oauth_tokens (grant_id);
create index if not exists oauth_codes_grant_idx on oauth_codes (grant_id);

create table if not exists login_attempts (
  ip                  text not null,
  attempted_at        timestamptz not null default now()
);

create index if not exists login_attempts_ip_time_idx on login_attempts (ip, attempted_at desc);

-- Demo data for the example tools. Replace with your own tables; the tools in
-- src/tools.ts are there to prove the write path works end to end.
create table if not exists notes (
  id                  bigserial primary key,
  title               text not null,
  body                text not null,
  created_at          timestamptz not null default now()
);
`

// Replicas start together on a deploy. Concurrent DDL against the same table
// can fail on catalog races, so one replica migrates while the others wait.
const MIGRATION_LOCK_KEY = 7_204_113

export async function migrate(): Promise<void> {
  const client = await pool.connect()
  try {
    await client.query("select pg_advisory_lock($1)", [MIGRATION_LOCK_KEY])
    try {
      await client.query(SCHEMA)
    } finally {
      await client.query("select pg_advisory_unlock($1)", [MIGRATION_LOCK_KEY])
    }
  } finally {
    client.release()
  }
}

/**
 * Expired rows are not an error, but they accumulate. Codes live a minute and
 * tokens a month; sweeping on an interval keeps the tables from growing without
 * bound on a long-running deployment.
 */
export async function sweepExpired(): Promise<void> {
  await pool.query(`delete from oauth_codes where expires_at < now() - interval '1 hour'`)
  await pool.query(`delete from oauth_tokens where expires_at < now() - interval '1 day'`)
  await pool.query(`delete from oauth_pending_authorizations where created_at < now() - interval '1 hour'`)
  await pool.query(`delete from login_attempts where attempted_at < now() - interval '1 day'`)
}

/** Runs `work` in one transaction: everything it wrote is kept, or none of it. */
export async function inTransaction<T>(work: (client: PoolClient) => Promise<T>): Promise<T> {
  const client = await pool.connect()
  try {
    await client.query("begin")
    const result = await work(client)
    await client.query("commit")
    return result
  } catch (error) {
    await client.query("rollback").catch(() => undefined)
    throw error
  } finally {
    client.release()
  }
}
