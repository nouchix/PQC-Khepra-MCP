// src/integrations/supabase/client.ts
//
// SOVEREIGN MODE — Supabase client replaced with local ASAF API stub.
//
// This stub satisfies all existing import sites that reference `supabase.rpc()`,
// `supabase.from()`, `supabase.auth.*`, etc. without throwing runtime errors.
// All data operations return empty successful responses so views render
// gracefully without a Supabase connection.
//
// Long-term: individual views will be migrated to call the ASAF agent API
// directly. This stub is the zero-disruption bridge during that migration.
//
// ASAF agent API: http://localhost:45444/api/v1/

const ASAF_API = 'http://localhost:45444/api/v1';

// Lightweight fetch wrapper for ASAF agent calls
const asafFetch = async (path: string, opts?: RequestInit) => {
  try {
    const resp = await fetch(`${ASAF_API}${path}`, {
      headers: { 'Content-Type': 'application/json' },
      ...opts,
    });
    if (resp.ok) return resp.json();
  } catch {
    // Agent offline — return empty data gracefully
  }
  return null;
};

// ── Query builder stub ────────────────────────────────────────────────────────
// Mimics the Supabase PostgREST builder enough to prevent crashes.
// Implements the Promise/thenable interface so `const { data, error } = await supabase.from(...)...`
// resolves to { data: null, error: null } for all queries.

type QueryResult = { data: null; error: null };

const makeQueryStub = (_table: string): QueryStub => {
  const stub: QueryStub = {
    select: (_cols?: string) => makeQueryStub(_table),
    insert: (_row: unknown) => Promise.resolve({ data: null, error: null }),
    update: (_row: unknown) => makeQueryStub(_table),
    upsert: (_row: unknown) => Promise.resolve({ data: null, error: null }),
    delete: () => makeQueryStub(_table),
    eq: (_col: string, _val: unknown) => makeQueryStub(_table),
    neq: (_col: string, _val: unknown) => makeQueryStub(_table),
    gt: (_col: string, _val: unknown) => makeQueryStub(_table),
    gte: (_col: string, _val: unknown) => makeQueryStub(_table),
    lt: (_col: string, _val: unknown) => makeQueryStub(_table),
    lte: (_col: string, _val: unknown) => makeQueryStub(_table),
    in: (_col: string, _vals: unknown[]) => makeQueryStub(_table),
    is: (_col: string, _val: unknown) => makeQueryStub(_table),
    ilike: (_col: string, _val: string) => makeQueryStub(_table),
    order: (_col: string, _opts?: unknown) => makeQueryStub(_table),
    limit: (_n: number) => makeQueryStub(_table),
    range: (_from: number, _to: number) => makeQueryStub(_table),
    single: () => Promise.resolve({ data: null, error: null }),
    maybeSingle: () => Promise.resolve({ data: null, error: null }),
    // Thenable: allows `const { data, error } = await supabase.from(...).select().eq(...)` to work.
    // Without this, destructuring `{ data, error }` from the builder fails at runtime and TS compile.
    then: <T>(
      resolve: (value: QueryResult) => T,
      reject?: (reason: unknown) => T
    ): Promise<T> => Promise.resolve({ data: null, error: null }).then(resolve, reject),
  };
  return stub;
};

// Stub type matching the builder interface + Promise thenable
interface QueryStub {
  select: (_cols?: string) => QueryStub;
  insert: (_row: unknown) => Promise<QueryResult>;
  update: (_row: unknown) => QueryStub;
  upsert: (_row: unknown) => Promise<QueryResult>;
  delete: () => QueryStub;
  eq: (_col: string, _val: unknown) => QueryStub;
  neq: (_col: string, _val: unknown) => QueryStub;
  gt: (_col: string, _val: unknown) => QueryStub;
  gte: (_col: string, _val: unknown) => QueryStub;
  lt: (_col: string, _val: unknown) => QueryStub;
  lte: (_col: string, _val: unknown) => QueryStub;
  in: (_col: string, _vals: unknown[]) => QueryStub;
  is: (_col: string, _val: unknown) => QueryStub;
  ilike: (_col: string, _val: string) => QueryStub;
  order: (_col: string, _opts?: unknown) => QueryStub;
  limit: (_n: number) => QueryStub;
  range: (_from: number, _to: number) => QueryStub;
  single: () => Promise<QueryResult>;
  maybeSingle: () => Promise<QueryResult>;
  then: <T>(resolve: (value: QueryResult) => T, reject?: (reason: unknown) => T) => Promise<T>;
}

// ── Auth stub ─────────────────────────────────────────────────────────────────
// Auth operations are handled by AuthProvider.tsx — this stub is a no-op fallback.

const authStub = {
  getSession: () => Promise.resolve({ data: { session: null }, error: null }),
  getUser: () => Promise.resolve({ data: { user: null }, error: null }),
  onAuthStateChange: (_cb: unknown) => ({ data: { subscription: { unsubscribe: () => {} } } }),
  signInWithPassword: async (_creds: unknown) => ({ data: null, error: { message: 'Use license key auth' } }),
  signUp: async (_creds: unknown) => ({ data: null, error: null }),
  signOut: async () => ({ error: null }),
  resetPasswordForEmail: async (_email: string, _opts?: unknown) => ({ error: null }),
};

// ── RPC stub ──────────────────────────────────────────────────────────────────
// Maps known RPC calls to ASAF agent endpoints where available.

const rpc = async (fnName: string, params?: unknown) => {
  // Route known RPC functions to ASAF agent
  const rpcRoutes: Record<string, string> = {
    'get_current_user_role': '/me/role',
    'is_sunsum_diminished': '/auth/lockout-check',
    'record_ritual_lapse': '/auth/record-failure',
  };

  const route = rpcRoutes[fnName];
  if (route) {
    const result = await asafFetch(route, {
      method: 'POST',
      body: JSON.stringify(params ?? {}),
    });
    return { data: result ?? null, error: null };
  }

  // Unknown RPC — return null gracefully
  console.debug(`[ASAF-STUB] Unmapped RPC: ${fnName}`, params);
  return { data: null, error: null };
};

// ── Functions stub ────────────────────────────────────────────────────────────
// Mimics supabase.functions.invoke() for Edge Function calls.

const functionsStub = {
  invoke: async (fnName: string, options?: { body?: unknown; headers?: Record<string, string> }) => {
    const result = await asafFetch(`/functions/${fnName}`, {
      method: 'POST',
      body: JSON.stringify(options?.body ?? {}),
    });
    if (result !== null) {
      return { data: result, error: null };
    }
    console.debug(`[ASAF-STUB] Edge Function not routed: ${fnName}`);
    return { data: null, error: null };
  },
};

// ── Storage stub ──────────────────────────────────────────────────────────────

const storage = {
  from: (_bucket: string) => ({
    upload: async (_path: string, _file: unknown) => ({ data: null, error: null }),
    download: async (_path: string) => ({ data: null, error: null }),
    getPublicUrl: (_path: string) => ({ data: { publicUrl: '' } }),
    list: async (_prefix?: string) => ({ data: [], error: null }),
    remove: async (_paths: string[]) => ({ data: null, error: null }),
  }),
};

// ── Main export ───────────────────────────────────────────────────────────────

export const supabase = {
  auth: authStub,
  functions: functionsStub,
  rpc,
  storage,
  from: (table: string) => makeQueryStub(table),
  channel: (_name: string) => ({
    on: (_event: string, _filter: unknown, _cb: unknown) => ({ subscribe: () => {} }),
    subscribe: () => ({}),
    unsubscribe: () => {},
  }),
  removeChannel: (_ch: unknown) => {},
};

// Type re-export for files that import from types.ts
export type { Database } from './types';