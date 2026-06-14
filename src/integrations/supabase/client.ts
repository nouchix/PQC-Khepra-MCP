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
// Mimics the Supabase PostgREST builder.
// - Supports full method chaining (select, eq, order, limit, etc.)
// - Is thenable: `const { data, error } = await supabase.from(...).select().eq(...)` works
// - Uses `any` for data so code using data.map(), data.name etc. type-checks without null guards

/* eslint-disable @typescript-eslint/no-explicit-any */
type QueryResult = { data: any; error: any | null; count?: number | null };

interface QueryStub extends Promise<QueryResult> {
  select: (_cols?: string, _opts?: any) => QueryStub;
  insert: (_row: any, _opts?: any) => QueryStub;
  update: (_row: any, _opts?: any) => QueryStub;
  upsert: (_row: any, _opts?: any) => QueryStub;
  delete: (_opts?: any) => QueryStub;
  eq: (_col: string, _val: any) => QueryStub;
  neq: (_col: string, _val: any) => QueryStub;
  gt: (_col: string, _val: any) => QueryStub;
  gte: (_col: string, _val: any) => QueryStub;
  lt: (_col: string, _val: any) => QueryStub;
  lte: (_col: string, _val: any) => QueryStub;
  in: (_col: string, _vals: any[]) => QueryStub;
  is: (_col: string, _val: any) => QueryStub;
  ilike: (_col: string, _val: string) => QueryStub;
  order: (_col: string, _opts?: any) => QueryStub;
  limit: (_n: number) => QueryStub;
  range: (_from: number, _to: number) => QueryStub;
  match: (_query: Record<string, any>) => QueryStub;
  not: (_col: string, _op: string, _val: any) => QueryStub;
  contains: (_col: string, _val: any) => QueryStub;
  containedBy: (_col: string, _val: any) => QueryStub;
  filter: (_col: string, _op: string, _val: any) => QueryStub;
  or: (_filters: string, _opts?: any) => QueryStub;
  like: (_col: string, _val: string) => QueryStub;
  single: () => QueryStub;
  maybeSingle: () => QueryStub;
  throwOnError: () => QueryStub;
  csv: () => QueryStub;
  returns: <T>() => QueryStub;
}
/* eslint-enable @typescript-eslint/no-explicit-any */

const makeQueryStub = (_table: string): QueryStub => {
  const base = Promise.resolve<QueryResult>({ data: null, error: null, count: null });

  const stub: QueryStub = Object.assign(base, {
    select: () => makeQueryStub(_table),
    insert: () => makeQueryStub(_table),
    update: () => makeQueryStub(_table),
    upsert: () => makeQueryStub(_table),
    delete: () => makeQueryStub(_table),
    eq: () => makeQueryStub(_table),
    neq: () => makeQueryStub(_table),
    gt: () => makeQueryStub(_table),
    gte: () => makeQueryStub(_table),
    lt: () => makeQueryStub(_table),
    lte: () => makeQueryStub(_table),
    in: () => makeQueryStub(_table),
    is: () => makeQueryStub(_table),
    ilike: () => makeQueryStub(_table),
    order: () => makeQueryStub(_table),
    limit: () => makeQueryStub(_table),
    range: () => makeQueryStub(_table),
    match: () => makeQueryStub(_table),
    not: () => makeQueryStub(_table),
    contains: () => makeQueryStub(_table),
    containedBy: () => makeQueryStub(_table),
    filter: () => makeQueryStub(_table),
    or: () => makeQueryStub(_table),
    like: () => makeQueryStub(_table),
    single: () => makeQueryStub(_table),
    maybeSingle: () => makeQueryStub(_table),
    throwOnError: () => makeQueryStub(_table),
    csv: () => makeQueryStub(_table),
    returns: () => makeQueryStub(_table),
  });

  return stub;
};

// ── Auth stub ─────────────────────────────────────────────────────────────────
// Auth operations are handled by AuthProvider.tsx — this stub is a no-op fallback.

/* eslint-disable @typescript-eslint/no-explicit-any */
const authStub = {
  getSession: () => Promise.resolve({ data: { session: null as any }, error: null }),
  getUser: () => Promise.resolve({ data: { user: null as any }, error: null }),
  onAuthStateChange: (_cb: any) => ({ data: { subscription: { unsubscribe: () => {} } } }),
  signInWithPassword: async (_creds: any) => ({ data: null as any, error: null as any }),
  signUp: async (_creds: any) => ({ data: null as any, error: null as any }),
  signOut: async () => ({ error: null }),
  resetPasswordForEmail: async (_email: string, _opts?: any) => ({ error: null }),
  updateUser: async (_attrs: any) => ({ data: { user: null as any }, error: null }),
  refreshSession: async (_opts?: any) => ({ data: { session: null as any, user: null as any }, error: null }),
  setSession: async (_tokens: { access_token: string; refresh_token: string }) => ({ data: { session: null as any, user: null as any }, error: null }),
  // MFA API stub
  mfa: {
    listFactors: async () => ({ data: { all: [] as any[], totp: [] as any[], phone: [] as any[] }, error: null }),
    enroll: async (_opts: any) => ({ data: null as any, error: null }),
    unenroll: async (_opts: any) => ({ data: null as any, error: null }),
    challenge: async (_opts: any) => ({ data: null as any, error: null }),
    verify: async (_opts: any) => ({ data: null as any, error: null }),
    challengeAndVerify: async (_opts: any) => ({ data: null as any, error: null }),
  },
  // Admin API stub — service role operations (admin panel only)
  admin: {
    getUserById: async (_uid: string) => ({ data: { user: null as any }, error: null }),
    listUsers: async (_opts?: any) => ({ data: { users: [] as any[] }, error: null }),
    createUser: async (_attrs: any) => ({ data: { user: null as any }, error: null }),
    deleteUser: async (_uid: string) => ({ data: {} as any, error: null }),
    updateUserById: async (_uid: string, _attrs: any) => ({ data: { user: null as any }, error: null }),
  },
};
/* eslint-enable @typescript-eslint/no-explicit-any */

// ── RPC stub ──────────────────────────────────────────────────────────────────
// Maps known RPC calls to ASAF agent endpoints where available.

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const rpc = async (fnName: string, params?: any) => {
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
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  invoke: async (fnName: string, options?: { body?: any; headers?: Record<string, string> }) => {
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
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  from: (_bucket: string) => ({
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    upload: async (_path: string, _file: any) => ({ data: null as any, error: null }),
    download: async (_path: string) => ({ data: null as any, error: null }),
    getPublicUrl: (_path: string) => ({ data: { publicUrl: '' } }),
    list: async (_prefix?: string) => ({ data: [] as any[], error: null }),
    remove: async (_paths: string[]) => ({ data: null as any, error: null }),
  }),
};

// ── Main export ───────────────────────────────────────────────────────────────

export const supabase = {
  auth: authStub,
  functions: functionsStub,
  rpc,
  storage,
  from: (table: string) => makeQueryStub(table),
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  channel: (_name: string) => {
    // Channel stub: fully chainable with .on().on().subscribe()
    const makeChannel = (): any => ({
      on: (_event: string, _filter: any, _cb: any) => makeChannel(),
      subscribe: (_cb?: any) => makeChannel(),
      unsubscribe: () => Promise.resolve('ok'),
    });
    return makeChannel();
  },
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  removeChannel: (_ch: any) => {},
};

// Type re-export for files that import from types.ts
export type { Database } from './types';