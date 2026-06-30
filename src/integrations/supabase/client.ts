// src/integrations/supabase/client.ts
//
// DUAL-MODE CLIENT — SouHimBou AI / AdinKhepra ASAF
//
// Mode A — SaaS (souhimbou.ai): When NEXT_PUBLIC_SUPABASE_URL +
//   NEXT_PUBLIC_SUPABASE_ANON_KEY are present, this creates a real
//   @supabase/supabase-js client. Auth, DB, storage all work.
//
// Mode B — Sovereign (air-gap, DoD bare-metal): When those env vars are
//   absent, the stub activates. All calls return graceful empty responses.
//   No Supabase dependency at runtime. Zero egress. Air-gappable.
//
// Switching modes: set/unset the env vars. No code changes needed.
//
// IP assignment: SOUHIMBOU DOH KONE LLC. Licensed to SecRed Knowledge Inc.

/* eslint-disable @typescript-eslint/no-explicit-any */
import { createClient } from '@supabase/supabase-js';

// ── Env resolution ────────────────────────────────────────────────────────────
// Support both Next.js (NEXT_PUBLIC_*) and legacy Vite (VITE_*) prefixes.
const SUPABASE_URL =
  (typeof process !== 'undefined' && process.env?.NEXT_PUBLIC_SUPABASE_URL) ||
  (typeof process !== 'undefined' && process.env?.VITE_SUPABASE_URL) ||
  '';

const SUPABASE_ANON_KEY =
  (typeof process !== 'undefined' && process.env?.NEXT_PUBLIC_SUPABASE_ANON_KEY) ||
  (typeof process !== 'undefined' && process.env?.VITE_SUPABASE_PUBLISHABLE_KEY) ||
  '';

// ── ASAF sovereign agent (local, for RPC routing in sovereign mode) ───────────
const ASAF_API = 'http://localhost:45444/api/v1';

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

// ── Mode A — Real Supabase client ─────────────────────────────────────────────

let _realClient: ReturnType<typeof createClient> | null = null;

function getRealClient(): ReturnType<typeof createClient> | null {
  if (_realClient) return _realClient;
  if (!isSaaS) return null;
  try {
    _realClient = createClient(SUPABASE_URL, SUPABASE_ANON_KEY, {
      auth: {
        // Use PKCE flow — Supabase default since v2.
        // Tokens are stored in localStorage; SSR pages use cookies via middleware.
        flowType: 'pkce',
        autoRefreshToken: true,
        persistSession: true,
        detectSessionInUrl: true,
      },
    });
  } catch (e) {
    console.error('[SouHimBou] Failed to create Supabase client:', e);
    return null;
  }
  return _realClient;
}

// Whether the real client is active for this runtime
const isSaaS = !!(SUPABASE_URL && SUPABASE_ANON_KEY);

if (isSaaS) {
  console.debug('[SouHimBou] Supabase SaaS mode active — real client initialised');
} else {
  console.debug('[SouHimBou] Sovereign stub mode active — no Supabase URL configured');
}

// ── Mode B — Sovereign stub ───────────────────────────────────────────────────
// Mimics the Supabase PostgREST query builder — fully chainable, thenable.

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

const authStub = {
  getSession: () => Promise.resolve({ data: { session: null as any }, error: null }),
  getUser: () => Promise.resolve({ data: { user: null as any }, error: null }),
  onAuthStateChange: (_cb: any) => ({ data: { subscription: { unsubscribe: () => {} } } }),
  signInWithPassword: async (_creds: any) => ({ data: null as any, error: { message: 'Sovereign mode — Supabase not configured' } }),
  signUp: async (_creds: any) => ({ data: null as any, error: { message: 'Sovereign mode — Supabase not configured' } }),
  signOut: async () => ({ error: null }),
  resetPasswordForEmail: async (_email: string, _opts?: any) => ({ error: null }),
  updateUser: async (_attrs: any) => ({ data: { user: null as any }, error: null }),
  refreshSession: async (_opts?: any) => ({ data: { session: null as any, user: null as any }, error: null }),
  setSession: async (_tokens: { access_token: string; refresh_token: string }) => ({ data: { session: null as any, user: null as any }, error: null }),
  exchangeCodeForSession: async (_code: string) => ({ data: { session: null as any, user: null as any }, error: null }),
  mfa: {
    listFactors: async () => ({ data: { all: [] as any[], totp: [] as any[], phone: [] as any[] }, error: null }),
    enroll: async (_opts: any) => ({ data: null as any, error: null }),
    unenroll: async (_opts: any) => ({ data: null as any, error: null }),
    challenge: async (_opts: any) => ({ data: null as any, error: null }),
    verify: async (_opts: any) => ({ data: null as any, error: null }),
    challengeAndVerify: async (_opts: any) => ({ data: null as any, error: null }),
  },
  admin: {
    getUserById: async (_uid: string) => ({ data: { user: null as any }, error: null }),
    listUsers: async (_opts?: any) => ({ data: { users: [] as any[] }, error: null }),
    createUser: async (_attrs: any) => ({ data: { user: null as any }, error: null }),
    deleteUser: async (_uid: string) => ({ data: {} as any, error: null }),
    updateUserById: async (_uid: string, _attrs: any) => ({ data: { user: null as any }, error: null }),
  },
};

// ── RPC — sovereign ASAF routes + unknown-function fallback ───────────────────

const rpcStub = async (fnName: string, params?: any) => {
  const rpcRoutes: Record<string, string> = {
    get_current_user_role: '/me/role',
    is_sunsum_diminished: '/auth/lockout-check',
    record_ritual_lapse: '/auth/record-failure',
  };
  const route = rpcRoutes[fnName];
  if (route) {
    const result = await asafFetch(route, { method: 'POST', body: JSON.stringify(params ?? {}) });
    return { data: result ?? null, error: null };
  }
  console.debug(`[SouHimBou-Stub] Unmapped RPC: ${fnName}`, params);
  return { data: null, error: null };
};

// ── Functions stub ────────────────────────────────────────────────────────────

const functionsStub = {
  invoke: async (fnName: string, options?: { body?: any; headers?: Record<string, string> }) => {
    const result = await asafFetch(`/functions/${fnName}`, {
      method: 'POST',
      body: JSON.stringify(options?.body ?? {}),
    });
    if (result !== null) return { data: result, error: null };
    console.debug(`[SouHimBou-Stub] Edge Function not routed: ${fnName}`);
    return { data: null, error: null };
  },
};

// ── Storage stub ──────────────────────────────────────────────────────────────

const storageStub = {
  from: (_bucket: string) => ({
    upload: async (_path: string, _file: any) => ({ data: null as any, error: null }),
    download: async (_path: string) => ({ data: null as any, error: null }),
    getPublicUrl: (_path: string) => ({ data: { publicUrl: '' } }),
    list: async (_prefix?: string) => ({ data: [] as any[], error: null }),
    remove: async (_paths: string[]) => ({ data: null as any, error: null }),
  }),
};

// ── Channel stub ──────────────────────────────────────────────────────────────

const makeChannelStub = (): any => ({
  on: (_event: string, _filter: any, _cb: any) => makeChannelStub(),
  subscribe: (_cb?: any) => makeChannelStub(),
  unsubscribe: () => Promise.resolve('ok'),
});

// ── Main export — unified API regardless of mode ──────────────────────────────

function getClient() {
  if (isSaaS) {
    const real = getRealClient();
    if (real) return real;
    // Real client init failed — fall back to stub with a warning
    console.error('[SouHimBou] Real Supabase client failed to init — falling back to stub');
  }

  // Sovereign stub
  return {
    auth: authStub,
    functions: functionsStub,
    rpc: rpcStub,
    storage: storageStub,
    from: (table: string) => makeQueryStub(table),
    channel: (_name: string) => makeChannelStub(),
    removeChannel: (_ch: any) => {},
  };
}

// Proxy so callers can do `supabase.auth.*`, `supabase.from(...)`, etc.
// The proxy defers resolution to call-time so SSR module loading order
// doesn't matter.
export const supabase = new Proxy({} as ReturnType<typeof getClient>, {
  get(_target, prop: string) {
    const client = getClient();
    const val = (client as any)[prop];
    return typeof val === 'function' ? val.bind(client) : val;
  },
});

// ── Helpers ───────────────────────────────────────────────────────────────────

/** True when running against real Supabase (SaaS mode). */
export const isSaaSMode = isSaaS;

// Type re-export for files that import from types.ts
export type { Database } from './types';