import { useState, useEffect, ReactNode, useMemo, useCallback } from 'react';
import type { User, Session } from '@supabase/supabase-js';
import { supabase } from '@/integrations/supabase/client';
import { AuthContext } from './AuthContext';

interface AuthProviderProps {
  children: ReactNode;
}

/**
 * AuthProvider — manages the Supabase auth session lifecycle.
 *
 * Dual-mode compatible:
 * - SaaS mode (NEXT_PUBLIC_SUPABASE_URL set): real Supabase auth events fire.
 * - Sovereign mode (stub): onAuthStateChange never fires; user stays null.
 *
 * Callbacks (signIn, signUp, signOut, resetPassword) are stable across
 * renders via useCallback so they are safe to pass as deps to child effects.
 *
 * IP assignment: SOUHIMBOU DOH KONE LLC. Licensed to SecRed Knowledge Inc.
 */
export const AuthProvider = ({ children }: AuthProviderProps) => {
  const [user, setUser] = useState<User | null>(null);
  const [session, setSession] = useState<Session | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    // Subscribe to auth state changes FIRST so we don't miss events that
    // fire synchronously during getSession() on some Supabase versions.
    const { data: { subscription } } = supabase.auth.onAuthStateChange(
      (_event, newSession) => {
        setSession(newSession);
        setUser(newSession?.user ?? null);
        setLoading(false);
      }
    );

    // Hydrate from existing session (e.g. returning user with localStorage token)
    supabase.auth.getSession().then(({ data: { session: existingSession } }) => {
      setSession(existingSession);
      setUser(existingSession?.user ?? null);
      setLoading(false);
    });

    return () => subscription.unsubscribe();
  }, []);

  // ── Stable auth actions ──────────────────────────────────────────────────────

  const signIn = useCallback(async (email: string, password: string) => {
    console.log('[SouHimBou-Auth] signIn:', email);

    // Lockout check via ASAF RPC (non-fatal — continues if RPC unavailable)
    try {
      const { data: isDiminished, error: lockError } = await supabase.rpc('is_sunsum_diminished', {
        user_email: email,
      });
      if (!lockError && isDiminished) {
        return { error: { message: 'Account temporarily locked due to too many failed attempts. Please try again later.' } };
      }
    } catch {
      // Non-critical — proceed
    }

    const { data, error } = await supabase.auth.signInWithPassword({ email, password });

    if (error) {
      // Record failure (non-fatal)
      try {
        await supabase.rpc('record_ritual_lapse', {
          user_email: email,
          client_ip: null,
          client_user_agent: typeof navigator !== 'undefined' ? navigator.userAgent : '',
        });
      } catch {
        // Non-critical
      }
    }

    return { data, error };
  }, []);

  const signUp = useCallback(async (email: string, password: string, metadata?: Record<string, unknown>) => {
    const redirectUrl = typeof globalThis !== 'undefined' && globalThis.location
      ? `${globalThis.location.origin}/auth/callback`
      : 'https://souhimbou.ai/auth/callback';

    const { data, error } = await supabase.auth.signUp({
      email,
      password,
      options: {
        emailRedirectTo: redirectUrl,
        data: metadata,
      },
    });
    return { data, error };
  }, []);

  const signOut = useCallback(async () => {
    const { error } = await supabase.auth.signOut();
    return { error };
  }, []);

  const resetPassword = useCallback(async (email: string) => {
    const redirectUrl = typeof globalThis !== 'undefined' && globalThis.location
      ? `${globalThis.location.origin}/auth/reset-password`
      : 'https://souhimbou.ai/auth/reset-password';

    const { error } = await supabase.auth.resetPasswordForEmail(email, {
      redirectTo: redirectUrl,
    });
    return { error };
  }, []);

  const contextValue = useMemo(() => ({
    user,
    session,
    loading,
    signIn,
    signUp,
    signOut,
    resetPassword,
  }), [user, session, loading, signIn, signUp, signOut, resetPassword]);

  return (
    <AuthContext.Provider value={contextValue}>
      {children}
    </AuthContext.Provider>
  );
};
