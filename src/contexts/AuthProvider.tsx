import { useState, useEffect, ReactNode, useMemo } from 'react';
import type { User, Session } from '@supabase/supabase-js';
import { supabase } from '@/integrations/supabase/client';
import { AuthContext } from './AuthContext';

interface AuthProviderProps {
  children: ReactNode;
}

export const AuthProvider = ({ children }: AuthProviderProps) => {
  const [user, setUser] = useState<User | null>(null);
  const [session, setSession] = useState<Session | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    // Set up auth state listener
    const { data: { subscription } } = supabase.auth.onAuthStateChange(
      (_event, session) => {
        setSession(session);
        setUser(session?.user ?? null);
        setLoading(false);
      }
    );

    // Get initial session
    supabase.auth.getSession().then(({ data: { session } }) => {
      setSession(session);
      setUser(session?.user ?? null);
      setLoading(false);
    });

    return () => subscription.unsubscribe();
  }, []);

  const signIn = async (email: string, password: string) => {
    console.log('[SOUHIMBOU-AUTH] Checking Sunsum Vitality for:', email);

    // Check if Sunsum is diminished (account locked) before attempting entry ritual
    try {
      const { data: isDiminished, error: lockError } = await supabase.rpc('is_sunsum_diminished', {
        user_email: email
      });

      if (lockError) {
        console.warn('[SOUHIMBOU-AUTH] Sunsum check failed (non-critical):', lockError.message);
        // Continue with ritual even if check fails
      } else if (isDiminished) {
        console.error('[SOUHIMBOU-AUTH] Sunsum is diminished. Entry denied.');
        return { error: { message: 'Sunsum is temporarily diminished due to ritual lapses. Please seek harmony and try again later.' } };
      }
    } catch (lockCheckError) {
      console.warn('[SOUHIMBOU-AUTH] Could not verify Sunsum status:', lockCheckError);
      // Continue with ritual even if check fails
    }

    console.log('[SOUHIMBOU-AUTH] Performing Entry Ritual (signInWithPassword)...');
    const { data, error } = await supabase.auth.signInWithPassword({
      email,
      password
    });

    if (error) {
      console.error('[SOUHIMBOU-AUTH] Entry ritual failed:', error.message, error);

      // Record ritual lapse
      try {
        await supabase.rpc('record_ritual_lapse', {
          user_email: email,
          client_ip: null,
          client_user_agent: navigator.userAgent
        });
      } catch (recordError) {
        console.warn('[SOUHIMBOU-AUTH] Could not record ritual lapse:', recordError);
      }
    } else {
      console.log('[SOUHIMBOU-AUTH] Entry successful. Sunsum harmonized for:', data.user?.email);
    }

    return { error };
  };

  const signUp = async (email: string, password: string, metadata?: any) => {
    const redirectUrl = `${globalThis.location.origin}/auth/callback`;

    const { error } = await supabase.auth.signUp({
      email,
      password,
      options: {
        emailRedirectTo: redirectUrl,
        data: metadata
      }
    });
    return { error };
  };

  const signOut = async () => {
    const { error } = await supabase.auth.signOut();
    return { error };
  };

  const resetPassword = async (email: string) => {
    const redirectUrl = `${globalThis.location.origin}/auth/callback`;

    const { error } = await supabase.auth.resetPasswordForEmail(email, {
      redirectTo: redirectUrl
    });
    return { error };
  };

  const contextValue = useMemo(() => ({
    user,
    session,
    loading,
    signIn,
    signUp,
    signOut,
    resetPassword
  }), [user, session, loading]);

  return (
    <AuthContext.Provider value={contextValue}>
      {children}
    </AuthContext.Provider>
  );
};
