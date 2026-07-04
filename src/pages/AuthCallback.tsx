"use client";
import { useEffect, useState } from 'react';
import { useNavigate } from '@/lib/router-compat';
import { supabase } from '@/integrations/supabase/client';
import { Card, CardContent } from '@/components/ui/card';
import { Shield, CheckCircle, AlertTriangle } from 'lucide-react';
import { useToast } from '@/hooks/use-toast';

/**
 * /auth/callback
 *
 * Handles two Supabase auth callback patterns:
 *
 * 1. PKCE flow (Supabase v2 default): ?code=xxx in query string
 *    → call exchangeCodeForSession(code) to swap the code for a session
 *
 * 2. Implicit flow (legacy / magic-link): #access_token=...&refresh_token=...
 *    → call setSession({ access_token, refresh_token })
 *
 * For password recovery (type=recovery in hash or PASSWORD_RECOVERY event),
 * redirect to /auth/reset-password instead of /dashboard.
 *
 * IP assignment: SOUHIMBOU DOH KONE LLC. Licensed to SecRed Knowledge Inc.
 */
const AuthCallback = () => {
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const navigate = useNavigate();
  const { toast } = useToast();

  // Read directly from window — router-compat shim always returns hash:"" because
  // Next.js doesn't expose the hash fragment server-side. This component is always
  // loaded with ssr:false so window is guaranteed available.
  const rawSearch = typeof window !== 'undefined' ? window.location.search : '';
  const rawHash   = typeof window !== 'undefined' ? window.location.hash   : '';

  useEffect(() => {
    const handleAuthCallback = async () => {
      try {
        console.log('[AuthCallback] Processing auth callback...');

        // ── 1. Check query params for PKCE code ───────────────────────────
        const searchParams = new URLSearchParams(rawSearch);
        const code = searchParams.get('code');
        const errorParam = searchParams.get('error');
        const errorDesc = searchParams.get('error_description');

        if (errorParam || errorDesc) {
          const msg = errorDesc || errorParam || 'Unknown error';
          console.error('[AuthCallback] Error in query params:', msg);
          setError(msg);
          toast({ title: 'Authentication Error', description: msg, variant: 'destructive' });
          setTimeout(() => navigate('/auth'), 2000);
          return;
        }

        if (code) {
          console.log('[AuthCallback] PKCE code found, exchanging for session...');
          const { data, error: exchErr } = await supabase.auth.exchangeCodeForSession(code);

          if (exchErr) {
            console.error('[AuthCallback] Code exchange failed:', exchErr.message);
            setError(exchErr.message);
            toast({ title: 'Session Error', description: exchErr.message, variant: 'destructive' });
            setTimeout(() => navigate('/auth'), 2000);
            return;
          }

          console.log('[AuthCallback] Session established via PKCE');

          // Clear the code from the URL for security
          globalThis.history?.replaceState({}, document.title, globalThis.location?.pathname ?? '/auth/callback');

          toast({ title: 'Authentication Successful', description: 'Welcome!', variant: 'default' });

          // Check if this was a password recovery — if so, send to reset page
          const isRecovery = data?.session?.user?.app_metadata?.provider === 'email' &&
            searchParams.get('type') === 'recovery';
          navigate(isRecovery ? '/auth/reset-password' : '/dashboard');
          return;
        }

        // ── 2. Fall back to hash fragment (implicit flow / magic-link) ────
        const hashParams = new URLSearchParams(rawHash.substring(1));
        const accessToken = hashParams.get('access_token');
        const refreshToken = hashParams.get('refresh_token');
        const type = hashParams.get('type');
        const hashError = hashParams.get('error_description');

        if (hashError) {
          console.error('[AuthCallback] Error in hash:', hashError);
          setError(hashError);
          toast({ title: 'Authentication Error', description: hashError, variant: 'destructive' });
          setTimeout(() => navigate('/auth'), 2000);
          return;
        }

        if (accessToken && refreshToken) {
          console.log('[AuthCallback] Hash tokens found, setting session...');
          const { error: sessionError } = await supabase.auth.setSession({
            access_token: accessToken,
            refresh_token: refreshToken,
          });

          if (sessionError) {
            console.error('[AuthCallback] setSession failed:', sessionError.message);
            setError('Failed to establish session');
            toast({ title: 'Session Error', description: 'Failed to establish user session', variant: 'destructive' });
            globalThis.history?.replaceState({}, document.title, globalThis.location?.pathname ?? '/auth/callback');
            setTimeout(() => navigate('/auth?error=session_failed'), 1000);
            return;
          }

          // Clear URL for security
          globalThis.history?.replaceState({}, document.title, globalThis.location?.pathname ?? '/auth/callback');
          console.log('[AuthCallback] Session established via hash tokens');

          toast({ title: 'Authentication Successful', description: 'Welcome back!', variant: 'default' });
          navigate(type === 'recovery' ? '/auth/reset-password' : '/dashboard');
          return;
        }

        // ── 3. No tokens found — direct visit or already processed ────────
        console.log('[AuthCallback] No auth tokens found — redirecting to login');
        navigate('/auth');

      } catch (err: any) {
        console.error('[AuthCallback] Unexpected error:', err);
        setError('Authentication processing failed');
        toast({ title: 'Authentication Error', description: 'Failed to process authentication callback', variant: 'destructive' });
        setTimeout(() => navigate('/auth?error=callback_exception'), 1000);
      } finally {
        setLoading(false);
      }
    };

    handleAuthCallback();
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []); // Run once on mount — rawSearch/rawHash captured at render time from window

  if (loading) {
    return (
      <div className="min-h-screen bg-gradient-dark flex items-center justify-center p-6">
        <Card className="w-full max-w-md card-cyber backdrop-blur-lg">
          <CardContent className="flex flex-col items-center space-y-4 p-8">
            <Shield className="h-12 w-12 text-primary animate-pulse" />
            <div className="text-center">
              <h2 className="text-xl font-semibold text-foreground mb-2">
                Securing Authentication
              </h2>
              <p className="text-muted-foreground">
                Processing your authentication securely...
              </p>
            </div>
            <div className="w-8 h-8 border-2 border-primary border-t-transparent rounded-full animate-spin" />
          </CardContent>
        </Card>
      </div>
    );
  }

  if (error) {
    return (
      <div className="min-h-screen bg-gradient-dark flex items-center justify-center p-6">
        <Card className="w-full max-w-md card-cyber backdrop-blur-lg">
          <CardContent className="flex flex-col items-center space-y-4 p-8">
            <AlertTriangle className="h-12 w-12 text-destructive" />
            <div className="text-center">
              <h2 className="text-xl font-semibold text-foreground mb-2">
                Authentication Error
              </h2>
              <p className="text-muted-foreground mb-4">{error}</p>
              <button
                onClick={() => navigate('/auth')}
                className="text-primary hover:text-primary-glow transition-colors"
              >
                Return to Authentication
              </button>
            </div>
          </CardContent>
        </Card>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gradient-dark flex items-center justify-center p-6">
      <Card className="w-full max-w-md card-cyber backdrop-blur-lg">
        <CardContent className="flex flex-col items-center space-y-4 p-8">
          <CheckCircle className="h-12 w-12 text-success" />
          <div className="text-center">
            <h2 className="text-xl font-semibold text-foreground mb-2">
              Authentication Complete
            </h2>
            <p className="text-muted-foreground">
              Redirecting you to the dashboard...
            </p>
          </div>
        </CardContent>
      </Card>
    </div>
  );
};

export default AuthCallback;