import { useEffect, useState } from 'react';
import { useNavigate, useLocation } from '@/lib/router-compat';
import { supabase } from '@/integrations/supabase/client';
import { Card, CardContent } from '@/components/ui/card';
import { Shield, CheckCircle, AlertTriangle } from 'lucide-react';
import { useToast } from '@/hooks/use-toast';

const AuthCallback = () => {
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const navigate = useNavigate();
  const location = useLocation();
  const { toast } = useToast();

  useEffect(() => {
    const handleAuthCallback = async () => {
      try {
        // Extract hash parameters (Supabase tokens arrive in the URL hash)
        const hashParams = new URLSearchParams(location.hash.substring(1));
        const accessToken = hashParams.get('access_token');
        const refreshToken = hashParams.get('refresh_token');
        const type = hashParams.get('type');   // 'signup' | 'recovery' | 'magiclink'

        if (accessToken && refreshToken) {
          // Directly establish the session from the tokens — do NOT relay through
          // an edge function that receives an empty body and can't read the hash.
          const { error: sessionError } = await supabase.auth.setSession({
            access_token: accessToken,
            refresh_token: refreshToken,
          });

          // Clear the URL hash immediately for security (tokens must not linger)
          globalThis.history.replaceState({}, document.title, globalThis.location.pathname);

          if (sessionError) {
            console.error('[AuthCallback] setSession error:', sessionError);
            setError('Failed to process authentication securely');
            toast({
              title: 'Authentication Error',
              description: 'Failed to process authentication callback securely',
              variant: 'destructive',
            });
            navigate('/auth?error=callback_failed');
            return;
          }

          toast({
            title: 'Authentication Successful',
            description: 'Your session has been established securely',
          });

          // Route based on token type
          if (type === 'recovery') {
            // Password-reset flow: let user set a new password
            navigate('/auth?mode=reset');
          } else {
            navigate('/dashboard');
          }
        } else {
          // No tokens — check for explicit error param in the query string
          const urlParams = new URLSearchParams(location.search);
          const errorParam = urlParams.get('error');

          window.history.replaceState({}, document.title, window.location.pathname);

          if (errorParam) {
            setError(`Authentication error: ${errorParam}`);
            toast({
              title: 'Authentication Error',
              description: `Authentication failed: ${errorParam}`,
              variant: 'destructive',
            });
          } else {
            // Possibly a direct visit — check if there's an active session already
            const { data: { session } } = await supabase.auth.getSession();
            if (session) {
              navigate('/dashboard');
              return;
            }
            setError('No authentication data found');
            toast({
              title: 'Invalid Access',
              description: 'No authentication data found in callback',
              variant: 'destructive',
            });
          }

          navigate('/auth');
        }
      } catch (err: any) {
        console.error('[AuthCallback] error:', err);
        setError('Authentication processing failed');
        toast({
          title: 'Authentication Error',
          description: 'Failed to process authentication callback',
          variant: 'destructive',
        });
        window.history.replaceState({}, document.title, window.location.pathname);
        navigate('/auth?error=callback_exception');
      } finally {
        setLoading(false);
      }
    };

    handleAuthCallback();
  }, []); // run once on mount — location ref is stable at that point

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
                Processing your authentication securely…
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
              Redirecting you to the dashboard…
            </p>
          </div>
        </CardContent>
      </Card>
    </div>
  );
};

export default AuthCallback;
