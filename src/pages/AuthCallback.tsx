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
        console.log('Processing auth callback...');

        // Extract hash parameters (tokens from Supabase)
        const hashParams = new URLSearchParams(location.hash.substring(1));

        // Check if we have auth tokens in the hash
        const accessToken = hashParams.get('access_token');
        const refreshToken = hashParams.get('refresh_token');
        const type = hashParams.get('type');
        const errorDescription = hashParams.get('error_description');

        if (errorDescription) {
          console.error('Auth error from hash:', errorDescription);
          setError(errorDescription);
          toast({
            title: "Authentication Error",
            description: errorDescription,
            variant: "destructive"
          });
          navigate('/auth');
          return;
        }

        if (accessToken && refreshToken) {
          console.log('Tokens found in URL, setting session...');

          // Set the session directly in the client
          const { error: sessionError } = await supabase.auth.setSession({
            access_token: accessToken,
            refresh_token: refreshToken,
          });

          if (sessionError) {
            console.error('Session creation error:', sessionError);
            setError('Failed to establish session');

            toast({
              title: "Session Error",
              description: "Failed to establish user session",
              variant: "destructive"
            });

            // Clear the URL immediately for security
            globalThis.history.replaceState({}, document.title, globalThis.location.pathname);
            navigate('/auth?error=session_failed');
            return;
          }

          // Clear the URL hash immediately for security
          globalThis.history.replaceState({}, document.title, globalThis.location.pathname);

          console.log('Auth session established successfully');

          toast({
            title: "Authentication Successful",
            description: "Welcome back!",
            variant: "default"
          });

          // Determine redirect based on type or default to dashboard
          let redirectUrl = '/dashboard';
          if (type === 'recovery') {
            redirectUrl = '/auth/reset-password';
          }

          navigate(redirectUrl);

        } else {
          // No tokens found, check for error in search params
          const urlParams = new URLSearchParams(location.search);
          const errorParam = urlParams.get('error');
          const errorDesc = urlParams.get('error_description');

          if (errorParam || errorDesc) {
            const msg = errorDesc || errorParam || 'Unknown error';
            setError(`Authentication error: ${msg}`);
            toast({
              title: "Authentication Error",
              description: msg,
              variant: "destructive"
            });
          } else {
            // Sometimes Supabase redirects to the callback URL with the tokens in the hash,
            // but if we are here and no hash params, maybe it's a direct visit?
            // Just redirect to auth page.
            console.log("No tokens found, redirecting to login");
            navigate('/auth');
          }
        }

      } catch (error) {
        console.error('Auth callback error:', error);
        setError('Authentication processing failed');

        toast({
          title: "Authentication Error",
          description: "Failed to process authentication callback",
          variant: "destructive"
        });

        navigate('/auth?error=callback_exception');
      } finally {
        setLoading(false);
      }
    };

    handleAuthCallback();
  }, [location, navigate, toast]);

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
            <div className="w-8 h-8 border-2 border-primary border-t-transparent rounded-full animate-spin"></div>
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
              <p className="text-muted-foreground mb-4">
                {error}
              </p>
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