import { useLocation, useNavigate } from '@/lib/router-compat';
import { useEffect } from 'react';
import { Shield, Home, ArrowLeft } from 'lucide-react';
import { Button } from '@/components/ui/button';

const NotFound = () => {
  const location = useLocation();
  const navigate = useNavigate();

  useEffect(() => {
    console.error('404 Error: User attempted to access non-existent route:', location.pathname);
  }, [location.pathname]);

  return (
    <div className="min-h-screen bg-gradient-dark flex items-center justify-center p-6 relative overflow-hidden">
      {/* Background glow */}
      <div className="absolute inset-0 bg-[radial-gradient(ellipse_at_center,_var(--primary-glow)_0%,_transparent_50%)] opacity-5 pointer-events-none" />

      <div className="text-center space-y-6 relative z-10">
        <div className="flex items-center justify-center">
          <div className="w-20 h-20 bg-gradient-to-br from-primary/20 to-accent/20 rounded-2xl flex items-center justify-center border border-primary/20">
            <Shield className="h-10 w-10 text-primary" />
          </div>
        </div>

        <div className="space-y-2">
          <h1 className="text-6xl font-bold bg-gradient-cyber bg-clip-text text-transparent">
            404
          </h1>
          <p className="text-xl font-semibold text-foreground">Page Not Found</p>
          <p className="text-muted-foreground max-w-sm mx-auto">
            The resource at <code className="text-primary font-mono text-sm">{location.pathname}</code> does not exist or you lack clearance to access it.
          </p>
        </div>

        <div className="flex items-center justify-center gap-3">
          <Button variant="outline" onClick={() => navigate(-1)} className="flex items-center gap-2">
            <ArrowLeft className="h-4 w-4" />
            Go Back
          </Button>
          <Button onClick={() => navigate('/')} className="flex items-center gap-2">
            <Home className="h-4 w-4" />
            Return Home
          </Button>
        </div>
      </div>
    </div>
  );
};

export default NotFound;
