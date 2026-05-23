import { useLocation, useNavigate } from '@/lib/router-compat';
import { useEffect } from "react";
import { Shield, Home, ArrowLeft } from "lucide-react";
import { Button } from "@/components/ui/button";

const NotFound = () => {
  const location = useLocation();
  const navigate = useNavigate();

  useEffect(() => {
    console.warn(
      "404: Route not found:",
      location.pathname
    );
  }, [location.pathname]);

  return (
    <div className="min-h-screen bg-[hsl(220,15%,6%)] text-white flex items-center justify-center p-6 relative overflow-hidden">
      {/* Background Effects */}
      <div className="absolute inset-0 bg-[radial-gradient(ellipse_at_center,_hsl(194,100%,50%,0.06)_0%,_transparent_50%)]" />
      <div className="absolute inset-0 bg-[linear-gradient(to_right,rgba(0,255,255,0.03)_1px,transparent_1px),linear-gradient(to_bottom,rgba(0,255,255,0.03)_1px,transparent_1px)] bg-[size:3rem_3rem]" />

      <div className="max-w-lg w-full relative z-10 text-center">
        {/* 404 Display */}
        <div className="mb-8">
          <h1 className="text-8xl font-black text-transparent bg-gradient-to-r from-cyan-400 to-purple-500 bg-clip-text italic">
            404
          </h1>
          <div className="w-24 h-1 bg-gradient-to-r from-cyan-500 to-purple-500 mx-auto mt-4 rounded-full" />
        </div>

        {/* Message */}
        <div className="space-y-3 mb-10">
          <h2 className="text-2xl font-bold text-white">
            Sector Not Found
          </h2>
          <p className="text-gray-400 leading-relaxed">
            The route <code className="text-cyan-400 bg-cyan-500/10 px-2 py-0.5 rounded text-sm">{location.pathname}</code> does not exist in this deployment.
          </p>
        </div>

        {/* Recovery Actions */}
        <div className="flex flex-col sm:flex-row gap-3 justify-center mb-12">
          <Button
            onClick={() => navigate('/')}
            className="bg-gradient-to-r from-cyan-500 to-blue-500 hover:from-cyan-400 hover:to-blue-400 text-black font-semibold shadow-[0_0_20px_rgba(0,255,255,0.3)] hover:shadow-[0_0_30px_rgba(0,255,255,0.5)]"
            size="lg"
          >
            <Home className="h-5 w-5 mr-2" />
            Return Home
          </Button>
          <Button
            onClick={() => navigate(-1)}
            variant="outline"
            size="lg"
            className="border-gray-600 hover:border-cyan-500/50 text-gray-300 hover:text-white"
          >
            <ArrowLeft className="h-5 w-5 mr-2" />
            Go Back
          </Button>
        </div>

        {/* Quick Links */}
        <div className="p-4 bg-white/5 backdrop-blur-xl border border-white/10 rounded-lg">
          <p className="text-xs text-gray-500 uppercase tracking-widest mb-3">Quick Navigation</p>
          <div className="flex flex-wrap gap-2 justify-center">
            <button onClick={() => navigate('/auth')} className="text-sm text-gray-400 hover:text-cyan-400 transition-colors px-3 py-1 rounded hover:bg-white/5">
              Sign In
            </button>
            <span className="text-gray-700">•</span>
            <button onClick={() => navigate('/blog')} className="text-sm text-gray-400 hover:text-cyan-400 transition-colors px-3 py-1 rounded hover:bg-white/5">
              Blog
            </button>
            <span className="text-gray-700">•</span>
            <button onClick={() => navigate('/vdp')} className="text-sm text-gray-400 hover:text-cyan-400 transition-colors px-3 py-1 rounded hover:bg-white/5">
              VDP
            </button>
            <span className="text-gray-700">•</span>
            <button onClick={() => navigate('/onboarding')} className="text-sm text-gray-400 hover:text-cyan-400 transition-colors px-3 py-1 rounded hover:bg-white/5">
              Get Started
            </button>
          </div>
        </div>

        {/* Brand Footer */}
        <div className="mt-10 flex items-center justify-center gap-2 text-gray-600">
          <Shield className="h-4 w-4" />
          <span className="text-xs uppercase tracking-widest">SouHimBou AI • Secure Navigation</span>
        </div>
      </div>
    </div>
  );
};

export default NotFound;
