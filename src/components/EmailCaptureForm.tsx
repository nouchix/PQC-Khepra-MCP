import { useState } from "react";
import { useNavigate } from '@/lib/router-compat';
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Play, ChevronRight, Shield, Target } from "lucide-react";
import { toast } from "sonner";

const EmailCaptureForm = () => {
  const [email, setEmail] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const navigate = useNavigate();

  const handleSubmit = async (action: string) => {
    if (!email) {
      toast.error("Please enter your email address");
      return;
    }

    // Basic email validation
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      toast.error("Please enter a valid email address");
      return;
    }

    setIsLoading(true);
    
    // Store email in sessionStorage (more secure than localStorage) for the auth page to use
    sessionStorage.setItem("capturedEmail", email);
    sessionStorage.setItem("selectedAction", action);
    
    // Navigate to auth page with email pre-filled
    navigate(`/auth?email=${encodeURIComponent(email)}&action=${action}`);
  };

  return (
    <div className="bg-black/20 backdrop-blur-lg border border-blue-500/20 rounded-2xl p-8 space-y-6">
      <div className="text-center space-y-4">
        <h3 className="text-2xl font-bold text-white">
          🚀 Join Trailblazer Beta
        </h3>
        <p className="text-gray-300">
          Experience next-gen cybersecurity • Starting at $19/month • Basic features included
        </p>
        <div className="flex items-center justify-center space-x-4 text-sm text-gray-400">
          <div className="flex items-center space-x-1">
            <div className="w-2 h-2 bg-green-400 rounded-full"></div>
            <span>SOC 2 Compliant</span>
          </div>
          <div className="flex items-center space-x-1">
            <div className="w-2 h-2 bg-blue-400 rounded-full"></div>
            <span>CMMC Ready</span>
          </div>
          <div className="flex items-center space-x-1">
            <div className="w-2 h-2 bg-purple-400 rounded-full"></div>
            <span>Designed for DoD</span>
          </div>
        </div>
      </div>

      <div className="space-y-4">
        <div className="relative">
          <Input
            type="email"
            placeholder="Enter your work email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            className="h-12 text-lg bg-white/10 border-blue-500/30 text-white placeholder:text-gray-400 focus:border-blue-400"
            onKeyPress={(e) => {
              if (e.key === 'Enter') {
                handleSubmit('trial');
              }
            }}
          />
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
          <Button
            size="lg"
            onClick={() => handleSubmit('beta')}
            disabled={isLoading}
            className="bg-gradient-to-r from-blue-500 to-purple-500 hover:from-blue-600 hover:to-purple-600 text-lg px-6 py-3 h-auto"
          >
            <Play className="h-4 w-4 mr-2" />
            Trailblazer Beta
            <ChevronRight className="h-4 w-4 ml-2" />
          </Button>

          <Button
            size="lg"
            variant="outline"
            onClick={() => handleSubmit('cmmc')}
            disabled={isLoading}
            className="border-blue-500/30 text-blue-400 hover:bg-blue-500/20 text-lg px-6 py-3 h-auto"
          >
            <Shield className="h-4 w-4 mr-2" />
            CMMC Compliance
          </Button>

          <Button
            size="lg"
            variant="outline"
            onClick={() => handleSubmit('assessment')}
            disabled={isLoading}
            className="border-green-500/30 text-green-400 hover:bg-green-500/20 text-lg px-6 py-3 h-auto"
          >
            <Target className="h-4 w-4 mr-2" />
            Security Assessment
          </Button>
        </div>

        <div className="text-center space-y-2">
          <p className="text-xs text-gray-400">
            ✅ Starting at $19/month • ✅ Setup in 5 minutes • ✅ Cancel anytime
          </p>
          <p className="text-xs text-blue-400 font-medium">
            🎯 Join our Product Hunt launch • Get exclusive early access features
          </p>
        </div>
      </div>
    </div>
  );
};

export default EmailCaptureForm;