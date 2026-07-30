"use client";
import { useState } from "react";
import { Lock, Mail, Terminal, ArrowRight } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";

export const OperatorConsoleDemo = () => {
  const [isUnlocked, setIsUnlocked] = useState(false);
  const [email, setEmail] = useState("");

  const handleUnlock = (e: React.FormEvent) => {
    e.preventDefault();
    if (!email.trim() || !email.includes("@")) return;
    
    // In a real implementation, you would save the email to Supabase/HubSpot here
    // For now, we simply unlock the console locally
    setIsUnlocked(true);
  };

  return (
    <div className="w-full py-12">
      <div className="max-w-6xl mx-auto">
        <div className="text-center mb-10 space-y-3">
          <h2 className="text-3xl md:text-4xl font-bold text-white">Live KHEPRA Operator Console</h2>
          <p className="text-gray-400 max-w-2xl mx-auto">
            Experience the Sovereign PQC Edge. Run an OmniScan against the agent gateway, attest every finding with ML-DSA-65 signatures, and generate a C3PAO-ready report.
          </p>
        </div>

        <div className="bg-[#050c16] border border-cyan-500/30 rounded-2xl overflow-hidden shadow-[0_0_40px_rgba(0,255,255,0.1)] relative">
          
          {/* Top Bar for Console */}
          <div className="bg-[#080f1c] border-b border-cyan-500/20 px-4 py-2 flex items-center gap-2">
            <div className="w-3 h-3 rounded-full bg-red-500"></div>
            <div className="w-3 h-3 rounded-full bg-yellow-500"></div>
            <div className="w-3 h-3 rounded-full bg-green-500"></div>
            <span className="ml-2 text-xs text-gray-500 font-mono">khepra-terminal // operator mode</span>
          </div>

          {!isUnlocked ? (
            <div className="flex flex-col items-center justify-center py-24 px-6 relative z-10 min-h-[500px]">
              <div className="absolute inset-0 flex items-center justify-center opacity-10">
                <Terminal className="w-96 h-96 text-cyan-500" />
              </div>
              
              <div className="relative z-20 bg-slate-900/80 backdrop-blur-xl border border-slate-700 p-8 rounded-2xl max-w-md w-full shadow-2xl">
                <div className="w-16 h-16 bg-cyan-500/10 border border-cyan-500/30 rounded-full flex items-center justify-center mx-auto mb-6">
                  <Lock className="w-8 h-8 text-cyan-400" />
                </div>
                
                <h3 className="text-xl font-bold text-white text-center mb-2">Access the Live Demo</h3>
                <p className="text-sm text-gray-400 text-center mb-8">
                  Enter your email to unlock the interactive KHEPRA Operator Console and run a simulated PQC-secured scan.
                </p>

                <form onSubmit={handleUnlock} className="space-y-4">
                  <div className="space-y-2">
                    <label htmlFor="email" className="text-xs font-semibold text-gray-300 uppercase tracking-wider">
                      Work Email
                    </label>
                    <div className="relative">
                      <Mail className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500" />
                      <Input 
                        id="email"
                        type="email"
                        placeholder="ciso@defense-contractor.com"
                        value={email}
                        onChange={(e) => setEmail(e.target.value)}
                        className="pl-10 bg-[#0a0a0a] border-gray-700 text-white focus:border-cyan-500"
                        required
                      />
                    </div>
                  </div>
                  <Button 
                    type="submit" 
                    className="w-full bg-gradient-to-r from-cyan-500 to-blue-600 text-white font-bold hover:shadow-[0_0_20px_rgba(0,255,255,0.4)] transition-all"
                  >
                    Unlock Live Console <ArrowRight className="w-4 h-4 ml-2" />
                  </Button>
                </form>
                
                <p className="text-[10px] text-gray-500 text-center mt-6">
                  By unlocking, you agree to receive follow-up information about the PQC-Khepra-MCP platform. No spam.
                </p>
              </div>
            </div>
          ) : (
            <div className="w-full h-[700px]">
              <iframe 
                src="/console.html" 
                title="KHEPRA Operator Console"
                className="w-full h-full border-none"
              />
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
