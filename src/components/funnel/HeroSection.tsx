"use client";
import { useState, useRef } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { useNavigate } from 'react-router-dom';
import { Shield, Zap, CheckCircle, AlertTriangle, XCircle, Lock, Loader2, ArrowRight, Terminal, Mail } from 'lucide-react';

export const HeroSection = () => {
  const navigate = useNavigate();

  return (
    <section className="relative min-h-screen flex items-center overflow-hidden">
      {/* Animated Background */}
      <div className="absolute inset-0 z-0">
        <div className="absolute inset-0 bg-gradient-to-br from-[#0a0a0a] via-[#0d1421] to-[#0a0a0a]" />
        <motion.div
          className="absolute inset-0 opacity-20"
          animate={{
            background: [
              'radial-gradient(circle at 20% 30%, #00ffff 0%, transparent 40%)',
              'radial-gradient(circle at 80% 70%, #d4af37 0%, transparent 40%)',
              'radial-gradient(circle at 50% 50%, #00ffff 0%, transparent 40%)',
              'radial-gradient(circle at 20% 30%, #00ffff 0%, transparent 40%)',
            ],
          }}
          transition={{ duration: 15, repeat: Infinity, ease: 'linear' }}
        />
        <div className="absolute inset-0 bg-[linear-gradient(to_right,#00ffff08_1px,transparent_1px),linear-gradient(to_bottom,#00ffff08_1px,transparent_1px)] bg-[size:3rem_3rem]" />
      </div>

      <div className="container mx-auto px-6 py-20 relative z-10">
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-12 items-center">
          {/* Left Column */}
          <motion.div
            initial={{ opacity: 0, x: -30 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ duration: 0.8 }}
            className="space-y-8"
          >
            <div className="space-y-4">
              <div className="inline-flex items-center gap-2 bg-amber-950/40 border border-amber-500/30 rounded-full px-4 py-1.5 text-sm text-amber-400 font-medium mb-2">
                <span className="w-2 h-2 bg-amber-500 rounded-full animate-pulse" />
                72 live MCP tools · SSRF-Clean · PQC-Native OmniScanner
              </div>
              <h1 className="text-4xl md:text-5xl lg:text-6xl font-bold leading-tight">
                <span className="text-white">Your AI agents</span>
                <br />
                <span className="text-[#00ffff]">are being watched.</span>
                <br />
                <span className="text-white">Are you watching back?</span>
              </h1>

              <p className="text-lg md:text-xl text-gray-300 leading-relaxed max-w-xl">
                Stop flying blind. The world's first Agentic SOC protects against <span className="text-[#00ffff] font-semibold">OWASP LLM vulnerabilities</span>, API abuse, and prompt injections. We monitor your AI's tool execution in real-time and attest every action to an immutable DAG with{' '}
                <span className="text-[#00ffff] font-semibold">ML-DSA-65 signatures</span>. Secure your compliance with AI mandates today. Zero token extortion—just predictable, flat pricing.
              </p>
            </div>

            {/* CTAs */}
            <div className="flex flex-col sm:flex-row gap-4">
              <Button
                size="lg"
                onClick={() => navigate('/onboarding')}
                className="bg-gradient-to-r from-[#00ffff] to-[#0088ff] hover:from-[#00dddd] hover:to-[#0066dd] text-black font-bold text-lg px-8 py-6 rounded-lg shadow-[0_0_25px_rgba(0,255,255,0.4)] hover:shadow-[0_0_40px_rgba(0,255,255,0.6)] transition-all duration-300"
              >
                Run Free Scan — No Card Required
              </Button>
              <Button
                size="lg"
                variant="outline"
                onClick={() => navigate('/billing')}
                className="border-[#d4af37]/60 text-[#d4af37] hover:bg-[#d4af37]/10 font-semibold text-lg px-8 py-6 rounded-lg"
              >
                See Pricing
              </Button>
            </div>

            {/* Trust signals */}
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.8, delay: 0.5 }}
              className="flex flex-wrap gap-2"
            >
              <span className="text-xs px-3 py-1.5 bg-cyan-500/10 text-cyan-300 rounded border border-cyan-500/20">
                PQC-Signed · ML-DSA-65 (FIPS 204)
              </span>
              <span className="text-xs px-3 py-1.5 bg-amber-500/10 text-amber-300 rounded border border-amber-500/20">
                ADINKHEPRA Attestation
              </span>
              <span className="text-xs px-3 py-1.5 bg-green-500/10 text-green-300 rounded border border-green-500/20">
                SSRF-Clean Verified
              </span>
              <span className="text-xs px-3 py-1.5 bg-cyan-500/10 text-cyan-300 rounded border border-cyan-500/20">
                NIST 800-53 · STIG · CMMC
              </span>
              <span className="text-xs px-3 py-1.5 bg-purple-500/10 text-purple-300 rounded border border-purple-500/20">
                SDVOSB · SecRed Knowledge Inc.
              </span>
              <span className="text-xs px-3 py-1.5 bg-blue-500/10 text-blue-300 rounded border border-blue-500/20">
                USPTO #73565085
              </span>
              <span className="text-xs px-3 py-1.5 bg-yellow-500/10 text-yellow-300 rounded border border-yellow-500/20">
                $7.3M Post-Money Validation
              </span>
            </motion.div>
          </motion.div>

          {/* Right Column — Live Scan Widget */}
          <motion.div
            initial={{ opacity: 0, x: 30 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ duration: 0.8, delay: 0.3 }}
            className="relative"
          >
            <OperatorConsoleWidget />
          </motion.div>
        </div>
      </div>
    </section>
  );
};

const OperatorConsoleWidget = () => {
  const [isUnlocked, setIsUnlocked] = useState(false);
  const [email, setEmail] = useState("");

  const handleUnlock = (e: React.FormEvent) => {
    e.preventDefault();
    if (!email.trim() || !email.includes("@")) return;
    setIsUnlocked(true);
  };

  return (
    <div className="bg-[#050c16] border border-cyan-500/30 rounded-2xl overflow-hidden shadow-[0_0_40px_rgba(0,255,255,0.1)] relative w-full h-[500px] flex flex-col">
      <div className="bg-[#080f1c] border-b border-cyan-500/20 px-4 py-2 flex items-center gap-2 shrink-0">
        <div className="w-3 h-3 rounded-full bg-red-500"></div>
        <div className="w-3 h-3 rounded-full bg-yellow-500"></div>
        <div className="w-3 h-3 rounded-full bg-green-500"></div>
        <span className="ml-2 text-xs text-gray-500 font-mono">khepra-terminal</span>
      </div>

      {!isUnlocked ? (
        <div className="flex flex-col items-center justify-center flex-1 p-6 relative">
          <div className="absolute inset-0 flex items-center justify-center opacity-10">
            <Terminal className="w-64 h-64 text-cyan-500" />
          </div>
          
          <div className="relative z-20 bg-slate-900/90 backdrop-blur-xl border border-slate-700 p-6 rounded-2xl w-full shadow-2xl">
            <div className="w-12 h-12 bg-cyan-500/10 border border-cyan-500/30 rounded-full flex items-center justify-center mx-auto mb-4">
              <Lock className="w-6 h-6 text-cyan-400" />
            </div>
            
            <h3 className="text-lg font-bold text-white text-center mb-2">Access the Live Demo</h3>
            <p className="text-xs text-gray-400 text-center mb-6">
              Enter your work email to unlock the interactive KHEPRA Operator Console.
            </p>

            <form onSubmit={handleUnlock} className="space-y-4">
              <div className="space-y-1">
                <div className="relative">
                  <Mail className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500" />
                  <Input 
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
          </div>
        </div>
      ) : (
        <div className="w-full flex-1">
          <iframe 
            src="/console.html" 
            title="KHEPRA Operator Console"
            className="w-full h-full border-none"
          />
        </div>
      )}
    </div>
  );
};
