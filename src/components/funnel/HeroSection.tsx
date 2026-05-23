import { motion } from 'framer-motion';
import { Button } from '@/components/ui/button';
import { Shield, Server, Database, Lock, Cpu, Network } from 'lucide-react';
import { useNavigate } from '@/lib/router-compat';

export const HeroSection = () => {
  const navigate = useNavigate();
  
  const scrollToSystemOverview = () => {
    document.getElementById('system-overview')?.scrollIntoView({ behavior: 'smooth' });
  };

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
        {/* Neural network grid */}
        <div className="absolute inset-0 bg-[linear-gradient(to_right,#00ffff08_1px,transparent_1px),linear-gradient(to_bottom,#00ffff08_1px,transparent_1px)] bg-[size:3rem_3rem]" />
      </div>

      <div className="container mx-auto px-6 py-20 relative z-10">
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-12 items-center">
          {/* Left Column - Headlines & CTAs */}
          <motion.div
            initial={{ opacity: 0, x: -30 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ duration: 0.8 }}
            className="space-y-8"
          >
            {/* Main Headline */}
            <div className="space-y-4">
              <div className="inline-flex items-center gap-2 bg-red-950/40 border border-red-500/30 rounded-full px-4 py-1.5 text-sm text-red-400 font-medium mb-2">
                <span className="w-2 h-2 bg-red-500 rounded-full animate-pulse" />
                30,000+ AI agent instances exposed. Is yours one of them?
              </div>
              <h1 className="text-4xl md:text-5xl lg:text-6xl font-bold leading-tight">
                <span className="text-white">We build agents</span>
                <br />
                <span className="text-[#00ffff]">that secure</span>{' '}
                <span className="text-white">other agents.</span>
              </h1>

              {/* Subheadline */}
              <p className="text-lg md:text-xl text-gray-300 leading-relaxed max-w-xl">
                ASAF scans, audits, and cryptographically certifies AI agent deployments —
                so your enterprise can say yes to agentic AI without saying yes to unacceptable risk.
                Earn your <span className="text-[#d4af37] font-semibold">ADINKHEPRA badge</span>: the security standard for the agentic era.
              </p>
            </div>

            {/* CTAs */}
            <div className="flex flex-col sm:flex-row gap-4">
              <Button
                size="lg"
                onClick={() => navigate('/onboarding')}
                className="bg-gradient-to-r from-[#00ffff] to-[#0088ff] hover:from-[#00dddd] hover:to-[#0066dd] text-black font-bold text-lg px-8 py-6 rounded-lg shadow-[0_0_25px_rgba(0,255,255,0.4)] hover:shadow-[0_0_40px_rgba(0,255,255,0.6)] transition-all duration-300"
              >
                Scan Free — No Card Required
              </Button>
              <Button
                size="lg"
                variant="outline"
                onClick={scrollToSystemOverview}
                className="border-[#d4af37]/60 text-[#d4af37] hover:bg-[#d4af37]/10 font-semibold text-lg px-8 py-6 rounded-lg"
              >
                See How It Works
              </Button>
            </div>

            {/* Development Status Banner */}
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.8, delay: 0.5 }}
              className="border border-yellow-500/40 rounded-lg bg-yellow-900/10 p-5 backdrop-blur-sm"
            >
              <div className="flex items-start gap-4">
                <Shield className="h-5 w-5 text-yellow-400 flex-shrink-0 mt-0.5" />
                <div className="space-y-3">
                  <h3 className="text-base font-semibold text-yellow-400">
                    🚧 Platform Development Status
                  </h3>
                  <p className="text-gray-300 text-sm leading-relaxed">
                    SouHimBou AI is in active development and <strong>NOT ready for production CUI workloads</strong>. 
                    Current prototypes are demonstration-only.
                  </p>
                  <div className="flex flex-wrap gap-2">
                    <span className="text-xs px-3 py-1.5 bg-yellow-500/15 text-yellow-300 rounded border border-yellow-500/30">
                      ⚠ Beta UI Only
                    </span>
                    <span className="text-xs px-3 py-1.5 bg-blue-500/15 text-blue-300 rounded border border-blue-500/30">
                      🔒 GovCloud Architecture Planned (Q2)
                    </span>
                    <span className="text-xs px-3 py-1.5 bg-blue-500/15 text-blue-300 rounded border border-blue-500/30">
                      📋 CMMC Alignment In Progress (Q3)
                    </span>
                    <span className="text-xs px-3 py-1.5 bg-green-500/15 text-green-300 rounded border border-green-500/30">
                      ✓ Accepting Pilot Partners
                    </span>
                  </div>
                </div>
              </div>
            </motion.div>
          </motion.div>

          {/* Right Column - Architecture Visual */}
          <motion.div
            initial={{ opacity: 0, x: 30 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ duration: 0.8, delay: 0.3 }}
            className="relative"
          >
            <div className="relative bg-gradient-to-br from-slate-800/40 to-slate-900/60 border border-[#00ffff]/30 rounded-2xl p-8 backdrop-blur-sm">
              {/* Concept Label */}
              <div className="absolute -top-3 left-6">
                <span className="text-xs px-3 py-1 bg-[#0a0a0a] text-gray-400 border border-gray-700 rounded-full">
                  In Development — Concept Only
                </span>
              </div>

              {/* Architecture Diagram */}
              <div className="space-y-6 pt-4">
                <h3 className="text-lg font-semibold text-white text-center mb-6">
                  SouHimBou AI Architecture
                </h3>

                {/* Top Layer - User Interface */}
                <motion.div 
                  className="bg-gradient-to-r from-[#00ffff]/10 to-[#0088ff]/10 border border-[#00ffff]/40 rounded-lg p-4 text-center"
                  animate={{ boxShadow: ['0 0 10px rgba(0,255,255,0.2)', '0 0 20px rgba(0,255,255,0.4)', '0 0 10px rgba(0,255,255,0.2)'] }}
                  transition={{ duration: 3, repeat: Infinity }}
                >
                  <Cpu className="h-6 w-6 text-[#00ffff] mx-auto mb-2" />
                  <span className="text-sm text-white font-medium">AI Compliance Engine</span>
                  <span className="text-xs text-gray-400 block">(Prototype)</span>
                </motion.div>

                {/* Connector */}
                <div className="flex justify-center">
                  <div className="w-px h-8 bg-gradient-to-b from-[#00ffff]/60 to-[#d4af37]/60" />
                </div>

                {/* Middle Layer - Processing */}
                <div className="grid grid-cols-3 gap-4">
                  <div className="bg-slate-800/50 border border-gray-700 rounded-lg p-3 text-center">
                    <Server className="h-5 w-5 text-[#d4af37] mx-auto mb-1" />
                    <span className="text-xs text-gray-300">STIG Parser</span>
                  </div>
                  <div className="bg-slate-800/50 border border-gray-700 rounded-lg p-3 text-center">
                    <Network className="h-5 w-5 text-[#d4af37] mx-auto mb-1" />
                    <span className="text-xs text-gray-300">Control Mapper</span>
                  </div>
                  <div className="bg-slate-800/50 border border-gray-700 rounded-lg p-3 text-center">
                    <Lock className="h-5 w-5 text-[#d4af37] mx-auto mb-1" />
                    <span className="text-xs text-gray-300">Evidence Gen</span>
                  </div>
                </div>

                {/* Connector */}
                <div className="flex justify-center">
                  <div className="w-px h-8 bg-gradient-to-b from-[#d4af37]/60 to-[#00ffff]/60" />
                </div>

                {/* Bottom Layer - Data */}
                <motion.div 
                  className="bg-gradient-to-r from-[#d4af37]/10 to-[#b8860b]/10 border border-[#d4af37]/40 rounded-lg p-4 text-center"
                  animate={{ boxShadow: ['0 0 10px rgba(212,175,55,0.2)', '0 0 20px rgba(212,175,55,0.4)', '0 0 10px rgba(212,175,55,0.2)'] }}
                  transition={{ duration: 3, repeat: Infinity, delay: 1.5 }}
                >
                  <Database className="h-6 w-6 text-[#d4af37] mx-auto mb-2" />
                  <span className="text-sm text-white font-medium">Secure Enclave</span>
                  <span className="text-xs text-gray-400 block">(AWS GovCloud — Planned)</span>
                </motion.div>
              </div>
            </div>
          </motion.div>
        </div>
      </div>
    </section>
  );
};
