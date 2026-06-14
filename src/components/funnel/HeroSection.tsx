import { motion } from 'framer-motion';
import { Button } from '@/components/ui/button';
import { Server, Lock } from 'lucide-react';
import { useNavigate } from 'react-router-dom';

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
              <div className="inline-flex items-center gap-2 bg-amber-950/40 border border-amber-500/30 rounded-full px-4 py-1.5 text-sm text-amber-400 font-medium mb-2">
                <span className="w-2 h-2 bg-amber-500 rounded-full animate-pulse" />
                CMMC &amp; NIST 800-171 — evidence packages assessors actually use
              </div>
              <h1 className="text-4xl md:text-5xl lg:text-6xl font-bold leading-tight">
                <span className="text-white">Audit-ready</span>
                <br />
                <span className="text-[#00ffff]">compliance</span>{' '}
                <span className="text-white">for regulated teams.</span>
              </h1>

              {/* Subheadline */}
              <p className="text-lg md:text-xl text-gray-300 leading-relaxed max-w-xl">
                ASAF runs readiness scans and maps findings to control-oriented evidence — so ISSMs and C3PAO prep teams get traceable outputs, not slide decks.
                Earn your <span className="text-[#d4af37] font-semibold">ADINKHEPRA seal</span> when you certify. Agent gateways (e.g. NemoClaw profile) supported where in scope.
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
                  onClick={() => navigate('/advisory')}
                className="border-[#d4af37]/60 text-[#d4af37] hover:bg-[#d4af37]/10 font-semibold text-lg px-8 py-6 rounded-lg"
              >
                Book Advisory Call
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
                PQC-Signed · ML-DSA-65
              </span>
              <span className="text-xs px-3 py-1.5 bg-amber-500/10 text-amber-300 rounded border border-amber-500/20">
                ADINKHEPRA Attestation
              </span>
              <span className="text-xs px-3 py-1.5 bg-green-500/10 text-green-300 rounded border border-green-500/20">
                Immutable DAG Audit Trail
              </span>
              <span className="text-xs px-3 py-1.5 bg-cyan-500/10 text-cyan-300 rounded border border-cyan-500/20">
                NIST 800-53 · STIG · CMMC
              </span>
            </motion.div>
          </motion.div>

          {/* Right Column - Live Scan Flow */}
          <motion.div
            initial={{ opacity: 0, x: 30 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ duration: 0.8, delay: 0.3 }}
            className="relative"
          >
            <div className="relative bg-gradient-to-br from-slate-800/40 to-slate-900/60 border border-[#00ffff]/30 rounded-2xl p-8 backdrop-blur-sm">
              <div className="space-y-5">
                <h3 className="text-base font-semibold text-gray-300 uppercase tracking-widest text-center">
                  How it works
                </h3>

                {/* Step 1 */}
                <motion.div
                  className="flex items-start gap-4 bg-slate-800/50 border border-gray-700/60 rounded-xl p-4"
                  animate={{ boxShadow: ['0 0 0px rgba(0,255,255,0)', '0 0 12px rgba(0,255,255,0.15)', '0 0 0px rgba(0,255,255,0)'] }}
                  transition={{ duration: 4, repeat: Infinity, delay: 0 }}
                >
                  <div className="flex-shrink-0 w-7 h-7 rounded-full bg-[#00ffff]/15 border border-[#00ffff]/40 flex items-center justify-center text-xs font-bold text-[#00ffff]">1</div>
                  <div>
                    <p className="text-sm font-medium text-white">Enter your target</p>
                    <p className="text-xs text-gray-400 mt-0.5">Hostname, IP, or agent gateway URL — no install required</p>
                  </div>
                </motion.div>

                {/* Connector */}
                <div className="flex justify-center"><div className="w-px h-5 bg-gradient-to-b from-[#00ffff]/40 to-[#d4af37]/40" /></div>

                {/* Step 2 */}
                <motion.div
                  className="flex items-start gap-4 bg-slate-800/50 border border-gray-700/60 rounded-xl p-4"
                  animate={{ boxShadow: ['0 0 0px rgba(0,255,255,0)', '0 0 12px rgba(0,255,255,0.15)', '0 0 0px rgba(0,255,255,0)'] }}
                  transition={{ duration: 4, repeat: Infinity, delay: 1.3 }}
                >
                  <div className="flex-shrink-0 w-7 h-7 rounded-full bg-[#00ffff]/15 border border-[#00ffff]/40 flex items-center justify-center text-xs font-bold text-[#00ffff]">2</div>
                  <div>
                    <div className="flex items-center gap-2">
                      <p className="text-sm font-medium text-white">ASAF scans in ~60s</p>
                      <Server className="h-3.5 w-3.5 text-gray-500" />
                    </div>
                    <p className="text-xs text-gray-400 mt-0.5">STIG checks · CMMC control mapping · exposure surface · AI agent risk</p>
                  </div>
                </motion.div>

                {/* Connector */}
                <div className="flex justify-center"><div className="w-px h-5 bg-gradient-to-b from-[#d4af37]/40 to-[#d4af37]/40" /></div>

                {/* Step 3 */}
                <motion.div
                  className="flex items-start gap-4 bg-slate-800/50 border border-gray-700/60 rounded-xl p-4"
                  animate={{ boxShadow: ['0 0 0px rgba(212,175,55,0)', '0 0 12px rgba(212,175,55,0.15)', '0 0 0px rgba(212,175,55,0)'] }}
                  transition={{ duration: 4, repeat: Infinity, delay: 2.6 }}
                >
                  <div className="flex-shrink-0 w-7 h-7 rounded-full bg-[#d4af37]/15 border border-[#d4af37]/40 flex items-center justify-center text-xs font-bold text-[#d4af37]">3</div>
                  <div>
                    <p className="text-sm font-medium text-white">Get your free exposure report</p>
                    <p className="text-xs text-gray-400 mt-0.5">Risk score · findings · CMMC readiness · remediation priorities</p>
                  </div>
                </motion.div>

                {/* Connector */}
                <div className="flex justify-center"><div className="w-px h-5 bg-gradient-to-b from-[#d4af37]/40 to-[#d4af37]/60" /></div>

                {/* Step 4 — Upsell hint */}
                <motion.div
                  className="flex items-start gap-4 bg-gradient-to-r from-[#d4af37]/10 to-[#b8860b]/10 border border-[#d4af37]/40 rounded-xl p-4"
                  animate={{ boxShadow: ['0 0 8px rgba(212,175,55,0.1)', '0 0 20px rgba(212,175,55,0.3)', '0 0 8px rgba(212,175,55,0.1)'] }}
                  transition={{ duration: 3, repeat: Infinity, delay: 1 }}
                >
                  <Lock className="h-5 w-5 text-[#d4af37] flex-shrink-0 mt-0.5" />
                  <div>
                    <p className="text-sm font-medium text-white">Earn your ADINKHEPRA seal — $99</p>
                    <p className="text-xs text-gray-400 mt-0.5">PQC-signed badge · DAG audit trail · shareable with CISOs &amp; auditors</p>
                  </div>
                </motion.div>
              </div>
            </div>
          </motion.div>
        </div>
      </div>
    </section>
  );
};
