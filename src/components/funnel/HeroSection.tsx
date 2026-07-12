"use client";
import { useState, useRef } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { useNavigate } from 'react-router-dom';
import { Shield, Zap, CheckCircle, AlertTriangle, XCircle, Lock, Loader2, ArrowRight } from 'lucide-react';

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
