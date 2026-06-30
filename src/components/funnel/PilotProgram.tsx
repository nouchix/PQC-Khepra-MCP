"use client";
import { motion } from 'framer-motion';
import { Button } from '@/components/ui/button';
import { Zap, Shield, FileText, BarChart3, Users, Star } from 'lucide-react';
import { useNavigate } from '@/lib/router-compat';

export const PilotProgram = () => {
  const navigate = useNavigate();

  const tiers = [
    {
      name: 'Free',
      price: '$0',
      period: '',
      highlight: false,
      badge: null,
      description: 'Scan any AI agent deployment. Instant exposure report.',
      features: [
        'Free agent exposure scan',
        'Risk score + top findings',
        'NIST/STIG control gaps identified',
        'No account required',
        'Powered by KHEPRA MCP live',
      ],
      cta: 'Run Free Scan',
      ctaAction: () => {},
    },
    {
      name: 'Certify',
      price: '$99',
      period: '/mo',
      highlight: true,
      badge: 'Most Popular',
      description: 'Full compliance audit + PQC-signed certification badge.',
      features: [
        'Everything in Free',
        'Full NIST 800-53 / STIG / CMMC audit',
        'ML-DSA-65 signed ADINKHEPRA badge',
        'Shareable attestation report',
        'DAG audit trail (90 days)',
        'Email support',
      ],
      cta: 'Start Certification',
      ctaAction: () => {},
    },
    {
      name: 'Enterprise',
      price: '$499',
      period: '/mo',
      highlight: false,
      badge: 'Agentic SOC',
      description: 'Full Agentic SOC — continuous monitoring + team seats.',
      features: [
        'Everything in Certify',
        'KASA continuous threat monitoring',
        'SOAR playbook engine (signed)',
        'Unlimited DAG history',
        'SIEM integration (Splunk/Elastic)',
        'Up to 10 team seats',
        'Priority support',
      ],
      cta: 'Contact Sales',
      ctaAction: () => {},
    },
  ];

  const stats = [
    { icon: Shield, value: '72', label: 'Live MCP Tools' },
    { icon: FileText, value: '36,195', label: 'Compliance Mappings' },
    { icon: BarChart3, value: 'ML-DSA-65', label: 'PQC Standard (FIPS 204)' },
    { icon: Users, value: 'SDVOSB', label: 'SecRed Knowledge Inc.' },
  ];

  return (
    <section className="py-32 bg-[#0a0a0a] relative overflow-hidden">
      <div className="absolute top-0 right-0 w-96 h-96 bg-[#d4af37] rounded-full filter blur-[200px] opacity-8" />
      <div className="absolute bottom-0 left-0 w-96 h-96 bg-[#00ffff] rounded-full filter blur-[200px] opacity-8" />

      <div className="container mx-auto px-6 relative z-10">
        {/* Stats bar */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6 }}
          viewport={{ once: true }}
          className="grid grid-cols-2 md:grid-cols-4 gap-4 max-w-4xl mx-auto mb-20"
        >
          {stats.map((stat, i) => (
            <div key={i} className="text-center bg-slate-900/40 border border-gray-800 rounded-xl p-5">
              <stat.icon className="h-5 w-5 text-[#00ffff] mx-auto mb-2" />
              <div className="text-xl font-bold text-white">{stat.value}</div>
              <div className="text-xs text-gray-500 mt-0.5">{stat.label}</div>
            </div>
          ))}
        </motion.div>

        <motion.div
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6 }}
          viewport={{ once: true }}
          className="text-center mb-12"
        >
          <div className="inline-flex items-center gap-2 px-4 py-2 bg-[#d4af37]/10 border border-[#d4af37]/30 rounded-full mb-6">
            <Star className="h-4 w-4 text-[#d4af37]" />
            <span className="text-sm text-[#d4af37] font-medium">Simple, transparent pricing</span>
          </div>
          <h2 className="text-3xl md:text-5xl font-bold text-white mb-4">
            Scan Free. <span className="text-[#d4af37]">Certify when ready.</span>
          </h2>
          <p className="text-xl text-gray-300 max-w-2xl mx-auto">
            No sales call required. No install. Scan your agent deployment now — upgrade to earn the badge your CISO needs.
          </p>
        </motion.div>

        {/* Pricing Grid */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6, delay: 0.2 }}
          viewport={{ once: true }}
          className="grid grid-cols-1 md:grid-cols-3 gap-6 max-w-5xl mx-auto mb-12"
        >
          {tiers.map((tier, index) => (
            <div
              key={index}
              className={`relative rounded-xl p-7 border transition-all duration-300 ${
                tier.highlight
                  ? 'bg-gradient-to-br from-cyan-900/20 to-blue-900/20 border-[#00ffff]/50 shadow-[0_0_30px_rgba(0,255,255,0.12)]'
                  : 'bg-slate-900/40 border-gray-800 hover:border-gray-700'
              }`}
            >
              {tier.badge && (
                <div className="absolute -top-3 right-5">
                  <span className={`text-xs px-3 py-1 rounded-full border font-medium ${
                    tier.highlight
                      ? 'bg-cyan-900/40 text-cyan-300 border-cyan-500/40'
                      : 'bg-amber-900/40 text-amber-300 border-amber-500/40'
                  }`}>
                    {tier.badge}
                  </span>
                </div>
              )}

              <div className="mb-5">
                <h3 className="text-lg font-bold text-white">{tier.name}</h3>
                <div className="flex items-end gap-1 mt-1">
                  <span className="text-3xl font-black text-white">{tier.price}</span>
                  <span className="text-gray-500 text-sm mb-1">{tier.period}</span>
                </div>
                <p className="text-sm text-gray-400 mt-2">{tier.description}</p>
              </div>

              <ul className="space-y-2.5 mb-7">
                {tier.features.map((f, i) => (
                  <li key={i} className="flex items-start gap-2 text-sm text-gray-300">
                    <Zap className="h-3.5 w-3.5 text-[#00ffff] shrink-0 mt-0.5" />
                    {f}
                  </li>
                ))}
              </ul>

              <Button
                onClick={() => tier.name === 'Free' ? navigate('/onboarding') : tier.name === 'Enterprise' ? window.location.href = 'mailto:skone@alumni.albany.edu?subject=SouHimBou%20AI%20Enterprise' : navigate('/billing')}
                variant={tier.highlight ? 'default' : 'outline'}
                className={`w-full ${
                  tier.highlight
                    ? 'bg-gradient-to-r from-[#00ffff] to-[#0088ff] text-black font-bold hover:opacity-90'
                    : 'border-gray-700 text-gray-300 hover:border-gray-600'
                }`}
              >
                {tier.cta}
              </Button>
            </div>
          ))}
        </motion.div>

        <p className="text-center text-xs text-gray-600">
          Billed monthly via Stripe. Cancel anytime. ADINKHEPRA badge issued within minutes of payment.
          Questions? <a href="mailto:skone@alumni.albany.edu" className="text-gray-500 hover:text-gray-400 underline">Email us</a>.
        </p>
      </div>
    </section>
  );
};
