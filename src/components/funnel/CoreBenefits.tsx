import { motion } from 'framer-motion';
import { Bot, Eye, ShieldCheck, Cpu } from 'lucide-react';

export const CoreBenefits = () => {
  const benefits = [
    {
      icon: Bot,
      title: 'Agentic SOC — AI Watching AI',
      badge: 'Live',
      badgeColor: 'bg-green-500/20 text-green-300 border-green-500/30',
      description:
        'SouHimBou AI is your AI Security Architect. It wraps every agent in your stack, attests each tool call to an immutable DAG, and runs KASA autonomous threat detection in the background — 24/7.',
      gradient: 'from-cyan-500/15 to-blue-500/10',
      borderColor: 'border-cyan-500/30',
      iconColor: 'text-cyan-400',
    },
    {
      icon: ShieldCheck,
      title: 'Post-Quantum Attestation',
      badge: 'FIPS 204',
      badgeColor: 'bg-amber-500/20 text-amber-300 border-amber-500/30',
      description:
        'Every tool call is ML-DSA-65 signed before it hits the DAG. Your audit trail is quantum-safe today — not after NIST mandates it. C3PAO and CMMC auditors can verify the chain cryptographically.',
      gradient: 'from-amber-500/15 to-orange-500/10',
      borderColor: 'border-amber-500/30',
      iconColor: 'text-amber-400',
    },
    {
      icon: Eye,
      title: '36,195 Compliance Mappings',
      badge: 'Embedded',
      badgeColor: 'bg-purple-500/20 text-purple-300 border-purple-500/30',
      description:
        'STIG → CCI → NIST 800-53 → NIST 800-171 → CMMC — all embedded in the binary. Zero external API calls, zero internet dependency. Air-gappable. Sovereign. The only compliance engine that runs on your metal.',
      gradient: 'from-purple-500/15 to-pink-500/10',
      borderColor: 'border-purple-500/30',
      iconColor: 'text-purple-400',
    },
    {
      icon: Cpu,
      title: 'KASA Autonomous Threat Engine',
      badge: 'EA-Powered',
      badgeColor: 'bg-cyan-500/20 text-cyan-300 border-cyan-500/30',
      description:
        'KASA runs a 50-individual evolutionary algorithm that continuously updates threat-weighted compliance fitness — so the system gets smarter as your threat landscape shifts. Every generation ML-DSA-65 signed to DAG.',
      gradient: 'from-blue-500/15 to-cyan-500/10',
      borderColor: 'border-blue-500/30',
      iconColor: 'text-blue-400',
    },
  ];

  return (
    <section className="py-24 bg-[#0a0a0a] relative overflow-hidden">
      <div className="absolute inset-0 opacity-10">
        <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[600px] h-[600px] bg-[#00ffff] rounded-full filter blur-[200px]" />
      </div>

      <div className="container mx-auto px-6 relative z-10">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6 }}
          viewport={{ once: true }}
          className="text-center mb-16"
        >
          <h2 className="text-3xl md:text-4xl font-bold text-white mb-4">
            What <span className="text-[#00ffff]">SouHimBou AI</span> Actually Does
          </h2>
          <p className="text-gray-400 max-w-2xl mx-auto">
            Not a concept. Not a prototype. Production-grade, running today, at{' '}
            <span className="text-[#00ffff] font-mono">mcp.souhimbou.ai</span>.
          </p>
        </motion.div>

        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-6 max-w-7xl mx-auto">
          {benefits.map((benefit, index) => (
            <motion.div
              key={index}
              initial={{ opacity: 0, y: 30 }}
              whileInView={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.6, delay: index * 0.12 }}
              viewport={{ once: true }}
              className={`relative bg-gradient-to-br ${benefit.gradient} border ${benefit.borderColor} rounded-xl p-7 backdrop-blur-sm hover:border-opacity-60 transition-all duration-300 group`}
            >
              {/* Badge */}
              <div className="absolute -top-3 right-5">
                <span className={`text-xs px-3 py-1 rounded-full border ${benefit.badgeColor}`}>
                  {benefit.badge}
                </span>
              </div>

              <div className="mb-5 pt-2">
                <benefit.icon className={`h-10 w-10 ${benefit.iconColor} group-hover:scale-110 transition-transform duration-300`} />
              </div>

              <h3 className="text-lg font-semibold text-white mb-3">{benefit.title}</h3>
              <p className="text-gray-400 text-sm leading-relaxed">{benefit.description}</p>
            </motion.div>
          ))}
        </div>
      </div>
    </section>
  );
};
