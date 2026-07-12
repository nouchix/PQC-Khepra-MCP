import { motion } from 'framer-motion';
import { Bot, Eye, ShieldCheck, Cpu } from 'lucide-react';

export const CoreBenefits = () => {
  const benefits = [
    {
      icon: Eye,
      title: 'Agentic Observability & Key Monitoring',
      badge: 'Live',
      badgeColor: 'bg-green-500/20 text-green-300 border-green-500/30',
      description:
        'Stop flying blind. SouHimBou AI acts as your flight recorder, wrapping every agent in your stack to attest each tool call to an immutable DAG. Monitor API key access and usage in real-time, 24/7.',
      gradient: 'from-green-500/15 to-emerald-500/10',
      borderColor: 'border-green-500/30',
      iconColor: 'text-green-400',
    },
    {
      icon: ShieldCheck,
      title: 'OWASP MCP & LLM Abuse Protection',
      badge: 'Active Defense',
      badgeColor: 'bg-amber-500/20 text-amber-300 border-amber-500/30',
      description:
        'Recent real-life cases of AI abuse (like prompt injections executing unauthorized terminal commands) cost companies millions. We enforce OWASP LLM and API Top 10 controls at the gateway level, keeping your agents SSRF-clean.',
      gradient: 'from-amber-500/15 to-orange-500/10',
      borderColor: 'border-amber-500/30',
      iconColor: 'text-amber-400',
    },
    {
      icon: Bot,
      title: 'AI Mandate Compliance',
      badge: 'FIPS 204',
      badgeColor: 'bg-purple-500/20 text-purple-300 border-purple-500/30',
      description:
        'From CMMC to the EU AI Act, prove your AI agents operate securely. 36,195 framework mappings embedded. Every tool call is ML-DSA-65 signed, delivering a cryptographically verifiable chain of custody for auditors.',
      gradient: 'from-purple-500/15 to-pink-500/10',
      borderColor: 'border-purple-500/30',
      iconColor: 'text-purple-400',
    },
    {
      icon: Cpu,
      title: 'Flat Pricing — No Token Extortion',
      badge: 'Unlimited',
      badgeColor: 'bg-cyan-500/20 text-cyan-300 border-cyan-500/30',
      description:
        'Developers are burning tens of thousands in unexpected API token fees with frontier models. SouHimBou AI provides an enterprise-grade agentic SOC with predictable, flat monthly pricing. No surprises.',
      gradient: 'from-cyan-500/15 to-blue-500/10',
      borderColor: 'border-cyan-500/30',
      iconColor: 'text-cyan-400',
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
