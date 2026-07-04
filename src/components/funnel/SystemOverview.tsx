import { motion } from 'framer-motion';
import { Layers, Cpu, Award, ArrowRight } from 'lucide-react';

export const SystemOverview = () => {
  const steps = [
    {
      number: '01',
      icon: Layers,
      title: 'Wrap Any AI Agent in 3 Lines',
      badge: 'SDK: Go + TypeScript',
      description:
        'npm install @souhimbou/sdk or go get souhimbou.ai/sdk. Call sb.wrap(myAgent). Every tool call is now attested to the DAG with ML-DSA-65 — zero changes to your agent\'s logic.',
      iconColor: 'text-[#00ffff]',
      borderColor: 'border-[#00ffff]/40',
      code: `const sb = new SouHimBou({ apiKey })\nconst agent = sb.wrap(myAgent)\n// ✓ Every tool call now PQC-attested`,
    },
    {
      number: '02',
      icon: Cpu,
      title: 'KASA Watches in the Background',
      badge: 'Autonomous · EA-Powered',
      description:
        'The KASA agent boots and runs its own perimeter sweeps, vulnerability hunts, and forensic checks every 15–60 minutes. You watch the SSE live feed at /events as it executes — every action signed to DAG.',
      iconColor: 'text-[#d4af37]',
      borderColor: 'border-[#d4af37]/40',
      code: `kasa_start → autonomous loop\n├─ Perimeter sweep (60s)\n├─ Vuln hunt (hourly)\n└─ Forensics (15min)`,
    },
    {
      number: '03',
      icon: Award,
      title: 'Earn Your ADINKHEPRA Seal',
      badge: '$99/mo',
      description:
        'Get a cryptographically-signed certification badge backed by an immutable DAG audit trail. Share it with your CISO, C3PAO assessors, and enterprise customers. Prove your agents are accountable.',
      iconColor: 'text-[#00ff88]',
      borderColor: 'border-[#00ff88]/40',
      code: `ML-DSA-65 signed badge\n├─ Full CMMC/NIST audit\n├─ Shareable attestation PDF\n└─ DAG-anchored chain of custody`,
    },
  ];

  return (
    <section id="system-overview" className="py-32 bg-gradient-to-b from-[#0a0a0a] via-[#0d1421] to-[#0a0a0a] relative overflow-hidden">
      <div className="absolute inset-0 bg-[linear-gradient(to_right,#00ffff05_1px,transparent_1px),linear-gradient(to_bottom,#00ffff05_1px,transparent_1px)] bg-[size:4rem_4rem]" />

      <div className="container mx-auto px-6 relative z-10">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6 }}
          viewport={{ once: true }}
          className="text-center mb-20"
        >
          <h2 className="text-3xl md:text-5xl font-bold text-white mb-4">
            How SouHimBou AI <span className="text-[#00ffff]">Works</span>
          </h2>
          <p className="text-gray-400 max-w-2xl mx-auto text-lg">
            Three steps from zero trust to cryptographic proof — deployed on your infrastructure in minutes.
          </p>
        </motion.div>

        <div className="max-w-6xl mx-auto">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-8 relative">
            {/* Connector line */}
            <div className="hidden md:block absolute top-16 left-[18%] right-[18%] h-px bg-gradient-to-r from-[#00ffff]/50 via-[#d4af37]/50 to-[#00ff88]/50" />

            {steps.map((step, index) => (
              <motion.div
                key={index}
                initial={{ opacity: 0, y: 30 }}
                whileInView={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.6, delay: index * 0.2 }}
                viewport={{ once: true }}
                className="relative"
              >
                <div className={`bg-slate-900/60 border ${step.borderColor} rounded-xl p-7 backdrop-blur-sm h-full flex flex-col gap-5`}>
                  <div className="flex items-center justify-between">
                    <span className={`text-5xl font-bold ${step.iconColor} opacity-25`}>{step.number}</span>
                    <span className="text-xs px-3 py-1 bg-slate-800/80 text-gray-400 rounded-full border border-gray-700">
                      {step.badge}
                    </span>
                  </div>

                  <div className={`inline-flex items-center justify-center w-12 h-12 rounded-xl bg-slate-800/50 border ${step.borderColor}`}>
                    <step.icon className={`h-6 w-6 ${step.iconColor}`} />
                  </div>

                  <div className="flex-1">
                    <h3 className="text-lg font-semibold text-white mb-2">{step.title}</h3>
                    <p className="text-gray-400 text-sm leading-relaxed">{step.description}</p>
                  </div>

                  {/* Code snippet */}
                  <pre className={`text-xs font-mono ${step.iconColor} bg-black/40 border ${step.borderColor} rounded-lg p-3 whitespace-pre-wrap leading-relaxed`}>
                    {step.code}
                  </pre>
                </div>

                {index < steps.length - 1 && (
                  <div className="md:hidden flex justify-center py-4">
                    <ArrowRight className="h-6 w-6 text-gray-600 rotate-90" />
                  </div>
                )}
              </motion.div>
            ))}
          </div>
        </div>
      </div>
    </section>
  );
};
