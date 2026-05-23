import { motion } from 'framer-motion';
import { Search, GitBranch, FileText, ArrowRight } from 'lucide-react';

export const SystemOverview = () => {
  const steps = [
    {
      number: '01',
      icon: Search,
      title: 'Discover & Classify Assets',
      status: 'Planned',
      description: 'Automatically inventory your environment and identify applicable STIGs based on asset type, OS, and software stack.',
      iconColor: 'text-[#00ffff]',
      borderColor: 'border-[#00ffff]/40',
    },
    {
      number: '02',
      icon: GitBranch,
      title: 'Map Controls Automatically',
      status: 'Prototype',
      description: 'AI-driven mapping between CMMC requirements, NIST 800-171, and specific STIG rules — eliminating manual correlation.',
      iconColor: 'text-[#d4af37]',
      borderColor: 'border-[#d4af37]/40',
    },
    {
      number: '03',
      icon: FileText,
      title: 'Generate Evidence Automatically',
      status: 'Prototype',
      description: 'Produce audit-ready documentation, POA&Ms, and compliance reports directly from your scanned configurations.',
      iconColor: 'text-[#00ff88]',
      borderColor: 'border-[#00ff88]/40',
    },
  ];

  return (
    <section id="system-overview" className="py-32 bg-gradient-to-b from-[#0a0a0a] via-[#0d1421] to-[#0a0a0a] relative overflow-hidden">
      {/* Grid overlay */}
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
            How SouHimBou AI <span className="text-[#00ffff]">Will Work</span>
          </h2>
          <p className="text-gray-400 max-w-2xl mx-auto text-lg">
            A conceptual overview of our automated compliance workflow
          </p>
          <p className="text-xs text-gray-500 mt-3 italic">
            This section describes intended functionality and may change during development.
          </p>
        </motion.div>

        {/* Steps */}
        <div className="max-w-5xl mx-auto">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-8 relative">
            {/* Connection lines (desktop) */}
            <div className="hidden md:block absolute top-24 left-[16.5%] right-[16.5%] h-px bg-gradient-to-r from-[#00ffff]/50 via-[#d4af37]/50 to-[#00ff88]/50" />

            {steps.map((step, index) => (
              <motion.div
                key={index}
                initial={{ opacity: 0, y: 30 }}
                whileInView={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.6, delay: index * 0.2 }}
                viewport={{ once: true }}
                className="relative"
              >
                <div className={`bg-slate-900/60 border ${step.borderColor} rounded-xl p-8 backdrop-blur-sm h-full`}>
                  {/* Step Number */}
                  <div className="flex items-center justify-between mb-6">
                    <span className={`text-5xl font-bold ${step.iconColor} opacity-30`}>{step.number}</span>
                    <span className="text-xs px-3 py-1 bg-slate-800/80 text-gray-400 rounded-full border border-gray-700">
                      {step.status}
                    </span>
                  </div>

                  {/* Icon */}
                  <div className={`inline-flex items-center justify-center w-14 h-14 rounded-xl bg-slate-800/50 border ${step.borderColor} mb-5`}>
                    <step.icon className={`h-7 w-7 ${step.iconColor}`} />
                  </div>

                  {/* Content */}
                  <h3 className="text-xl font-semibold text-white mb-3">{step.title}</h3>
                  <p className="text-gray-400 text-sm leading-relaxed">{step.description}</p>
                </div>

                {/* Arrow connector (mobile) */}
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
