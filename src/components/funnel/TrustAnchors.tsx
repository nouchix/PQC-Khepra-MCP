import { motion } from 'framer-motion';
import { Database, Shield, Award, Globe, Zap, CheckCircle } from 'lucide-react';

export const TrustAnchors = () => {
  const apiFeatures = [
    'Faster STIG updates',
    'Direct rule ingestion',
    'Automated control mapping',
    'Cleaner compliance workflows',
    'Reduced manual parsing of XML/Excel STIG files',
  ];

  const trustIndicators = [
    {
      icon: Shield,
      title: 'Veteran-Led Development',
      description: 'Cybersecurity R&D team with military service background',
    },
    {
      icon: Award,
      title: 'Digital Forensics Expertise',
      description: 'Backgrounds in digital forensics, SATCOM, and secure system operations',
    },
    {
      icon: Globe,
      title: 'Research-Informed Approach',
      description: 'Development methodology grounded in academic and industry research',
    },
    {
      icon: Database,
      title: 'Framework Alignment',
      description: 'Built around NIST, STIG, and CMMC frameworks (alignment in progress)',
    },
  ];

  return (
    <section className="py-32 bg-gradient-to-b from-[#0d1421] via-[#0a0a0a] to-[#0a0a0a] relative overflow-hidden">
      <div className="container mx-auto px-6 relative z-10">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6 }}
          viewport={{ once: true }}
          className="text-center mb-16"
        >
          <h2 className="text-3xl md:text-5xl font-bold text-white mb-4">
            Trust Anchors & <span className="text-[#00ffff]">Industry Collaborations</span>
          </h2>
          <p className="text-xl text-gray-400">
            Built With Real STIG Expertise
          </p>
        </motion.div>

        {/* STIG Viewer CAB Section */}
        <motion.div
          initial={{ opacity: 0, y: 30 }}
          whileInView={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6, delay: 0.1 }}
          viewport={{ once: true }}
          className="max-w-4xl mx-auto mb-16"
        >
          <div className="bg-gradient-to-br from-[#00ffff]/5 to-[#0088ff]/5 border border-[#00ffff]/30 rounded-2xl p-8 md:p-10 backdrop-blur-sm">
            <div className="flex items-start gap-6">
              <div className="hidden md:flex items-center justify-center w-16 h-16 rounded-xl bg-[#00ffff]/10 border border-[#00ffff]/30 flex-shrink-0">
                <Zap className="h-8 w-8 text-[#00ffff]" />
              </div>
              <div className="space-y-4">
                <h3 className="text-2xl font-bold text-white">
                  STIG Viewer Customer Advisory Board
                </h3>
                <p className="text-gray-300 leading-relaxed">
                  SouHimBou AI participates on the <strong className="text-white">STIG Viewer Customer Advisory Board</strong>, 
                  collaborating with the team working to improve accessibility to publicly available STIG data.
                </p>
                <p className="text-gray-300 leading-relaxed">
                  Through this collaboration, SouHimBou AI has been granted <strong className="text-[#00ffff]">exclusive API access</strong> for 
                  direct STIG data integration into our compliance engine — enabling:
                </p>

                {/* API Features */}
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 pt-2">
                  {apiFeatures.map((feature, index) => (
                    <div key={index} className="flex items-center gap-2">
                      <CheckCircle className="h-4 w-4 text-[#00ffff] flex-shrink-0" />
                      <span className="text-sm text-gray-300">{feature}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>

            {/* Disclaimer */}
            <div className="mt-8 pt-6 border-t border-gray-700/50">
              <p className="text-xs text-gray-500 leading-relaxed">
                <strong>Important:</strong> STIG Viewer is an independently developed tool. Participation on its 
                Customer Advisory Board does not imply endorsement by DISA or the Department of Defense. All STIG 
                content remains sourced from the publicly available DISA STIG Library.
              </p>
            </div>
          </div>
        </motion.div>

        {/* Additional Trust Indicators */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6, delay: 0.2 }}
          viewport={{ once: true }}
          className="max-w-5xl mx-auto"
        >
          <h3 className="text-xl font-semibold text-white text-center mb-8">
            Additional Trust Indicators
          </h3>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
            {trustIndicators.map((indicator, index) => (
              <motion.div
                key={index}
                initial={{ opacity: 0, y: 20 }}
                whileInView={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.5, delay: index * 0.1 }}
                viewport={{ once: true }}
                className="bg-slate-900/40 border border-gray-800 rounded-lg p-6 hover:border-[#00ffff]/30 transition-colors duration-300"
              >
                <indicator.icon className="h-8 w-8 text-[#d4af37] mb-4" />
                <h4 className="text-white font-semibold mb-2 text-sm">{indicator.title}</h4>
                <p className="text-gray-500 text-xs leading-relaxed">{indicator.description}</p>
              </motion.div>
            ))}
          </div>
        </motion.div>
      </div>
    </section>
  );
};
