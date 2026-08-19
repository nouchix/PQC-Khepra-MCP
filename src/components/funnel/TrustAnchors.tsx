import { motion } from 'framer-motion';
import { Database, Shield, Award, Globe, Zap, CheckCircle, Lock, Download } from 'lucide-react';

export const TrustAnchors = () => {
  const apiFeatures = [
    'Direct STIG rule ingestion — no XML parsing',
    'Automated CCI → NIST 800-53 → CMMC mapping',
    'Real-time STIG update pipeline',
    'Cleaner audit-trail output for C3PAO assessors',
    '36,195 cross-framework mappings embedded in binary',
  ];

  const trustIndicators = [
    {
      icon: Download,
      title: 'Proven Market Traction',
      description: 'Over 424+ verified downloads of the PQC-Khepra-MCP public kernel container on GitHub Package Registry.',
    },

    {
      icon: Shield,
      title: 'SDVOSB — Service-Disabled Veteran',
      description: 'SecRed Knowledge Inc., Army National Guard Signal Corps 25S SATCOM, Active Secret clearance',
    },
    {
      icon: Award,
      title: 'Patent Pending — USPTO #73565085',
      description: 'KHEPRA Protocol: PQC attestation + Adinkra symbol-bound cryptographic identity',
    },
    {
      icon: Globe,
      title: 'NSA CAE-CDE Graduate Program',
      description: 'M.S. Digital Forensics & Cybersecurity, University at Albany — NSA Center of Academic Excellence',
    },
    {
      icon: Database,
      title: 'Iron Bank Submission In Progress',
      description: 'DoD container hardening (Platform One). GovCloud-ready architecture with FIPS-validated build pipeline',
    },
    {
      icon: Lock,
      title: 'Post-Quantum Cryptography',
      description: 'ML-DSA-65 (FIPS 204) + ML-KEM-768 (FIPS 203) via Cloudflare CIRCL — NIST-standardized PQC primitives',
    },
    {
      icon: Zap,
      title: 'STIG Viewer Advisory Board',
      description: 'Exclusive API access for direct STIG data integration — faster updates, no manual XML parsing',
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
            Built on <span className="text-[#00ffff]">Real Credentials</span>
          </h2>
          <p className="text-xl text-gray-400">
            Not a startup with a deck. A veteran-led company with cleared personnel, a patent, and a live product.
          </p>
        </motion.div>

        {/* STIG Viewer CAB */}
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
                  SouHimBou AI sits on the{' '}
                  <strong className="text-white">STIG Viewer Customer Advisory Board</strong>, collaborating
                  directly with the team improving access to publicly available STIG data. We hold exclusive
                  API access for direct STIG ingestion — eliminating the XML/Excel parsing that kills every
                  other compliance tool's update cadence.
                </p>

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

            <div className="mt-8 pt-6 border-t border-gray-700/50">
              <p className="text-xs text-gray-500 leading-relaxed">
                <strong>Important:</strong> STIG Viewer is an independently developed tool. Advisory Board
                participation does not imply endorsement by DISA or the Department of Defense. All STIG
                content is sourced from the publicly available DISA STIG Library.
              </p>
            </div>
          </div>
        </motion.div>

        {/* Trust indicators grid */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6, delay: 0.2 }}
          viewport={{ once: true }}
          className="max-w-5xl mx-auto"
        >
          <h3 className="text-xl font-semibold text-white text-center mb-8">
            Credentials & Infrastructure
          </h3>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
            {trustIndicators.map((indicator, index) => (
              <motion.div
                key={index}
                initial={{ opacity: 0, y: 20 }}
                whileInView={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.5, delay: index * 0.08 }}
                viewport={{ once: true }}
                className="bg-slate-900/40 border border-gray-800 rounded-lg p-6 hover:border-[#00ffff]/30 transition-colors duration-300"
              >
                <indicator.icon className="h-7 w-7 text-[#d4af37] mb-3" />
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
