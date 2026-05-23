import { motion } from 'framer-motion';
import { Button } from '@/components/ui/button';
import { Users, MessageSquare, Lightbulb, DollarSign, Shield, AlertTriangle } from 'lucide-react';
import { useNavigate } from '@/lib/router-compat';

export const PilotProgram = () => {
  const navigate = useNavigate();

  const pilotBenefits = [
    {
      icon: Users,
      title: 'Non-Production Prototypes',
      description: 'Access to demonstration-only features and UI previews',
    },
    {
      icon: MessageSquare,
      title: 'Feature Demos & Feedback',
      description: 'Regular sessions to explore capabilities and provide input',
    },
    {
      icon: Lightbulb,
      title: 'Roadmap Input',
      description: 'Direct influence on feature prioritization and development direction',
    },
    {
      icon: Users,
      title: 'Founder Collaboration',
      description: 'One-on-one access to the founding team throughout the pilot',
    },
    {
      icon: DollarSign,
      title: 'Preferred Early Pricing',
      description: 'Locked-in rates once commercial launch begins',
    },
  ];

  return (
    <section className="py-32 bg-[#0a0a0a] relative overflow-hidden">
      {/* Background glow */}
      <div className="absolute top-0 right-0 w-96 h-96 bg-[#d4af37] rounded-full filter blur-[200px] opacity-10" />
      <div className="absolute bottom-0 left-0 w-96 h-96 bg-[#00ffff] rounded-full filter blur-[200px] opacity-10" />

      <div className="container mx-auto px-6 relative z-10">
        <div className="max-w-4xl mx-auto">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6 }}
            viewport={{ once: true }}
            className="text-center mb-12"
          >
            <div className="inline-flex items-center gap-2 px-4 py-2 bg-[#d4af37]/10 border border-[#d4af37]/30 rounded-full mb-6">
              <Shield className="h-4 w-4 text-[#d4af37]" />
              <span className="text-sm text-[#d4af37] font-medium">Limited Availability</span>
            </div>
            <h2 className="text-3xl md:text-5xl font-bold text-white mb-4">
              Early Access <span className="text-[#d4af37]">Pilot Program</span>
            </h2>
            <p className="text-xl text-gray-300">
              <span className="text-[#d4af37] font-semibold">10 Slots</span> Per Quarter
            </p>
          </motion.div>

          {/* Benefits Grid */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6, delay: 0.2 }}
            viewport={{ once: true }}
            className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6 mb-12"
          >
            {pilotBenefits.map((benefit, index) => (
              <div
                key={index}
                className="bg-slate-900/50 border border-gray-800 rounded-lg p-6 hover:border-[#d4af37]/40 transition-colors duration-300"
              >
                <benefit.icon className="h-8 w-8 text-[#d4af37] mb-4" />
                <h3 className="text-white font-semibold mb-2">{benefit.title}</h3>
                <p className="text-gray-400 text-sm">{benefit.description}</p>
              </div>
            ))}
          </motion.div>

          {/* Important Notice */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6, delay: 0.3 }}
            viewport={{ once: true }}
            className="bg-orange-900/10 border border-orange-500/30 rounded-lg p-6 mb-10"
          >
            <div className="flex items-start gap-4">
              <AlertTriangle className="h-5 w-5 text-orange-400 flex-shrink-0 mt-0.5" />
              <div>
                <h4 className="text-orange-400 font-semibold mb-2">Important Notice</h4>
                <p className="text-gray-300 text-sm leading-relaxed">
                  Pilot access does <strong>not</strong> include production deployments, CUI handling capabilities, 
                  compliance guarantees, or incident response services. All pilot features are for demonstration 
                  and evaluation purposes only.
                </p>
              </div>
            </div>
          </motion.div>

          {/* CTA */}
          <motion.div
            initial={{ opacity: 0, scale: 0.95 }}
            whileInView={{ opacity: 1, scale: 1 }}
            transition={{ duration: 0.6, delay: 0.4 }}
            viewport={{ once: true }}
            className="text-center"
          >
            <motion.div
              animate={{
                boxShadow: [
                  '0 0 20px rgba(212,175,55,0.3)',
                  '0 0 40px rgba(212,175,55,0.5)',
                  '0 0 20px rgba(212,175,55,0.3)',
                ],
              }}
              transition={{ duration: 2, repeat: Infinity }}
              className="inline-block rounded-lg"
            >
              <Button
                size="lg"
                onClick={() => navigate('/onboarding')}
                className="bg-gradient-to-r from-[#d4af37] to-[#b8860b] hover:from-[#c49b2d] hover:to-[#9d7509] text-black font-bold text-lg px-12 py-6 rounded-lg"
              >
                Apply for Pilot Access
              </Button>
            </motion.div>
            <p className="text-gray-500 text-sm mt-4">
              Applications reviewed weekly • Response within 48 hours
            </p>
          </motion.div>
        </div>
      </div>
    </section>
  );
};
