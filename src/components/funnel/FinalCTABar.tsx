import { motion } from 'framer-motion';
import { Button } from '@/components/ui/button';
import { useNavigate } from '@/lib/router-compat';

export const FinalCTABar = () => {
  const navigate = useNavigate();

  const scrollToSystemOverview = () => {
    document.getElementById('system-overview')?.scrollIntoView({ behavior: 'smooth' });
  };

  return (
    <section className="py-24 bg-gradient-to-r from-[#0d1421] via-[#0a0a0a] to-[#0d1421] relative overflow-hidden">
      {/* Background glow */}
      <motion.div
        className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[600px] h-[300px] bg-[#00ffff] rounded-full filter blur-[200px] opacity-10"
        animate={{
          scale: [1, 1.1, 1],
          opacity: [0.1, 0.15, 0.1],
        }}
        transition={{ duration: 5, repeat: Infinity }}
      />

      <div className="container mx-auto px-6 relative z-10">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6 }}
          viewport={{ once: true }}
          className="max-w-3xl mx-auto text-center space-y-8"
        >
          <h2 className="text-3xl md:text-4xl font-bold text-white">
            Is your AI agent deployment{' '}
            <span className="text-[#00ffff]">enterprise-safe</span>?
          </h2>
          <p className="text-gray-400 text-lg max-w-xl mx-auto">
            Scan free. Get your exposure report in minutes. Upgrade to earn your
            <span className="text-[#d4af37] font-semibold"> ADINKHEPRA certification badge</span> — the proof your CISO needs.
          </p>

          <div className="flex flex-col sm:flex-row gap-4 justify-center">
            <Button
              size="lg"
              onClick={() => navigate('/onboarding')}
              className="bg-gradient-to-r from-[#00ffff] to-[#0088ff] hover:from-[#00dddd] hover:to-[#0066dd] text-black font-bold text-lg px-10 py-6 rounded-lg shadow-[0_0_20px_rgba(0,255,255,0.3)] hover:shadow-[0_0_35px_rgba(0,255,255,0.5)] transition-all duration-300"
            >
              Start Free Scan
            </Button>
            <Button
              size="lg"
              variant="outline"
              onClick={() => navigate('/billing')}
              className="border-[#d4af37]/60 text-[#d4af37] hover:bg-[#d4af37]/10 font-semibold text-lg px-10 py-6 rounded-lg"
            >
              Get Certified — $99/mo
            </Button>
          </div>

          <p className="text-xs text-gray-500 pt-4">
            Free scan requires no credit card. Certification plans billed via Stripe. Cancel anytime.
          </p>
        </motion.div>
      </div>
    </section>
  );
};
