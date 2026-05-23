import { motion } from 'framer-motion';
import { Button } from '@/components/ui/button';
import { ChevronRight, Award, Globe, BookOpen, Shield } from 'lucide-react';
import founderBanner from '@/assets/founder-veteran-banner.png';
import founderMrap from '@/assets/founder-mrap.png';

export const FounderNarrative = () => {
  const achievements = [
    {
      icon: Shield,
      title: 'Combat Veteran',
      description: 'Operation Spartan Shield, CENTCOM • Signal Corps (25S)',
    },
    {
      icon: Award,
      title: 'Cybersecurity Researcher',
      description: 'M.S. Digital Forensics & Cybersecurity, NSA CAE-CDE Program',
    },
    {
      icon: BookOpen,
      title: 'Published Author & Artist',
      description: 'National Poetry Prize Nominee • Identity Project Co-Creator',
    },
    {
      icon: Globe,
      title: 'Son of Two Nations',
      description: 'From Abidjan, Côte d\'Ivoire to Albany, NY • Servant-Leader',
    },
  ];

  return (
    <section id="founder" className="py-32 bg-gradient-to-br from-[#0a0a0a] via-[#1a1a2e] to-[#0a0a0a] relative overflow-hidden">
      {/* Cinematic overlay */}
      <div className="absolute inset-0 bg-gradient-to-r from-[#00ffff]/5 via-transparent to-[#d4af37]/5" />

      <div className="container mx-auto px-6 relative z-10">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6 }}
          viewport={{ once: true }}
          className="text-center mb-16"
        >
          <h2 className="text-3xl md:text-5xl font-bold text-white mb-4">
            From the <span className="text-[#d4af37]">Battlefield</span> to the <span className="text-[#00ffff]">Banner</span>
          </h2>
          <p className="text-gray-400 text-lg max-w-2xl mx-auto">
            A Veteran's Legacy in Signal Operations & Cybersecurity
          </p>
        </motion.div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-16 items-center max-w-7xl mx-auto">
          {/* Left: Veteran Banner Portrait */}
          <motion.div
            initial={{ opacity: 0, x: -50 }}
            whileInView={{ opacity: 1, x: 0 }}
            transition={{ duration: 0.8 }}
            viewport={{ once: true }}
            className="relative"
          >
            <div className="relative rounded-2xl overflow-hidden border border-[#d4af37]/40 shadow-[0_0_50px_rgba(212,175,55,0.3)]">
              <img
                src={founderBanner}
                alt="SGT Souhimbou Kone - U.S. Army Veteran Banner"
                className="w-full h-auto object-contain"
              />
            </div>
            {/* Secondary MRAP image */}
            <motion.div
              initial={{ opacity: 0, scale: 0.9 }}
              whileInView={{ opacity: 1, scale: 1 }}
              transition={{ duration: 0.6, delay: 0.3 }}
              viewport={{ once: true }}
              className="absolute -bottom-8 -right-8 w-48 h-48 rounded-xl overflow-hidden border-2 border-[#00ffff]/40 shadow-[0_0_30px_rgba(0,255,255,0.2)] hidden lg:block"
            >
              <img
                src={founderMrap}
                alt="SGT Kone with MRAP vehicle during deployment"
                className="w-full h-full object-cover"
              />
            </motion.div>
          </motion.div>

          {/* Right: Narrative */}
          <motion.div
            initial={{ opacity: 0, x: 50 }}
            whileInView={{ opacity: 1, x: 0 }}
            transition={{ duration: 0.8 }}
            viewport={{ once: true }}
            className="space-y-6"
          >
            <div className="space-y-4">
              <p className="text-sm font-semibold text-[#00ffff] tracking-wider uppercase">
                🪖 SGT Souhimbou Kone
              </p>
              <h3 className="text-3xl md:text-4xl font-bold">
                <span className="text-white">U.S. Army </span>
                <span className="text-[#d4af37]">Combat Veteran</span>
              </h3>
              <p className="text-lg text-gray-400">
                Signal Corps (25S) • NY Army National Guard • Operation Spartan Shield, CENTCOM
              </p>
            </div>

            {/* Mission Statement */}
            <div className="border-l-4 border-[#d4af37] pl-4 py-2 bg-slate-800/30">
              <p className="text-xl text-white italic leading-relaxed">
                "In the military, we ride in MRAPs — Mine Resistant Ambush-Protected vehicles. In cybersecurity? We build virtual MRAPs."
              </p>
            </div>

            {/* Bio */}
            <div className="space-y-4 text-gray-400 leading-relaxed">
              <p>
                Born in <strong className="text-[#d4af37]">Abidjan, Côte d'Ivoire</strong> — raised by a community that instilled honor, rhythm, and purpose. Now serving in <strong className="text-white">Albany, NY</strong> — defending freedom with both hands: one operating satellite terminals and the other building digital fortresses.
              </p>
              <p>
                From commanding comms infrastructure across CENTCOM in real-time operations, to now leading a new kind of defense effort — powered by <strong className="text-[#00ffff]">innovation, machine learning, and mission-first integrity</strong>.
              </p>
              <p>
                At <strong className="text-white">SecRed Knowledge Inc.</strong>, we've translated battle-tested logic into agentic AI, network-aware detection, and compliance-first architectures — all wrapped in the kind of discipline only a deployment teaches you.
              </p>
            </div>

            {/* Digital MRAP Analogy */}
            <div className="bg-slate-900/50 border border-[#00ffff]/20 rounded-lg p-4 space-y-2">
              <p className="text-sm font-semibold text-[#00ffff]">Building Cyber-Armor:</p>
              <ul className="text-sm text-gray-400 space-y-1">
                <li>🔰 The helmet becomes the <strong className="text-white">endpoint firewall</strong></li>
                <li>🔰 The armor plating becomes <strong className="text-white">Zero Trust perimeters</strong></li>
                <li>🔰 The radio comms become <strong className="text-white">encrypted VPN tunnels</strong></li>
                <li>🔰 And I, the soldier, become the <strong className="text-[#d4af37]">Cyber Architect</strong></li>
              </ul>
            </div>

            {/* Achievement Grid */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pt-4">
              {achievements.map((achievement, index) => (
                <motion.div
                  key={index}
                  initial={{ opacity: 0, y: 20 }}
                  whileInView={{ opacity: 1, y: 0 }}
                  transition={{ duration: 0.6, delay: index * 0.1 }}
                  viewport={{ once: true }}
                  className="bg-slate-800/30 border border-[#00ffff]/20 rounded-lg p-4 backdrop-blur-sm"
                >
                  <achievement.icon className="h-6 w-6 text-[#00ffff] mb-2" />
                  <h4 className="text-sm font-semibold text-white mb-1">{achievement.title}</h4>
                  <p className="text-xs text-gray-500">{achievement.description}</p>
                </motion.div>
              ))}
            </div>

            {/* Closing Statement */}
            <p className="text-gray-400 italic text-sm">
              Forever Grateful. Forever On Mission. 🇺🇸 🇨🇮
            </p>

            {/* CTA */}
            <Button
              size="lg"
              onClick={() => globalThis.open('https://calendly.com/cybersouhimbou', '_blank')}
              className="bg-gradient-to-r from-[#d4af37] to-[#b8860b] hover:from-[#c49b2d] hover:to-[#9d7509] text-black font-semibold mt-4"
            >
              Join the Mission
              <ChevronRight className="ml-2 h-5 w-5" />
            </Button>
          </motion.div>
        </div>
      </div>
    </section>
  );
};
