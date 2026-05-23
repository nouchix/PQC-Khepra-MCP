import { motion } from 'framer-motion';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Shield, Mail, ChevronRight, Linkedin, Twitter, Github } from 'lucide-react';
import { useState } from 'react';
import { useNavigate } from '@/lib/router-compat';

export const FooterConversion = () => {
  const navigate = useNavigate();
  const [email, setEmail] = useState('');

  const handleNewsletterSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    // TODO: Connect to Supabase newsletter table
    console.log('Newsletter signup:', email);
  };

  const footerLinks = {
    solutions: [
      { label: 'HPE GreenLake Solutions', href: 'https://www.hpe.com/greenlake', target: '_blank' },
      { label: 'SouHimBou AI ASOC', href: '/onboarding' },
      { label: 'Cyber-Rig Formula™', href: '/blog' },
      { label: 'Managed Security', href: '/dod' },
    ],
    compliance: [
      { label: 'NIST Framework', href: '/compliance' },
      { label: 'CMMC Certification', href: '/compliance' },
      { label: 'MITRE ATT&CK', href: 'https://attack.mitre.org/', target: '_blank' },
      { label: 'FedRAMP Pathway', href: '/compliance' },
    ],
    company: [
      { label: 'About NouchiX', href: 'https://www.linkedin.com/company/nouchix', target: '_blank' },
      { label: 'Leadership Team', href: 'https://www.linkedin.com/company/nouchix', target: '_blank' },
      { label: 'Veteran-Led Mission', href: '/blog/episode-3-founder-inception-story' },
      { label: 'Partner Program', href: '/onboarding' },
    ],
    resources: [
      { label: 'Product Catalog', href: '/onboarding' },
      { label: 'Case Studies', href: '/blog' },
      { label: 'Whitepapers', href: '/blog' },
      { label: 'Security Blog', href: '/blog' },
    ],
    recognition: [
      { label: 'F6S Profile', href: 'https://www.f6s.com', target: '_blank' },
      { label: 'DesignRush Featured', href: 'https://www.designrush.com', target: '_blank' },
      { label: 'SecRed Knowledge Inc.', href: 'https://www.linkedin.com/company/nouchix', target: '_blank' },
      { label: 'LinkedIn Company', href: 'https://www.linkedin.com/company/nouchix', target: '_blank' },
    ],
  };

  return (
    <footer className="bg-[#0a0a0a] border-t border-gray-800 relative overflow-hidden">
      {/* Subtle grid overlay */}
      <div className="absolute inset-0 bg-[linear-gradient(to_right,#00ffff05_1px,transparent_1px),linear-gradient(to_bottom,#00ffff05_1px,transparent_1px)] bg-[size:4rem_4rem] opacity-30" />

      <div className="container mx-auto px-6 py-16 relative z-10">
        {/* Conversion Ladder */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-12 mb-16 pb-16 border-b border-gray-800">
          {/* Newsletter Sign-up */}
          <motion.div
            initial={{ opacity: 0, x: -30 }}
            whileInView={{ opacity: 1, x: 0 }}
            transition={{ duration: 0.8 }}
            viewport={{ once: true }}
            className="space-y-4"
          >
            <div className="flex items-center gap-3 mb-4">
              <Mail className="h-6 w-6 text-[#00ffff]" />
              <h3 className="text-xl font-bold text-white">Intel Briefings</h3>
            </div>
            <p className="text-gray-400">
              Weekly AI x Defense Insights — Stay ahead of threats and compliance changes
            </p>
            <form onSubmit={handleNewsletterSubmit} className="flex gap-3">
              <Input
                type="email"
                placeholder="your.email@company.com"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                className="bg-slate-800/50 border-gray-700 text-white placeholder:text-gray-500 focus:border-[#00ffff]"
                required
              />
              <Button
                type="submit"
                className="bg-gradient-to-r from-[#00ffff]/20 to-[#0088ff]/20 hover:from-[#00ffff]/30 hover:to-[#0088ff]/30 text-[#00ffff] border border-[#00ffff]/50"
              >
                Subscribe
              </Button>
            </form>
          </motion.div>

          {/* Waitlist CTA */}
          <motion.div
            initial={{ opacity: 0, x: 30 }}
            whileInView={{ opacity: 1, x: 0 }}
            transition={{ duration: 0.8 }}
            viewport={{ once: true }}
            className="space-y-4"
          >
            <div className="flex items-center gap-3 mb-4">
              <Shield className="h-6 w-6 text-[#d4af37]" />
              <h3 className="text-xl font-bold text-white">Reserve Your Pilot Slot</h3>
            </div>
            <p className="text-gray-400">
              Only 10 slots available per quarter — secure your spot in the next cohort
            </p>
            <Button
              size="lg"
              onClick={() => navigate('/onboarding')}
              className="bg-gradient-to-r from-[#d4af37] to-[#b8860b] hover:from-[#c49b2d] hover:to-[#9d7509] text-black font-semibold w-full"
            >
              Reserve Pilot Slot
              <ChevronRight className="ml-2 h-5 w-5" />
            </Button>
          </motion.div>
        </div>

        {/* Footer Links Grid */}
        <div className="grid grid-cols-1 md:grid-cols-6 gap-8 mb-12">
          {/* Brand Column - spans 2 columns */}
          <div className="space-y-4 md:col-span-2">
            <div className="flex items-center gap-3">
              <img
                src="/lovable-uploads/94f06ba5-2c93-4be0-a03f-e3fff4157ca6.png"
                alt="NouchiX - SouHimBou AI"
                className="h-10 w-auto"
              />
            </div>
            <h4 className="text-white font-bold">NouchiX</h4>
            <p className="text-gray-400 text-sm">
              Veteran-led, Minority-owned cybersecurity firm delivering AI-native solutions and agentic security operations for defense contractors and critical infrastructure.
            </p>
            <div className="space-y-2 text-sm">
              <p className="text-gray-400">
                <a href="mailto:support@souhimbou.ai" className="hover:text-[#00ffff] transition-colors">
                  support@souhimbou.ai
                </a>
              </p>
              <p className="text-gray-400">
                <a href="mailto:hello@souhimbou.com" className="hover:text-[#00ffff] transition-colors">
                  hello@souhimbou.com
                </a>
              </p>
              <p className="text-gray-400">
                <a href="tel:+13322754335" className="hover:text-[#00ffff] transition-colors">
                  (332) 275-4335 x 1000
                </a>
              </p>
              <p className="text-gray-400">
                401 New Karner Rd, Suite 301<br />
                Albany, NY 12205
              </p>
            </div>
            <div className="flex items-center gap-4">
              <a href="https://www.linkedin.com" target="_blank" rel="noopener noreferrer" className="text-gray-400 hover:text-[#00ffff] transition-colors">
                <Linkedin className="h-5 w-5" />
              </a>
              <a href="#" className="text-gray-400 hover:text-[#00ffff] transition-colors">
                <Twitter className="h-5 w-5" />
              </a>
              <a href="#" className="text-gray-400 hover:text-[#00ffff] transition-colors">
                <Github className="h-5 w-5" />
              </a>
            </div>
          </div>

          {/* Solutions Links */}
          <div>
            <h4 className="text-white font-semibold mb-4">Solutions</h4>
            <ul className="space-y-3">
              {footerLinks.solutions.map((link) => (
                <li key={link.label}>
                  <a
                    href={link.href}
                    className="text-gray-400 hover:text-[#00ffff] transition-colors text-sm"
                  >
                    {link.label}
                  </a>
                </li>
              ))}
            </ul>
          </div>

          {/* Compliance Links */}
          <div>
            <h4 className="text-white font-semibold mb-4">Compliance</h4>
            <ul className="space-y-3">
              {footerLinks.compliance.map((link) => (
                <li key={link.label}>
                  <a
                    href={link.href}
                    className="text-gray-400 hover:text-[#00ffff] transition-colors text-sm"
                  >
                    {link.label}
                  </a>
                </li>
              ))}
            </ul>
          </div>

          {/* Company Links */}
          <div>
            <h4 className="text-white font-semibold mb-4">Company</h4>
            <ul className="space-y-3">
              {footerLinks.company.map((link) => (
                <li key={link.label}>
                  <a
                    href={link.href}
                    className="text-gray-400 hover:text-[#00ffff] transition-colors text-sm"
                  >
                    {link.label}
                  </a>
                </li>
              ))}
            </ul>
          </div>

          {/* Resources & Recognition */}
          <div>
            <h4 className="text-white font-semibold mb-4">Resources</h4>
            <ul className="space-y-3 mb-6">
              {footerLinks.resources.map((link) => (
                <li key={link.label}>
                  <a
                    href={link.href}
                    className="text-gray-400 hover:text-[#00ffff] transition-colors text-sm"
                  >
                    {link.label}
                  </a>
                </li>
              ))}
            </ul>
            <h4 className="text-white font-semibold mb-4">Recognition</h4>
            <ul className="space-y-3">
              {footerLinks.recognition.map((link) => (
                <li key={link.label}>
                  <a
                    href={link.href}
                    target={link.target}
                    rel={link.target ? "noopener noreferrer" : undefined}
                    className="text-gray-400 hover:text-[#00ffff] transition-colors text-sm"
                  >
                    {link.label}
                  </a>
                </li>
              ))}
            </ul>
          </div>
        </div>

        {/* Certifications & Badges */}
        <div className="mb-8 pb-8 border-b border-gray-800">
          <div className="flex flex-wrap items-center justify-center gap-4 text-xs text-gray-500">
            <span className="px-3 py-1 bg-gray-800/50 rounded border border-gray-700">🪖 Veteran-Owned Small Business</span>
            <span className="px-3 py-1 bg-gray-800/50 rounded border border-gray-700">Minority Business Enterprise</span>
            <span className="px-3 py-1 bg-gray-800/50 rounded border border-gray-700">HPE Partner Ready T2</span>
            <span className="px-3 py-1 bg-gray-800/50 rounded border border-gray-700">SOC 2 Compliant</span>
            <span className="px-3 py-1 bg-gray-800/50 rounded border border-gray-700">CMMC Ready</span>
          </div>
        </div>

        {/* Bottom Bar */}
        <div className="space-y-4">
          <div className="text-center text-gray-500 text-sm">
            <p>
              © {new Date().getFullYear()} SecRed Knowledge Inc. dba NouchiX. An authorized HPE Partner Ready T2 Solution Provider. All rights reserved.
            </p>
            <div className="flex flex-wrap items-center justify-center gap-4 mt-3 text-xs">
              <a href="/privacy" className="hover:text-[#00ffff] transition-colors">Privacy Policy</a>
              <span>•</span>
              <a href="/terms" className="hover:text-[#00ffff] transition-colors">Terms of Service</a>
              <span>•</span>
              <a href="/security" className="hover:text-[#00ffff] transition-colors">Security</a>
              <span>•</span>
              <a href="/compliance" className="hover:text-[#00ffff] transition-colors">Compliance</a>
            </div>
            <p className="mt-3 text-xs text-gray-600">
              Partner ID: 1040611756 • Certified & Compliant
            </p>
          </div>
          <div className="text-center text-xs text-gray-600 pt-4 border-t border-gray-800">
            <p>
              Platform in active development • Beta features for demonstration only • Production CUI handling requires AWS GovCloud deployment
            </p>
          </div>
        </div>
      </div>
    </footer>
  );
};
