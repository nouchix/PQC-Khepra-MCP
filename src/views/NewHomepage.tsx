import { useNavigate } from '@/lib/router-compat';
import { Button } from '@/components/ui/button';
import { Shield, Menu } from 'lucide-react';
import { HeroSection } from '@/components/funnel/HeroSection';
import { CoreBenefits } from '@/components/funnel/CoreBenefits';
import { SystemOverview } from '@/components/funnel/SystemOverview';
import { PilotProgram } from '@/components/funnel/PilotProgram';
import { TrustAnchors } from '@/components/funnel/TrustAnchors';
import { FounderNarrative } from '@/components/funnel/FounderNarrative';
import { FinalCTABar } from '@/components/funnel/FinalCTABar';
import { FooterConversion } from '@/components/funnel/FooterConversion';
import { useState } from 'react';

const NewHomepage = () => {
  const navigate = useNavigate();
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  return (
    <div className="min-h-screen bg-[#0a0a0a] text-white font-[Inter,sans-serif]">
      {/* Fixed Header */}
      <header className="fixed top-0 left-0 right-0 z-50 border-b border-gray-800 bg-[#0a0a0a]/90 backdrop-blur-xl">
        <div className="container mx-auto px-6 py-4">
          <div className="flex items-center justify-between">
            {/* Logo */}
            <div className="flex items-center gap-3">
              <img
                src="/lovable-uploads/94f06ba5-2c93-4be0-a03f-e3fff4157ca6.png"
                alt="SouHimBou AI Logo"
                className="h-10 w-auto"
              />
              <div className="flex items-center gap-2">
                <span className="text-xl font-bold text-white">SouHimBou AI</span>
              </div>
            </div>

            {/* Desktop Navigation */}
            <nav className="hidden md:flex items-center gap-8 text-sm">
              <a href="#system-overview" className="text-gray-300 hover:text-[#00ffff] transition-colors">
                How It Works
              </a>
              <a href="#founder" className="text-gray-300 hover:text-[#00ffff] transition-colors">
                Founder
              </a>
              <button onClick={() => navigate('/blog')} className="text-gray-300 hover:text-[#00ffff] transition-colors">
                Blog
              </button>
              <Button
                onClick={() => navigate('/dod')}
                variant="outline"
                size="sm"
                className="border-[#00ffff]/50 text-[#00ffff] hover:bg-[#00ffff]/10"
              >
                <Shield className="h-4 w-4 mr-2" />
                DoD Center
              </Button>
              <Button
                onClick={() => navigate('/onboarding')}
                size="sm"
                className="bg-gradient-to-r from-[#d4af37] to-[#b8860b] hover:from-[#c49b2d] hover:to-[#9d7509] text-black font-semibold"
              >
                Apply for Pilot
              </Button>
            </nav>

            {/* Mobile Menu Toggle */}
            <button
              className="md:hidden text-white"
              onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
            >
              <Menu className="h-6 w-6" />
            </button>
          </div>

          {/* Mobile Menu */}
          {mobileMenuOpen && (
            <nav className="md:hidden mt-4 pb-4 flex flex-col gap-4">
              <a href="#system-overview" className="text-gray-300 hover:text-[#00ffff] transition-colors">
                How It Works
              </a>
              <a href="#founder" className="text-gray-300 hover:text-[#00ffff] transition-colors">
                Founder
              </a>
              <button onClick={() => navigate('/blog')} className="text-gray-300 hover:text-[#00ffff] transition-colors text-left">
                Blog
              </button>
              <Button
                onClick={() => navigate('/dod')}
                variant="outline"
                size="sm"
                className="border-[#00ffff]/50 text-[#00ffff] hover:bg-[#00ffff]/10 w-full"
              >
                <Shield className="h-4 w-4 mr-2" />
                DoD Center
              </Button>
              <Button
                onClick={() => navigate('/onboarding')}
                size="sm"
                className="bg-gradient-to-r from-[#d4af37] to-[#b8860b] hover:from-[#c49b2d] hover:to-[#9d7509] text-black font-semibold w-full"
              >
                Apply for Pilot
              </Button>
            </nav>
          )}
        </div>
      </header>

      {/* Main Content */}
      <main className="pt-20">
        <HeroSection />
        <CoreBenefits />
        <SystemOverview />
        <PilotProgram />
        <TrustAnchors />
        <FounderNarrative />
        <FinalCTABar />
        <FooterConversion />
      </main>
    </div>
  );
};

export default NewHomepage;
