import { useNavigate } from 'react-router-dom';
import { Button } from '@/components/ui/button';
import { Phone, Shield } from 'lucide-react';

const ADVISORY_CALENDLY_URL = 'https://calendly.com/cybersouhimbou';
const ADVISORY_MAILTO = 'mailto:hello@souhimbou.com?subject=ASAF%20Advisory%20Call%20Request';

export default function Advisory() {
  const navigate = useNavigate();

  return (
    <div className="min-h-screen bg-[#0a0a0a] text-white">
      <div className="container mx-auto px-6 py-16">
        <div className="max-w-3xl mx-auto space-y-8 text-center">
          <div className="space-y-3">
            <div className="inline-flex items-center gap-2 bg-amber-950/40 border border-amber-500/30 rounded-full px-4 py-1.5 text-sm text-amber-400 font-medium">
              <span className="w-2 h-2 bg-amber-500 rounded-full animate-pulse" />
              CMMC / NIST 800-171 evidence advisory
            </div>
            <h1 className="text-4xl md:text-5xl font-bold leading-tight">
              Book an <span className="text-[#00ffff]">Advisory Call</span>
            </h1>
            <p className="text-gray-300 text-lg leading-relaxed">
              Talk with an ASAF specialist about readiness scans, assessor-oriented evidence mapping, and optional ADINKHEPRA attestation.
              We’ll discuss scope, artifacts, and next steps for C3PAO / ISSM intake.
            </p>
          </div>

          <div className="flex flex-col sm:flex-row gap-4 justify-center">
            <Button
              size="lg"
              onClick={() => window.open(ADVISORY_CALENDLY_URL, '_blank', 'noopener,noreferrer')}
              className="bg-gradient-to-r from-[#d4af37] to-[#b8860b] hover:from-[#c49b2d] hover:to-[#9d7509] text-black font-bold text-lg px-8 py-6 rounded-lg shadow-[0_0_25px_rgba(212,175,55,0.25)] hover:shadow-[0_0_40px_rgba(212,175,55,0.35)] transition-all duration-300"
            >
              <Phone className="h-5 w-5 mr-2" />
              Book Advisory Call
            </Button>

            <Button
              size="lg"
              variant="outline"
              onClick={() => {
                window.location.href = ADVISORY_MAILTO;
              }}
              className="border-[#00ffff]/40 text-[#00ffff] hover:bg-[#00ffff]/10 font-semibold text-lg px-8 py-6 rounded-lg"
            >
              <Shield className="h-5 w-5 mr-2" />
              Email Request
            </Button>
          </div>

          <div className="text-xs text-gray-500 pt-2">
            Prefer self-serve? Run a free readiness scan first.
          </div>

          <Button
            size="lg"
            variant="secondary"
            onClick={() => navigate('/onboarding')}
            className="w-full sm:w-auto bg-[#00ffff]/10 border border-[#00ffff]/30 text-[#00ffff] hover:bg-[#00ffff]/15 font-semibold px-10 py-6 rounded-lg"
          >
            Run Free Scan
          </Button>
        </div>
      </div>
    </div>
  );
}

