import { useState, useEffect } from "react";
import { useNavigate } from '@/lib/router-compat';
import { Button } from "@/components/ui/button";
import { Shield, Brain, Activity, ChevronRight, Crown, Heart, Users, Scan, Database } from "lucide-react";
import InteractiveDemoVideo from "@/components/InteractiveDemoVideo";
import EmailCaptureForm from "@/components/EmailCaptureForm";
import RevenueStrategies from "@/components/billing/RevenueStrategies";
import ReferralProgram from "@/components/billing/ReferralProgram";
import CacheStatusBadge from "@/components/CacheStatusBadge";

const Homepage = () => {
  const navigate = useNavigate();
  const [currentTime, setCurrentTime] = useState(new Date());

  useEffect(() => {
    const timer = setInterval(() => {
      setCurrentTime(new Date());
    }, 3000);
    return () => clearInterval(timer);
  }, []);

  const stats = [
    { label: "Configuration Baselines", value: "Live", icon: Database, color: "text-green-400" },
    { label: "Drift Detection", value: "Real-Time", icon: Activity, color: "text-purple-400" },
    { label: "AI Verification", value: "Active", icon: Brain, color: "text-cyan-400" },
    { label: "Trusted Registry", value: "Enabled", icon: Shield, color: "text-blue-400" },
  ];

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-blue-900 to-slate-900 text-white overflow-hidden">
      {/* Header */}
      <header className="border-b border-blue-500/20 bg-black/20 backdrop-blur-lg relative z-10">
        <div className="container mx-auto px-6 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-4">
              <img
                src="/lovable-uploads/94f06ba5-2c93-4be0-a03f-e3fff4157ca6.png"
                alt="SouHimBou AI Logo"
                className="h-12 w-auto"
              />
              <div className="flex items-center space-x-2">
                <h1 className="text-2xl font-bold bg-gradient-to-r from-cyan-400 to-blue-400 bg-clip-text text-transparent">
                  SouHimBou AI
                </h1>
                <span className="text-xs bg-yellow-600/20 text-yellow-400 px-2 py-1 rounded border border-yellow-500/30">
                  IN DEVELOPMENT
                </span>
              </div>
            </div>
            <div className="flex items-center space-x-4">
              <CacheStatusBadge />
              <div className="text-right hidden md:block">
                <div className="text-sm text-gray-300">
                  {currentTime.toLocaleString()}
                </div>
                <div className="text-xs text-gray-400">ZULU TIME</div>
              </div>
              <Button
                onClick={() => navigate('/dod')}
                variant="outline"
                className="border-red-500/50 text-red-400 hover:bg-red-500/10 hidden lg:flex"
              >
                <Shield className="h-4 w-4 mr-2" />
                DoD Center
              </Button>
              <Button
                onClick={() => navigate('/onboarding')}
                className="bg-gradient-to-r from-blue-500 to-purple-500 hover:from-blue-600 hover:to-purple-600"
              >
                <Scan className="h-4 w-4 mr-2" />
                Run Read-Only Gap Scan
              </Button>
            </div>
          </div>
        </div>
      </header>

      {/* Hero Section */}
      <section className="relative overflow-hidden">
        <div className="absolute inset-0 bg-gradient-to-r from-blue-600/10 to-purple-600/10 animate-pulse"></div>
        <div className="container mx-auto px-6 py-20 relative z-10">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-12 items-center">
            {/* Left Side - Hero Text */}
            <div className="space-y-8">
              <div className="space-y-6">
                <div className="space-y-2">
                  <p className="text-sm font-medium text-cyan-400 tracking-wide uppercase">
                    STIG-First Compliance Platform - In Development
                  </p>
                </div>

                <h1 className="text-5xl lg:text-6xl font-bold leading-tight">
                  <span className="text-white">Building the Future of</span>
                  <br />
                  <span className="bg-gradient-to-r from-yellow-400 via-orange-400 to-red-400 bg-clip-text text-transparent">
                    CMMC Compliance Automation
                  </span>
                </h1>

                <p className="text-xl text-gray-300 leading-relaxed">
                  A compliance-first GRC platform being built specifically for the Defense Industrial Base, featuring STIG automation, AI-powered verification, and AWS GovCloud deployment for CUI handling.
                </p>

                {/* Development Status Disclaimer */}
                <div className="border border-yellow-500/50 rounded-lg bg-yellow-900/20 p-5 space-y-3">
                  <div className="flex items-start gap-3">
                    <div className="flex-shrink-0 mt-1">
                      <Shield className="h-5 w-5 text-yellow-400" />
                    </div>
                    <div className="space-y-2">
                      <h3 className="text-base font-semibold text-yellow-400">
                        🚧 Platform Development Status
                      </h3>
                      <p className="text-gray-300 text-sm leading-relaxed">
                        <strong>Important:</strong> SouHimBou AI is currently in active development and <strong>NOT ready for production CUI workloads</strong>.
                        We're building with a secure-enclave architecture using AWS GovCloud (US) for future CMMC Level 2 compliance.
                        Current prototypes are for demonstration and beta testing only.
                      </p>
                    </div>
                  </div>
                </div>

                <div className="border border-blue-500/30 rounded-lg bg-blue-900/20 p-6 space-y-3">
                  <h3 className="text-lg font-semibold text-blue-400">
                    Current Development Roadmap
                  </h3>
                  <p className="text-gray-300 text-sm">
                    <strong>Beta Features (Non-CUI):</strong> STIG configuration search • AI verification prototypes • Dashboard UI • Compliance tracking mockups
                  </p>
                  <p className="text-gray-300 text-sm">
                    <strong>Planned Production (Q2-Q3):</strong> AWS GovCloud deployment • NIST 800-171 controls • Secure evidence collection • C3PAO assessment readiness
                  </p>
                  <div className="flex flex-wrap gap-2 pt-2">
                    <span className="text-xs px-2 py-1 bg-yellow-500/20 text-yellow-300 rounded border border-yellow-500/30">⚠ Beta UI Only</span>
                    <span className="text-xs px-2 py-1 bg-blue-500/20 text-blue-300 rounded">🔒 GovCloud Q2</span>
                    <span className="text-xs px-2 py-1 bg-blue-500/20 text-blue-300 rounded">📋 CMMC Assessment Q3</span>
                    <span className="text-xs px-2 py-1 bg-green-500/20 text-green-300 rounded border border-green-500/30">✓ Accepting Pilot Partners</span>
                  </div>
                </div>
              </div>

              <EmailCaptureForm />

              {/* DoD STIG-Codex Center CTA */}
              <div className="pt-6">
                <Button
                  size="lg"
                  onClick={() => navigate('/dod')}
                  className="w-full bg-gradient-to-r from-red-600 to-orange-600 hover:from-red-700 hover:to-orange-700 text-white font-semibold py-4 px-8 text-lg border border-red-500/50"
                >
                  <Shield className="h-6 w-6 mr-3" />
                  Access DoD STIG-Codex Center
                  <ChevronRight className="h-5 w-5 ml-2" />
                </Button>
                <p className="text-xs text-gray-400 mt-2 text-center">
                  Unified STIG-First compliance automation platform
                </p>
              </div>
            </div>

            {/* Right Side - Interactive Demo Video */}
            <div className="space-y-6">
              <InteractiveDemoVideo />
            </div>
          </div>
        </div>
      </section>

      {/* Stats Section */}
      <section className="py-16 bg-black/20 backdrop-blur-lg">
        <div className="container mx-auto px-6">
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-8">
            {stats.map((stat, index) => (
              <div
                key={stat.label}
                className="text-center space-y-2 animate-fade-in"
                style={{ animationDelay: `${index * 200}ms` }}
              >
                <stat.icon className={`h-8 w-8 mx-auto ${stat.color}`} />
                <div className="text-2xl lg:text-3xl font-bold text-white">{stat.value}</div>
                <div className="text-sm text-gray-400">{stat.label}</div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Special Revenue Offers Section */}
      <section className="py-20 bg-gradient-to-br from-slate-900/50 to-blue-900/20">
        <div className="container mx-auto px-6">
          <div className="text-center space-y-4 mb-16">
            <h2 className="text-4xl font-bold text-white">🚀 Beta Early Access & Pilot Partnership Program</h2>
            <p className="text-xl text-gray-300">Help shape the future of DoD compliance automation - Current features limited to non-CUI prototyping</p>
            <div className="inline-block bg-yellow-500/20 border border-yellow-500/50 text-yellow-300 px-4 py-2 rounded-lg text-sm max-w-2xl">
              <strong>Note:</strong> Beta access provides UI/dashboard prototyping only. Production CUI handling requires AWS GovCloud deployment (Q2 2025).
            </div>
          </div>

          {/* Revenue Strategies Component */}
          <RevenueStrategies />
        </div>
      </section>

      {/* Referral Program Section */}
      <section className="py-20 bg-black/20">
        <div className="container mx-auto px-6">
          <div className="text-center space-y-4 mb-16">
            <h2 className="text-4xl font-bold text-white">Earn Rewards Through Referrals</h2>
            <p className="text-xl text-gray-300">Share the platform and get rewarded</p>
          </div>

          <div className="max-w-4xl mx-auto">
            <ReferralProgram />
          </div>
        </div>
      </section>

      {/* Pricing Section */}
      <section className="py-20 bg-black/10">
        <div className="container mx-auto px-6">
          <div className="text-center space-y-4 mb-16">
            <h2 className="text-4xl font-bold text-white">Development Partnerships - Limited Availability</h2>
            <p className="text-xl text-gray-300">Beta UI prototyping now • Production GovCloud deployment Q2 2025</p>
            <div className="inline-block bg-orange-500/20 border border-orange-500/50 text-orange-300 px-4 py-2 rounded-lg text-sm max-w-3xl">
              🚀 Seeking 5 pilot partners to co-develop production-ready AWS GovCloud deployment for CUI handling
            </div>
            <div className="inline-block bg-yellow-500/20 border border-yellow-500/50 text-yellow-300 px-4 py-2 rounded-lg text-sm max-w-3xl mt-2">
              ⚠ Current beta pricing is for non-CUI UI/prototype access only. Production CUI workloads require separate GovCloud deployment contract.
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8 max-w-5xl mx-auto">
            {/* Beta MVP 1.0 Plan */}
            <div className="bg-slate-800/50 border border-cyan-500/50 rounded-lg p-6 space-y-6 relative">
              <div className="absolute -top-3 left-1/2 transform -translate-x-1/2 bg-cyan-500 text-black text-xs px-3 py-1 rounded-full font-semibold">
                MVP 1.0 BETA
              </div>
              <div className="space-y-2">
                <h3 className="text-xl font-bold text-white">Beta Prototyping Access</h3>
                <div className="text-3xl font-bold text-cyan-400">$497<span className="text-sm text-gray-400">/month</span></div>
                <p className="text-xs text-gray-400">UI/Dashboard beta • Non-CUI only</p>
              </div>
              <div className="bg-yellow-500/10 border border-yellow-500/30 rounded p-3 mb-3">
                <p className="text-xs text-yellow-300"><strong>Beta Limitation:</strong> Dashboard UI only. No CUI storage or processing.</p>
              </div>
              <ul className="space-y-3 text-sm text-gray-300">
                <li className="flex items-center"><div className="w-2 h-2 bg-yellow-400 rounded-full mr-2"></div>STIG Configuration Search (Demo)</li>
                <li className="flex items-center"><div className="w-2 h-2 bg-yellow-400 rounded-full mr-2"></div>AI Verification (Prototype)</li>
                <li className="flex items-center"><div className="w-2 h-2 bg-yellow-400 rounded-full mr-2"></div>Dashboard UI Access</li>
                <li className="flex items-center"><div className="w-2 h-2 bg-blue-400 rounded-full mr-2"></div>GovCloud Production (Q2 2025)</li>
                <li className="flex items-center"><div className="w-2 h-2 bg-blue-400 rounded-full mr-2"></div>CUI Handling (Q2 2025)</li>
              </ul>
              <Button
                className="w-full bg-cyan-600 hover:bg-cyan-700 text-white"
                onClick={() => navigate('/onboarding')}
              >
                Start Beta Access
              </Button>
              <p className="text-xs text-gray-500 text-center">Beta pricing locked for 12 months</p>
            </div>

            {/* MSP Tiered Plan */}
            <div className="bg-gradient-to-br from-blue-900/50 to-purple-900/50 border border-blue-500 rounded-lg p-6 space-y-6 relative">
              <div className="absolute -top-3 left-1/2 transform -translate-x-1/2 bg-gradient-to-r from-blue-500 to-purple-500 text-white text-xs px-3 py-1 rounded-full font-semibold">
                FOR MSPs/MSSPs
              </div>
              <div className="space-y-2">
                <h3 className="text-xl font-bold text-white">MSP Beta Partnership</h3>
                <div className="text-3xl font-bold text-blue-400">$997<span className="text-sm text-gray-400">/month</span></div>
                <p className="text-xs text-gray-400">Multi-tenant UI beta • Non-CUI</p>
              </div>
              <div className="bg-yellow-500/10 border border-yellow-500/30 rounded p-3 mb-3">
                <p className="text-xs text-yellow-300"><strong>Beta Limitation:</strong> Multi-tenant dashboard UI only. Production requires GovCloud deployment.</p>
              </div>
              <ul className="space-y-3 text-sm text-gray-300">
                <li className="flex items-center"><div className="w-2 h-2 bg-yellow-400 rounded-full mr-2"></div>Multi-Asset Dashboard (Demo)</li>
                <li className="flex items-center"><div className="w-2 h-2 bg-yellow-400 rounded-full mr-2"></div>Drift Detection UI (Prototype)</li>
                <li className="flex items-center"><div className="w-2 h-2 bg-yellow-400 rounded-full mr-2"></div>Compliance Tracking (Mock Data)</li>
                <li className="flex items-center"><div className="w-2 h-2 bg-blue-400 rounded-full mr-2"></div>Multi-Tenant Production (Q2)</li>
                <li className="flex items-center"><div className="w-2 h-2 bg-blue-400 rounded-full mr-2"></div>Real CUI Processing (Q2 GovCloud)</li>
              </ul>
              <Button
                className="w-full bg-gradient-to-r from-blue-500 to-purple-500 hover:from-blue-600 hover:to-purple-600 text-white"
                onClick={() => navigate('/onboarding')}
              >
                Start MSP Beta
              </Button>
              <p className="text-xs text-gray-500 text-center">Volume discounts available</p>
            </div>

            {/* MVP 2.0 Pilot Plan */}
            <div className="bg-gradient-to-br from-orange-900/50 to-red-900/50 border border-orange-500 rounded-lg p-6 space-y-6 relative">
              <div className="absolute -top-3 left-1/2 transform -translate-x-1/2 bg-gradient-to-r from-orange-500 to-red-500 text-white text-xs px-3 py-1 rounded-full font-semibold">
                MVP 2.0 PILOT
              </div>
              <div className="space-y-2">
                <h3 className="text-xl font-bold text-white">AWS GovCloud Pilot Partner</h3>
                <div className="text-3xl font-bold text-orange-400">Custom</div>
                <p className="text-xs text-gray-400">Full production co-development</p>
              </div>
              <div className="bg-orange-500/10 border border-orange-500/30 rounded p-3 mb-3">
                <p className="text-xs text-orange-300"><strong>Production Track:</strong> AWS GovCloud deployment • NIST 800-171 controls • C3PAO assessment readiness</p>
              </div>
              <ul className="space-y-3 text-sm text-gray-300">
                <li className="flex items-center"><div className="w-2 h-2 bg-orange-400 rounded-full mr-2"></div>Dedicated GovCloud Enclave</li>
                <li className="flex items-center"><div className="w-2 h-2 bg-orange-400 rounded-full mr-2"></div>CUI-Ready Evidence Collection</li>
                <li className="flex items-center"><div className="w-2 h-2 bg-orange-400 rounded-full mr-2"></div>CMMC Assessment Support</li>
                <li className="flex items-center"><div className="w-2 h-2 bg-orange-400 rounded-full mr-2"></div>DISA STIG Automation</li>
                <li className="flex items-center"><div className="w-2 h-2 bg-orange-400 rounded-full mr-2"></div>Co-branded Success Story</li>
              </ul>
              <Button
                className="w-full bg-gradient-to-r from-orange-500 to-red-500 hover:from-orange-600 hover:to-red-600 text-white"
                onClick={() => navigate('/onboarding')}
              >
                Apply for Pilot
              </Button>
              <p className="text-xs text-gray-500 text-center">Limited to 5 pilot partners in Q1</p>
            </div>
          </div>

          <div className="mt-12 text-center space-y-3">
            <p className="text-gray-400 text-sm">
              Beta plans include: Dashboard UI access • Prototype workflows • Mock data visualization • Email support
            </p>
            <p className="text-yellow-400 text-sm font-medium">
              Production CUI handling requires separate AWS GovCloud deployment contract. Contact us for enterprise requirements.
            </p>
          </div>
        </div>
      </section>

      {/* Final CTA Section */}
      <section id="demo" className="py-20 bg-gradient-to-r from-blue-900/30 to-purple-900/30">
        <div className="container mx-auto px-6 text-center">
          <div className="max-w-4xl mx-auto space-y-8">
            <h2 className="text-4xl font-bold text-white">
              🎯 Join Our Development Partnership Program
            </h2>
            <p className="text-xl text-gray-300">
              Help us build the future of DoD compliance automation. Beta UI access available now.
              Production AWS GovCloud deployment for CUI handling launching Q2 2025.
            </p>
            <div className="bg-yellow-500/10 border border-yellow-500/30 rounded-lg p-4 max-w-2xl mx-auto">
              <p className="text-sm text-yellow-300">
                <strong>Transparency Notice:</strong> Current platform is in active development. Beta features are for UI prototyping and demonstration only.
                Production workloads handling CUI require our AWS GovCloud deployment (Q2 2025) with full NIST 800-171 controls.
              </p>
            </div>

            {/* CTA Options */}
            <div className="grid md:grid-cols-3 gap-6 mt-12">
              {/* Beta Pricing CTA */}
              <div className="bg-gradient-to-br from-cyan-900/30 to-blue-900/30 border border-cyan-500/50 rounded-lg p-6 space-y-4">
                <Crown className="h-12 w-12 text-cyan-400 mx-auto" />
                <h3 className="text-xl font-bold text-cyan-400">MVP 1.0 Beta Access</h3>
                <p className="text-sm text-gray-300">Starting at $497/month • Beta pricing locked</p>
                <Button
                  size="lg"
                  onClick={() => navigate('/onboarding')}
                  className="w-full bg-cyan-600 hover:bg-cyan-700 text-white font-semibold"
                >
                  <Crown className="h-4 w-4 mr-2" />
                  Join Beta Program
                </Button>
              </div>

              {/* Read-Only Gap Scan CTA */}
              <div className="bg-gradient-to-br from-blue-900/30 to-purple-900/30 border border-blue-500/50 rounded-lg p-6 space-y-4">
                <Scan className="h-12 w-12 text-blue-400 mx-auto" />
                <h3 className="text-xl font-bold text-blue-400">Free STIG Gap Scan</h3>
                <p className="text-sm text-gray-300">48-hour read-only assessment</p>
                <Button
                  size="lg"
                  onClick={() => navigate('/onboarding')}
                  className="w-full bg-gradient-to-r from-blue-500 to-purple-500 hover:from-blue-600 hover:to-purple-600"
                >
                  <Scan className="h-4 w-4 mr-2" />
                  Run Gap Scan
                </Button>
              </div>

              {/* Pilot Program CTA */}
              <div className="bg-gradient-to-br from-orange-900/30 to-red-900/30 border border-orange-500/50 rounded-lg p-6 space-y-4">
                <Heart className="h-12 w-12 text-orange-400 mx-auto" />
                <h3 className="text-xl font-bold text-orange-400">MVP 2.0 Pilot</h3>
                <p className="text-sm text-gray-300">Co-development partnership</p>
                <Button
                  size="lg"
                  onClick={() => navigate('/onboarding')}
                  className="w-full bg-gradient-to-r from-orange-500 to-red-500 hover:from-orange-600 hover:to-red-600"
                >
                  <Users className="h-4 w-4 mr-2" />
                  Apply for Pilot
                </Button>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Footer */}
      <footer className="border-t border-blue-500/20 bg-black/20 backdrop-blur-lg py-8">
        <div className="container mx-auto px-6 text-center">
          <div className="text-sm text-gray-400">
            © 2024 SouHimBou AI. All rights reserved. | DoD Classified System
          </div>
        </div>
      </footer>
    </div>
  );
};

export default Homepage;