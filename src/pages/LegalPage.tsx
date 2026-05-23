import { Shield, ArrowLeft, FileText, Lock, Scale, CheckCircle } from 'lucide-react';
import { useNavigate, useLocation } from '@/lib/router-compat';
import { Button } from '@/components/ui/button';

const legalPages: Record<string, { title: string; icon: React.ReactNode; description: string; sections: { heading: string; content: string }[] }> = {
    '/privacy': {
        title: 'Privacy Policy',
        icon: <Lock className="h-8 w-8 text-cyan-400" />,
        description: 'How we collect, use, and protect your information.',
        sections: [
            {
                heading: 'Data Collection',
                content: 'SouHimBou AI collects only the information necessary to provide our STIG compliance automation services. This includes account credentials, organization metadata, and compliance scan results. We do not sell or share personal data with third parties.'
            },
            {
                heading: 'Data Storage & Security',
                content: 'All data is encrypted at rest (AES-256) and in transit (TLS 1.3). Production deployments target AWS GovCloud for FedRAMP-aligned data residency. Scan results and compliance evidence are stored within your organization\'s isolated tenant.'
            },
            {
                heading: 'Your Rights',
                content: 'You may request data export or deletion at any time by contacting support@souhimbou.ai. We honor all applicable data protection regulations including GDPR and CCPA.'
            },
            {
                heading: 'Cookies & Analytics',
                content: 'We use Google Analytics (G-0R9HRJH65R) and Apollo tracking for aggregate usage analytics. No personally identifiable information is shared with analytics providers. You may opt out via your browser settings.'
            }
        ]
    },
    '/terms': {
        title: 'Terms of Service',
        icon: <FileText className="h-8 w-8 text-cyan-400" />,
        description: 'The agreement governing your use of SouHimBou AI.',
        sections: [
            {
                heading: 'Acceptance of Terms',
                content: 'By accessing SouHimBou AI, you agree to these Terms of Service and our Privacy Policy. If you are using the platform on behalf of an organization, you represent that you have authority to bind that organization.'
            },
            {
                heading: 'Service Description',
                content: 'SouHimBou AI provides AI-powered STIG compliance automation, configuration drift detection, and audit evidence generation. The platform is currently in active development (Beta). Features marked as "Prototype" or "In Development" are demonstration-only and should not be used for production CUI workloads.'
            },
            {
                heading: 'Acceptable Use',
                content: 'You agree not to reverse-engineer, decompile, or attempt to extract source code from the platform. You will not use the service to process data in violation of export control regulations (ITAR/EAR). Automated scraping or API abuse is prohibited.'
            },
            {
                heading: 'Limitation of Liability',
                content: 'SouHimBou AI is provided "as is" during the Beta period. SecRed Knowledge Inc. (dba NouchiX) shall not be liable for any indirect, incidental, or consequential damages arising from your use of the service. Compliance scan results are advisory and do not constitute legal or regulatory certification.'
            }
        ]
    },
    '/security': {
        title: 'Security',
        icon: <Shield className="h-8 w-8 text-cyan-400" />,
        description: 'Our commitment to protecting your data and infrastructure.',
        sections: [
            {
                heading: 'Security Architecture',
                content: 'SouHimBou AI is built on a zero-trust architecture with post-quantum cryptographic foundations (Kyber-1024 / Dilithium Mode 3). Our infrastructure follows DoD STIG hardening guidelines and is designed for Iron Bank container ingestion.'
            },
            {
                heading: 'Vulnerability Disclosure',
                content: 'We maintain an active Vulnerability Disclosure Program (VDP). Security researchers can report vulnerabilities through our /vdp page. We commit to acknowledging reports within 48 hours and remediating critical issues within 72 hours.'
            },
            {
                heading: 'Incident Response',
                content: 'We maintain a documented incident response plan aligned with NIST SP 800-61. In the event of a security incident, affected customers will be notified within 72 hours via email and in-platform notification.'
            },
            {
                heading: 'Compliance Certifications',
                content: 'SOC 2 Type II compliance is in progress. CMMC Level 2 alignment is planned for Q3 2026. FedRAMP authorization pathway has been initiated. Current status: demonstration platform only.'
            }
        ]
    },
    '/compliance': {
        title: 'Compliance',
        icon: <Scale className="h-8 w-8 text-cyan-400" />,
        description: 'Regulatory frameworks and standards we adhere to.',
        sections: [
            {
                heading: 'NIST Framework Alignment',
                content: 'SouHimBou AI\'s controls are mapped to NIST SP 800-53 Rev. 5 and NIST Cybersecurity Framework 2.0. Our platform assists organizations in implementing these controls through automated STIG configuration management.'
            },
            {
                heading: 'CMMC Readiness',
                content: 'Our platform is designed to help defense contractors achieve and maintain CMMC Level 2 compliance. Automated evidence collection, baseline management, and drift detection reduce the audit preparation burden by up to 70%.'
            },
            {
                heading: 'Data Sovereignty',
                content: 'Production deployments support tri-modal data residency: Edge (on-premise), Hybrid (customer VPC + managed control plane), and Sovereign (AWS GovCloud). All CUI-handling deployments will require GovCloud infrastructure.'
            },
            {
                heading: 'Export Controls',
                content: 'SouHimBou AI complies with all applicable U.S. export control regulations. Post-quantum cryptographic components are subject to EAR classification. Community Edition uses NIST-standardized algorithms only (CIRCL library, MIT licensed).'
            }
        ]
    }
};

const LegalPage = () => {
    const navigate = useNavigate();
    const location = useLocation();
    const page = legalPages[location.pathname];

    if (!page) {
        return null;
    }

    return (
        <div className="min-h-screen bg-[hsl(220,15%,6%)] text-white">
            {/* Header */}
            <header className="border-b border-gray-800 bg-[hsl(220,15%,6%)]/90 backdrop-blur-xl sticky top-0 z-50">
                <div className="container mx-auto px-6 py-4 flex items-center justify-between">
                    <div className="flex items-center gap-3">
                        <button onClick={() => navigate('/')} className="flex items-center gap-2 hover:opacity-80 transition-opacity">
                            <img
                                src="/lovable-uploads/94f06ba5-2c93-4be0-a03f-e3fff4157ca6.png"
                                alt="SouHimBou AI Logo"
                                className="h-8 w-auto"
                            />
                            <span className="text-lg font-bold text-white">SouHimBou AI</span>
                        </button>
                    </div>
                    <Button
                        onClick={() => navigate(-1)}
                        variant="outline"
                        size="sm"
                        className="border-gray-600 hover:border-cyan-500/50 text-gray-300 hover:text-white"
                    >
                        <ArrowLeft className="h-4 w-4 mr-2" />
                        Back
                    </Button>
                </div>
            </header>

            {/* Content */}
            <main className="container mx-auto px-6 py-16 max-w-3xl">
                {/* Page Header */}
                <div className="text-center mb-12">
                    <div className="w-16 h-16 mx-auto mb-6 bg-gradient-to-br from-cyan-500/20 to-blue-500/20 border border-cyan-500/30 rounded-2xl flex items-center justify-center">
                        {page.icon}
                    </div>
                    <h1 className="text-4xl font-bold text-white mb-3">{page.title}</h1>
                    <p className="text-gray-400 text-lg">{page.description}</p>
                    <p className="text-xs text-gray-600 mt-4">
                        Last updated: February 2026 • SecRed Knowledge Inc. dba NouchiX
                    </p>
                </div>

                {/* Sections */}
                <div className="space-y-8">
                    {page.sections.map((section) => (
                        <div key={section.heading} className="p-6 bg-white/5 backdrop-blur-xl border border-white/10 rounded-lg">
                            <div className="flex items-center gap-3 mb-4">
                                <CheckCircle className="h-5 w-5 text-cyan-400 flex-shrink-0" />
                                <h2 className="text-xl font-semibold text-white">{section.heading}</h2>
                            </div>
                            <p className="text-gray-400 leading-relaxed">{section.content}</p>
                        </div>
                    ))}
                </div>

                {/* Contact */}
                <div className="mt-12 p-6 bg-gradient-to-r from-cyan-500/5 to-purple-500/5 border border-cyan-500/20 rounded-lg text-center">
                    <p className="text-gray-400 text-sm">
                        Questions about this policy? Contact us at{' '}
                        <a href="mailto:support@souhimbou.ai" className="text-cyan-400 hover:text-cyan-300 transition-colors">
                            support@souhimbou.ai
                        </a>
                    </p>
                </div>
            </main>

            {/* Footer */}
            <footer className="border-t border-gray-800 py-8 text-center text-gray-600 text-xs">
                <p>© {new Date().getFullYear()} SecRed Knowledge Inc. dba NouchiX. All rights reserved.</p>
            </footer>
        </div>
    );
};

export default LegalPage;
