import { useState, useEffect, useCallback } from 'react';
import { useSearchParams } from '@/lib/router-compat';
import { X, ChevronRight, ChevronLeft, Shield, Activity, Globe, Lock, Brain } from 'lucide-react';
import { Button } from '@/components/ui/button';

interface TourStep {
    title: string;
    description: string;
    icon: React.ComponentType<{ className?: string }>;
    highlightSelector?: string;
    position: 'center' | 'bottom-left' | 'bottom-right' | 'top-center';
}

const tourSteps: TourStep[] = [
    {
        title: 'Welcome to SouHimBou AI',
        description: 'Your sovereign cybersecurity workspace is ready. Let me walk you through the key areas of your dashboard.',
        icon: Shield,
        position: 'center',
    },
    {
        title: 'STIG Dashboard',
        description: 'Your compliance command center. View real-time STIG compliance scores, track findings by severity, and monitor your security posture at a glance.',
        icon: Shield,
        position: 'bottom-left',
    },
    {
        title: 'Asset Scanning',
        description: 'Run automated scans against your infrastructure. Detect configuration drift, identify vulnerabilities, and generate remediation plans.',
        icon: Activity,
        position: 'bottom-left',
    },
    {
        title: 'Compliance Reports',
        description: 'Generate audit-ready reports for CMMC, FedRAMP, and NIST frameworks. Export as PDF or CKL for DISA submission.',
        icon: Globe,
        position: 'bottom-left',
    },
    {
        title: 'Evidence Collection',
        description: 'Collect, organize, and timestamp evidence artifacts. Automatically map evidence to control requirements for seamless audits.',
        icon: Lock,
        position: 'bottom-left',
    },
    {
        title: 'Command Palette',
        description: 'Press Ctrl+K (or ⌘K on Mac) at any time to quickly navigate, search, or launch actions. It\'s the fastest way to work.',
        icon: Brain,
        position: 'center',
    },
];

const GuidedTour = () => {
    const [searchParams, setSearchParams] = useSearchParams();
    const [currentStep, setCurrentStep] = useState(0);
    const [isActive, setIsActive] = useState(false);

    useEffect(() => {
        if (searchParams.get('tour') === 'true') {
            setIsActive(true);
            setCurrentStep(0);
        }
    }, [searchParams]);

    const endTour = useCallback(() => {
        setIsActive(false);
        const newParams = new URLSearchParams(searchParams);
        newParams.delete('tour');
        setSearchParams(newParams, { replace: true });
    }, [searchParams, setSearchParams]);

    const nextStep = () => {
        if (currentStep < tourSteps.length - 1) {
            setCurrentStep(prev => prev + 1);
        } else {
            endTour();
        }
    };

    const prevStep = () => {
        if (currentStep > 0) {
            setCurrentStep(prev => prev - 1);
        }
    };

    // Keyboard navigation
    useEffect(() => {
        if (!isActive) return;

        const handleKey = (e: KeyboardEvent) => {
            if (e.key === 'Escape') endTour();
            if (e.key === 'ArrowRight') nextStep();
            if (e.key === 'ArrowLeft') prevStep();
        };

        document.addEventListener('keydown', handleKey);
        return () => document.removeEventListener('keydown', handleKey);
    }, [isActive, currentStep, endTour]);

    if (!isActive) return null;

    const step = tourSteps[currentStep];
    const Icon = step.icon;
    const isLast = currentStep === tourSteps.length - 1;
    const isFirst = currentStep === 0;

    const positionClasses = {
        'center': 'left-1/2 top-1/2 -translate-x-1/2 -translate-y-1/2',
        'bottom-left': 'left-8 bottom-8',
        'bottom-right': 'right-8 bottom-8',
        'top-center': 'left-1/2 top-8 -translate-x-1/2',
    };

    return (
        <>
            {/* Overlay */}
            <div className="fixed inset-0 bg-black/50 backdrop-blur-[2px] z-[150]" />

            {/* Tour Card */}
            <div
                className={`fixed z-[151] w-full max-w-md ${positionClasses[step.position]}`}
                role="dialog"
                aria-modal="true"
                aria-label={`Tour step ${currentStep + 1} of ${tourSteps.length}`}
            >
                <div className="bg-[hsl(220,13%,10%)] border border-cyan-500/20 rounded-xl shadow-[0_25px_50px_-12px_hsl(194,100%,50%,0.15)] overflow-hidden">
                    {/* Progress bar */}
                    <div className="h-1 bg-gray-800">
                        <div
                            className="h-full bg-gradient-to-r from-cyan-500 to-purple-500 transition-all duration-500 ease-out"
                            style={{ width: `${((currentStep + 1) / tourSteps.length) * 100}%` }}
                        />
                    </div>

                    <div className="p-6">
                        {/* Icon + Title */}
                        <div className="flex items-start gap-4 mb-4">
                            <div className="w-12 h-12 rounded-xl bg-gradient-to-br from-cyan-500/20 to-purple-500/20 border border-cyan-500/20 flex items-center justify-center flex-shrink-0">
                                <Icon className="h-6 w-6 text-cyan-400" />
                            </div>
                            <div>
                                <p className="text-[10px] uppercase tracking-widest text-gray-500 mb-1">
                                    Step {currentStep + 1} of {tourSteps.length}
                                </p>
                                <h3 className="text-white font-semibold text-base">{step.title}</h3>
                            </div>
                            <Button
                                variant="ghost"
                                size="sm"
                                onClick={endTour}
                                className="ml-auto h-7 w-7 p-0 text-gray-500 hover:text-white"
                                aria-label="Close tour"
                            >
                                <X className="h-4 w-4" />
                            </Button>
                        </div>

                        {/* Description */}
                        <p className="text-sm text-gray-300 leading-relaxed mb-6">{step.description}</p>

                        {/* Navigation */}
                        <div className="flex items-center justify-between">
                            <Button
                                variant="ghost"
                                size="sm"
                                onClick={prevStep}
                                disabled={isFirst}
                                className="text-gray-400 hover:text-white disabled:opacity-30"
                            >
                                <ChevronLeft className="h-4 w-4 mr-1" />
                                Back
                            </Button>

                            <div className="flex gap-1.5">
                                {tourSteps.map((_, i) => (
                                    <button
                                        key={i}
                                        onClick={() => setCurrentStep(i)}
                                        className={`w-2 h-2 rounded-full transition-all duration-300 ${i === currentStep
                                            ? 'bg-cyan-400 w-6'
                                            : i < currentStep
                                                ? 'bg-cyan-400/30'
                                                : 'bg-gray-600'
                                            }`}
                                        aria-label={`Go to step ${i + 1}`}
                                    />
                                ))}
                            </div>

                            <Button
                                size="sm"
                                onClick={nextStep}
                                className="bg-cyan-600 hover:bg-cyan-700 text-white"
                            >
                                {isLast ? 'Get Started' : 'Next'}
                                {!isLast && <ChevronRight className="h-4 w-4 ml-1" />}
                            </Button>
                        </div>
                    </div>
                </div>
            </div>
        </>
    );
};

export default GuidedTour;
