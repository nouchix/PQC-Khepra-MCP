import React, { useState } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import {
  Play,
  Eye,
  CheckCircle,
  ArrowRight,
  Shield,
  Brain,
  Clock,
  Lock
} from 'lucide-react';
import { useUserAgreements } from '@/hooks/useUserAgreements';

interface ExperienceSelectorProps {
  onExperienceSelected: (experience: string) => void;
}

const ExperienceSelector: React.FC<ExperienceSelectorProps> = ({ onExperienceSelected }) => {
  const [selectedExperience, setSelectedExperience] = useState<string | null>(null);
  const { hasAcceptedAll } = useUserAgreements();

  const experiences = [
    {
      id: 'enterprise-setup',
      title: 'STIG Configuration Setup',
      description: 'Connect your environment for STIG configuration search, AI verification, baseline capture, and drift detection.',
      icon: Shield,
      color: 'from-orange-500 to-red-500',
      bgColor: 'bg-gradient-to-br from-orange-50 to-red-50 dark:from-orange-950/20 dark:to-red-950/20',
      borderColor: 'border-orange-200 dark:border-orange-800',
      features: [
        'STIG configuration registry',
        'AI-powered verification',
        'Configuration baselines',
        'Drift detection monitoring'
      ],
      buttonText: 'Start Setup',
      estimatedTime: '10-15 minutes',
      requiresAcceptance: true
    },
    {
      id: 'quick-tour',
      title: 'Quick Platform Tour',
      description: 'Explore STIG configuration search, AI verification, and drift detection capabilities with sample data.',
      icon: Play,
      color: 'from-blue-500 to-cyan-500',
      bgColor: 'bg-gradient-to-br from-blue-50 to-cyan-50 dark:from-blue-950/20 dark:to-cyan-950/20',
      borderColor: 'border-blue-200 dark:border-blue-800',
      features: [
        'Interactive demo mode',
        'Sample STIG configurations',
        'Live drift detection preview'
      ],
      buttonText: 'Start Tour',
      estimatedTime: '5-10 minutes',
      requiresAcceptance: false
    },
    {
      id: 'executive-summary',
      title: 'Compliance Dashboard',
      description: 'High-level view of STIG compliance status, configuration drift, and baseline health across your environment.',
      icon: Eye,
      color: 'from-purple-500 to-indigo-500',
      bgColor: 'bg-gradient-to-br from-purple-50 to-indigo-50 dark:from-purple-950/20 dark:to-indigo-950/20',
      borderColor: 'border-purple-200 dark:border-purple-800',
      features: [
        'STIG compliance overview',
        'Configuration drift status',
        'Baseline health metrics'
      ],
      buttonText: 'View Dashboard',
      estimatedTime: 'Immediate access',
      requiresAcceptance: true
    }
  ];

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 via-blue-50 to-indigo-50 dark:from-slate-900 dark:via-blue-900 dark:to-indigo-900 flex items-center justify-center p-6 bg-animate">
      <div className="w-full max-w-6xl">
        {/* Header */}
        <div className="text-center mb-12 animate-fade-in">
          <div className="flex items-center justify-center mb-6">
            <div className="p-4 bg-gradient-to-r from-blue-600 to-purple-600 rounded-2xl shadow-xl shadow-blue-500/20 rotate-3 hover:rotate-0 transition-transform cursor-pointer">
              <Brain className="h-10 w-10 text-white" />
            </div>
          </div>
          <h1 className="text-5xl font-extrabold tracking-tight text-gray-900 dark:text-white mb-4 bg-gradient-to-r from-blue-600 to-indigo-600 bg-clip-text text-transparent italic">
            Choose Your Experience
          </h1>
          <p className="text-xl text-gray-600 dark:text-gray-300 max-w-3xl mx-auto leading-relaxed">
            Welcome to STIG-first compliance automation. Select how you'd like to explore
            configuration management, AI verification, and drift detection.
          </p>
          <div className="mt-4">
            <Badge variant="outline" className="text-xs uppercase tracking-widest border-primary/30 text-primary px-3 py-1">
              Powered by SouHimBou AI • Ra (Standard) Enabled
            </Badge>
          </div>
        </div>

        {/* Experience Cards */}
        <div className="grid md:grid-cols-1 lg:grid-cols-3 gap-8 mb-12">
          {experiences.map((experience, idx) => {
            const isLocked = experience.requiresAcceptance && !hasAcceptedAll;
            return (
              <Card
                key={experience.id}
                className={`
                  relative overflow-hidden ${experience.bgColor} ${experience.borderColor} border-2 
                  shadow-lg hover:shadow-2xl transition-all duration-500 cursor-pointer group
                  ${selectedExperience === experience.id ? 'ring-4 ring-blue-500/30 scale-[1.03] border-blue-400' : 'scale-100'}
                  animate-slide-up
                `}
                style={{ animationDelay: `${idx * 100}ms` }}
                onClick={() => setSelectedExperience(experience.id)}
              >
                {/* Status Badges */}
                <div className="absolute top-4 right-4 flex flex-col gap-2 items-end z-10">
                  {isLocked && (
                    <Badge variant="destructive" className="animate-pulse shadow-lg shadow-red-500/20 text-[10px] font-bold py-1">
                      <Lock className="h-3 w-3 mr-1" />
                      Requires Acceptance
                    </Badge>
                  )}
                  {experience.id === 'enterprise-setup' && (
                    <Badge variant="outline" className="bg-orange-500/10 text-orange-600 border-orange-500/20 text-[10px]">
                      Ra (Standard)
                    </Badge>
                  )}
                </div>

                <CardHeader className="text-center pb-4 pt-8">
                  <div className={`w-20 h-20 mx-auto rounded-3xl bg-gradient-to-br ${experience.color} flex items-center justify-center mb-6 shadow-lg group-hover:scale-110 transition-transform duration-500`}>
                    <experience.icon className="h-10 w-10 text-white" />
                  </div>
                  <CardTitle className="text-2xl font-bold text-gray-900 dark:text-white mb-2">
                    {experience.title}
                  </CardTitle>
                  <CardDescription className="text-gray-600 dark:text-gray-300 leading-relaxed px-4">
                    {experience.description}
                  </CardDescription>
                </CardHeader>

                <CardContent className="space-y-6 px-8">
                  {/* Features */}
                  <div className="space-y-3 min-h-[120px]">
                    {experience.features.map((feature) => (
                      <div key={feature} className="flex items-center space-x-3 group/item">
                        <CheckCircle className="h-5 w-5 text-green-500 flex-shrink-0 transition-transform group-hover/item:scale-125" />
                        <span className="text-sm font-medium text-gray-700 dark:text-gray-200">
                          {feature}
                        </span>
                      </div>
                    ))}
                  </div>

                  {/* Time Estimate */}
                  <div className="flex items-center justify-center space-x-2 text-sm font-semibold text-gray-500 dark:text-gray-400 py-2 bg-white/30 dark:bg-black/20 rounded-xl">
                    <Clock className="h-4 w-4" />
                    <span>{experience.estimatedTime}</span>
                  </div>

                  {/* Action Button */}
                  <Button
                    onClick={(e) => {
                      e.stopPropagation();
                      onExperienceSelected(experience.id);
                    }}
                    className={`
                      w-full h-12 bg-gradient-to-r ${experience.color} 
                      hover:brightness-110 hover:shadow-lg text-white font-bold
                      transition-all duration-300 group/btn rounded-xl
                    `}
                  >
                    <span className="flex items-center justify-center gap-2">
                      {experience.buttonText}
                      <ArrowRight className="h-5 w-5 group-hover/btn:translate-x-2 transition-transform" />
                    </span>
                  </Button>
                </CardContent>
              </Card>
            );
          })}
        </div>

        {/* Bottom Status */}
        <div className="text-center animate-fade-in" style={{ animationDelay: '500ms' }}>
          <div className="inline-flex items-center space-x-3 bg-white/90 dark:bg-gray-800/90 backdrop-blur-xl rounded-2xl px-8 py-4 border-2 border-primary/10 shadow-xl">
            <div className="flex items-center space-x-3">
              <div className="relative">
                <div className="w-4 h-4 bg-green-500 rounded-full animate-ping absolute opacity-75"></div>
                <div className="w-4 h-4 bg-green-500 rounded-full relative"></div>
              </div>
              <span className="text-base font-bold text-gray-800 dark:text-white">
                STIG-Codex Engine Live
              </span>
            </div>
            <div className="text-gray-300 font-thin text-xl">|</div>
            <span className="text-sm font-medium text-gray-600 dark:text-gray-300">
              TRL-10 Verification Protocol Active • Secure Connection Established
            </span>
          </div>
        </div>
      </div>
    </div>
  );
};

export default ExperienceSelector;