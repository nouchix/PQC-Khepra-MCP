import { useState, Fragment } from 'react';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Progress } from '@/components/ui/progress';
import { Separator } from '@/components/ui/separator';
import { 
  Shield, 
  TrendingUp, 
  Award, 
  CheckCircle2, 
  ArrowRight,
  Clock,
  Target,
  Zap,
  Users,
  Settings
} from 'lucide-react';
import { IndustryType, AutomationLevel, INDUSTRY_DEPLOYMENT_TEMPLATES } from '@/types/deployment';

interface JourneyStage {
  id: string;
  name: string;
  automationLevel: AutomationLevel;
  description: string;
  duration: string;
  requirements: {
    trustScore: number;
    successfulActions: number;
    timeInStage: number; // days
  };
  benefits: string[];
  risks: string[];
  current?: boolean;
  completed?: boolean;
}

interface CustomerConfidenceJourneyProps {
  organizationId: string;
  industry: IndustryType;
  currentTrustScore: number;
  successfulActions: number;
  daysInCurrentStage: number;
  onAdvanceStage?: () => void;
  onCustomizeJourney?: () => void;
}

export const CustomerConfidenceJourney: React.FC<CustomerConfidenceJourneyProps> = ({
  organizationId,
  industry,
  currentTrustScore,
  successfulActions,
  daysInCurrentStage,
  onAdvanceStage,
  onCustomizeJourney
}) => {
  const [selectedStage, setSelectedStage] = useState<string | null>(null);

  const getJourneyStages = (industryType: IndustryType): JourneyStage[] => {
    const template = INDUSTRY_DEPLOYMENT_TEMPLATES[industryType];
    
    const baseStages: JourneyStage[] = [
      {
        id: 'discovery',
        name: 'Discovery & Monitoring',
        automationLevel: 'monitor_only',
        description: 'Platform learns your environment and provides visibility into security posture',
        duration: '30-60 days',
        requirements: {
          trustScore: 60,
          successfulActions: 0,
          timeInStage: 0
        },
        benefits: [
          'Complete asset discovery',
          'STIG compliance assessment',
          'Risk prioritization',
          'No system changes'
        ],
        risks: ['Information gathering only'],
        current: true
      },
      {
        id: 'guided',
        name: 'Guided Remediation',
        automationLevel: 'guided',
        description: 'AI provides step-by-step remediation guidance with human oversight',
        duration: '60-90 days',
        requirements: {
          trustScore: template.trustThresholds.minimum,
          successfulActions: 10,
          timeInStage: 30
        },
        benefits: [
          'Expert remediation guidance',
          'Risk-aware recommendations',
          'Change validation',
          'Skill development'
        ],
        risks: ['Requires manual execution', 'Time intensive']
      },
      {
        id: 'semi_automated',
        name: 'Semi-Automated',
        automationLevel: 'semi_automated',
        description: 'Automated low-risk actions with approval workflows for higher-risk changes',
        duration: '90+ days',
        requirements: {
          trustScore: template.trustThresholds.promotion,
          successfulActions: 50,
          timeInStage: 60
        },
        benefits: [
          'Faster low-risk remediation',
          'Reduced manual workload',
          'Maintained oversight',
          'Improved efficiency'
        ],
        risks: ['Some automated changes', 'Requires trust in AI decisions']
      }
    ];

    // Add fully automated stage only for industries that support it
    if (template.trustThresholds.autonomous < 100) {
      baseStages.push({
        id: 'fully_automated',
        name: 'Fully Automated',
        automationLevel: 'fully_automated',
        description: 'AI handles most remediation actions automatically with comprehensive monitoring',
        duration: 'Ongoing',
        requirements: {
          trustScore: template.trustThresholds.autonomous,
          successfulActions: 200,
          timeInStage: 120
        },
        benefits: [
          'Maximum efficiency',
          'Continuous compliance',
          'Proactive remediation',
          'Minimal human intervention'
        ],
        risks: ['High automation dependency', 'Requires established trust']
      });
    }

    return baseStages;
  };

  const stages = getJourneyStages(industry);
  const currentStageIndex = stages.findIndex(s => s.current) || 0;
  const currentStage = stages[currentStageIndex];
  const nextStage = stages[currentStageIndex + 1];

  const canAdvance = nextStage && 
    currentTrustScore >= nextStage.requirements.trustScore &&
    successfulActions >= nextStage.requirements.successfulActions &&
    daysInCurrentStage >= nextStage.requirements.timeInStage;

  const getStageIcon = (automationLevel: AutomationLevel) => {
    switch (automationLevel) {
      case 'monitor_only':
        return <Shield className="h-5 w-5" />;
      case 'guided':
        return <Users className="h-5 w-5" />;
      case 'semi_automated':
        return <Settings className="h-5 w-5" />;
      case 'fully_automated':
        return <Zap className="h-5 w-5" />;
    }
  };

  const getStageColor = (stage: JourneyStage) => {
    if (stage.completed) return 'success';
    if (stage.current) return 'default';
    return 'secondary';
  };

  return (
    <div className="space-y-6">
      {/* Journey Overview */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center space-x-2">
            <TrendingUp className="h-5 w-5" />
            <span>Customer Confidence Journey</span>
          </CardTitle>
          <CardDescription>
            Graduated deployment approach for {INDUSTRY_DEPLOYMENT_TEMPLATES[industry].name}
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="flex items-center justify-between mb-6">
            {stages.map((stage, index) => (
              <Fragment key={stage.id}>
                <div 
                  className={`flex flex-col items-center space-y-2 cursor-pointer transition-all ${
                    selectedStage === stage.id ? 'scale-105' : ''
                  }`}
                  onClick={() => setSelectedStage(stage.id)}
                >
                  <div className={`
                    w-12 h-12 rounded-full border-2 flex items-center justify-center
                    ${stage.current ? 'border-primary bg-primary text-primary-foreground' : 
                      stage.completed ? 'border-success bg-success text-success-foreground' :
                      'border-muted bg-muted text-muted-foreground'}
                  `}>
                    {stage.completed ? (
                      <CheckCircle2 className="h-6 w-6" />
                    ) : (
                      getStageIcon(stage.automationLevel)
                    )}
                  </div>
                  <div className="text-center">
                    <div className="text-sm font-medium">{stage.name}</div>
                    <Badge variant={getStageColor(stage) as "success" | "default" | "secondary" | "destructive" | "outline"} className="text-xs mt-1">
                      {stage.automationLevel.replaceAll('_', ' ')}
                    </Badge>
                  </div>
                </div>
                {index < stages.length - 1 && (
                  <ArrowRight className="h-4 w-4 text-muted-foreground" />
                )}
              </Fragment>
            ))}
          </div>

          {/* Current Stage Progress */}
          <div className="space-y-4">
            <div>
              <div className="flex justify-between text-sm mb-2">
                <span>Trust Score Progress</span>
                <span>{currentTrustScore}% / {nextStage?.requirements.trustScore || 100}%</span>
              </div>
              <Progress 
                value={nextStage ? (currentTrustScore / nextStage.requirements.trustScore) * 100 : 100} 
                className="h-2"
              />
            </div>

            <div>
              <div className="flex justify-between text-sm mb-2">
                <span>Successful Actions</span>
                <span>{successfulActions} / {nextStage?.requirements.successfulActions || successfulActions}</span>
              </div>
              <Progress 
                value={nextStage ? Math.min((successfulActions / nextStage.requirements.successfulActions) * 100, 100) : 100}
                className="h-2"
              />
            </div>

            <div>
              <div className="flex justify-between text-sm mb-2">
                <span>Time in Stage</span>
                <span>{daysInCurrentStage} / {nextStage?.requirements.timeInStage || daysInCurrentStage} days</span>
              </div>
              <Progress 
                value={nextStage ? Math.min((daysInCurrentStage / nextStage.requirements.timeInStage) * 100, 100) : 100}
                className="h-2"
              />
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Stage Details */}
      {selectedStage && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center space-x-2">
              {getStageIcon(stages.find(s => s.id === selectedStage)!.automationLevel)}
              <span>{stages.find(s => s.id === selectedStage)!.name}</span>
            </CardTitle>
            <CardDescription>
              {stages.find(s => s.id === selectedStage)!.description}
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <div>
                <h4 className="font-semibold mb-3 text-success">Benefits</h4>
                <ul className="space-y-2">
                  {stages.find(s => s.id === selectedStage)!.benefits.map((benefit, index) => (
                    <li key={index} className="flex items-start space-x-2">
                      <CheckCircle2 className="h-4 w-4 text-success mt-0.5 flex-shrink-0" />
                      <span className="text-sm">{benefit}</span>
                    </li>
                  ))}
                </ul>
              </div>

              <div>
                <h4 className="font-semibold mb-3 text-warning">Considerations</h4>
                <ul className="space-y-2">
                  {stages.find(s => s.id === selectedStage)!.risks.map((risk, index) => (
                    <li key={index} className="flex items-start space-x-2">
                      <Target className="h-4 w-4 text-warning mt-0.5 flex-shrink-0" />
                      <span className="text-sm">{risk}</span>
                    </li>
                  ))}
                </ul>
              </div>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Next Stage Advancement */}
      {nextStage && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center space-x-2">
              <Award className="h-5 w-5" />
              <span>Ready for Next Stage?</span>
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex items-center justify-between">
              <div>
                <h4 className="font-semibold">{nextStage.name}</h4>
                <p className="text-sm text-muted-foreground">{nextStage.description}</p>
                <div className="mt-2">
                  {canAdvance ? (
                    <Badge variant="default" className="bg-success text-success-foreground">
                      <CheckCircle2 className="h-3 w-3 mr-1" />
                      Ready to Advance
                    </Badge>
                  ) : (
                    <Badge variant="secondary">
                      <Clock className="h-3 w-3 mr-1" />
                      Requirements Not Met
                    </Badge>
                  )}
                </div>
              </div>
              <div className="text-right space-x-2">
                {onCustomizeJourney && (
                  <Button variant="outline" onClick={onCustomizeJourney}>
                    <Settings className="h-4 w-4 mr-2" />
                    Customize
                  </Button>
                )}
                {canAdvance && onAdvanceStage && (
                  <Button onClick={onAdvanceStage}>
                    <TrendingUp className="h-4 w-4 mr-2" />
                    Advance Stage
                  </Button>
                )}
              </div>
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
};