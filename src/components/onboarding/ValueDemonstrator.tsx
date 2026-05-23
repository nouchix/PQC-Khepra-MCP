import { useState, useEffect } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Progress } from '@/components/ui/progress';
import { 
  TrendingUp, 
  Shield, 
  Clock, 
  DollarSign,
  CheckCircle2,
  AlertTriangle,
  Zap,
  Target,
  Users,
  ArrowRight
} from 'lucide-react';
import { useNavigate } from '@/lib/router-compat';
import { useUsageTracker } from '@/components/UsageTracker';

interface ValueMetric {
  label: string;
  value: string;
  improvement: string;
  icon: any;
  color: string;
  description: string;
}

export const ValueDemonstrator = () => {
  const navigate = useNavigate();
  const { trackFeatureAccess } = useUsageTracker();
  const [animatedValues, setAnimatedValues] = useState<Record<string, number>>({});

  const metrics: ValueMetric[] = [
    {
      label: 'Threat Detection Speed',
      value: '99.7%',
      improvement: '+47% faster',
      icon: Zap,
      color: 'text-green-500',
      description: 'Average time to detect threats vs traditional methods'
    },
    {
      label: 'Compliance Readiness',
      value: '85%',
      improvement: '+60% improvement',
      icon: Shield,
      color: 'text-blue-500',
      description: 'CMMC controls automatically monitored and tracked'
    },
    {
      label: 'Cost Reduction',
      value: '$127K',
      improvement: '67% saved annually',
      icon: DollarSign,
      color: 'text-emerald-500',
      description: 'Estimated annual savings vs manual processes'
    },
    {
      label: 'Response Time',
      value: '2.3s',
      improvement: '94% faster',
      icon: Clock,
      color: 'text-orange-500',
      description: 'Average automated response time to threats'
    }
  ];

  const quickWins = [
    { task: 'Infrastructure Discovery Scan', status: 'ready', time: '5 min', value: 'Discover all assets' },
    { task: 'Security Assessment', status: 'ready', time: '10 min', value: 'Identify vulnerabilities' },
    { task: 'Compliance Check', status: 'ready', time: '3 min', value: 'CMMC readiness score' },
    { task: 'Team Collaboration Setup', status: 'ready', time: '2 min', value: 'Invite team members' }
  ];

  useEffect(() => {
    // Animate values on mount
    const timers = metrics.map((metric, index) => {
      return setTimeout(() => {
        const finalValue = Number.parseFloat(metric.value.replace(/[^\d.]/g, ''));
        let current = 0;
        const increment = finalValue / 30;
        
        const valueTimer = setInterval(() => {
          current += increment;
          if (current >= finalValue) {
            current = finalValue;
            clearInterval(valueTimer);
          }
          setAnimatedValues(prev => ({
            ...prev,
            [metric.label]: current
          }));
        }, 50);
      }, index * 200);
    });

    return () => timers.forEach(clearTimeout);
  }, []);

  const handleQuickAction = (task: string) => {
    trackFeatureAccess(`quick_win_${task.toLowerCase().replace(/\s+/g, '_')}`, 'premium');
    
    // Navigate to relevant section based on task
    switch (task) {
      case 'Infrastructure Discovery Scan':
        navigate('/automation');
        break;
      case 'Security Assessment':
        navigate('/security');
        break;
      case 'Compliance Check':
        navigate('/security?tab=compliance');
        break;
      case 'Team Collaboration Setup':
        navigate('/setup');
        break;
    }
  };

  return (
    <div className="space-y-6">
      {/* Value Metrics */}
      <Card className="border-primary/20 bg-gradient-to-r from-primary/5 to-secondary/5">
        <CardHeader>
          <div className="flex items-center space-x-2">
            <TrendingUp className="h-6 w-6 text-primary" />
            <CardTitle>Your Potential Impact</CardTitle>
            <Badge variant="outline" className="ml-auto">Live Demo Data</Badge>
          </div>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
            {metrics.map((metric) => {
              const Icon = metric.icon;
              const animatedValue = animatedValues[metric.label] || 0;
              const displayValue = metric.value.includes('%') 
                ? `${animatedValue.toFixed(1)}%`
                : metric.value.includes('$')
                ? `$${Math.round(animatedValue)}K`
                : metric.value.includes('s')
                ? `${animatedValue.toFixed(1)}s`
                : animatedValue.toFixed(1);

              return (
                <div key={metric.label} className="text-center space-y-2 p-4 bg-background/50 rounded-lg">
                  <Icon className={`h-8 w-8 mx-auto ${metric.color}`} />
                  <div className="space-y-1">
                    <div className={`text-2xl font-bold ${metric.color}`}>
                      {displayValue}
                    </div>
                    <div className="text-xs font-medium text-green-500">
                      {metric.improvement}
                    </div>
                    <div className="text-xs text-muted-foreground">
                      {metric.label}
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
          <p className="text-center text-sm text-muted-foreground mt-4">
            * Based on aggregated data from similar organizations
          </p>
        </CardContent>
      </Card>

      {/* Quick Wins */}
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-2">
              <Target className="h-6 w-6 text-primary" />
              <CardTitle>Get Value in Minutes</CardTitle>
            </div>
            <Badge variant="outline">4 Quick Wins</Badge>
          </div>
        </CardHeader>
        <CardContent>
          <div className="space-y-3">
            {quickWins.map((win, index) => (
              <div 
                key={win.task}
                className="flex items-center justify-between p-4 bg-muted/30 rounded-lg hover:bg-muted/50 transition-colors cursor-pointer"
                onClick={() => handleQuickAction(win.task)}
              >
                <div className="flex items-center space-x-3">
                  <div className="w-8 h-8 bg-primary/10 rounded-full flex items-center justify-center">
                    <span className="text-sm font-semibold text-primary">{index + 1}</span>
                  </div>
                  <div>
                    <h4 className="font-medium">{win.task}</h4>
                    <div className="flex items-center space-x-2 text-sm text-muted-foreground">
                      <Clock className="h-3 w-3" />
                      <span>{win.time}</span>
                      <span>•</span>
                      <span className="text-primary font-medium">{win.value}</span>
                    </div>
                  </div>
                </div>
                <div className="flex items-center space-x-2">
                  <Badge variant="outline" className="text-green-600 border-green-600/30">
                    Ready
                  </Badge>
                  <ArrowRight className="h-4 w-4 text-muted-foreground" />
                </div>
              </div>
            ))}
          </div>
          
          <div className="mt-6 p-4 bg-blue-500/10 border border-blue-500/20 rounded-lg text-center">
            <div className="flex items-center justify-center space-x-2 mb-2">
              <CheckCircle2 className="h-5 w-5 text-blue-500" />
              <span className="font-semibold text-blue-600 dark:text-blue-400">
                Complete all 4 tasks to unlock your security score!
              </span>
            </div>
            <Progress value={0} className="h-2" />
            <p className="text-xs text-muted-foreground mt-2">
              Progress: 0 of 4 completed
            </p>
          </div>
        </CardContent>
      </Card>
    </div>
  );
};