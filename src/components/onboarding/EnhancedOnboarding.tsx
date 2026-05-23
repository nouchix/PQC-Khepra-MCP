import { useState } from 'react';
import { useNavigate } from '@/lib/router-compat';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Dialog, DialogContent, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { 
  UserCheck, 
  Play, 
  ArrowRight, 
  CheckCircle2,
  Users,
  Building,
  Shield,
  Settings,
  Eye,
  Zap
} from 'lucide-react';
import { useUserProfile } from '@/hooks/useUserProfile';
import { RoleBasedTour } from './RoleBasedTour';
import { ExecutiveDashboardMode } from './ExecutiveDashboardMode';
import { PapyrusOnboarding } from './PapyrusOnboarding';

interface EnhancedOnboardingProps {
  open: boolean;
  onClose: () => void;
  onComplete: () => void;
}

export const EnhancedOnboarding = ({ open, onClose, onComplete }: EnhancedOnboardingProps) => {
  const navigate = useNavigate();
  const { profile } = useUserProfile();
  const [showRoleBasedTour, setShowRoleBasedTour] = useState(false);
  const [showPapyrusOnboarding, setShowPapyrusOnboarding] = useState(false);
  const [isExecutiveMode, setIsExecutiveMode] = useState(false);

  const getUserRole = () => {
    const role = profile?.role || 'viewer';
    switch (role) {
      case 'admin': return { title: 'Administrator', icon: Settings, color: 'bg-red-500' };
      case 'executive': return { title: 'Executive', icon: Building, color: 'bg-purple-500' };
      case 'security_engineer': return { title: 'Security Engineer', icon: Shield, color: 'bg-blue-500' };
      case 'analyst': return { title: 'Security Analyst', icon: Eye, color: 'bg-green-500' };
      default: return { title: 'Team Member', icon: Users, color: 'bg-gray-500' };
    }
  };

  const startGuidedTour = () => {
    setShowRoleBasedTour(true);
  };

  const startPapyrusOnboarding = () => {
    setShowPapyrusOnboarding(true);
  };

  const handleTourComplete = () => {
    setShowRoleBasedTour(false);
    onComplete();
  };

  const userRole = getUserRole();
  const RoleIcon = userRole.icon;

  if (showRoleBasedTour) {
    return (
      <RoleBasedTour
        open={showRoleBasedTour}
        onClose={() => setShowRoleBasedTour(false)}
        onComplete={handleTourComplete}
      />
    );
  }

  if (showPapyrusOnboarding) {
    return (
      <PapyrusOnboarding
        open={showPapyrusOnboarding}
        onClose={() => setShowPapyrusOnboarding(false)}
        onComplete={onComplete}
      />
    );
  }

  return (
    <Dialog open={open} onOpenChange={onClose}>
      <DialogContent className="max-w-2xl">
        <DialogHeader>
          <DialogTitle className="text-2xl">Welcome to SouHimBou AI Platform</DialogTitle>
        </DialogHeader>

        <div className="space-y-6">
          {/* User Role Card */}
          <Card className="border-primary/20 bg-gradient-to-r from-primary/5 to-secondary/5">
            <CardContent className="p-6">
              <div className="flex items-center space-x-4">
                <div className={`p-3 rounded-lg ${userRole.color} text-white`}>
                  <RoleIcon className="h-6 w-6" />
                </div>
                <div className="flex-1">
                  <h3 className="text-lg font-semibold">
                    Welcome, {profile?.full_name || 'User'}
                  </h3>
                  <div className="flex items-center space-x-2">
                    <Badge variant="outline" className="text-primary border-primary/50">
                      {userRole.title}
                    </Badge>
                    <span className="text-sm text-muted-foreground">
                      • {profile?.department || 'Security Team'}
                    </span>
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>

          {/* Onboarding Options */}
          <div className="space-y-4">
            <h3 className="text-lg font-semibold">Choose Your Experience</h3>
            
            {/* Papyrus AI-Guided Setup */}
            <Card className="cursor-pointer hover:shadow-md transition-shadow border-primary/30 bg-gradient-to-r from-primary/5 to-purple-500/5">
              <CardContent className="p-6">
                <div className="flex items-start space-x-4">
                  <div className="p-3 bg-primary/10 rounded-lg">
                    <Zap className="h-6 w-6 text-primary" />
                  </div>
                  <div className="flex-1">
                    <h4 className="text-lg font-semibold mb-2">
                      AI-Guided Setup with Papyrus
                    </h4>
                    <p className="text-muted-foreground mb-4">
                      Let Papyrus, your AI guide, walk you through a personalized setup experience.
                      Conversational, enjoyable, and tailored to your needs.
                    </p>
                    <div className="flex items-center space-x-2 text-sm text-primary">
                      <CheckCircle2 className="h-4 w-4" />
                      <span>Personalized AI guidance</span>
                    </div>
                    <div className="flex items-center space-x-2 text-sm text-primary mt-1">
                      <CheckCircle2 className="h-4 w-4" />
                      <span>Cultural wisdom integration</span>
                    </div>
                    <div className="flex items-center space-x-2 text-sm text-primary mt-1">
                      <CheckCircle2 className="h-4 w-4" />
                      <span>Quick profile setup</span>
                    </div>
                  </div>
                  <Button onClick={startPapyrusOnboarding} className="mt-4 bg-primary hover:bg-primary/90">
                    Meet Papyrus
                    <ArrowRight className="h-4 w-4 ml-2" />
                  </Button>
                </div>
              </CardContent>
            </Card>

            {/* Guided Tour Option */}
            <Card className="cursor-pointer hover:shadow-md transition-shadow border-primary/20">
              <CardContent className="p-6">
                <div className="flex items-start space-x-4">
                  <div className="p-3 bg-primary/10 rounded-lg">
                    <Play className="h-6 w-6 text-primary" />
                  </div>
                  <div className="flex-1">
                    <h4 className="text-lg font-semibold mb-2">
                      Quick Tour
                    </h4>
                    <p className="text-muted-foreground mb-4">
                      Take a personalized tour based on your role. We'll show you the most relevant features and help you get started quickly.
                    </p>
                    <div className="flex items-center space-x-2 text-sm text-primary">
                      <CheckCircle2 className="h-4 w-4" />
                      <span>Personalized for {userRole.title.toLowerCase()}s</span>
                    </div>
                    <div className="flex items-center space-x-2 text-sm text-primary mt-1">
                      <CheckCircle2 className="h-4 w-4" />
                      <span>5-10 minutes to complete</span>
                    </div>
                  </div>
                  <Button onClick={() => {
                    startGuidedTour();
                    navigate('/dashboard?tour=quick');
                  }} className="mt-4" variant="outline">
                    Start Tour
                    <ArrowRight className="h-4 w-4 ml-2" />
                  </Button>
                </div>
              </CardContent>
            </Card>

            {/* Executive Mode Option - Only for Admins/Executives */}
            {['admin', 'executive'].includes(profile?.role || '') && (
              <Card className="border-secondary/20">
                <CardContent className="p-6">
                  <div className="flex items-start space-x-4">
                    <div className="p-3 bg-secondary/10 rounded-lg">
                      <Eye className="h-6 w-6 text-secondary" />
                    </div>
                    <div className="flex-1">
                      <h4 className="text-lg font-semibold mb-2">
                        Executive Summary Mode
                      </h4>
                      <p className="text-muted-foreground mb-4">
                        Simplified dashboard view focusing on high-level KPIs, security posture, and key decision points.
                      </p>
                      <ExecutiveDashboardMode
                        isExecutiveMode={isExecutiveMode}
                        onToggle={setIsExecutiveMode}
                      />
                    </div>
                  </div>
                </CardContent>
              </Card>
            )}

            {/* Skip Option */}
            <Card className="border-muted/50">
              <CardContent className="p-6">
                <div className="flex items-center justify-between">
                  <div>
                    <h4 className="font-semibold">Skip and Explore</h4>
                    <p className="text-sm text-muted-foreground">
                      Jump straight into the platform and explore on your own
                    </p>
                  </div>
                  <Button variant="outline" onClick={onComplete}>
                    Skip Setup
                  </Button>
                </div>
              </CardContent>
            </Card>
          </div>

          {/* Quick Access Information */}
          <Card className="bg-muted/30">
            <CardContent className="p-4">
              <h4 className="font-medium mb-2">Need Help Later?</h4>
              <p className="text-sm text-muted-foreground">
                You can always restart this tour from the help menu or access our documentation 
                and support resources from any page.
              </p>
            </CardContent>
          </Card>
        </div>
      </DialogContent>
    </Dialog>
  );
};