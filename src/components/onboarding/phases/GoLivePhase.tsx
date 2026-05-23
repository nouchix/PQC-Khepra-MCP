import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Rocket, Calendar, BarChart3, Shield, CheckCircle2 } from 'lucide-react';
import { Badge } from '@/components/ui/badge';

interface GoLivePhaseProps {
  organizationId: string;
  onboardingId: string;
}

export function GoLivePhase() {
  return (
    <div className="space-y-6">
      <div className="rounded-lg bg-gradient-to-r from-primary/20 to-primary/10 p-6 border border-primary/20">
        <div className="flex items-center gap-4 mb-4">
          <div className="h-16 w-16 rounded-full bg-primary flex items-center justify-center">
            <Rocket className="h-8 w-8 text-primary-foreground" />
          </div>
          <div>
            <h2 className="text-2xl font-bold">Congratulations!</h2>
            <p className="text-muted-foreground">
              Your organization is now live with continuous STIG compliance automation
            </p>
          </div>
        </div>
      </div>

      <div className="grid gap-4 md:grid-cols-2">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Continuous Monitoring</CardTitle>
            <Shield className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-primary">Active</div>
            <p className="text-xs text-muted-foreground mt-2">
              30-minute enforcement cycles with automated drift detection
            </p>
            <div className="mt-4">
              <Badge variant="outline" className="bg-primary/10">
                <CheckCircle2 className="h-3 w-3 mr-1" />
                Real-time Alerts
              </Badge>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Evidence Collection</CardTitle>
            <BarChart3 className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-primary">Automated</div>
            <p className="text-xs text-muted-foreground mt-2">
              Continuous evidence gathering for audit readiness
            </p>
            <div className="mt-4">
              <Badge variant="outline" className="bg-primary/10">
                <CheckCircle2 className="h-3 w-3 mr-1" />
                7-Year Retention
              </Badge>
            </div>
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>What's Next</CardTitle>
          <CardDescription>Your ongoing compliance journey</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex items-start gap-4 p-4 border rounded-lg">
            <div className="h-10 w-10 rounded-full bg-primary/10 flex items-center justify-center flex-shrink-0">
              <Calendar className="h-5 w-5 text-primary" />
            </div>
            <div className="flex-1">
              <h4 className="font-semibold mb-1">Quarterly Business Reviews</h4>
              <p className="text-sm text-muted-foreground mb-3">
                Scheduled compliance health checks and strategic planning sessions
              </p>
              <Button variant="outline" size="sm">
                Schedule First QBR
              </Button>
            </div>
          </div>

          <div className="flex items-start gap-4 p-4 border rounded-lg">
            <div className="h-10 w-10 rounded-full bg-primary/10 flex items-center justify-center flex-shrink-0">
              <Shield className="h-5 w-5 text-primary" />
            </div>
            <div className="flex-1">
              <h4 className="font-semibold mb-1">Penetration Testing</h4>
              <p className="text-sm text-muted-foreground mb-3">
                Optional post-deployment security validation
              </p>
              <Button variant="outline" size="sm">
                Request Pen Test
              </Button>
            </div>
          </div>

          <div className="flex items-start gap-4 p-4 border rounded-lg">
            <div className="h-10 w-10 rounded-full bg-primary/10 flex items-center justify-center flex-shrink-0">
              <BarChart3 className="h-5 w-5 text-primary" />
            </div>
            <div className="flex-1">
              <h4 className="font-semibold mb-1">Compliance Dashboard</h4>
              <p className="text-sm text-muted-foreground mb-3">
                Real-time visibility into your security posture
              </p>
              <Button variant="outline" size="sm">
                View Dashboard
              </Button>
            </div>
          </div>
        </CardContent>
      </Card>

      <Card className="border-primary bg-primary/5">
        <CardContent className="pt-6">
          <div className="flex items-center gap-4">
            <div className="h-12 w-12 rounded-full bg-primary flex items-center justify-center flex-shrink-0">
              <CheckCircle2 className="h-6 w-6 text-primary-foreground" />
            </div>
            <div className="flex-1">
              <h3 className="font-semibold">Need Support?</h3>
              <p className="text-sm text-muted-foreground">
                Your dedicated support team is available 24/7
              </p>
            </div>
            <Button>Contact Support</Button>
          </div>
        </CardContent>
      </Card>

      <div className="text-center space-y-4 pt-6">
        <h3 className="text-xl font-semibold">You're All Set!</h3>
        <p className="text-muted-foreground max-w-2xl mx-auto">
          Your organization is now protected by enterprise-grade STIG automation.
          Monitor your compliance dashboard for real-time insights and automated
          remediation activities.
        </p>
        <Button size="lg" className="mt-4">
          <Rocket className="mr-2 h-5 w-5" />
          Go to Dashboard
        </Button>
      </div>
    </div>
  );
}
