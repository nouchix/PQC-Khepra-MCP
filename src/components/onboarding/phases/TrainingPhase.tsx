import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { BookOpen, FileText, Video, CheckCircle2 } from 'lucide-react';
import { Badge } from '@/components/ui/badge';

interface TrainingPhaseProps {
  organizationId: string;
  onboardingId: string;
}

const trainingModules = [
  {
    role: 'System Administrator',
    modules: [
      { title: 'Platform Dashboard Overview', duration: '15 min', type: 'video' },
      { title: 'Managing STIG Baselines', duration: '20 min', type: 'video' },
      { title: 'Ansible Playbook Execution', duration: '25 min', type: 'hands-on' },
      { title: 'Drift Detection & Alerts', duration: '15 min', type: 'video' },
    ],
  },
  {
    role: 'Security Officer',
    modules: [
      { title: 'Compliance Dashboard', duration: '20 min', type: 'video' },
      { title: 'Evidence Collection & Audit Trails', duration: '30 min', type: 'hands-on' },
      { title: 'Report Generation', duration: '15 min', type: 'video' },
      { title: 'Risk Assessment Tools', duration: '25 min', type: 'hands-on' },
    ],
  },
  {
    role: 'IT Manager',
    modules: [
      { title: 'Executive Dashboard', duration: '10 min', type: 'video' },
      { title: 'Team Management', duration: '15 min', type: 'video' },
      { title: 'Quarterly Business Reviews', duration: '20 min', type: 'documentation' },
      { title: 'Budget & Resource Planning', duration: '15 min', type: 'documentation' },
    ],
  },
];

const documentation = [
  { title: 'Platform User Guide', pages: 45, icon: BookOpen },
  { title: 'STIG Automation Playbook', pages: 78, icon: FileText },
  { title: 'API Integration Guide', pages: 32, icon: FileText },
  { title: 'Audit Readiness Checklist', pages: 15, icon: CheckCircle2 },
];

export function TrainingPhase() {
  return (
    <div className="space-y-6">
      <div className="rounded-lg bg-primary/10 p-4 border border-primary/20">
        <h3 className="font-semibold mb-2">Training & Documentation</h3>
        <ul className="space-y-2 text-sm">
          <li>✓ Role-based training modules for your team</li>
          <li>✓ Hands-on platform walkthroughs</li>
          <li>✓ Comprehensive documentation library</li>
          <li>✓ Audit-ready reporting tools</li>
        </ul>
      </div>

      <div className="space-y-4">
        {trainingModules.map((roleTraining) => (
          <Card key={roleTraining.role}>
            <CardHeader>
              <CardTitle className="text-lg">{roleTraining.role}</CardTitle>
              <CardDescription>
                {roleTraining.modules.length} training modules
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-2">
                {roleTraining.modules.map((module, idx) => (
                  <div
                    key={idx}
                    className="flex items-center justify-between p-3 border rounded-lg hover:bg-accent/50 transition-colors"
                  >
                    <div className="flex items-center gap-3">
                      <div className="h-10 w-10 rounded-full bg-primary/10 flex items-center justify-center">
                        {module.type === 'video' ? (
                          <Video className="h-5 w-5 text-primary" />
                        ) : module.type === 'hands-on' ? (
                          <CheckCircle2 className="h-5 w-5 text-primary" />
                        ) : (
                          <FileText className="h-5 w-5 text-primary" />
                        )}
                      </div>
                      <div>
                        <div className="font-medium">{module.title}</div>
                        <div className="text-sm text-muted-foreground flex items-center gap-2">
                          <span>{module.duration}</span>
                          <Badge variant="outline" className="text-xs">
                            {module.type}
                          </Badge>
                        </div>
                      </div>
                    </div>
                    <Button variant="ghost" size="sm">
                      Start
                    </Button>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        ))}
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Documentation Library</CardTitle>
          <CardDescription>
            Comprehensive guides and reference materials
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {documentation.map((doc) => {
              const Icon = doc.icon;
              return (
                <div
                  key={doc.title}
                  className="flex items-center gap-3 p-4 border rounded-lg hover:bg-accent/50 transition-colors cursor-pointer"
                >
                  <div className="h-12 w-12 rounded-lg bg-primary/10 flex items-center justify-center">
                    <Icon className="h-6 w-6 text-primary" />
                  </div>
                  <div className="flex-1">
                    <div className="font-medium">{doc.title}</div>
                    <div className="text-sm text-muted-foreground">{doc.pages} pages</div>
                  </div>
                  <Button variant="outline" size="sm">
                    Download
                  </Button>
                </div>
              );
            })}
          </div>
        </CardContent>
      </Card>

      <Card className="border-primary bg-primary/5">
        <CardContent className="pt-6">
          <div className="text-center space-y-2">
            <h3 className="font-semibold">Need Additional Training?</h3>
            <p className="text-sm text-muted-foreground mb-4">
              Schedule a live training session with our compliance experts
            </p>
            <Button>Schedule Training Session</Button>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
