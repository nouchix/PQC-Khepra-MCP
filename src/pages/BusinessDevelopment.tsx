import { useState } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Progress } from '@/components/ui/progress';
import {
  Users,
  Target,
  TrendingUp,
  Building,
  DollarSign,
  Calendar,
  CheckCircle,
  AlertCircle,
  BarChart3,
  Network
} from 'lucide-react';
import { PageLayout } from '@/components/PageLayout';

const BusinessDevelopment = () => {

  const phases = [
    {
      name: 'Phase 1',
      title: 'Foundation & Validation',
      timeline: 'Q1-Q2 2026',
      progress: 75,
      status: 'active',
      goals: [
        'Complete 50+ customer discovery interviews',
        'Develop detailed buyer personas',
        'Create sales enablement materials',
        'Establish pricing strategy',
        'Build initial sales team'
      ]
    },
    {
      name: 'Phase 2',
      title: 'Market Entry',
      timeline: 'Q2-Q3 2026',
      progress: 25,
      status: 'upcoming',
      goals: [
        'Launch freemium tier',
        'Execute CMMC compliance campaigns',
        'Establish 3-5 strategic partnerships',
        'Develop customer success playbooks',
        'Achieve $1M ARR'
      ]
    },
    {
      name: 'Phase 3',
      title: 'Scale & Expansion',
      timeline: 'Q3-Q4 2026',
      progress: 0,
      status: 'planned',
      goals: [
        'Expand into enterprise market',
        'Build channel partner program',
        'Develop thought leadership strategy',
        'Establish government contracting',
        'Target $5M ARR'
      ]
    },
    {
      name: 'Phase 4',
      title: 'Growth & Optimization',
      timeline: '2027',
      progress: 0,
      status: 'planned',
      goals: [
        'International expansion planning',
        'Advanced AI capabilities',
        'Strategic acquisition evaluation',
        'IPO readiness preparation',
        'Path to $25M+ ARR'
      ]
    }
  ];

  const customerSegments = [
    {
      name: 'Defense Contractors',
      size: '~2,500 companies',
      value: '$45B TAM',
      priority: 'High',
      painPoints: ['CMMC Compliance', 'Supply Chain Security', 'Audit Readiness'],
      engagement: 85
    },
    {
      name: 'Enterprise (Fortune 1000)',
      size: '~1,000 companies',
      value: '$120B TAM',
      priority: 'High',
      painPoints: ['Zero Trust Implementation', 'Compliance Automation', 'Threat Intelligence'],
      engagement: 65
    },
    {
      name: 'MSSPs',
      size: '~3,000 providers',
      value: '$25B TAM',
      priority: 'Medium',
      painPoints: ['Client Onboarding', 'Scalable Security Operations', 'Compliance Reporting'],
      engagement: 45
    },
    {
      name: 'Critical Infrastructure',
      size: '~500 entities',
      value: '$30B TAM',
      priority: 'High',
      painPoints: ['Regulatory Compliance', 'OT Security', 'Incident Response'],
      engagement: 70
    }
  ];

  const businessMetrics = {
    totalTAM: '$220B',
    totalSAM: '$15B',
    totalSOM: '$2.5B',
    currentARR: '$250K',
    targetARR: '$1M',
    customerAcquisitionCost: '$15K',
    lifetimeValue: '$125K',
    churnRate: '5%'
  };

  return (
    <PageLayout title="Business Development" showBack={true}>
      <div className="space-y-6">
        {/* Executive Summary */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Total TAM</CardTitle>
              <TrendingUp className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{businessMetrics.totalTAM}</div>
              <p className="text-xs text-muted-foreground">Total Addressable Market</p>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Current ARR</CardTitle>
              <DollarSign className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{businessMetrics.currentARR}</div>
              <p className="text-xs text-muted-foreground">Annual Recurring Revenue</p>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">LTV/CAC Ratio</CardTitle>
              <BarChart3 className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">8.3x</div>
              <p className="text-xs text-muted-foreground">Lifetime Value / Customer Acquisition Cost</p>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Customer Segments</CardTitle>
              <Users className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{customerSegments.length}</div>
              <p className="text-xs text-muted-foreground">Active Market Segments</p>
            </CardContent>
          </Card>
        </div>

        {/* Business Development Tabs */}
        <Tabs defaultValue="phases" className="w-full">
          <TabsList className="grid w-full grid-cols-5">
            <TabsTrigger value="phases">Development Phases</TabsTrigger>
            <TabsTrigger value="customers">Customer Discovery</TabsTrigger>
            <TabsTrigger value="canvas">Business Model</TabsTrigger>
            <TabsTrigger value="competitive">Competitive Analysis</TabsTrigger>
            <TabsTrigger value="partnerships">Partnerships</TabsTrigger>
          </TabsList>

          {/* Development Phases */}
          <TabsContent value="phases" className="space-y-4">
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              {phases.map((phase) => (
                <Card key={phase.name} className={`cursor-pointer transition-all hover:shadow-md ${phase.status === 'active' ? 'ring-2 ring-primary' : ''
                  }`}>
                  <CardHeader>
                    <div className="flex items-center justify-between">
                      <CardTitle className="text-lg">{phase.title}</CardTitle>
                      <Badge variant={(() => {
                        if (phase.status === 'active') return 'default';
                        if (phase.status === 'upcoming') return 'secondary';
                        return 'outline';
                      })()}>
                        {phase.timeline}
                      </Badge>
                    </div>
                    <CardDescription>{phase.name}</CardDescription>
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-3">
                      <div className="flex items-center justify-between text-sm">
                        <span>Progress</span>
                        <span>{phase.progress}%</span>
                      </div>
                      <Progress value={phase.progress} className="w-full" />

                      <div className="space-y-2">
                        <h4 className="font-medium text-sm">Key Goals:</h4>
                        {phase.goals.map((goal, index) => (
                          <div key={goal} className="flex items-center gap-2 text-sm">
                            {phase.progress > index * 20 ? (
                              <CheckCircle className="h-4 w-4 text-green-500" />
                            ) : (
                              <AlertCircle className="h-4 w-4 text-yellow-500" />
                            )}
                            <span className={phase.progress > index * 20 ? 'line-through text-muted-foreground' : ''}>
                              {goal}
                            </span>
                          </div>
                        ))}
                      </div>
                    </div>
                  </CardContent>
                </Card>
              ))}
            </div>
          </TabsContent>

          {/* Customer Discovery */}
          <TabsContent value="customers" className="space-y-4">
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              {customerSegments.map((segment) => (
                <Card key={segment.name}>
                  <CardHeader>
                    <div className="flex items-center justify-between">
                      <CardTitle className="text-lg">{segment.name}</CardTitle>
                      <Badge variant={segment.priority === 'High' ? 'default' : 'secondary'}>
                        {segment.priority} Priority
                      </Badge>
                    </div>
                    <CardDescription>{segment.size} • {segment.value}</CardDescription>
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-3">
                      <div className="flex items-center justify-between text-sm">
                        <span>Engagement Level</span>
                        <span>{segment.engagement}%</span>
                      </div>
                      <Progress value={segment.engagement} className="w-full" />

                      <div className="space-y-2">
                        <h4 className="font-medium text-sm">Key Pain Points:</h4>
                        <div className="flex flex-wrap gap-1">
                          {segment.painPoints.map((pain) => (
                            <Badge key={pain} variant="outline" className="text-xs">
                              {pain}
                            </Badge>
                          ))}
                        </div>
                      </div>

                      <Button variant="outline" size="sm" className="w-full">
                        <Target className="h-4 w-4 mr-2" />
                        View Discovery Insights
                      </Button>
                    </div>
                  </CardContent>
                </Card>
              ))}
            </div>
          </TabsContent>

          {/* Business Model Canvas */}
          <TabsContent value="canvas" className="space-y-4">
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
              <Card>
                <CardHeader>
                  <CardTitle className="text-sm">Value Propositions</CardTitle>
                </CardHeader>
                <CardContent className="space-y-2">
                  <Badge variant="outline">KHEPRA Protocol Security</Badge>
                  <Badge variant="outline">Automated CMMC Compliance</Badge>
                  <Badge variant="outline">Cultural Threat Intelligence</Badge>
                  <Badge variant="outline">Zero Trust Architecture</Badge>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle className="text-sm">Revenue Streams</CardTitle>
                </CardHeader>
                <CardContent className="space-y-2">
                  <div className="flex justify-between text-sm">
                    <span>SaaS Subscriptions</span>
                    <span>70%</span>
                  </div>
                  <div className="flex justify-between text-sm">
                    <span>Professional Services</span>
                    <span>20%</span>
                  </div>
                  <div className="flex justify-between text-sm">
                    <span>Usage-Based Pricing</span>
                    <span>10%</span>
                  </div>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle className="text-sm">Key Partnerships</CardTitle>
                </CardHeader>
                <CardContent className="space-y-2">
                  <Badge variant="outline">System Integrators</Badge>
                  <Badge variant="outline">Technology Vendors</Badge>
                  <Badge variant="outline">Compliance Consultants</Badge>
                  <Badge variant="outline">Government Partners</Badge>
                </CardContent>
              </Card>
            </div>
          </TabsContent>

          {/* Competitive Analysis */}
          <TabsContent value="competitive" className="space-y-4">
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              <Card>
                <CardHeader>
                  <CardTitle>Competitive Advantages</CardTitle>
                </CardHeader>
                <CardContent className="space-y-3">
                  <div className="flex items-center gap-3">
                    <CheckCircle className="h-5 w-5 text-green-500" />
                    <div>
                      <p className="font-medium">KHEPRA Protocol</p>
                      <p className="text-sm text-muted-foreground">Patent-pending Afrofuturist cryptographic framework</p>
                    </div>
                  </div>
                  <div className="flex items-center gap-3">
                    <CheckCircle className="h-5 w-5 text-green-500" />
                    <div>
                      <p className="font-medium">Cultural Threat Intelligence</p>
                      <p className="text-sm text-muted-foreground">Unique symbolic logic and threat taxonomy</p>
                    </div>
                  </div>
                  <div className="flex items-center gap-3">
                    <CheckCircle className="h-5 w-5 text-green-500" />
                    <div>
                      <p className="font-medium">Automated CMMC Compliance</p>
                      <p className="text-sm text-muted-foreground">Push-button enforcement and remediation</p>
                    </div>
                  </div>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle>Market Positioning</CardTitle>
                </CardHeader>
                <CardContent className="space-y-3">
                  <div className="flex justify-between items-center">
                    <span className="text-sm">Innovation Score</span>
                    <div className="flex items-center gap-2">
                      <Progress value={95} className="w-20" />
                      <span className="text-sm">95%</span>
                    </div>
                  </div>
                  <div className="flex justify-between items-center">
                    <span className="text-sm">Market Fit</span>
                    <div className="flex items-center gap-2">
                      <Progress value={80} className="w-20" />
                      <span className="text-sm">80%</span>
                    </div>
                  </div>
                  <div className="flex justify-between items-center">
                    <span className="text-sm">Competitive Moat</span>
                    <div className="flex items-center gap-2">
                      <Progress value={90} className="w-20" />
                      <span className="text-sm">90%</span>
                    </div>
                  </div>
                </CardContent>
              </Card>
            </div>
          </TabsContent>

          {/* Partnerships */}
          <TabsContent value="partnerships" className="space-y-4">
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
              <Card>
                <CardHeader>
                  <CardTitle className="text-sm flex items-center gap-2">
                    <Network className="h-4 w-4" />
                    Strategic Partners
                  </CardTitle>
                </CardHeader>
                <CardContent className="space-y-2">
                  <div className="flex justify-between text-sm">
                    <span>Technology Integrations</span>
                    <Badge variant="secondary">5 Active</Badge>
                  </div>
                  <div className="flex justify-between text-sm">
                    <span>Channel Partners</span>
                    <Badge variant="secondary">3 Active</Badge>
                  </div>
                  <div className="flex justify-between text-sm">
                    <span>Government Relations</span>
                    <Badge variant="secondary">2 Active</Badge>
                  </div>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle className="text-sm flex items-center gap-2">
                    <Building className="h-4 w-4" />
                    Enterprise Alliances
                  </CardTitle>
                </CardHeader>
                <CardContent className="space-y-2">
                  <div className="flex justify-between text-sm">
                    <span>Joint Go-to-Market</span>
                    <Badge variant="outline">2 Pipeline</Badge>
                  </div>
                  <div className="flex justify-between text-sm">
                    <span>Reseller Program</span>
                    <Badge variant="outline">Planning</Badge>
                  </div>
                  <div className="flex justify-between text-sm">
                    <span>OEM Partnerships</span>
                    <Badge variant="outline">1 Active</Badge>
                  </div>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle className="text-sm flex items-center gap-2">
                    <Calendar className="h-4 w-4" />
                    Partnership Pipeline
                  </CardTitle>
                </CardHeader>
                <CardContent className="space-y-2">
                  <div className="text-xs text-muted-foreground">Q1 2024 Targets</div>
                  <div className="flex justify-between text-sm">
                    <span>New Partners</span>
                    <span>5-7</span>
                  </div>
                  <div className="flex justify-between text-sm">
                    <span>Partner Revenue</span>
                    <span>30%</span>
                  </div>
                  <Button variant="outline" size="sm" className="w-full mt-2">
                    View Pipeline
                  </Button>
                </CardContent>
              </Card>
            </div>
          </TabsContent>
        </Tabs>
      </div>
    </PageLayout>
  );
};

export default BusinessDevelopment;