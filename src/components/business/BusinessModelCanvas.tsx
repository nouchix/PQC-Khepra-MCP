import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { 
  Users, 
  DollarSign, 
  Target, 
  Building, 
  Zap, 
  Heart, 
  Phone, 
  Truck,
  PieChart
} from 'lucide-react';

export const BusinessModelCanvas = () => {
  const canvasData = {
    keyPartners: [
      'System Integrators (Accenture, Deloitte)',
      'Technology Vendors (Microsoft, AWS)',
      'Compliance Consultants',
      'Government Partners (DoD, DHS)',
      'Academic Institutions',
      'Cybersecurity VARs'
    ],
    keyActivities: [
      'KHEPRA Protocol Development',
      'AI/ML Model Training',
      'Compliance Automation',
      'Customer Success Management',
      'Security Research & Development',
      'Partnership Development'
    ],
    keyResources: [
      'KHEPRA IP & Patents',
      'AI/ML Engineering Team',
      'Cultural Threat Intelligence DB',
      'Government Security Clearances',
      'Cloud Infrastructure',
      'Compliance Expertise'
    ],
    valuePropositions: [
      'Automated CMMC Compliance (80% time reduction)',
      'KHEPRA Quantum-Resilient Security',
      'Cultural Threat Intelligence',
      'Zero Trust Architecture',
      'AI-Powered Incident Response',
      'One-Click Audit Readiness'
    ],
    customerRelationships: [
      'Dedicated Account Management',
      'Customer Success Programs',
      'Community Forums',
      'Training & Certification',
      '24/7 Technical Support',
      'Strategic Advisory Services'
    ],
    channels: [
      'Direct Sales Team',
      'Partner Channel Program',
      'Digital Marketing',
      'Industry Conferences',
      'Government Contracting',
      'Thought Leadership Content'
    ],
    customerSegments: [
      'Defense Contractors (Prime/Sub)',
      'Fortune 1000 Enterprises',
      'Managed Security Providers',
      'Critical Infrastructure',
      'Government Agencies',
      'Healthcare Organizations'
    ],
    costStructure: [
      'R&D and Engineering (40%)',
      'Sales & Marketing (25%)',
      'Cloud Infrastructure (15%)',
      'Personnel & Operations (20%)'
    ],
    revenueStreams: [
      'SaaS Subscriptions (70%)',
      'Professional Services (20%)',
      'Usage-Based Pricing (10%)'
    ]
  };

  const revenueDetails = {
    saas: {
      starter: '$5K/month',
      professional: '$25K/month',
      enterprise: '$100K/month'
    },
    services: {
      implementation: '$50K-500K',
      training: '$10K-50K',
      consulting: '$200-500/hour'
    },
    usage: {
      api_calls: '$0.01/call',
      storage: '$0.10/GB',
      advanced_ai: '$1.00/analysis'
    }
  };

  return (
    <div className="space-y-6">
      {/* Business Model Canvas Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-5 gap-4">
        {/* Row 1: Key Partners, Key Activities, Value Propositions, Customer Relationships, Customer Segments */}
        <Card className="lg:row-span-2">
          <CardHeader>
            <CardTitle className="text-sm flex items-center gap-2">
              <Building className="h-4 w-4" />
              Key Partners
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-2">
            {canvasData.keyPartners.map((partner, index) => (
              <Badge key={index} variant="outline" className="text-xs block text-center">
                {partner}
              </Badge>
            ))}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="text-sm flex items-center gap-2">
              <Zap className="h-4 w-4" />
              Key Activities
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-2">
            {canvasData.keyActivities.map((activity, index) => (
              <Badge key={index} variant="secondary" className="text-xs block text-center">
                {activity}
              </Badge>
            ))}
          </CardContent>
        </Card>

        <Card className="lg:row-span-2 border-2 border-primary">
          <CardHeader>
            <CardTitle className="text-sm flex items-center gap-2">
              <Target className="h-4 w-4" />
              Value Propositions
            </CardTitle>
            <CardDescription>Core value we deliver</CardDescription>
          </CardHeader>
          <CardContent className="space-y-2">
            {canvasData.valuePropositions.map((value, index) => (
              <Badge key={index} variant="default" className="text-xs block text-center">
                {value}
              </Badge>
            ))}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="text-sm flex items-center gap-2">
              <Heart className="h-4 w-4" />
              Customer Relationships
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-2">
            {canvasData.customerRelationships.map((relationship, index) => (
              <Badge key={index} variant="secondary" className="text-xs block text-center">
                {relationship}
              </Badge>
            ))}
          </CardContent>
        </Card>

        <Card className="lg:row-span-2">
          <CardHeader>
            <CardTitle className="text-sm flex items-center gap-2">
              <Users className="h-4 w-4" />
              Customer Segments
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-2">
            {canvasData.customerSegments.map((segment, index) => (
              <Badge key={index} variant="outline" className="text-xs block text-center">
                {segment}
              </Badge>
            ))}
          </CardContent>
        </Card>

        {/* Row 2: Key Resources, Channels */}
        <Card>
          <CardHeader>
            <CardTitle className="text-sm flex items-center gap-2">
              <Truck className="h-4 w-4" />
              Key Resources
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-2">
            {canvasData.keyResources.map((resource, index) => (
              <Badge key={index} variant="secondary" className="text-xs block text-center">
                {resource}
              </Badge>
            ))}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="text-sm flex items-center gap-2">
              <Phone className="h-4 w-4" />
              Channels
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-2">
            {canvasData.channels.map((channel, index) => (
              <Badge key={index} variant="secondary" className="text-xs block text-center">
                {channel}
              </Badge>
            ))}
          </CardContent>
        </Card>
      </div>

      {/* Row 3: Cost Structure and Revenue Streams */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <Card>
          <CardHeader>
            <CardTitle className="text-sm flex items-center gap-2">
              <PieChart className="h-4 w-4" />
              Cost Structure
            </CardTitle>
            <CardDescription>Major cost categories</CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            {canvasData.costStructure.map((cost, index) => (
              <div key={index} className="flex items-center justify-between">
                <span className="text-sm">{cost.split(' (')[0]}</span>
                <Badge variant="destructive">{cost.split(' (')[1]?.replaceAll(')', '') || ''}</Badge>
              </div>
            ))}
            <div className="mt-4 p-3 bg-muted rounded-lg">
              <p className="text-xs text-muted-foreground">
                Cost-focused on R&D to maintain competitive advantage and build defensible IP moat
              </p>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="text-sm flex items-center gap-2">
              <DollarSign className="h-4 w-4" />
              Revenue Streams
            </CardTitle>
            <CardDescription>How we generate revenue</CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            {canvasData.revenueStreams.map((revenue, index) => (
              <div key={index} className="flex items-center justify-between">
                <span className="text-sm">{revenue.split(' (')[0]}</span>
                <Badge variant="default">{revenue.split(' (')[1]?.replaceAll(')', '') || ''}</Badge>
              </div>
            ))}
            
            <div className="mt-4 space-y-3">
              <div className="p-3 bg-muted rounded-lg">
                <h4 className="font-medium text-sm mb-2">SaaS Pricing Tiers</h4>
                <div className="space-y-1 text-xs">
                  <div className="flex justify-between">
                    <span>Starter:</span>
                    <span>{revenueDetails.saas.starter}</span>
                  </div>
                  <div className="flex justify-between">
                    <span>Professional:</span>
                    <span>{revenueDetails.saas.professional}</span>
                  </div>
                  <div className="flex justify-between">
                    <span>Enterprise:</span>
                    <span>{revenueDetails.saas.enterprise}</span>
                  </div>
                </div>
              </div>
              
              <div className="p-3 bg-muted rounded-lg">
                <h4 className="font-medium text-sm mb-2">Professional Services</h4>
                <div className="space-y-1 text-xs">
                  <div className="flex justify-between">
                    <span>Implementation:</span>
                    <span>{revenueDetails.services.implementation}</span>
                  </div>
                  <div className="flex justify-between">
                    <span>Training:</span>
                    <span>{revenueDetails.services.training}</span>
                  </div>
                  <div className="flex justify-between">
                    <span>Consulting:</span>
                    <span>{revenueDetails.services.consulting}</span>
                  </div>
                </div>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Action Buttons */}
      <div className="flex gap-4">
        <Button variant="outline">
          Export Canvas
        </Button>
        <Button variant="outline">
          Share with Team
        </Button>
        <Button>
          Update Model
        </Button>
      </div>
    </div>
  );
};