import { useState } from 'react';
import { useNavigate } from '@/lib/router-compat';
import { supabase } from '@/integrations/supabase/client';
import { useAuth } from '@/hooks/useAuth';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Badge } from '@/components/ui/badge';
import { Building2, Users, Shield, CheckCircle, ArrowRight, DollarSign } from 'lucide-react';
import { useToast } from '@/hooks/use-toast';
import { UsageBillingSetup } from './UsageBillingSetup';
import { useResourceTracker } from '@/hooks/useResourceTracker';

interface OrganizationData {
  name: string;
  slug: string;
  domain: string;
  description: string;
  industry: string;
  size: string;
  securityRequirements: string[];
}

export const OrganizationSetup = () => {
  const { user } = useAuth();
  const { toast } = useToast();
  const navigate = useNavigate();
  const { trackResource } = useResourceTracker();
  
  const [step, setStep] = useState(1);
  const [loading, setLoading] = useState(false);
  const [createdOrgId, setCreatedOrgId] = useState<string | null>(null);
  const [orgData, setOrgData] = useState<OrganizationData>({
    name: '',
    slug: '',
    domain: '',
    description: '',
    industry: '',
    size: '',
    securityRequirements: []
  });

  const industries = [
    'Defense & Military',
    'Government',
    'Healthcare',
    'Financial Services',
    'Technology',
    'Manufacturing',
    'Energy & Utilities',
    'Transportation',
    'Education',
    'Other'
  ];

  const organizationSizes = [
    '1-10 employees',
    '11-50 employees',
    '51-200 employees',
    '201-1000 employees',
    '1000+ employees'
  ];

  const securityRequirements = [
    'SOC 2 Compliance',
    'FISMA Compliance',
    'NIST Framework',
    'ISO 27001',
    'HIPAA Compliance',
    'PCI DSS',
    'GDPR Compliance',
    'Custom Security Framework'
  ];

  const generateSlug = (name: string) => {
    return name
      .toLowerCase()
      .replace(/[^a-z0-9\s-]/g, '')
      .replace(/\s+/g, '-')
      .replace(/-+/g, '-')
      .trim();
  };

  const handleNameChange = (name: string) => {
    setOrgData(prev => ({
      ...prev,
      name,
      slug: generateSlug(name)
    }));
  };

  const toggleSecurityRequirement = (requirement: string) => {
    setOrgData(prev => ({
      ...prev,
      securityRequirements: prev.securityRequirements.includes(requirement)
        ? prev.securityRequirements.filter(r => r !== requirement)
        : [...prev.securityRequirements, requirement]
    }));
  };

  const validateStep = (stepNumber: number): boolean => {
    switch (stepNumber) {
      case 1:
        return orgData.name.length >= 2 && orgData.slug.length >= 2;
      case 2:
        return orgData.industry !== '' && orgData.size !== '';
      case 3:
        return orgData.securityRequirements.length > 0;
      case 4:
        return true; // Billing setup is optional
      default:
        return true;
    }
  };

  const createOrganization = async () => {
    if (!user) return;

    setLoading(true);
    try {
      // Check if slug is already taken
      const { data: existingOrg } = await supabase
        .from('organizations')
        .select('id')
        .eq('slug', orgData.slug)
        .single();

      if (existingOrg) {
        toast({
          title: "Organization Slug Taken",
          description: "Please choose a different organization name or slug.",
          variant: "destructive"
        });
        setLoading(false);
        return;
      }

      // Create organization
      const { data: organization, error: orgError } = await supabase
        .from('organizations')
        .insert({
          name: orgData.name,
          slug: orgData.slug,
          domain: orgData.domain || null,
          primary_contact_email: '',
          settings: {
            description: orgData.description,
            industry: orgData.industry,
            size: orgData.size,
            securityRequirements: orgData.securityRequirements,
            setupCompleted: true,
            createdAt: new Date().toISOString()
          }
        } as any)
        .select()
        .single();

      if (orgError) throw orgError;

      // Add user as owner to the organization
      const { error: memberError } = await supabase
        .from('user_organizations')
        .insert({
          user_id: user.id,
          organization_id: organization.id,
          role: 'owner',
          joined_at: new Date().toISOString()
        });

      if (memberError) throw memberError;

      // Create initial compliance framework
      if (orgData.securityRequirements.length > 0) {
        await supabase
          .from('compliance_frameworks')
          .insert({
            organization_id: organization.id,
            name: `${orgData.name} Security Framework`,
            category: 'organizational',
            version: '1.0',
            description: `Initial security framework for ${orgData.name}`,
            metadata: {
              requirements: orgData.securityRequirements,
              industry: orgData.industry
            }
          });
      }

      // Log the organization creation
      await supabase.from('audit_logs').insert({
        user_id: user.id,
        action: 'organization_created',
        resource_type: 'organization',
        resource_id: organization.id,
        details: {
          organizationName: orgData.name,
          industry: orgData.industry,
          timestamp: new Date().toISOString()
        }
      });

      // Track organization creation as a billable compute operation (1 hour for setup)
      await trackResource('compute', 1, 'cpu_hours', 'organization_setup', {
        organization_name: orgData.name,
        industry: orgData.industry,
        size: orgData.size,
        security_requirements_count: orgData.securityRequirements.length
      });

      setCreatedOrgId(organization.id);
      
      toast({
        title: "Organization Created",
        description: `${orgData.name} has been successfully created. Now let's set up your billing.`,
        variant: "default"
      });

      // Move to billing setup step
      setStep(4);
    } catch (error: any) {
      console.error('Error creating organization:', error);
      toast({
        title: "Setup Failed",
        description: error.message || "Failed to create organization. Please try again.",
        variant: "destructive"
      });
    } finally {
      setLoading(false);
    }
  };

  const renderStep = () => {
    switch (step) {
      case 1:
        return (
          <div className="space-y-4">
            <div className="text-center mb-6">
              <Building2 className="h-12 w-12 text-primary mx-auto mb-4" />
              <h3 className="text-xl font-semibold">Organization Details</h3>
              <p className="text-muted-foreground">Let's start with the basics</p>
            </div>

            <div className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="orgName">Organization Name *</Label>
                <Input
                  id="orgName"
                  value={orgData.name}
                  onChange={(e) => handleNameChange(e.target.value)}
                  placeholder="Enter your organization name"
                  className="w-full"
                />
              </div>

              <div className="space-y-2">
                <Label htmlFor="orgSlug">Organization Slug *</Label>
                <Input
                  id="orgSlug"
                  value={orgData.slug}
                  onChange={(e) => setOrgData(prev => ({ ...prev, slug: e.target.value }))}
                  placeholder="organization-slug"
                  className="w-full font-mono"
                />
                <p className="text-xs text-muted-foreground">
                  This will be used in URLs and must be unique
                </p>
              </div>

              <div className="space-y-2">
                <Label htmlFor="orgDomain">Domain (Optional)</Label>
                <Input
                  id="orgDomain"
                  value={orgData.domain}
                  onChange={(e) => setOrgData(prev => ({ ...prev, domain: e.target.value }))}
                  placeholder="yourcompany.com"
                  className="w-full"
                />
              </div>

              <div className="space-y-2">
                <Label htmlFor="orgDescription">Description</Label>
                <Textarea
                  id="orgDescription"
                  value={orgData.description}
                  onChange={(e) => setOrgData(prev => ({ ...prev, description: e.target.value }))}
                  placeholder="Brief description of your organization"
                  className="w-full"
                  rows={3}
                />
              </div>
            </div>
          </div>
        );

      case 2:
        return (
          <div className="space-y-4">
            <div className="text-center mb-6">
              <Users className="h-12 w-12 text-primary mx-auto mb-4" />
              <h3 className="text-xl font-semibold">Organization Profile</h3>
              <p className="text-muted-foreground">Help us customize your experience</p>
            </div>

            <div className="space-y-4">
              <div className="space-y-2">
                <Label>Industry *</Label>
                <Select value={orgData.industry} onValueChange={(value) => setOrgData(prev => ({ ...prev, industry: value }))}>
                  <SelectTrigger>
                    <SelectValue placeholder="Select your industry" />
                  </SelectTrigger>
                  <SelectContent>
                    {industries.map((industry) => (
                      <SelectItem key={industry} value={industry}>
                        {industry}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>

              <div className="space-y-2">
                <Label>Organization Size *</Label>
                <Select value={orgData.size} onValueChange={(value) => setOrgData(prev => ({ ...prev, size: value }))}>
                  <SelectTrigger>
                    <SelectValue placeholder="Select organization size" />
                  </SelectTrigger>
                  <SelectContent>
                    {organizationSizes.map((size) => (
                      <SelectItem key={size} value={size}>
                        {size}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
            </div>
          </div>
        );

      case 3:
        return (
          <div className="space-y-4">
            <div className="text-center mb-6">
              <Shield className="h-12 w-12 text-primary mx-auto mb-4" />
              <h3 className="text-xl font-semibold">Security Requirements</h3>
              <p className="text-muted-foreground">Select applicable compliance frameworks</p>
            </div>

            <div className="space-y-4">
              <p className="text-sm text-muted-foreground">
                Choose the security frameworks and compliance requirements that apply to your organization:
              </p>
              
              <div className="grid grid-cols-1 gap-2">
                {securityRequirements.map((requirement) => (
                  <div
                    key={requirement}
                    onClick={() => toggleSecurityRequirement(requirement)}
                    className={`p-3 border rounded-lg cursor-pointer transition-colors ${
                      orgData.securityRequirements.includes(requirement)
                        ? 'border-primary bg-primary/5'
                        : 'border-border hover:border-primary/50'
                    }`}
                  >
                    <div className="flex items-center justify-between">
                      <span className="text-sm">{requirement}</span>
                      {orgData.securityRequirements.includes(requirement) && (
                        <CheckCircle className="h-4 w-4 text-primary" />
                      )}
                    </div>
                  </div>
                ))}
              </div>

              {orgData.securityRequirements.length > 0 && (
                <div className="mt-4">
                  <p className="text-sm font-medium mb-2">Selected Requirements:</p>
                  <div className="flex flex-wrap gap-2">
                    {orgData.securityRequirements.map((req) => (
                      <Badge key={req} variant="secondary">
                        {req}
                      </Badge>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </div>
        );

      case 4:
        if (!createdOrgId) return null;
        return (
          <UsageBillingSetup
            organizationId={createdOrgId}
            onComplete={() => {
              toast({
                title: "Setup Complete!",
                description: "Your organization and billing are now configured.",
              });
              navigate('/');
            }}
            onSkip={() => {
              toast({
                title: "Setup Complete!",
                description: "You can configure billing anytime from your dashboard.",
              });
              navigate('/');
            }}
          />
        );

      default:
        return null;
    }
  };

  return (
    <div className="min-h-screen bg-gradient-dark flex items-center justify-center p-6">
      <Card className="w-full max-w-2xl card-cyber">
        <CardHeader>
          <CardTitle className="text-center">
            <div className="flex items-center justify-center space-x-2 mb-2">
              <img 
                src="/lovable-uploads/94f06ba5-2c93-4be0-a03f-e3fff4157ca6.png" 
                alt="SouHimBou AI Logo" 
                className="h-8 w-auto"
              />
              <span className="text-2xl font-bold bg-gradient-cyber bg-clip-text text-transparent">
                SouHimBou AI
              </span>
            </div>
            <div className="text-lg">Organization Setup</div>
          </CardTitle>
          <CardDescription className="text-center">
            Step {step} of 4 - {
              step === 1 ? 'Organization Details' : 
              step === 2 ? 'Organization Profile' : 
              step === 3 ? 'Security Requirements' :
              'Usage & Billing Setup'
            }
          </CardDescription>
        </CardHeader>
        
        <CardContent>
            <div className="mb-6">
              <div className="flex items-center justify-between mb-2">
                {[1, 2, 3, 4].map((stepNumber) => (
                  <div
                    key={stepNumber}
                    className={`flex items-center justify-center w-8 h-8 rounded-full text-sm font-medium ${
                      stepNumber <= step
                        ? 'bg-primary text-primary-foreground'
                        : 'bg-muted text-muted-foreground'
                    }`}
                  >
                    {stepNumber < step ? <CheckCircle className="h-4 w-4" /> : 
                     stepNumber === 4 ? <DollarSign className="h-4 w-4" /> : stepNumber}
                  </div>
                ))}
              </div>
              <div className="w-full bg-muted rounded-full h-2">
                <div
                  className="bg-primary h-2 rounded-full transition-all duration-300"
                  style={{ width: `${(step / 4) * 100}%` }}
                />
              </div>
            </div>

          {renderStep()}

          <div className="flex justify-between mt-8">
            {step === 4 ? null : (
              <>
                <Button
                  variant="outline"
                  onClick={() => setStep(step - 1)}
                  disabled={step === 1}
                >
                  Previous
                </Button>
                
                {step < 3 ? (
                  <Button
                    onClick={() => setStep(step + 1)}
                    disabled={!validateStep(step)}
                  >
                    Next
                    <ArrowRight className="h-4 w-4 ml-2" />
                  </Button>
                ) : (
                  <Button
                    onClick={createOrganization}
                    disabled={!validateStep(step) || loading}
                    className="min-w-[120px]"
                  >
                    {loading ? 'Creating...' : 'Create & Configure Billing'}
                  </Button>
                )}
              </>
            )}
          </div>
        </CardContent>
      </Card>
    </div>
  );
};

export default OrganizationSetup;