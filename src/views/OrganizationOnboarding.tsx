import { PageLayout } from '@/components/PageLayout';
import { OnboardingWizard } from '@/components/onboarding/OnboardingWizard';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { useEffect, useState } from 'react';
import { supabase } from '@/integrations/supabase/client';
import { Loader2 } from 'lucide-react';

const OrganizationOnboardingPage = () => {
  const [organizationId, setOrganizationId] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchUserOrganization();
  }, []);

  const fetchUserOrganization = async () => {
    try {
      const { data: { user } } = await supabase.auth.getUser();
      if (!user) return;

      const { data: userOrg } = await supabase
        .from('user_organizations')
        .select('organization_id')
        .eq('user_id', user.id)
        .single();

      if (userOrg) {
        setOrganizationId(userOrg.organization_id);
      }
    } catch (error) {
      console.error('Error fetching organization:', error);
    } finally {
      setLoading(false);
    }
  };

  return (
    <PageLayout>
      <div className="container max-w-6xl mx-auto py-8 space-y-8">
        <div className="space-y-2">
          <h1 className="text-3xl font-bold tracking-tight">STIG Compliance Onboarding</h1>
          <p className="text-muted-foreground">
            5-phase enterprise onboarding with Ansible, OpenSCAP, and continuous monitoring
          </p>
        </div>

        {loading ? (
          <Card>
            <CardContent className="flex items-center justify-center min-h-[400px]">
              <Loader2 className="h-8 w-8 animate-spin text-primary" />
            </CardContent>
          </Card>
        ) : !organizationId ? (
          <Card>
            <CardHeader>
              <CardTitle>Organization Required</CardTitle>
              <CardDescription>
                You need to be part of an organization to access onboarding
              </CardDescription>
            </CardHeader>
          </Card>
        ) : (
          <OnboardingWizard organizationId={organizationId} />
        )}
      </div>
    </PageLayout>
  );
};

export default OrganizationOnboardingPage;
