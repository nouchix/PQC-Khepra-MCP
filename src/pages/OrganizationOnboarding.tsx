import { PageLayout } from '@/components/PageLayout';
import { OnboardingWizard } from '@/components/onboarding/OnboardingWizard';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Loader2 } from 'lucide-react';
import { useOrganization } from '@/hooks/useOrganization';

const OrganizationOnboardingPage = () => {
  const { currentOrganization, loading } = useOrganization();

  const renderContent = () => {
    if (loading) {
      return (
        <Card>
          <CardContent className="flex items-center justify-center min-h-[400px]">
            <Loader2 className="h-8 w-8 animate-spin text-primary" />
          </CardContent>
        </Card>
      );
    }

    if (!currentOrganization) {
      return (
        <Card>
          <CardHeader>
            <CardTitle>Organization Required</CardTitle>
            <CardDescription>
              You need to be part of an organization to access onboarding.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <p className="text-sm text-muted-foreground">
              Please create or join an organization to continue.
            </p>
          </CardContent>
        </Card>
      );
    }

    return <OnboardingWizard organizationId={currentOrganization.organization_id} />;
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

        {renderContent()}
      </div>
    </PageLayout>
  );
};

export default OrganizationOnboardingPage;
