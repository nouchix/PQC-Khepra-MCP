
import { PageLayout } from '@/components/PageLayout';
import SaaSTestingChecklist from '@/components/testing/SaaSTestingChecklist';

const SaaSTestingDashboard = () => {
  return (
    <PageLayout 
      title="SaaS Testing Framework"
      breadcrumbs={[
        { label: 'Home', path: '/' },
        { label: 'Testing', path: '/testing' }
      ]}
    >
      <SaaSTestingChecklist />
    </PageLayout>
  );
};

export default SaaSTestingDashboard;