
import { PageLayout } from '@/components/PageLayout';
import { AgenticComplianceArchitect } from '@/components/compliance/AgenticComplianceArchitect';

const SouHimBouAI: React.FC = () => {
  return (
    <PageLayout>
      <div className="container mx-auto py-6">
        <AgenticComplianceArchitect />
      </div>
    </PageLayout>
  );
};

export default SouHimBouAI;