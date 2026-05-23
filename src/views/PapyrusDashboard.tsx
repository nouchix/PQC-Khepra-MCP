
import { PapyrusChecklist } from '@/components/papyrus/PapyrusChecklist';
import { BrowserNavigation } from '@/components/ui/browser-navigation';
import { FloatingAIAssistant } from '@/components/FloatingAIAssistant';

const PapyrusDashboard = () => {
  return (
    <div className="min-h-screen bg-background">
      {/* Browser-like Navigation */}
      <BrowserNavigation
        tabs={[
          { id: 'guidance', title: 'Wisdom Guidance', path: '/papyrus', isActive: true },
          { id: 'progress', title: 'Progress Tracking', path: '/papyrus' },
          { id: 'insights', title: 'AI Insights', path: '/papyrus' },
          { id: 'cultural', title: 'Cultural Intelligence', path: '/papyrus' }
        ]}
        title="Papyrus Wisdom Dashboard"
        subtitle="AI-Powered Personalized Security & Optimization Guidance"
      />
      
      <div className="container mx-auto p-6">
        <PapyrusChecklist />
      </div>
      
      <FloatingAIAssistant />
    </div>
  );
};

export default PapyrusDashboard;