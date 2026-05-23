
import { KhepraDashboard } from '@/components/khepra/KhepraDashboard';
import { FloatingAIAssistant } from '@/components/FloatingAIAssistant';

const KhepraProtocol = () => {
  return (
    <div className="relative">
      <KhepraDashboard />
      <FloatingAIAssistant />
    </div>
  );
};

export default KhepraProtocol;