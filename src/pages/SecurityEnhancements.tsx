import ThreatDetectionCenter from '@/components/threat/ThreatDetectionCenter';
import ZeroTrustPolicyManager from '@/components/security/ZeroTrustPolicyManager';
import ZeroTrustDeviceAssessment from '@/components/security/ZeroTrustDeviceAssessment';
import ZeroTrustNetworkSegmentation from '@/components/security/ZeroTrustNetworkSegmentation';
import { SecurityCompliancePanel } from '@/components/security/SecurityCompliancePanel';
import { DeviceTrustManager } from '@/components/security/DeviceTrustManager';
import { PageLayout } from '@/components/PageLayout';

const SecurityEnhancements = () => {
  return (
    <PageLayout>
      <header className="mb-6">
        <h1 className="text-2xl font-bold">Phase 2: Security Enhancements</h1>
        <p className="text-sm text-muted-foreground">Threat detection integrations and Zero Trust continuous validation.</p>
      </header>
      <main className="space-y-8">
        <section aria-labelledby="security-compliance">
          <h2 id="security-compliance" className="sr-only">Security Compliance Panel</h2>
          <SecurityCompliancePanel />
        </section>
        <section aria-labelledby="device-trust">
          <h2 id="device-trust" className="sr-only">Device Trust Manager</h2>
          <DeviceTrustManager />
        </section>
        <section aria-labelledby="threat-detection">
          <h2 id="threat-detection" className="sr-only">Threat Detection Center</h2>
          <ThreatDetectionCenter />
        </section>
        <section aria-labelledby="zt-device">
          <h2 id="zt-device" className="sr-only">Zero Trust Device Assessment</h2>
          <ZeroTrustDeviceAssessment />
        </section>
        <section aria-labelledby="zt-net">
          <h2 id="zt-net" className="sr-only">Zero Trust Network Segmentation</h2>
          <ZeroTrustNetworkSegmentation />
        </section>
        <section aria-labelledby="zt-policy">
          <h2 id="zt-policy" className="sr-only">Zero Trust Policy Manager</h2>
          <ZeroTrustPolicyManager />
        </section>
      </main>
    </PageLayout>
  );
};

export default SecurityEnhancements;
