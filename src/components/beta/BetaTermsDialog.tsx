import { useState } from 'react';
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription } from '@/components/ui/dialog';
import { Button } from '@/components/ui/button';
import { Checkbox } from '@/components/ui/checkbox';
import { AlertTriangle, Shield } from 'lucide-react';
import { supabase } from '@/integrations/supabase/client';
import { useToast } from '@/hooks/use-toast';

interface BetaTermsDialogProps {
  open: boolean;
  enrollmentId: string;
  onAccept: () => void;
}

export const BetaTermsDialog = ({ open, enrollmentId, onAccept }: BetaTermsDialogProps) => {
  const [betaTermsChecked, setBetaTermsChecked] = useState(false);
  const [cuiAcknowledgmentChecked, setCuiAcknowledgmentChecked] = useState(false);
  const [govCloudChecked, setGovCloudChecked] = useState(false);
  const { toast } = useToast();
  const [loading, setLoading] = useState(false);

  const handleAccept = async () => {
    if (!betaTermsChecked || !cuiAcknowledgmentChecked || !govCloudChecked) {
      toast({
        title: "All acknowledgments required",
        description: "Please check all boxes to proceed",
        variant: "destructive"
      });
      return;
    }

    setLoading(true);
    try {
      const { error } = await supabase
        .from('beta_enrollments')
        .update({
          beta_terms_accepted: true,
          cui_acknowledgment_signed: true,
          updated_at: new Date().toISOString()
        })
        .eq('id', enrollmentId);

      if (error) throw error;

      toast({
        title: "Beta access activated",
        description: "You can now access the beta environment",
      });

      onAccept();
    } catch (error) {
      console.error('Error accepting terms:', error);
      toast({
        title: "Error",
        description: "Failed to activate beta access",
        variant: "destructive"
      });
    } finally {
      setLoading(false);
    }
  };

  return (
    <Dialog open={open}>
      <DialogContent className="max-w-3xl max-h-[80vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <AlertTriangle className="h-6 w-6 text-yellow-500" />
            Beta Environment Terms & Conditions
          </DialogTitle>
          <DialogDescription>
            Please read and acknowledge the following before accessing the beta environment
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-6 py-4">
          {/* CUI Warning */}
          <div className="bg-yellow-500/10 border border-yellow-500/30 p-4 rounded-lg">
            <div className="flex items-start gap-3">
              <Shield className="h-5 w-5 text-yellow-500 mt-0.5" />
              <div>
                <h3 className="font-semibold text-yellow-500 mb-2">⚠️ CRITICAL: NO CUI ALLOWED</h3>
                <p className="text-sm text-muted-foreground">
                  This beta environment is <strong>NOT approved for Controlled Unclassified Information (CUI)</strong>. 
                  Do not upload, enter, or process any data classified as CUI, FOUO, or any other controlled information.
                </p>
              </div>
            </div>
          </div>

          {/* GovCloud Disclosure */}
          <div className="bg-blue-500/10 border border-blue-500/30 p-4 rounded-lg">
            <h3 className="font-semibold text-blue-400 mb-2">🏛️ Production Environment</h3>
            <p className="text-sm text-muted-foreground">
              Production CUI-ready deployment will be hosted in <strong>AWS GovCloud (US)</strong> and is 
              targeted for <strong>Q2 2025</strong>. This beta environment is for UI/UX validation and 
              non-CUI testing only.
            </p>
          </div>

          {/* Beta Terms */}
          <div className="space-y-3">
            <h3 className="font-semibold">Beta Program Terms</h3>
            <ul className="list-disc list-inside space-y-2 text-sm text-muted-foreground">
              <li>Beta data retention: 90 days after enrollment period ends</li>
              <li>Features may change without notice during beta</li>
              <li>No SLA guarantees for uptime or data persistence</li>
              <li>Automated CUI scanning will block suspicious content</li>
              <li>Export your evidence bundles regularly for backup</li>
              <li>Production migration requires new AWS GovCloud contract</li>
            </ul>
          </div>

          {/* Checkboxes */}
          <div className="space-y-4 pt-4 border-t">
            <div className="flex items-start space-x-3">
              <Checkbox
                id="beta-terms"
                checked={betaTermsChecked}
                onCheckedChange={(checked) => setBetaTermsChecked(checked as boolean)}
              />
              <label htmlFor="beta-terms" className="text-sm leading-tight cursor-pointer">
                I have read and agree to the beta program terms and conditions
              </label>
            </div>

            <div className="flex items-start space-x-3">
              <Checkbox
                id="cui-ack"
                checked={cuiAcknowledgmentChecked}
                onCheckedChange={(checked) => setCuiAcknowledgmentChecked(checked as boolean)}
              />
              <label htmlFor="cui-ack" className="text-sm leading-tight cursor-pointer">
                <strong>I acknowledge that this environment does NOT support CUI workloads</strong> and 
                I will not upload any controlled, classified, or sensitive government information
              </label>
            </div>

            <div className="flex items-start space-x-3">
              <Checkbox
                id="govcloud-ack"
                checked={govCloudChecked}
                onCheckedChange={(checked) => setGovCloudChecked(checked as boolean)}
              />
              <label htmlFor="govcloud-ack" className="text-sm leading-tight cursor-pointer">
                I understand that production CUI handling requires AWS GovCloud deployment (Q2 2025) 
                and a separate production contract
              </label>
            </div>
          </div>

          <Button
            onClick={handleAccept}
            disabled={!betaTermsChecked || !cuiAcknowledgmentChecked || !govCloudChecked || loading}
            className="w-full"
          >
            {loading ? 'Activating...' : 'Accept & Activate Beta Access'}
          </Button>
        </div>
      </DialogContent>
    </Dialog>
  );
};