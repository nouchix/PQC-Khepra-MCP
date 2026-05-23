import { useState } from 'react';
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { Card, CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Checkbox } from '@/components/ui/checkbox';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Badge } from '@/components/ui/badge';
import { AlertTriangle, Shield, FileText, Scale, Users, Globe, CheckCircle, ArrowRight } from 'lucide-react';
import { useUserAgreements } from '@/hooks/useUserAgreements';
import { useToast } from '@/hooks/use-toast';

interface TermsAcceptanceProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onAccepted: () => void;
}

export const TermsAcceptance: React.FC<TermsAcceptanceProps> = ({
  open,
  onOpenChange,
  onAccepted
}) => {
  const { acceptAllAgreements } = useUserAgreements();
  const { toast } = useToast();
  const [acceptedTerms, setAcceptedTerms] = useState({
    tosAgree: false,
    privacyAgree: false,
    saasAgree: false,
    betaAgree: false,
    dodCompliance: false,
    liabilityWaiver: false,
    exportControl: false
  });
  const [isSubmitting, setIsSubmitting] = useState(false);

  const allTermsAccepted = Object.values(acceptedTerms).every(Boolean);

  const handleTermChange = (term: keyof typeof acceptedTerms, checked: boolean) => {
    setAcceptedTerms(prev => ({ ...prev, [term]: checked }));
  };

  const handleAcceptAll = () => {
    setAcceptedTerms({
      tosAgree: true,
      privacyAgree: true,
      saasAgree: true,
      betaAgree: true,
      dodCompliance: true,
      liabilityWaiver: true,
      exportControl: true
    });
  };

  const handleSubmit = async () => {
    if (!allTermsAccepted) {
      toast({
        title: "Incomplete Acceptance",
        description: "Please accept all terms and conditions to continue.",
        variant: "destructive"
      });
      return;
    }

    setIsSubmitting(true);
    try {
      console.log('Submitting agreements...', acceptedTerms);
      const success = await acceptAllAgreements(acceptedTerms);
      if (success) {
        // Delay slightly to ensure state is propagated
        setTimeout(() => {
          onAccepted();
          onOpenChange(false);
          toast({
            title: "Access Granted",
            description: "Legal agreements successfully processed. Welcome to DoD Operations.",
          });
        }, 500);
      } else {
        toast({
          title: "Submission Failed",
          description: "Could not save agreements. Please try again or contact support.",
          variant: "destructive"
        });
      }
    } catch (error) {
      console.error('Error submitting agreements:', error);
      toast({
        title: "System Error",
        description: "An unexpected error occurred during legal processing.",
        variant: "destructive"
      });
    } finally {
      setIsSubmitting(false);
    }
  };

  const termsData = [
    {
      key: 'tosAgree' as keyof typeof acceptedTerms,
      title: 'Khepra Master License Agreement (v3.0)',
      icon: FileText,
      description: 'Commercial license grant, restrictions, and reservation of rights. Includes Ra-Standard compliance clauses.',
      classification: 'Required',
      type: 'Standard'
    },
    {
      key: 'privacyAgree' as keyof typeof acceptedTerms,
      title: 'Privacy Policy & Data Sovereignity',
      icon: Shield,
      description: 'Data collection, processing, and protection practices. Telemetry beacon and license validation.',
      classification: 'Required',
      type: 'Privacy'
    },
    {
      key: 'saasAgree' as keyof typeof acceptedTerms,
      title: 'SaaS Terms & Authorized Use',
      icon: Globe,
      description: 'Cloud service delivery for Khepra-Edge, Khepra-Hybrid, and Khepra-Sovereign deployments.',
      classification: 'Required',
      type: 'Service'
    },
    {
      key: 'betaAgree' as keyof typeof acceptedTerms,
      title: 'Beta Testing Agreement (Early Access)',
      icon: Users,
      description: 'Pre-release software testing terms. Software provided "AS IS" with no warranty of quantum-proof perpetuity.',
      classification: 'Required',
      type: 'Beta'
    },
    {
      key: 'dodCompliance' as keyof typeof acceptedTerms,
      title: 'U.S. Government Rights (DFARS Compliance)',
      icon: Shield,
      description: 'Commercial Computer Software with RESTRICTED RIGHTS per DFARS 252.227-7014.',
      classification: 'Critical',
      type: 'Security'
    },
    {
      key: 'liabilityWaiver' as keyof typeof acceptedTerms,
      title: 'Confidentiality & Trade Secrets',
      icon: Scale,
      description: 'Acknowledgment of proprietary AdinKhepra-PQC Lattice structures as Trade Secrets.',
      classification: 'Required',
      type: 'Legal'
    },
    {
      key: 'exportControl' as keyof typeof acceptedTerms,
      title: 'Export Control Compliance (ECCN 5D992)',
      icon: AlertTriangle,
      description: 'Subject to EAR. No export to nuclear/chemical/biological weapons countries.',
      classification: 'Critical',
      type: 'Regulatory'
    }
  ];

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-4xl max-h-[95vh] bg-background border-primary/20 shadow-2xl overflow-hidden flex flex-col p-0">
        <DialogHeader className="p-6 border-b bg-muted/30">
          <DialogTitle className="flex items-center space-x-2 text-2xl">
            <Scale className="h-6 w-6 text-primary" />
            <span>Legal Agreement Acceptance</span>
          </DialogTitle>
          <DialogDescription>
            Acceptance of all legal agreements is required to access SouHimBou AI DoD operations.
          </DialogDescription>
        </DialogHeader>

        <ScrollArea className="flex-1 px-6 py-4">
          <div className="space-y-6 pb-4">
            {/* Header Warning */}
            <Card className="border-orange-500/30 bg-orange-500/5">
              <CardContent className="p-4">
                <div className="flex items-start space-x-3">
                  <AlertTriangle className="h-5 w-5 text-orange-500 mt-0.5" />
                  <div>
                    <h3 className="font-semibold text-orange-400 mb-1">
                      Required Legal Compliance
                    </h3>
                    <p className="text-sm text-muted-foreground leading-relaxed">
                      Access to the STIG-Codex and DoD Operations environment requires active acceptance of all legal frameworks.
                      Your IP and digital signature will be captured for audit compliance.
                    </p>
                  </div>
                </div>
              </CardContent>
            </Card>

            {/* Terms Grid */}
            <div className="grid gap-4">
              {termsData.map((term) => {
                const Icon = term.icon;
                const isAccepted = acceptedTerms[term.key];

                return (
                  <Card
                    key={term.key}
                    className={`transition-all duration-300 border-2 cursor-pointer ${isAccepted
                      ? 'border-green-500/50 bg-green-500/5 shadow-sm'
                      : 'border-border/50 hover:border-primary/30'
                      }`}
                    onClick={() => handleTermChange(term.key, !isAccepted)}
                  >
                    <div className="p-4">
                      <div className="flex items-start justify-between gap-4">
                        <div className="flex items-start space-x-3 flex-1">
                          <div className={`p-2 rounded-lg ${isAccepted ? 'bg-green-500/20' : 'bg-muted'}`}>
                            <Icon className={`h-5 w-5 ${isAccepted ? 'text-green-500' : 'text-muted-foreground'}`} />
                          </div>
                          <div className="space-y-1">
                            <div className="flex flex-wrap items-center gap-2">
                              <h4 className="text-sm font-bold tracking-tight">
                                {term.title}
                              </h4>
                              <Badge
                                variant={term.classification === 'Critical' ? 'destructive' : 'secondary'}
                                className="text-[10px] h-4 uppercase"
                              >
                                {term.classification}
                              </Badge>
                              <Badge variant="outline" className="text-[10px] h-4 border-primary/20">
                                {term.type === 'Standard' ? 'Ra (Standard)' : term.type}
                              </Badge>
                            </div>
                            <p className="text-xs text-muted-foreground leading-relaxed">
                              {term.description}
                            </p>
                          </div>
                        </div>
                        <Checkbox
                          checked={isAccepted}
                          onCheckedChange={(checked) =>
                            handleTermChange(term.key, checked as boolean)
                          }
                          className="mt-1"
                          onClick={(e) => e.stopPropagation()}
                        />
                      </div>
                    </div>
                  </Card>
                );
              })}
            </div>

            {/* Summary */}
            <Card className="border-primary/20 bg-primary/5">
              <CardContent className="p-4">
                <div className="text-center space-y-2">
                  <div className="flex items-center justify-center gap-2 text-primary font-semibold">
                    <CheckCircle className="h-4 w-4" />
                    <span>Agreement Summary</span>
                  </div>
                  <p className="text-xs text-muted-foreground">
                    By accepting these terms, you acknowledge that you have read and agree to be bound by all applicable agreements.
                  </p>
                  <div className="inline-flex items-center px-4 py-1 bg-background/50 rounded-full border border-primary/10 text-xs font-medium">
                    Status: {Object.values(acceptedTerms).filter(Boolean).length} of {termsData.length} sections accepted
                  </div>
                </div>
              </CardContent>
            </Card>
          </div>
        </ScrollArea>

        {/* Actions - Explicitly ensuring footer is fixed */}
        <div className="p-6 border-t bg-muted/10">
          <div className="flex flex-col sm:flex-row justify-between items-center gap-4">
            <Button
              variant="outline"
              onClick={(e) => {
                e.preventDefault();
                handleAcceptAll();
              }}
              disabled={allTermsAccepted || isSubmitting}
              className="w-full sm:w-auto border-primary/20 hover:bg-primary/5"
            >
              Accept All Sections
            </Button>

            <div className="flex gap-3 w-full sm:w-auto">
              <Button
                variant="ghost"
                onClick={() => onOpenChange(false)}
                disabled={isSubmitting}
                className="flex-1 sm:flex-none"
              >
                Cancel
              </Button>
              <Button
                onClick={handleSubmit}
                disabled={!allTermsAccepted || isSubmitting}
                variant="cyber"
                className="flex-1 sm:min-w-[180px] shadow-lg shadow-primary/20"
              >
                {isSubmitting ? (
                  <div className="flex items-center gap-2">
                    <div className="w-4 h-4 border-2 border-current border-t-transparent rounded-full animate-spin" />
                    <span>Processing...</span>
                  </div>
                ) : (
                  <div className="flex items-center gap-2">
                    <span>Accept & Continue</span>
                    <ArrowRight className="h-4 w-4" />
                  </div>
                )}
              </Button>
            </div>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
};

export default TermsAcceptance;