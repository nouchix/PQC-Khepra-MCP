import React from 'react';
import { useNavigate } from 'react-router-dom';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
} from '@/components/ui/dialog';
import { AlertTriangle, ArrowRight, X, Building2 } from 'lucide-react';
import { PolymorphicIngestionEngine } from '@/components/discovery/PolymorphicIngestionEngine';
import { DEMO_ORG_NAME } from '@/lib/demoData';
import type { DemoModeState } from '@/hooks/useDemoMode';

interface DemoBannerProps {
  demoMode: DemoModeState;
}

export const DemoBanner: React.FC<DemoBannerProps> = ({ demoMode }) => {
  const navigate = useNavigate();

  const handleIngestionComplete = ({ primaryTarget, envType }: { count: number; primaryTarget: string; envType: string }) => {
    demoMode.closeConnectDialog();
    const params = new URLSearchParams({ prefill_env: envType });
    if (primaryTarget) params.set('prefill_target', primaryTarget);
    navigate(`/onboarding?${params.toString()}`);
  };

  return (
    <>
      {/* Sticky banner */}
      <div className="sticky top-0 z-40 w-full bg-gradient-to-r from-amber-500/90 via-orange-500/90 to-amber-600/90 backdrop-blur-sm border-b border-amber-400/50 shadow-lg shadow-amber-900/20">
        <div className="flex items-center justify-between px-4 py-2.5 max-w-screen-2xl mx-auto">
          <div className="flex items-center gap-3">
            <div className="flex items-center gap-2 shrink-0">
              <AlertTriangle className="h-4 w-4 text-amber-900" />
              <Badge className="bg-amber-900/20 text-amber-950 border-amber-900/30 text-[10px] font-black uppercase tracking-widest px-2">
                Demo Mode
              </Badge>
            </div>
            <div className="flex items-center gap-2 text-amber-950">
              <Building2 className="h-4 w-4 shrink-0 opacity-70" />
              <span className="text-sm font-semibold">
                Viewing <span className="font-black">{DEMO_ORG_NAME}</span> sample data
              </span>
              <span className="hidden sm:inline text-amber-900/70 text-sm">—</span>
              <span className="hidden sm:inline text-sm text-amber-900">
                Connect your environment to see your actual compliance posture
              </span>
            </div>
          </div>

          <div className="flex items-center gap-2 shrink-0">
            <Button
              size="sm"
              className="bg-amber-950 hover:bg-amber-900 text-amber-50 text-xs font-black uppercase tracking-wider h-7 px-3 gap-1.5"
              onClick={demoMode.openConnectDialog}
            >
              Connect Now
              <ArrowRight className="h-3 w-3" />
            </Button>
            <button
              onClick={demoMode.dismissDemo}
              className="p-1.5 rounded-md text-amber-900 hover:bg-amber-900/20 transition-colors"
              aria-label="Dismiss demo banner"
            >
              <X className="h-4 w-4" />
            </button>
          </div>
        </div>
      </div>

      {/* Connect environment dialog */}
      <Dialog open={demoMode.isConnectDialogOpen} onOpenChange={(open) => !open && demoMode.closeConnectDialog()}>
        <DialogContent className="max-w-5xl w-full bg-slate-950 border-slate-800 text-white p-0 overflow-hidden">
          <DialogHeader className="px-6 pt-6 pb-4 border-b border-slate-800">
            <DialogTitle className="text-xl font-black tracking-tight text-white flex items-center gap-3">
              <div className="p-2 bg-indigo-500/10 rounded-lg">
                <Building2 className="h-5 w-5 text-indigo-400" />
              </div>
              Connect Your Environment
            </DialogTitle>
            <DialogDescription className="text-slate-400 mt-1">
              Select your infrastructure type and initialize the asset discovery handshake. Your compliance posture will replace the demo data.
            </DialogDescription>
          </DialogHeader>
          <div className="p-6 overflow-y-auto max-h-[75vh]">
            <PolymorphicIngestionEngine
              organizationId="pending-onboarding"
              onComplete={handleIngestionComplete}
            />
          </div>
        </DialogContent>
      </Dialog>
    </>
  );
};
