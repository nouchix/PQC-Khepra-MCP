import { useState, useCallback, useMemo } from 'react';
import { useOrganizationContext } from '@/components/OrganizationProvider';

const DEMO_DISMISSED_KEY = 'asaf_demo_dismissed';

export interface DemoModeState {
  isDemoMode: boolean;
  isConnectDialogOpen: boolean;
  openConnectDialog: () => void;
  closeConnectDialog: () => void;
  dismissDemo: () => void;
}

export const useDemoMode = (): DemoModeState => {
  const { organizations, loading } = useOrganizationContext();
  const [isConnectDialogOpen, setIsConnectDialogOpen] = useState(false);

  const isDemoMode = useMemo(() => {
    if (loading) return false;
    if (typeof window !== 'undefined' && localStorage.getItem(DEMO_DISMISSED_KEY) === 'true') {
      return false;
    }
    return organizations.length === 0;
  }, [organizations, loading]);

  const openConnectDialog = useCallback(() => setIsConnectDialogOpen(true), []);
  const closeConnectDialog = useCallback(() => setIsConnectDialogOpen(false), []);

  const dismissDemo = useCallback(() => {
    if (typeof window !== 'undefined') {
      localStorage.setItem(DEMO_DISMISSED_KEY, 'true');
    }
    setIsConnectDialogOpen(false);
  }, []);

  return { isDemoMode, isConnectDialogOpen, openConnectDialog, closeConnectDialog, dismissDemo };
};
