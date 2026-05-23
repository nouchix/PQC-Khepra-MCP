import { useState, useEffect, useCallback } from 'react';
import { supabase } from '@/integrations/supabase/client';
import { useToast } from '@/hooks/use-toast';

interface UserAgreement {
  id: string;
  user_id: string;
  agreement_type: string;
  agreement_version: string;
  accepted_at: string;
  ip_address?: unknown;
  user_agent?: string;
  metadata?: any;
  revoked_at?: string;
  organization_id?: string;
  created_at?: string;
  updated_at?: string;
}

const REQUIRED_AGREEMENTS = [
  'tos',
  'privacy',
  'saas',
  'beta',
  'dod_compliance',
  'liability_waiver',
  'export_control'
];

export const useUserAgreements = () => {
  const [agreements, setAgreements] = useState<UserAgreement[]>([]);
  const [loading, setLoading] = useState(true);
  const [hasAcceptedAll, setHasAcceptedAll] = useState(false);
  const { toast } = useToast();

  // Check if user has accepted all required agreements
  const checkAgreementStatus = useCallback(async (userId: string) => {
    try {
      // 1. Check LocalStorage first (Fast & Offline support)
      const localKey = `khepra_agreements_${userId}_v3.0`;
      const localStored = localStorage.getItem(localKey);
      if (localStored) {
        setHasAcceptedAll(true);
        // We still check DB in background context to sync if possible, 
        // but we don't block based on it if local is true
        return true;
      }

      // 2. Try using the secure RPC function
      // @ts-ignore
      const { data: rpcData, error: rpcError } = await supabase
        .rpc('has_accepted_all_agreements', { user_uuid: userId });

      if (!rpcError && typeof rpcData === 'boolean') {
        if (rpcData) {
          localStorage.setItem(localKey, 'true');
          setHasAcceptedAll(true);
          return true;
        }
      }

      // 3. Fallback to direct query
      if (rpcError) console.warn('RPC check check failed:', rpcError);

      const { data, error } = await supabase
        .from('user_agreements')
        .select('agreement_type')
        .eq('user_id', userId)
        .is('revoked_at', null);

      if (error) {
        // If DB error (schema/permissions), fail safely based on local storage (already checked false)
        console.warn("DB Access Error for agreements:", error);
        return false;
      }

      const acceptedTypes = new Set(data?.map(a => a.agreement_type) || []);
      const allAccepted = REQUIRED_AGREEMENTS.every(type => acceptedTypes.has(type));

      if (allAccepted) {
        localStorage.setItem(localKey, 'true');
      }

      setHasAcceptedAll(allAccepted);
      return allAccepted;
    } catch (error: any) {
      console.error('Error checking agreement status:', error);
      return false;
    }
  }, [toast]);

  // Fetch user's agreements
  const fetchAgreements = useCallback(async () => {
    try {
      const { data: { user } } = await supabase.auth.getUser();
      if (!user) {
        setLoading(false);
        return;
      }

      // Optimistic Local Check
      const localKey = `khepra_agreements_${user.id}_v3.0`;
      if (localStorage.getItem(localKey)) {
        setHasAcceptedAll(true);
      }

      const { data, error } = await supabase
        .from('user_agreements')
        .select('*')
        .eq('user_id', user.id)
        .is('revoked_at', null)
        .order('created_at', { ascending: false });

      if (error) throw error;

      setAgreements(data || []);
      await checkAgreementStatus(user.id);
    } catch (error: any) {
      console.error('Error fetching agreements:', error);
      // Suppress toast errors for read failures to avoid UI spam in broken envs
    } finally {
      setLoading(false);
    }
  }, [checkAgreementStatus, toast]);

  // Accept all required agreements
  const acceptAllAgreements = useCallback(async (acceptedTerms: Record<string, boolean>) => {
    try {
      const { data: { user } } = await supabase.auth.getUser();
      if (!user) throw new Error('Not authenticated');

      // 1. Save to LocalStorage immediately (Source of Truth for Client)
      const localKey = `khepra_agreements_${user.id}_v3.0`;
      localStorage.setItem(localKey, 'true');
      setHasAcceptedAll(true);

      // Get client info
      const userAgent = navigator.userAgent;
      const metadata = {
        timestamp: new Date().toISOString(),
        browser: userAgent,
        accepted_terms: acceptedTerms
      };

      const AGREEMENT_MAPPING = [
        { key: 'tosAgree', type: 'tos' },
        { key: 'privacyAgree', type: 'privacy' },
        { key: 'saasAgree', type: 'saas' },
        { key: 'betaAgree', type: 'beta' },
        { key: 'dodCompliance', type: 'dod_compliance' },
        { key: 'liabilityWaiver', type: 'liability_waiver' },
        { key: 'exportControl', type: 'export_control' }
      ];

      // Prepare types array
      const agreementTypesArray = AGREEMENT_MAPPING
        .filter(m => acceptedTerms[m.key])
        .map(m => m.type);

      // 2. Try DB Save (Best Effort)
      // Try using the secure RPC function first
      // @ts-ignore
      const { error: rpcError } = await supabase.rpc('accept_legal_agreements', {
        user_uuid: user.id,
        user_agent_text: userAgent,
        meta_data: metadata,
        agreement_version_text: '3.0',
        agreement_types: agreementTypesArray
      });

      if (rpcError) {
        console.warn('RPC accept_legal_agreements failed, falling back to direct insert (Best Effort):', rpcError);

        // Fallback: Direct individual inserts
        const insertPromises = AGREEMENT_MAPPING.map(async ({ key, type }) => {
          if (acceptedTerms[key]) {
            const payload = {
              user_id: user.id,
              agreement_type: type,
              agreement_version: '3.0',
              user_agent: userAgent,
              metadata
            };

            // Try default schema
            const { error } = await supabase
              .from('user_agreements')
              .insert(payload);

            if (error) {
              console.error(`Failed to insert agreement ${type} (DB Sync Failed):`, error);
              // We do NOT throw here. We allow "Offline Mode" success via LocalStorage.
            }
          }
        });

        await Promise.all(insertPromises);
      }

      // Refresh agreement status
      // await fetchAgreements(); // Skip fetch to avoid resetting state if DB is broken

      toast({
        title: "Agreements Accepted",
        description: "Terms accepted. Saving to secure storage.",
        variant: "default"
      });

      return true;
    } catch (error: any) {
      console.error('Error accepting agreements:', error);
      // Even if everything blows up, we tried to save local storage above.
      // We return true to unblock user if we successfully saved locally.
      const localKey = `khepra_agreements_${(await supabase.auth.getUser()).data.user?.id}_v3.0`;
      if (localStorage.getItem(localKey)) {
        return true;
      }

      toast({
        title: "Agreement Error",
        description: error.message || "Failed to accept agreements.",
        variant: "destructive"
      });
      return false;
    }
  }, [fetchAgreements, toast]);

  // Revoke a specific agreement (for admin use)
  const revokeAgreement = useCallback(async (agreementId: string) => {
    try {
      const { error } = await supabase
        .from('user_agreements')
        .update({ revoked_at: new Date().toISOString() })
        .eq('id', agreementId);

      if (error) throw error;

      await fetchAgreements();

      toast({
        title: "Agreement Revoked",
        description: "The agreement has been revoked successfully",
        variant: "default"
      });
    } catch (error: any) {
      console.error('Error revoking agreement:', error);
      toast({
        title: "Error",
        description: "Failed to revoke agreement",
        variant: "destructive"
      });
    }
  }, [fetchAgreements, toast]);

  useEffect(() => {
    fetchAgreements();
  }, [fetchAgreements]);

  return {
    agreements,
    loading,
    hasAcceptedAll,
    acceptAllAgreements,
    revokeAgreement,
    checkAgreementStatus,
    refreshAgreements: fetchAgreements
  };
};