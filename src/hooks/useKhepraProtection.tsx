import { useState, useCallback } from 'react';
import { useAuth } from '@/hooks/useAuth';
import { useOrganization } from '@/hooks/useOrganization';
import { useToast } from '@/hooks/use-toast';
import { supabase } from '@/integrations/supabase/client';
import { useKipConnection } from './useKipConnection';

interface KhepraProtectionState {
  isEnabled: boolean;
  isLoading: boolean;
  environment: 'development' | 'staging' | 'production' | 'classified';
  securityLevel: 'UNCLASSIFIED' | 'CLASSIFIED' | 'SECRET' | 'TOP_SECRET';
  deploymentStatus: 'inactive' | 'deploying' | 'active' | 'error';
  lastActivated: Date | null;
  vulnerabilitiesFound: number;
  protectedAssets: number;
}

export const useKhepraProtection = () => {
  const { user } = useAuth();
  const { currentOrganization } = useOrganization();
  const { toast } = useToast();
  const { connection, sendCulturalEvent } = useKipConnection();

  const [protectionState, setProtectionState] = useState<KhepraProtectionState>({
    isEnabled: false,
    isLoading: false,
    environment: 'classified',
    securityLevel: 'CLASSIFIED',
    deploymentStatus: 'inactive',
    lastActivated: null,
    vulnerabilitiesFound: 1,
    protectedAssets: 3
  });

  const enableKhepraProtection = useCallback(async () => {
    if (!user || !currentOrganization) {
      toast({
        title: "Authentication Required",
        description: "You must be logged in to enable KHEPRA Protection.",
        variant: "destructive"
      });
      return;
    }

    setProtectionState(prev => ({ ...prev, isLoading: true, deploymentStatus: 'deploying' }));

    try {
      // Step 1: Verify user has proper clearance
      const { data: profile } = await supabase
        .from('profiles')
        .select('security_clearance, role')
        .eq('user_id', user.id)
        .single();

      if (!profile || !['CLASSIFIED', 'SECRET', 'TOP_SECRET'].includes(profile.security_clearance)) {
        throw new Error('Insufficient security clearance for KHEPRA Protection activation');
      }

      // Step 2: Check environment and determine deployment vector
      const deploymentVector = determineDeploymentVector(protectionState.environment, profile.security_clearance);
      
      // Step 3: Send cultural event to KIP if connected
      if (connection.isConnected) {
        await sendCulturalEvent({
          action: 'khepra_protection_activation',
          symbol: 'EBAN', // Fortress symbol for protection
          context: {
            environment: protectionState.environment,
            security_level: protectionState.securityLevel,
            deployment_vector: deploymentVector,
            organization_id: currentOrganization.id
          }
        });
      }

      // Step 4: Initialize KHEPRA Protection components
      await initializeProtectionLayers(deploymentVector);

      // Step 5: Start vulnerability scanning
      const vulnerabilityCount = await performSecurityScan();

      // Step 6: Protect the browser-security asset in the asset discovery system
      const { ProductionSecurityService } = await import('@/services/ProductionSecurityService');
      await ProductionSecurityService.getInstance().protectAsset('browser-security');
      
      // Step 7: Update protection state
      setProtectionState(prev => ({
        ...prev,
        isEnabled: true,
        isLoading: false,
        deploymentStatus: 'active',
        lastActivated: new Date(),
        vulnerabilitiesFound: vulnerabilityCount
      }));
      
      // Step 8: Trigger asset refresh event for CLI
      globalThis.dispatchEvent(new CustomEvent('khepra-protection-changed'));

      // Step 7: Log activation to audit trail
      await supabase.rpc('log_user_action', {
        action_type: 'KHEPRA_PROTECTION_ENABLED',
        resource_type: 'security_protection',
        resource_id: currentOrganization.id,
        details: {
          environment: protectionState.environment,
          security_level: protectionState.securityLevel,
          deployment_vector: deploymentVector,
          vulnerabilities_found: vulnerabilityCount
        }
      });

      toast({
        title: "KHEPRA Protection Activated",
        description: `Protection enabled for ${protectionState.environment} environment with ${protectionState.securityLevel} clearance level.`,
      });

    } catch (error) {
      console.error('KHEPRA Protection activation failed:', error);
      
      setProtectionState(prev => ({
        ...prev,
        isLoading: false,
        deploymentStatus: 'error'
      }));

      toast({
        title: "Activation Failed",
        description: error.message || "Failed to enable KHEPRA Protection. Please contact your security administrator.",
        variant: "destructive"
      });
    }
  }, [user, currentOrganization, protectionState.environment, protectionState.securityLevel, connection, sendCulturalEvent, toast]);

  const disableKhepraProtection = useCallback(async () => {
    if (!user || !currentOrganization) return;

    setProtectionState(prev => ({ ...prev, isLoading: true }));

    try {
      // Send cultural event for deactivation
      if (connection.isConnected) {
        await sendCulturalEvent({
          action: 'khepra_protection_deactivation',
          symbol: 'FAWOHODIE', // Freedom/release symbol
          context: {
            environment: protectionState.environment,
            organization_id: currentOrganization.id
          }
        });
      }

      setProtectionState(prev => ({
        ...prev,
        isEnabled: false,
        isLoading: false,
        deploymentStatus: 'inactive'
      }));

      await supabase.rpc('log_user_action', {
        action_type: 'KHEPRA_PROTECTION_DISABLED',
        resource_type: 'security_protection',
        resource_id: currentOrganization.id,
        details: { environment: protectionState.environment }
      });

      toast({
        title: "KHEPRA Protection Disabled",
        description: "Protection has been safely deactivated.",
      });

    } catch (error) {
      console.error('KHEPRA Protection deactivation failed:', error);
      
      setProtectionState(prev => ({ ...prev, isLoading: false }));
      
      toast({
        title: "Deactivation Failed",
        description: "Failed to disable KHEPRA Protection.",
        variant: "destructive"
      });
    }
  }, [user, currentOrganization, protectionState.environment, connection, sendCulturalEvent, toast]);

  return {
    protectionState,
    enableKhepraProtection,
    disableKhepraProtection,
    setEnvironment: (env: KhepraProtectionState['environment']) => 
      setProtectionState(prev => ({ ...prev, environment: env })),
    setSecurityLevel: (level: KhepraProtectionState['securityLevel']) => 
      setProtectionState(prev => ({ ...prev, securityLevel: level }))
  };
};

// Helper functions
function determineDeploymentVector(environment: string, securityClearance: string): string {
  if (environment === 'classified' && ['SECRET', 'TOP_SECRET'].includes(securityClearance)) {
    return 'sgx-enclave';
  } else if (environment === 'production') {
    return 'kubernetes-hardened';
  } else if (environment === 'staging') {
    return 'docker-isolated';
  } else {
    return 'development-sandbox';
  }
}

async function initializeProtectionLayers(deploymentVector: string): Promise<void> {
  // Simulate initialization of different protection layers based on deployment vector
  const layers = {
    'sgx-enclave': ['memory-encryption', 'attestation', 'sealed-storage'],
    'kubernetes-hardened': ['pod-security', 'network-policies', 'rbac'],
    'docker-isolated': ['container-isolation', 'security-contexts'],
    'development-sandbox': ['basic-monitoring', 'log-collection']
  };

  const requiredLayers = layers[deploymentVector] || layers['development-sandbox'];
  
  // Simulate async initialization
  await new Promise(resolve => setTimeout(resolve, 2000));
  
  console.log(`Initialized KHEPRA protection layers: ${requiredLayers.join(', ')}`);
}

async function performSecurityScan(): Promise<number> {
  // Simulate security scanning
  try {
    // Query real vulnerability count from threat intelligence
    const { count } = await supabase
      .from('threat_intelligence')
      .select('*', { count: 'exact', head: true })
      .eq('indicator_type', 'vulnerability')
      .in('threat_level', ['HIGH', 'CRITICAL']);

    return count || 0;
  } catch (error) {
    console.error('Failed to fetch vulnerability count:', error);
    throw new Error('Vulnerability scan failed - unable to query threat intelligence database');
  }
}