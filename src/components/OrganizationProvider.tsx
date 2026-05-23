import { createContext, useContext } from 'react';
import { useOrganization } from '@/hooks/useOrganization';

const OrganizationContext = createContext<ReturnType<typeof useOrganization> | undefined>(undefined);

export const OrganizationProvider = ({ children }: { children: React.ReactNode }) => {
  const organizationData = useOrganization();

  return (
    <OrganizationContext.Provider value={organizationData}>
      {children}
    </OrganizationContext.Provider>
  );
};

export const useOrganizationContext = () => {
  const context = useContext(OrganizationContext);
  if (context === undefined) {
    throw new Error('useOrganizationContext must be used within an OrganizationProvider');
  }
  return context;
};