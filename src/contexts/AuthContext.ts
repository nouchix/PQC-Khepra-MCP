import { createContext, useContext, useState, useEffect } from 'react';
import type { User, Session } from '@supabase/supabase-js';
import { supabase } from '@/integrations/supabase/client';

export interface AuthContextType {
  user: User | null;
  session: Session | null;
  loading: boolean;
  signIn: (email: string, password: string) => Promise<{ error: any }>;
  signUp: (email: string, password: string, metadata?: any) => Promise<{ error: any }>;
  signOut: () => Promise<{ error: any }>;
  resetPassword: (email: string) => Promise<{ error: any }>;
}

export const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};

// Hook to get user role from secure system (will use user_roles table after migration)
export const useUserRoles = () => {
  const { user } = useAuth();
  const [role, setRole] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchRole = async () => {
      if (!user) {
        setRole(null);
        setLoading(false);
        return;
      }

      try {
        // Use existing get_current_user_role function which will be updated by migration
        const { data, error } = await supabase.rpc('get_current_user_role');

        if (error) throw error;
        setRole(data as string || 'viewer');
      } catch (error) {
        console.error('Error fetching user role:', error);
        setRole('viewer');
      } finally {
        setLoading(false);
      }
    };

    fetchRole();
  }, [user]);

  return { 
    role, 
    loading, 
    hasRole: (checkRole: string) => role === checkRole,
    isAdmin: () => role === 'admin'
  };
};
