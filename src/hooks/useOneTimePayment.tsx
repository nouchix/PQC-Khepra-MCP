import { useState } from 'react';
import { supabase } from '@/integrations/supabase/client';
import { useAuth } from '@/hooks/useAuth';
import { useToast } from '@/hooks/use-toast';

export const useOneTimePayment = () => {
  const [isProcessing, setIsProcessing] = useState(false);
  const { user } = useAuth();
  const { toast } = useToast();

  const createPayment = async (
    paymentType: 'founding-member' | 'supporter' | 'donation' | 'beta-access',
    amount?: number,
    customAmount?: number
  ) => {
    setIsProcessing(true);
    try {
      const { data, error } = await supabase.functions.invoke('create-one-time-payment', {
        body: { 
          paymentType, 
          amount,
          customAmount: customAmount ? customAmount * 100 : undefined // Convert to cents
        },
        headers: {
          Authorization: user ? `Bearer ${(await supabase.auth.getSession()).data.session?.access_token}` : undefined,
        },
      });

      if (error) throw error;

      // Open Stripe checkout in a new tab
      globalThis.open(data.url, '_blank');
      
      toast({
        title: "Redirecting to checkout",
        description: "Opening payment page in a new tab...",
      });

      return data;
    } catch (error: any) {
      console.error('Error creating payment:', error);
      toast({
        title: "Error",
        description: error.message || "Failed to create payment session",
        variant: "destructive"
      });
      throw error;
    } finally {
      setIsProcessing(false);
    }
  };

  return {
    createPayment,
    isProcessing
  };
};