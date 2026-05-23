import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { 
  Crown, 
  Coffee, 
  Heart, 
  Users, 
  Star, 
  Gift,
  Zap,
  Target
} from "lucide-react";
import { useState } from "react";
import { useToast } from "@/hooks/use-toast";
import { supabase } from "@/integrations/supabase/client";
import { useAuth } from "@/hooks/useAuth";

const RevenueStrategies = () => {
  const [customAmount, setCustomAmount] = useState("");
  const [isProcessing, setIsProcessing] = useState(false);
  const { toast } = useToast();
  const { user } = useAuth();

  const createOneTimePayment = async (paymentType: string, amount?: number, customAmountOverride?: number) => {
    setIsProcessing(true);
    try {
      const { data, error } = await supabase.functions.invoke('create-one-time-payment', {
        body: { 
          paymentType, 
          amount,
          customAmount: customAmountOverride ? customAmountOverride * 100 : undefined // Convert to cents
        },
        headers: {
          Authorization: user ? `Bearer ${(await supabase.auth.getSession()).data.session?.access_token}` : undefined,
        },
      });

      if (error) throw error;

      globalThis.open(data.url, '_blank');
      toast({
        title: "Redirecting to checkout",
        description: "Opening payment page in a new tab...",
      });
    } catch (error: any) {
      toast({
        title: "Error",
        description: error.message || "Failed to create payment session",
        variant: "destructive"
      });
    } finally {
      setIsProcessing(false);
    }
  };

  return (
    <div className="space-y-6">
      <div className="text-center space-y-2">
        <h2 className="text-2xl font-bold text-white">Beta Pricing Programs</h2>
        <p className="text-muted-foreground">
          Lock in beta pricing • No free trials • Limited availability
        </p>
      </div>

      {/* MVP 1.0 Beta Access */}
      <Card className="border-cyan-500/50 bg-gradient-to-br from-cyan-900/20 to-blue-900/20 relative overflow-hidden">
        <div className="absolute top-0 right-0 bg-cyan-500 text-black px-3 py-1 text-xs font-bold">
          MVP 1.0 BETA
        </div>
        <CardHeader>
          <div className="flex items-center gap-3">
            <div className="p-2 bg-cyan-500/20 rounded-full">
              <Target className="h-6 w-6 text-cyan-400" />
            </div>
            <div>
              <CardTitle className="text-cyan-400">Subcontractor Starter</CardTitle>
              <CardDescription>CMMC→STIG mapping with evidence bundles</CardDescription>
            </div>
          </div>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex items-baseline gap-2">
            <span className="text-3xl font-bold text-white">$497</span>
            <span className="text-sm text-muted-foreground">/month</span>
            <Badge className="bg-cyan-500 text-black">Beta</Badge>
          </div>
          
          <ul className="space-y-2">
            <li className="flex items-center text-sm">
              <Star className="h-4 w-4 text-cyan-400 mr-2 flex-shrink-0" />
              CMMC→STIG Mapper (Windows/Ubuntu)
            </li>
            <li className="flex items-center text-sm">
              <Star className="h-4 w-4 text-cyan-400 mr-2 flex-shrink-0" />
              Evidence Bundles + POA&M Export
            </li>
            <li className="flex items-center text-sm">
              <Star className="h-4 w-4 text-cyan-400 mr-2 flex-shrink-0" />
              5 Guided Remediations with Approval/Rollback
            </li>
            <li className="flex items-center text-sm">
              <Star className="h-4 w-4 text-cyan-400 mr-2 flex-shrink-0" />
              Up to 50 Assets • 1 Export Profile
            </li>
            <li className="flex items-center text-sm">
              <Star className="h-4 w-4 text-cyan-400 mr-2 flex-shrink-0" />
              Beta pricing locked for 12 months
            </li>
          </ul>

          <Button 
            onClick={() => globalThis.location.href = '/onboarding'}
            disabled={isProcessing}
            className="w-full bg-cyan-600 hover:bg-cyan-700 text-white font-semibold"
          >
            <Target className="h-4 w-4 mr-2" />
            Join MVP 1.0 Beta
          </Button>
        </CardContent>
      </Card>

      {/* MSP Tiered */}
      <Card className="bg-gradient-to-br from-blue-900/20 to-purple-900/20 border-blue-500/30">
        <CardHeader>
          <div className="flex items-center gap-3">
            <div className="p-2 bg-blue-500/20 rounded-full">
              <Users className="h-6 w-6 text-blue-400" />
            </div>
            <div>
              <CardTitle className="text-blue-400">MSP/MSSP Tiered</CardTitle>
              <CardDescription>Multi-tenant with bulk exports</CardDescription>
            </div>
          </div>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex items-baseline gap-2">
            <span className="text-2xl font-bold text-white">$997</span>
            <span className="text-sm text-muted-foreground">/month</span>
            <Badge variant="outline" className="text-blue-400">MSP</Badge>
          </div>
          
          <ul className="space-y-2 text-sm">
            <li className="flex items-center">
              <Zap className="h-4 w-4 text-blue-400 mr-2" />
              Multi-Tenant Dashboard
            </li>
            <li className="flex items-center">
              <Zap className="h-4 w-4 text-blue-400 mr-2" />
              Bulk Evidence Exports
            </li>
            <li className="flex items-center">
              <Zap className="h-4 w-4 text-blue-400 mr-2" />
              Reusable STIG Baselines
            </li>
            <li className="flex items-center">
              <Zap className="h-4 w-4 text-blue-400 mr-2" />
              White-Label Reports
            </li>
            <li className="flex items-center">
              <Zap className="h-4 w-4 text-blue-400 mr-2" />
              Up to 5 Tenants • 250 Assets
            </li>
          </ul>

          <Button 
            onClick={() => globalThis.location.href = '/onboarding'}
            disabled={isProcessing}
            className="w-full bg-gradient-to-r from-blue-500 to-purple-500 hover:from-blue-600 hover:to-purple-600"
          >
            <Users className="h-4 w-4 mr-2" />
            Join MSP Beta
          </Button>
        </CardContent>
      </Card>

      {/* MVP 2.0 Pilot Program */}
      <Card className="bg-gradient-to-br from-orange-900/20 to-red-900/20 border-orange-500/30">
        <CardHeader>
          <div className="flex items-center gap-3">
            <div className="p-2 bg-orange-500/20 rounded-full">
              <Crown className="h-6 w-6 text-orange-400" />
            </div>
            <div>
              <CardTitle className="text-orange-400">MVP 2.0 Pilot Partner</CardTitle>
              <CardDescription>Co-development with full feature access</CardDescription>
            </div>
          </div>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex items-baseline gap-2">
            <span className="text-2xl font-bold text-white">Custom</span>
            <Badge variant="outline" className="text-orange-400">Limited to 5 partners</Badge>
          </div>
          
          <ul className="space-y-2 text-sm">
            <li className="flex items-center">
              <Gift className="h-4 w-4 text-orange-400 mr-2" />
              STIG Drift Detection (GrokAI)
            </li>
            <li className="flex items-center">
              <Gift className="h-4 w-4 text-orange-400 mr-2" />
              Khepra Trust Kernel (PQ-signing)
            </li>
            <li className="flex items-center">
              <Gift className="h-4 w-4 text-orange-400 mr-2" />
              Expanded OS Support (RHEL 8/9)
            </li>
            <li className="flex items-center">
              <Gift className="h-4 w-4 text-orange-400 mr-2" />
              ServiceNow/Jira Integration
            </li>
            <li className="flex items-center">
              <Gift className="h-4 w-4 text-orange-400 mr-2" />
              Co-branded Case Study & Premium Support
            </li>
          </ul>

          <Button 
            onClick={() => globalThis.location.href = '/onboarding'}
            disabled={isProcessing}
            className="w-full bg-gradient-to-r from-orange-500 to-red-500 hover:from-orange-600 hover:to-red-600"
          >
            <Crown className="h-4 w-4 mr-2" />
            Apply for Pilot Program
          </Button>
        </CardContent>
      </Card>

      {/* Tip Jar / Buy Me a Coffee */}
      <Card className="bg-orange-900/20 border-orange-500/30">
        <CardHeader>
          <div className="flex items-center gap-3">
            <div className="p-2 bg-orange-500/20 rounded-full">
              <Coffee className="h-6 w-6 text-orange-400" />
            </div>
            <div>
              <CardTitle className="text-orange-400">Buy Me a Coffee</CardTitle>
              <CardDescription>Support our mission with any amount</CardDescription>
            </div>
          </div>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex gap-2">
            {[5, 10, 20, 50].map((amount) => (
              <Button
                key={amount}
                variant="outline"
                size="sm"
                onClick={() => createOneTimePayment('donation', amount * 100)}
                disabled={isProcessing}
                className="flex-1"
              >
                ${amount}
              </Button>
            ))}
          </div>
          
          <div className="space-y-2">
            <Label htmlFor="custom-amount">Custom Amount</Label>
            <div className="flex gap-2">
              <div className="relative flex-1">
                <span className="absolute left-3 top-1/2 -translate-y-1/2 text-sm text-muted-foreground">$</span>
                <Input
                  id="custom-amount"
                  type="number"
                  placeholder="25"
                  value={customAmount}
                  onChange={(e) => setCustomAmount(e.target.value)}
                  className="pl-6"
                  min="1"
                />
              </div>
              <Button 
                onClick={() => {
                  const amount = Number.parseFloat(customAmount);
                  if (amount && amount >= 1) {
                    createOneTimePayment('donation', 0, amount);
                  }
                }}
                disabled={isProcessing || !customAmount || Number.parseFloat(customAmount) < 1}
              >
                <Coffee className="h-4 w-4 mr-2" />
                Tip
              </Button>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
};

export default RevenueStrategies;