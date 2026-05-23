import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { 
  Share2, 
  Users, 
  Gift, 
  Copy,
  Percent,
  CreditCard
} from "lucide-react";
import { useState, useEffect } from "react";
import { useToast } from "@/hooks/use-toast";
import { supabase } from "@/integrations/supabase/client";
import { useAuth } from "@/hooks/useAuth";

const ReferralProgram = () => {
  const [referralCode, setReferralCode] = useState("");
  const [referralStats, setReferralStats] = useState({
    totalReferrals: 0,
    completedReferrals: 0,
    pendingRewards: 0
  });
  const [isLoading, setIsLoading] = useState(false);
  const { toast } = useToast();
  const { user } = useAuth();

  useEffect(() => {
    if (user) {
      generateOrFetchReferralCode();
      fetchReferralStats();
    }
  }, [user]);

  const generateOrFetchReferralCode = async () => {
    if (!user) return;

    try {
      // Check if user already has a referral code
      const { data: existing, error } = await supabase
        .from('referrals')
        .select('referral_code')
        .eq('referrer_user_id', user.id)
        .maybeSingle();

      if (error && error.code !== 'PGRST116') throw error;

      if (existing) {
        setReferralCode(existing.referral_code);
      } else {
        // Generate new referral code
        const code = `${user.email?.split('@')[0] || 'user'}-${crypto.randomUUID().substring(0, 6)}`.toUpperCase();
        
        const { data, error: insertError } = await supabase
          .from('referrals')
          .insert({
            referrer_user_id: user.id,
            referral_code: code,
            reward_type: 'discount',
            reward_amount: 25 // 25% discount
          })
          .select('referral_code')
          .single();

        if (insertError) throw insertError;
        
        setReferralCode(data.referral_code);
      }
    } catch (error: any) {
      console.error('Error with referral code:', error);
      toast({
        title: "Error",
        description: "Failed to generate referral code",
        variant: "destructive"
      });
    }
  };

  const fetchReferralStats = async () => {
    if (!user) return;

    try {
      const { data, error } = await supabase
        .from('referrals')
        .select('*')
        .eq('referrer_user_id', user.id);

      if (error) throw error;

      const stats = {
        totalReferrals: data.length,
        completedReferrals: data.filter(r => r.status === 'completed').length,
        pendingRewards: data.filter(r => r.status === 'pending').length
      };

      setReferralStats(stats);
    } catch (error: any) {
      console.error('Error fetching referral stats:', error);
    }
  };

  const copyReferralLink = () => {
    const referralLink = `${globalThis.location.origin}/signup?ref=${referralCode}`;
    navigator.clipboard.writeText(referralLink);
    toast({
      title: "Link copied!",
      description: "Referral link has been copied to your clipboard",
    });
  };

  const shareReferralCode = () => {
    navigator.clipboard.writeText(referralCode);
    toast({
      title: "Code copied!",
      description: "Share this code with your friends",
    });
  };

  if (!user) {
    return (
      <Card className="bg-slate-900/40">
        <CardHeader className="text-center">
          <Users className="h-8 w-8 text-blue-400 mx-auto mb-2" />
          <CardTitle>Referral Program</CardTitle>
          <CardDescription>Sign in to access your referral program</CardDescription>
        </CardHeader>
        <CardContent>
          <Button variant="outline" className="w-full" disabled>
            Login Required
          </Button>
        </CardContent>
      </Card>
    );
  }

  return (
    <div className="space-y-6">
      <div className="text-center space-y-2">
        <h3 className="text-xl font-bold text-white">Referral Program</h3>
        <p className="text-muted-foreground">
          Share the platform and earn rewards for every successful referral
        </p>
      </div>

      {/* Referral Code Card */}
      <Card className="bg-gradient-to-br from-blue-900/20 to-purple-900/20 border-blue-500/30">
        <CardHeader>
          <div className="flex items-center gap-3">
            <div className="p-2 bg-blue-500/20 rounded-full">
              <Share2 className="h-6 w-6 text-blue-400" />
            </div>
            <div>
              <CardTitle className="text-blue-400">Your Referral Code</CardTitle>
              <CardDescription>Share this code or link with friends</CardDescription>
            </div>
          </div>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex items-center gap-2">
            <Input 
              value={referralCode} 
              readOnly 
              className="font-mono text-lg font-bold text-center"
            />
            <Button 
              size="sm" 
              onClick={shareReferralCode}
              variant="outline"
            >
              <Copy className="h-4 w-4" />
            </Button>
          </div>
          
          <Button 
            onClick={copyReferralLink} 
            className="w-full bg-blue-600 hover:bg-blue-700"
          >
            <Copy className="h-4 w-4 mr-2" />
            Copy Referral Link
          </Button>
        </CardContent>
      </Card>

      {/* Referral Stats */}
      <div className="grid md:grid-cols-3 gap-4">
        <Card className="bg-slate-900/40 text-center">
          <CardContent className="pt-6">
            <Users className="h-8 w-8 text-green-400 mx-auto mb-2" />
            <div className="text-2xl font-bold text-white">{referralStats.totalReferrals}</div>
            <p className="text-sm text-muted-foreground">Total Referrals</p>
          </CardContent>
        </Card>

        <Card className="bg-slate-900/40 text-center">
          <CardContent className="pt-6">
            <Gift className="h-8 w-8 text-blue-400 mx-auto mb-2" />
            <div className="text-2xl font-bold text-white">{referralStats.completedReferrals}</div>
            <p className="text-sm text-muted-foreground">Successful Referrals</p>
          </CardContent>
        </Card>

        <Card className="bg-slate-900/40 text-center">
          <CardContent className="pt-6">
            <CreditCard className="h-8 w-8 text-yellow-400 mx-auto mb-2" />
            <div className="text-2xl font-bold text-white">{referralStats.pendingRewards}</div>
            <p className="text-sm text-muted-foreground">Pending Rewards</p>
          </CardContent>
        </Card>
      </div>

      {/* Rewards Information */}
      <Card className="bg-green-900/20 border-green-500/30">
        <CardHeader>
          <div className="flex items-center gap-3">
            <div className="p-2 bg-green-500/20 rounded-full">
              <Percent className="h-6 w-6 text-green-400" />
            </div>
            <div>
              <CardTitle className="text-green-400">Referral Rewards</CardTitle>
              <CardDescription>What you and your friends get</CardDescription>
            </div>
          </div>
        </CardHeader>
        <CardContent className="space-y-3">
          <div className="flex items-center justify-between p-3 bg-slate-800/40 rounded border border-slate-600/30">
            <span className="text-sm">Your friend gets:</span>
            <Badge className="bg-green-500 text-black">25% Off First Month</Badge>
          </div>
          <div className="flex items-center justify-between p-3 bg-slate-800/40 rounded border border-slate-600/30">
            <span className="text-sm">You get:</span>
            <Badge className="bg-blue-500 text-black">$25 Account Credit</Badge>
          </div>
          <div className="flex items-center justify-between p-3 bg-slate-800/40 rounded border border-slate-600/30">
            <span className="text-sm">After 5 referrals:</span>
            <Badge className="bg-purple-500 text-black">1 Month Free</Badge>
          </div>
        </CardContent>
      </Card>

      {/* How It Works */}
      <Card className="bg-slate-900/40">
        <CardHeader>
          <CardTitle className="text-white">How It Works</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-3 text-sm text-muted-foreground">
            <div className="flex items-start gap-3">
              <div className="flex-shrink-0 w-6 h-6 rounded-full bg-blue-500 text-white text-xs flex items-center justify-center">1</div>
              <p>Share your referral code or link with friends and colleagues</p>
            </div>
            <div className="flex items-start gap-3">
              <div className="flex-shrink-0 w-6 h-6 rounded-full bg-blue-500 text-white text-xs flex items-center justify-center">2</div>
              <p>They sign up using your code and get 25% off their first subscription</p>
            </div>
            <div className="flex items-start gap-3">
              <div className="flex-shrink-0 w-6 h-6 rounded-full bg-blue-500 text-white text-xs flex items-center justify-center">3</div>
              <p>You earn $25 account credit for each successful referral</p>
            </div>
            <div className="flex items-start gap-3">
              <div className="flex-shrink-0 w-6 h-6 rounded-full bg-blue-500 text-white text-xs flex items-center justify-center">4</div>
              <p>Unlock bonus rewards as you refer more users</p>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
};

export default ReferralProgram;