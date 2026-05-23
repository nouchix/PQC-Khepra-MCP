import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Check, Crown, Zap, Building2, RefreshCw, Clock, CheckCircle, CreditCard, BarChart3 } from "lucide-react";
import { useToast } from "@/hooks/use-toast";
import { useTrialStatus } from "@/hooks/useTrialStatus";
import { useSubscription } from "@/hooks/useSubscription";
import { useState } from "react";
import ContactSalesDialog from "@/components/billing/ContactSalesDialog";
import RevenueStrategies from "@/components/billing/RevenueStrategies";
import ReferralProgram from "@/components/billing/ReferralProgram";
import { UsageDashboard } from "@/components/billing/UsageDashboard";

const BillingDashboard = () => {
  const { 
    subscribed, 
    subscription_tier, 
    subscription_end, 
    loading, 
    createCheckout, 
    openCustomerPortal,
    checkSubscription 
  } = useSubscription();
  const { toast } = useToast();
  const { trialStatus, loading: trialLoading } = useTrialStatus();

  const [contactOpen, setContactOpen] = useState(false);

  const plans = [
    {
      id: "trailblazer_beta",
      name: "Trailblazer Beta",
      price: "Free",
      tier: "trailblazer_beta",
      description: "Basic cybersecurity features - always free",
      icon: Zap,
      features: [
        "Basic threat monitoring", 
        "Security event alerts",
        "Compliance dashboard", 
        "Community support",
        "Core integrations"
      ],
      color: "blue",
      isFree: true
    },
    {
      id: "trailblazer_plus", 
      name: "Trailblazer Plus",
      price: "$19",
      tier: "trailblazer_plus",
      description: "Enhanced features and customization",
      icon: Crown,
      features: [
        "All Beta features",
        "Custom security dashboards",
        "Daily/weekly automated reminders", 
        "Grace Mode - flexible compliance",
        "Priority email support",
        "Advanced integrations"
      ],
      color: "purple",
      popular: true
    },
    {
      id: "enterprise",
      name: "Enterprise",
      price: "Contact Sales",
      tier: "enterprise",
      description: "Full platform with custom deployment options",
      icon: Building2,
      features: [
        "Everything in Plus",
        "M-XDR Core platform",
        "SOAR automation", 
        "AI-powered threat hunting",
        "Dedicated enclave/on-prem",
        "FedRAMP/FIPS compliance",
        "24/7 dedicated support",
        "Custom SLAs"
      ],
      color: "gold"
    }
  ];

  const handleUpgrade = async (planTier: 'trailblazer_plus') => {
    try {
      await createCheckout(planTier);
      toast({
        title: "Redirecting to checkout",
        description: "Opening Stripe checkout in a new tab...",
      });
    } catch (error: any) {
      toast({
        title: "Error", 
        description: error.message || "Failed to create checkout session",
        variant: "destructive"
      });
    }
  };

  const handleManageSubscription = async () => {
    try {
      await openCustomerPortal();
      toast({
        title: "Opening customer portal",
        description: "Manage your subscription in a new tab...",
      });
    } catch (error: any) {
      toast({
        title: "Error",
        description: error.message || "Failed to open customer portal",
        variant: "destructive"
      });
    }
  };

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold">Billing & Usage</h1>
          <p className="text-muted-foreground">Manage your subscription and monitor resource usage</p>
        </div>
        <div className="flex items-center space-x-4">
          <Button onClick={checkSubscription} disabled={loading} variant="outline">
            <RefreshCw className={`mr-2 h-4 w-4 ${loading ? 'animate-spin' : ''}`} />
            Refresh Status
          </Button>
          {subscribed && (
            <Button onClick={handleManageSubscription}>
              <CreditCard className="h-4 w-4 mr-2" />
              Manage Subscription
            </Button>
          )}
        </div>
      </div>

      <Tabs defaultValue="usage" className="w-full">
        <TabsList className="grid w-full grid-cols-2">
          <TabsTrigger value="usage" className="flex items-center space-x-2">
            <BarChart3 className="h-4 w-4" />
            <span>Usage & Costs</span>
          </TabsTrigger>
          <TabsTrigger value="subscription" className="flex items-center space-x-2">
            <CreditCard className="h-4 w-4" />
            <span>Subscription Plans</span>
          </TabsTrigger>
        </TabsList>

        <TabsContent value="usage" className="mt-6">
          <UsageDashboard />
        </TabsContent>

        <TabsContent value="subscription" className="mt-6 space-y-6">
          {subscribed && (
        <Card className="bg-green-900/20 border-green-500/30">
          <CardHeader>
            <CardTitle className="flex items-center text-green-400">
              <CheckCircle className="h-5 w-5 mr-2" />
              Active Subscription
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex justify-between items-center">
              <div>
                <Badge variant="outline" className="text-green-400 border-green-500/30 mb-2">
                  {subscription_tier?.toUpperCase()} PLAN
                </Badge>
                <p className="text-slate-300">
                  Next billing: {subscription_end ? new Date(subscription_end).toLocaleDateString() : 'Unknown'}
                </p>
              </div>
            </div>
          </CardContent>
        </Card>
      )}

      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        {plans.map((plan) => {
          const Icon = plan.icon;
          const isCurrentPlan = subscribed && subscription_tier?.toLowerCase() === plan.tier;
          
          return (
            <Card
              key={plan.name}
              className={`relative ${
                plan.popular
                  ? "border-yellow-500/50 bg-yellow-900/10" 
                  : isCurrentPlan
                  ? "border-green-500/50 bg-green-900/10"
                  : "bg-slate-900/40 border-slate-600/30"
              }`}
            >
              {plan.popular && (
                <div className="absolute -top-3 left-1/2 transform -translate-x-1/2">
                  <Badge className="bg-yellow-500 text-black">Most Popular</Badge>
                </div>
              )}
              
              {isCurrentPlan && (
                <div className="absolute -top-3 right-4">
                  <Badge className="bg-green-500 text-black">Current Plan</Badge>
                </div>
              )}

              <CardHeader className="text-center">
                <div className="mx-auto mb-4 p-3 rounded-full bg-slate-800/50 w-fit">
                  <Icon className="h-8 w-8 text-blue-400" />
                </div>
                <CardTitle className="text-slate-200">{plan.name}</CardTitle>
                <div className="text-3xl font-bold text-white">
                  {plan.price}
                  <span className="text-sm font-normal text-slate-400">/month</span>
                </div>
                <CardDescription className="text-slate-400">{plan.description}</CardDescription>
              </CardHeader>

              <CardContent className="space-y-4">
                <ul className="space-y-2">
                  {plan.features.map((feature, index) => (
                    <li key={index} className="flex items-center text-slate-300">
                      <CheckCircle className="h-4 w-4 text-green-400 mr-2 flex-shrink-0" />
                      <span className="text-sm">{feature}</span>
                    </li>
                  ))}
                </ul>

                <Button
                  onClick={() => {
                    if (plan.isFree) return; // Can't upgrade to free plan
                    if (isCurrentPlan) return handleManageSubscription();
                    if (plan.tier === 'enterprise') return setContactOpen(true);
                    if (plan.tier === 'trailblazer_plus') return handleUpgrade('trailblazer_plus');
                  }}
                  className={`w-full ${
                    plan.isFree
                      ? "bg-slate-600 text-slate-400 cursor-default"
                      : plan.popular 
                      ? "bg-yellow-600 hover:bg-yellow-700" 
                      : isCurrentPlan
                      ? "bg-green-600 hover:bg-green-700"
                      : "bg-blue-600 hover:bg-blue-700"
                  }`}
                  disabled={loading || plan.isFree}
                >
                  {plan.isFree ? "Current Plan" : 
                   isCurrentPlan ? "Manage Plan" : 
                   (plan.tier === 'enterprise' ? 'Contact Sales' : `Upgrade to ${plan.name}`)}
                </Button>
              </CardContent>
            </Card>
          );
          })}
          </div>

          <Card className="bg-slate-900/40 border-slate-600/30">
        <CardHeader>
          <CardTitle className="text-slate-200">Enterprise Features</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
            {[
              { name: "M-XDR Core", status: "PRODUCTION-READY", desc: "Extended Detection & Response" },
              { name: "SOAR Platform", status: "PRODUCTION-READY", desc: "Security Orchestration" },
              { name: "Threat Intelligence", status: "PRODUCTION-READY", desc: "Real-time feeds" },
              { name: "Compliance Suite", status: "PRODUCTION-READY", desc: "CMMC, NIST, FedRAMP" }
            ].map((feature) => (
              <div key={feature.name} className="p-4 bg-slate-800/40 rounded border border-slate-600/30">
                <h4 className="font-semibold text-white">{feature.name}</h4>
                <Badge variant="outline" className="text-xs bg-green-500/10 text-green-400 border-green-500/20 mt-1">
                  {feature.status}
                </Badge>
                <p className="text-xs text-slate-400 mt-2">{feature.desc}</p>
              </div>
            ))}
          </div>
        </CardContent>
          </Card>

          {/* Revenue Strategies Section */}
          <div className="space-y-8">
            <div className="border-t border-slate-600/30 pt-6">
              <RevenueStrategies />
            </div>
            
            <div className="border-t border-slate-600/30 pt-6">
              <ReferralProgram />
            </div>
          </div>
        </TabsContent>
      </Tabs>

      <ContactSalesDialog open={contactOpen} onOpenChange={setContactOpen} />
    </div>
  );
};

export default BillingDashboard;