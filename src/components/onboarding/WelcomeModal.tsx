import { useState } from 'react';
import { Dialog, DialogContent, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import {
  Rocket,
  Shield,
  Target,
  Users,
  CheckCircle2,
  ArrowRight,
  Sparkles,
  Clock
} from 'lucide-react';
import { useUsageTracker } from '@/components/UsageTracker';

interface WelcomeModalProps {
  open: boolean;
  onClose: () => void;
  userEmail?: string;
}

export const WelcomeModal = ({ open, onClose, userEmail }: WelcomeModalProps) => {
  const [currentSlide, setCurrentSlide] = useState(0);
  const { trackFeatureAccess } = useUsageTracker();

  const slides = [
    {
      title: "Welcome to SouHimBou AI! 🎉",
      content: (
        <div className="text-center space-y-4">
          <div className="p-4 bg-primary/10 rounded-full w-fit mx-auto">
            <Sparkles className="h-8 w-8 text-primary" />
          </div>
          <h3 className="text-2xl font-bold">You're In!</h3>
          <p className="text-muted-foreground">
            Welcome to the future of AI-powered cybersecurity. Your 30-day premium trial is now active.
          </p>
          <div className="bg-green-500/10 border border-green-500/20 rounded-lg p-4">
            <div className="flex items-center justify-center space-x-2">
              <Clock className="h-5 w-5 text-green-400" />
              <span className="font-semibold text-green-400">
                Trailblazer Beta access active
              </span>
            </div>
          </div>
        </div>
      )
    },
    {
      title: "What You Get During Your Trial",
      content: (
        <div className="space-y-4">
          <div className="grid gap-4">
            {[
              { icon: Shield, title: "Advanced Threat Detection", desc: "AI-powered real-time monitoring" },
              { icon: Target, title: "CMMC Compliance Tools", desc: "Automated compliance tracking" },
              { icon: Users, title: "Unlimited Team Members", desc: "Collaborate with your entire team" },
              { icon: Rocket, title: "Infrastructure Discovery", desc: "Auto-catalog your IT assets" }
            ].map((feature) => (
              <div key={feature.title} className="flex items-start space-x-3 p-3 bg-muted/30 rounded-lg">
                <div className="p-2 bg-primary/10 rounded-lg">
                  <feature.icon className="h-5 w-5 text-primary" />
                </div>
                <div>
                  <h4 className="font-semibold">{feature.title}</h4>
                  <p className="text-sm text-muted-foreground">{feature.desc}</p>
                </div>
                <CheckCircle2 className="h-5 w-5 text-green-500 flex-shrink-0" />
              </div>
            ))}
          </div>
        </div>
      )
    },
    {
      title: "Get Value in 5 Minutes",
      content: (
        <div className="space-y-4">
          <p className="text-muted-foreground">Here's how to see immediate results:</p>
          <div className="space-y-3">
            {[
              "🔍 Run an infrastructure scan to discover your assets",
              "📊 Check your security dashboard for live metrics",
              "✅ Review your CMMC compliance status",
              "👥 Invite your team to collaborate"
            ].map((step, idx) => (
              <div key={step} className="flex items-center space-x-3 p-3 bg-blue-500/5 border border-blue-500/20 rounded-lg">
                <Badge variant="outline" className="w-6 h-6 rounded-full p-0 flex items-center justify-center text-xs">
                  {idx + 1}
                </Badge>
                <span>{step}</span>
              </div>
            ))}
          </div>
          <div className="bg-primary/10 border border-primary/20 rounded-lg p-4 text-center">
            <p className="font-semibold text-primary">💡 Pro Tip</p>
            <p className="text-sm text-muted-foreground mt-1">
              Complete all 4 steps to unlock your personalized security recommendations!
            </p>
          </div>
        </div>
      )
    }
  ];

  const handleNext = () => {
    if (currentSlide < slides.length - 1) {
      setCurrentSlide(currentSlide + 1);
    } else {
      trackFeatureAccess('welcome_modal_completed', 'basic');
      onClose();
    }
  };

  const handleSkip = () => {
    trackFeatureAccess('welcome_modal_skipped', 'basic');
    onClose();
  };

  return (
    <Dialog open={open} onOpenChange={onClose}>
      <DialogContent className="max-w-md">
        <DialogHeader>
          <DialogTitle className="text-center">
            {slides[currentSlide].title}
          </DialogTitle>
        </DialogHeader>

        <div className="py-4">
          {slides[currentSlide].content}
        </div>

        {/* Progress indicators */}
        <div className="flex justify-center space-x-2 mb-4">
          {slides.map((slide, idx) => (
            <div
              key={slide.title}
              className={`w-2 h-2 rounded-full transition-colors ${idx === currentSlide ? 'bg-primary' : 'bg-muted'
                }`}
            />
          ))}
        </div>

        <div className="flex justify-between">
          <Button variant="ghost" onClick={handleSkip}>
            Skip Tour
          </Button>
          <Button onClick={handleNext} className="min-w-24">
            {currentSlide === slides.length - 1 ? (
              <>Get Started <Rocket className="h-4 w-4 ml-2" /></>
            ) : (
              <>Next <ArrowRight className="h-4 w-4 ml-2" /></>
            )}
          </Button>
        </div>
      </DialogContent>
    </Dialog>
  );
};