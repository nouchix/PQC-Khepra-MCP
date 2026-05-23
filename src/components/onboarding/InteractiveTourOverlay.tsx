import { useEffect } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Progress } from '@/components/ui/progress';
import { Dialog, DialogContent, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { useInteractiveTour } from '@/hooks/useInteractiveTour';
import { 
  X, 
  ArrowRight, 
  ArrowLeft, 
  Play, 
  Pause,
  CheckCircle2,
  Clock,
  Brain,
  Target,
  Shield,
  FileText,
  Users,
  Activity
} from 'lucide-react';

export const InteractiveTourOverlay: React.FC = () => {
  const {
    tourActive,
    currentStep,
    currentTourStep,
    progress,
    isProcessing,
    nextStep,
    previousStep,
    skipTour,
    completeTour,
    completedSteps,
    tourSteps
  } = useInteractiveTour();

  if (!tourActive || !currentTourStep) return null;

  const isLastStep = currentStep === tourSteps.length - 1;
  const isFirstStep = currentStep === 0;

  const getCategoryIcon = (category: string) => {
    switch (category) {
      case 'security': return Shield;
      case 'compliance': return FileText;
      case 'operations': return Activity;
      case 'analytics': return Target;
      default: return Brain;
    }
  };

  const CategoryIcon = getCategoryIcon(currentTourStep.category);

  return (
    <>
      {/* Overlay backdrop */}
      <div className="fixed inset-0 z-40 tour-overlay" />
      
      {/* Tour dialog */}
      <Dialog open={tourActive} onOpenChange={skipTour}>
        <DialogContent className="max-w-2xl z-50 border-primary/20 bg-gradient-to-br from-card to-card/80 backdrop-blur-lg">
          <DialogHeader>
            <div className="flex items-center justify-between">
              <div className="flex items-center space-x-3">
                <div className="p-2 bg-primary/10 rounded-lg">
                  <CategoryIcon className="h-6 w-6 text-primary" />
                </div>
                <div>
                  <DialogTitle className="text-xl flex items-center space-x-2">
                    <span>Interactive Tour</span>
                    <Badge variant="outline" className="text-xs">
                      Step {currentStep + 1} of {tourSteps.length}
                    </Badge>
                  </DialogTitle>
                  <p className="text-sm text-muted-foreground">
                    {currentTourStep.category.charAt(0).toUpperCase() + currentTourStep.category.slice(1)} • 
                    {currentTourStep.estimatedTime} min
                  </p>
                </div>
              </div>
              <Button variant="ghost" size="icon" onClick={skipTour}>
                <X className="h-4 w-4" />
              </Button>
            </div>
          </DialogHeader>

          <div className="space-y-6">
            {/* Progress Bar */}
            <Card className="border-primary/20 bg-gradient-to-r from-primary/5 to-secondary/5">
              <CardContent className="p-4">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-sm font-medium">Tour Progress</span>
                  <span className="text-sm text-muted-foreground">
                    {completedSteps.size} of {tourSteps.length} completed
                  </span>
                </div>
                <Progress value={progress} className="h-2" />
              </CardContent>
            </Card>

            {/* Current Step Details */}
            <Card className="border-primary shadow-lg">
              <CardHeader>
                <div className="flex items-start space-x-4">
                  <div className="p-3 bg-primary/10 rounded-lg">
                    <CategoryIcon className="h-6 w-6 text-primary" />
                  </div>
                  <div className="flex-1">
                    <CardTitle className="text-lg flex items-center space-x-2">
                      <span>{currentTourStep.title}</span>
                      {currentTourStep.actions.some(a => a.type === 'ai-analysis') && (
                        <Badge variant="secondary" className="text-xs">
                          <Brain className="h-3 w-3 mr-1" />
                          AI-Powered
                        </Badge>
                      )}
                    </CardTitle>
                    <p className="text-muted-foreground mt-2">
                      {currentTourStep.description}
                    </p>
                  </div>
                </div>
              </CardHeader>
              
              <CardContent>
                {/* Step Actions Preview */}
                <div className="space-y-2 mb-4">
                  <h4 className="font-medium text-sm">What you'll experience:</h4>
                  <div className="flex flex-wrap gap-2">
                    {currentTourStep.actions.map((action, index) => (
                      <Badge key={index} variant="outline" className="text-xs">
                        {action.type === 'ai-analysis' && '🤖 AI Analysis'}
                        {action.type === 'navigate' && '🧭 Navigate'}
                        {action.type === 'highlight' && '✨ Highlight'}
                        {action.type === 'demo' && '🎯 Interactive Demo'}
                      </Badge>
                    ))}
                  </div>
                </div>

                {/* Navigation Controls */}
                <div className="flex items-center justify-between">
                  <Button
                    variant="outline"
                    onClick={skipTour}
                    className="text-muted-foreground"
                  >
                    Skip Tour
                  </Button>
                  
                  <div className="flex space-x-2">
                    {!isFirstStep && (
                      <Button
                        variant="outline"
                        onClick={previousStep}
                        disabled={isProcessing}
                        className="flex items-center space-x-2"
                      >
                        <ArrowLeft className="h-4 w-4" />
                        <span>Previous</span>
                      </Button>
                    )}
                    
                    <Button
                      onClick={isLastStep ? completeTour : nextStep}
                      disabled={isProcessing}
                      className="flex items-center space-x-2 bg-primary hover:bg-primary/90"
                    >
                      {isProcessing ? (
                        <>
                          <div className="w-4 h-4 border-2 border-current border-t-transparent rounded-full animate-spin" />
                          <span>Processing...</span>
                        </>
                      ) : isLastStep ? (
                        <>
                          <CheckCircle2 className="h-4 w-4" />
                          <span>Complete Tour</span>
                        </>
                      ) : (
                        <>
                          <Play className="h-4 w-4" />
                          <span>Start Step</span>
                          <ArrowRight className="h-4 w-4" />
                        </>
                      )}
                    </Button>
                  </div>
                </div>
              </CardContent>
            </Card>

            {/* Mini Step Overview */}
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2">
              {tourSteps.map((step, index) => {
                const StepIcon = getCategoryIcon(step.category);
                const isActive = index === currentStep;
                const isCompleted = completedSteps.has(step.id);
                
                return (
                  <Card 
                    key={step.id}
                    className={`p-2 cursor-pointer transition-all duration-200 ${
                      isActive ? 'border-primary bg-primary/5' : ''
                    } ${isCompleted ? 'bg-success/10 border-success/20' : ''}`}
                  >
                    <div className="flex items-center space-x-2">
                      <div className={`p-1 rounded ${
                        isCompleted ? 'bg-success text-primary-foreground' : 
                        isActive ? 'bg-primary/10 text-primary' : 'bg-muted text-muted-foreground'
                      }`}>
                        {isCompleted ? (
                          <CheckCircle2 className="h-3 w-3" />
                        ) : (
                          <StepIcon className="h-3 w-3" />
                        )}
                      </div>
                      <div className="flex-1 min-w-0">
                        <p className="text-xs font-medium truncate">{step.title}</p>
                        <p className="text-xs text-muted-foreground">{step.estimatedTime} min</p>
                      </div>
                    </div>
                  </Card>
                );
              })}
            </div>
          </div>
        </DialogContent>
      </Dialog>
    </>
  );
};