
import { Switch } from '@/components/ui/switch';
import { Label } from '@/components/ui/label';
import { Card, CardContent } from '@/components/ui/card';
import { TrendingUp, Eye } from 'lucide-react';

interface ExecutiveModeToggleProps {
  isExecutiveMode: boolean;
  onToggle: (enabled: boolean) => void;
  className?: string;
}

export const ExecutiveModeToggle: React.FC<ExecutiveModeToggleProps> = ({
  isExecutiveMode,
  onToggle,
  className = ""
}) => {
  return (
    <Card className={`border-primary/20 ${className}`}>
      <CardContent className="p-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <div className="w-10 h-10 bg-gradient-primary rounded-lg flex items-center justify-center">
              {isExecutiveMode ? (
                <TrendingUp className="h-5 w-5 text-primary-foreground" />
              ) : (
                <Eye className="h-5 w-5 text-primary-foreground" />
              )}
            </div>
            <div>
              <Label htmlFor="executive-mode" className="text-sm font-medium">
                Executive Summary Mode
              </Label>
              <p className="text-xs text-muted-foreground">
                {isExecutiveMode ? 'High-level overview with key metrics' : 'Detailed technical view'}
              </p>
            </div>
          </div>
          
          <Switch
            id="executive-mode"
            checked={isExecutiveMode}
            onCheckedChange={onToggle}
            className="data-[state=checked]:bg-primary"
          />
        </div>
      </CardContent>
    </Card>
  );
};