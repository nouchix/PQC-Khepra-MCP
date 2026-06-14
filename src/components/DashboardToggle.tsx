

import { Switch } from '@/components/ui/switch';
import { Label } from '@/components/ui/label';
import { GitBranch, LayoutDashboard } from 'lucide-react';
import { useNavigate, useLocation } from 'react-router-dom';

interface DashboardToggleProps {
  className?: string;
}

export const DashboardToggle: React.FC<DashboardToggleProps> = ({ className }) => {
  const navigate = useNavigate();
  const location = useLocation();
  
  const isDOD = location.pathname === '/dod';
  
  const handleToggle = (checked: boolean) => {
    if (checked) {
      navigate('/dod');
    } else {
      navigate('/dashboard');
    }
  };

  return (
    <div className={`flex items-center space-x-3 ${className}`}>
      <div className="flex items-center space-x-2">
        <LayoutDashboard className="h-4 w-4 text-muted-foreground" />
        <Label htmlFor="dashboard-mode" className="text-sm font-medium">
          Console
        </Label>
      </div>
      
      <Switch
        id="dashboard-mode"
        checked={isDOD}
        onCheckedChange={handleToggle}
        className="data-[state=checked]:bg-primary"
      />
      
      <div className="flex items-center space-x-2">
        <GitBranch className="h-4 w-4 text-muted-foreground" />
        <Label htmlFor="dashboard-mode" className="text-sm font-medium">
          DOD
        </Label>
      </div>
    </div>
  );
};