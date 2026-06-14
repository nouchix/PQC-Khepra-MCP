
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { useNavigate } from 'react-router-dom';
import { useIndustryIntegrations } from '@/hooks/useIndustryIntegrations';
import { useIntegrations } from '@/hooks/useIntegrations';
import { Plug, CheckCircle, AlertCircle, ExternalLink, Plus } from 'lucide-react';

export const IntegrationStatusWidget = () => {
  const navigate = useNavigate();
  const { userIntegrations } = useIndustryIntegrations();
  const { integrations } = useIntegrations();
  
  const totalIntegrations = userIntegrations.length + integrations.length;
  const activeIntegrations = userIntegrations.filter(i => i.status === 'connected').length + 
                            integrations.filter(i => i.status === 'CONNECTED').length;
  const failedIntegrations = userIntegrations.filter(i => i.status === 'error').length + 
                           integrations.filter(i => i.status === 'ERROR').length;

  const getHealthStatus = () => {
    if (totalIntegrations === 0) return { status: 'none', color: 'bg-gray-500', text: 'No integrations' };
    if (failedIntegrations > 0) return { status: 'warning', color: 'bg-yellow-500', text: 'Issues detected' };
    if (activeIntegrations === totalIntegrations) return { status: 'healthy', color: 'bg-green-500', text: 'All systems operational' };
    return { status: 'partial', color: 'bg-blue-500', text: 'Partial connectivity' };
  };

  const healthStatus = getHealthStatus();

  return (
    <Card className="cursor-pointer hover:shadow-md transition-shadow" onClick={() => navigate('/integrations')}>
      <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
        <CardTitle className="text-sm font-medium">Integration Status</CardTitle>
        <div className="flex items-center gap-2">
          <div className={`w-2 h-2 rounded-full ${healthStatus.color}`} />
          <Plug className="h-4 w-4 text-muted-foreground" />
        </div>
      </CardHeader>
      <CardContent>
        <div className="flex items-center justify-between">
          <div>
            <div className="text-2xl font-bold">{activeIntegrations}/{totalIntegrations}</div>
            <p className="text-xs text-muted-foreground">{healthStatus.text}</p>
          </div>
          <div className="flex flex-col gap-1">
            {activeIntegrations > 0 && (
              <Badge variant="secondary" className="text-xs">
                <CheckCircle className="h-3 w-3 mr-1" />
                {activeIntegrations} Active
              </Badge>
            )}
            {failedIntegrations > 0 && (
              <Badge variant="destructive" className="text-xs">
                <AlertCircle className="h-3 w-3 mr-1" />
                {failedIntegrations} Issues
              </Badge>
            )}
          </div>
        </div>
        
        {totalIntegrations === 0 && (
          <Button 
            size="sm" 
            className="w-full mt-3" 
            onClick={(e) => {
              e.stopPropagation();
              navigate('/integrations');
            }}
          >
            <Plus className="h-4 w-4 mr-2" />
            Add First Integration
          </Button>
        )}
        
        {totalIntegrations > 0 && (
          <div className="flex items-center justify-between mt-3 pt-3 border-t">
            <span className="text-xs text-muted-foreground">View details</span>
            <ExternalLink className="h-3 w-3 text-muted-foreground" />
          </div>
        )}
      </CardContent>
    </Card>
  );
};

export const IntegrationQuickActions = () => {
  const navigate = useNavigate();
  
  const popularIntegrations = [
    { name: 'Splunk', icon: '🔍', category: 'SIEM' },
    { name: 'CrowdStrike', icon: '🛡️', category: 'EDR' },
    { name: 'Microsoft Sentinel', icon: '☁️', category: 'Cloud' },
    { name: 'Palo Alto', icon: '🔥', category: 'Firewall' }
  ];

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-sm font-medium">Quick Integration Setup</CardTitle>
      </CardHeader>
      <CardContent>
        <div className="grid grid-cols-2 gap-2">
          {popularIntegrations.map((integration, index) => (
            <Button
              key={index}
              variant="outline"
              size="sm"
              className="justify-start h-auto p-2"
              onClick={() => navigate('/integrations')}
            >
              <div className="flex items-center gap-2 text-left">
                <span className="text-sm">{integration.icon}</span>
                <div>
                  <div className="text-xs font-medium">{integration.name}</div>
                  <div className="text-xs text-muted-foreground">{integration.category}</div>
                </div>
              </div>
            </Button>
          ))}
        </div>
        
        <Button 
          variant="ghost" 
          size="sm" 
          className="w-full mt-3 text-xs"
          onClick={() => navigate('/integrations')}
        >
          View All Integrations
          <ExternalLink className="h-3 w-3 ml-2" />
        </Button>
      </CardContent>
    </Card>
  );
};