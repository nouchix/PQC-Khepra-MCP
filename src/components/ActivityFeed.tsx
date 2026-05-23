
import { useState, useEffect } from "react";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Activity, Shield, Brain, Zap, Eye, User, Database, FileText } from "lucide-react";
import { supabase } from "@/integrations/supabase/client";
import { useOrganization } from "@/hooks/useOrganization";
import { formatDistanceToNow } from "date-fns";

export const ActivityFeed = () => {
  const [activities, setActivities] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const { currentOrganization } = useOrganization();

  useEffect(() => {
    if (currentOrganization) {
      fetchRealActivityData();
      
      // Set up real-time subscription for new activities
      const channel = supabase
        .channel('activity_changes')
        .on('postgres_changes', {
          event: 'INSERT',
          schema: 'public',
          table: 'audit_logs'
        }, (payload) => {
          const newActivity = formatAuditLogToActivity(payload.new);
          setActivities(prev => [newActivity, ...prev.slice(0, 9)]);
        })
        .subscribe();

      return () => {
        supabase.removeChannel(channel);
      };
    }
  }, [currentOrganization]);

  const fetchRealActivityData = async () => {
    if (!currentOrganization) return;
    
    try {
      // Fetch recent audit logs for the organization
      const { data: auditLogs, error } = await supabase
        .from('audit_logs')
        .select('*')
        .order('created_at', { ascending: false })
        .limit(10);

      if (error) throw error;

      const formattedActivities = auditLogs?.map(formatAuditLogToActivity) || [];
      setActivities(formattedActivities);

    } catch (error) {
      console.error('Error fetching activity data:', error);
      setActivities([]);
    } finally {
      setLoading(false);
    }
  };

  const formatAuditLogToActivity = (log: any) => {
    const getIconAndColor = (action: string, resourceType?: string) => {
      switch (action) {
        case 'security_event':
          return { icon: Shield, color: "text-red-400", type: "security" };
        case 'threat_investigation':
          return { icon: Eye, color: "text-yellow-400", type: "investigation" };
        case 'user_login':
        case 'user_logout':
          return { icon: User, color: "text-blue-400", type: "auth" };
        case 'database_query':
        case 'data_access':
          return { icon: Database, color: "text-cyan-400", type: "data" };
        case 'ai_interaction':
          return { icon: Brain, color: "text-purple-400", type: "ai" };
        case 'document_access':
        case 'document_update':
          return { icon: FileText, color: "text-green-400", type: "document" };
        default:
          return { icon: Activity, color: "text-gray-400", type: "system" };
      }
    };

    const { icon, color, type } = getIconAndColor(log.action, log.resource_type);
    
    const formatMessage = (action: string, resourceType?: string, details?: any) => {
      switch (action) {
        case 'security_event':
          return details?.event_type ? `Security event: ${details.event_type}` : 'Security event detected';
        case 'threat_investigation':
          return `Threat investigation: ${details?.indicator || 'Unknown indicator'}`;
        case 'user_login':
          return 'User logged in';
        case 'user_logout':
          return 'User logged out';
        case 'ai_interaction':
          return 'AI security agent interaction';
        case 'document_access':
          return `Document accessed: ${resourceType || 'Unknown'}`;
        default:
          return `${action.replaceAll('_', ' ')} - ${resourceType || 'System'}`;
      }
    };

    return {
      id: log.id,
      type,
      message: formatMessage(log.action, log.resource_type, log.details),
      time: formatDistanceToNow(new Date(log.created_at), { addSuffix: true }),
      icon,
      color,
      timestamp: log.created_at
    };
  };

  if (loading) {
    return (
      <Card className="bg-black/40 border-green-500/30 backdrop-blur-lg">
        <CardHeader>
          <CardTitle className="flex items-center space-x-2 text-green-400">
            <Activity className="h-5 w-5" />
            <span>Live Activity</span>
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="text-center text-gray-400">Loading activity feed...</div>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center space-x-2">
          <Activity className="h-5 w-5" />
          <span>Recent Activity</span>
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-3">
        {activities.length > 0 ? (
          activities.map((activity) => {
            const IconComponent = activity.icon;
            return (
              <div key={activity.id} className="flex items-center space-x-3 p-3 bg-muted/50 rounded-lg border border-border/50 hover:bg-muted/70 transition-colors">
                <div className={`w-2 h-2 rounded-full ${
                  activity.type === 'security' ? 'bg-red-500' :
                  activity.type === 'investigation' ? 'bg-yellow-500' :
                  activity.type === 'auth' ? 'bg-blue-500' :
                  activity.type === 'data' ? 'bg-cyan-500' :
                  activity.type === 'ai' ? 'bg-purple-500' :
                  activity.type === 'document' ? 'bg-green-500' :
                  'bg-gray-500'
                }`} />
                <IconComponent className={`h-4 w-4 ${activity.color}`} />
                <div className="flex-1">
                  <p className="text-sm font-medium">{activity.message}</p>
                  <div className="flex items-center space-x-2 mt-1">
                    <span className="text-xs text-muted-foreground">{activity.time}</span>
                    <Badge variant="outline" className="text-xs">
                      {activity.type}
                    </Badge>
                  </div>
                </div>
              </div>
            );
          })
        ) : (
          <div className="text-center text-muted-foreground py-8">
            <Activity className="h-12 w-12 mx-auto mb-4 opacity-50" />
            <p>No recent activity</p>
            <p className="text-xs mt-1">System monitoring...</p>
          </div>
        )}
      </CardContent>
    </Card>
  );
};
