import { useRealTimeData } from '@/hooks/useRealTimeData';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, AreaChart, Area } from 'recharts';
import { Activity, Shield, AlertTriangle, Zap, Wifi, WifiOff } from 'lucide-react';
import { format } from 'date-fns';

export const RealTimeMetrics = () => {
  const { metrics, currentMetrics, isConnected } = useRealTimeData();

  const formatTime = (timestamp: string) => {
    return format(new Date(timestamp), 'HH:mm:ss');
  };

  const MetricCard = ({ 
    title, 
    value, 
    change, 
    icon: Icon, 
    color = "text-cyan-400",
    bgColor = "bg-cyan-500/10"
  }: {
    title: string;
    value: number;
    change?: number;
    icon: any;
    color?: string;
    bgColor?: string;
  }) => (
    <Card className="bg-slate-800/50 border-slate-700">
      <CardContent className="p-6">
        <div className="flex items-center justify-between">
          <div>
            <p className="text-sm font-medium text-slate-400">{title}</p>
            <div className="flex items-center space-x-2">
              <p className="text-2xl font-bold text-white">{value}</p>
              {change !== undefined && (
                <Badge 
                  variant={change > 0 ? "destructive" : "default"}
                  className="text-xs"
                >
                  {change > 0 ? '+' : ''}{change}
                </Badge>
              )}
            </div>
          </div>
          <div className={`p-3 rounded-full ${bgColor}`}>
            <Icon className={`h-6 w-6 ${color}`} />
          </div>
        </div>
      </CardContent>
    </Card>
  );

  return (
    <div className="space-y-6">
      {/* Connection Status */}
      <div className="flex items-center justify-between">
        <h2 className="text-xl font-bold text-white">Real-Time Analytics</h2>
        <div className="flex items-center space-x-2">
          {isConnected ? (
            <>
              <Wifi className="h-4 w-4 text-green-400" />
              <span className="text-sm text-green-400">Live</span>
              <div className="w-2 h-2 bg-green-400 rounded-full animate-pulse"></div>
            </>
          ) : (
            <>
              <WifiOff className="h-4 w-4 text-red-400" />
              <span className="text-sm text-red-400">Disconnected</span>
            </>
          )}
        </div>
      </div>

      {/* Key Metrics Grid */}
      {currentMetrics && (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          <MetricCard
            title="Active Threats"
            value={currentMetrics.activeThreats}
            icon={Shield}
            color="text-red-400"
            bgColor="bg-red-500/10"
          />
          <MetricCard
            title="Critical Alerts"
            value={currentMetrics.criticalAlerts}
            icon={AlertTriangle}
            color="text-orange-400"
            bgColor="bg-orange-500/10"
          />
          <MetricCard
            title="Network Activity"
            value={currentMetrics.networkActivity}
            icon={Activity}
            color="text-blue-400"
            bgColor="bg-blue-500/10"
          />
          <MetricCard
            title="Resolved Today"
            value={currentMetrics.resolvedThreats}
            icon={Zap}
            color="text-green-400"
            bgColor="bg-green-500/10"
          />
        </div>
      )}

      {/* Threat Activity Chart */}
      <Card className="bg-slate-800/50 border-slate-700">
        <CardHeader>
          <CardTitle className="text-white flex items-center space-x-2">
            <Activity className="h-5 w-5 text-cyan-400" />
            <span>Threat Activity Timeline</span>
          </CardTitle>
          <CardDescription className="text-slate-400">
            Real-time threat detection and resolution metrics
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="h-80">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={metrics}>
                <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                <XAxis 
                  dataKey="timestamp" 
                  tickFormatter={formatTime}
                  stroke="#9CA3AF"
                  fontSize={12}
                />
                <YAxis stroke="#9CA3AF" fontSize={12} />
                <Tooltip 
                  contentStyle={{
                    backgroundColor: '#1F2937',
                    border: '1px solid #374151',
                    borderRadius: '8px',
                    color: '#F3F4F6'
                  }}
                  labelFormatter={(value) => `Time: ${formatTime(value)}`}
                />
                <Area
                  type="monotone"
                  dataKey="activeThreats"
                  stroke="#EF4444"
                  fill="#EF4444"
                  fillOpacity={0.2}
                  name="Active Threats"
                />
                <Area
                  type="monotone"
                  dataKey="resolvedThreats"
                  stroke="#10B981"
                  fill="#10B981"
                  fillOpacity={0.2}
                  name="Resolved Threats"
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </CardContent>
      </Card>

      {/* System Performance Chart */}
      <Card className="bg-slate-800/50 border-slate-700">
        <CardHeader>
          <CardTitle className="text-white flex items-center space-x-2">
            <Zap className="h-5 w-5 text-cyan-400" />
            <span>System Performance</span>
          </CardTitle>
          <CardDescription className="text-slate-400">
            Real-time system resource utilization
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="h-80">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={metrics}>
                <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                <XAxis 
                  dataKey="timestamp" 
                  tickFormatter={formatTime}
                  stroke="#9CA3AF"
                  fontSize={12}
                />
                <YAxis 
                  stroke="#9CA3AF" 
                  fontSize={12}
                  domain={[0, 100]}
                  tickFormatter={(value) => `${value}%`}
                />
                <Tooltip 
                  contentStyle={{
                    backgroundColor: '#1F2937',
                    border: '1px solid #374151',
                    borderRadius: '8px',
                    color: '#F3F4F6'
                  }}
                  labelFormatter={(value) => `Time: ${formatTime(value)}`}
                  formatter={(value: any) => [`${value}%`, '']}
                />
                <Line
                  type="monotone"
                  dataKey="cpuUsage"
                  stroke="#3B82F6"
                  strokeWidth={2}
                  dot={false}
                  name="CPU Usage"
                />
                <Line
                  type="monotone"
                  dataKey="memoryUsage"
                  stroke="#8B5CF6"
                  strokeWidth={2}
                  dot={false}
                  name="Memory Usage"
                />
                <Line
                  type="monotone"
                  dataKey="diskUsage"
                  stroke="#F59E0B"
                  strokeWidth={2}
                  dot={false}
                  name="Disk Usage"
                />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </CardContent>
      </Card>
    </div>
  );
};