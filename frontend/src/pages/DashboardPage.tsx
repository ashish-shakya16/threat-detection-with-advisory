import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { AlertOctagon, AlertTriangle, AlertCircle, Info, RefreshCw, Play, Square } from 'lucide-react';
import { TopBar } from '@/components/layout/TopBar';
import { StatCard } from '@/components/StatCard';
import { ThreatTable } from '@/components/ThreatTable';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Skeleton } from '@/components/ui/skeleton';
import { toast } from 'sonner';
import { useStats } from '@/hooks/useStats';
import { useSystemMetrics } from '@/hooks/useSystemMetrics';
import { useSocket } from '@/hooks/useSocket';
import { api } from '@/lib/api';
import {
  LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend,
} from 'recharts';

export default function DashboardPage() {
  useSocket();
  const queryClient = useQueryClient();
  const [monitoring, setMonitoring] = useState(false);

  const { data: stats, isLoading: statsLoading } = useStats();
  const { data: metrics } = useSystemMetrics();

  const { data: threats, isLoading: threatsLoading } = useQuery({
    queryKey: ['threats', { limit: 10 }],
    queryFn: () => api.threats.list({ limit: 10 }),
  });

  const { data: timeline } = useQuery({
    queryKey: ['timeline', 24],
    queryFn: () => api.timeline.hourly(24),
  });

  const scanMutation = useMutation({
    mutationFn: api.scan.start,
    onSuccess: (data) => {
      toast.success('Scan complete', { description: data.message });
      queryClient.invalidateQueries({ queryKey: ['stats'] });
      queryClient.invalidateQueries({ queryKey: ['threats'] });
      queryClient.invalidateQueries({ queryKey: ['timeline'] });
    },
    onError: (error: Error) => {
      toast.error('Scan failed', { description: error.message });
    },
  });

  const monitorMutation = useMutation({
    mutationFn: () => (monitoring ? api.monitoring.stop() : api.monitoring.start()),
    onSuccess: () => {
      setMonitoring(!monitoring);
      toast.success(monitoring ? 'Monitoring stopped' : 'Monitoring started');
    },
  });

  const bySeverity = stats?.by_severity ?? {};

  return (
    <div>
      <TopBar
        title="Security Dashboard"
        description="Real-time threat monitoring and analysis"
        actions={
          <>
            <Button onClick={() => scanMutation.mutate()} disabled={scanMutation.isPending}>
              <RefreshCw className={`mr-2 h-4 w-4 ${scanMutation.isPending ? 'animate-spin' : ''}`} />
              Run Scan
            </Button>
            <Button variant={monitoring ? 'destructive' : 'outline'} onClick={() => monitorMutation.mutate()}>
              {monitoring ? <Square className="mr-2 h-4 w-4" /> : <Play className="mr-2 h-4 w-4" />}
              {monitoring ? 'Stop Monitoring' : 'Start Monitoring'}
            </Button>
          </>
        }
      />

      <div className="space-y-6 p-8">
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
          {statsLoading ? (
            Array.from({ length: 4 }).map((_, i) => <Skeleton key={i} className="h-24" />)
          ) : (
            <>
              <StatCard label="Critical Threats" value={bySeverity.critical ?? 0} icon={AlertOctagon} colorClass="bg-red-600/15 text-red-500" />
              <StatCard label="High Severity" value={bySeverity.high ?? 0} icon={AlertCircle} colorClass="bg-orange-600/15 text-orange-500" />
              <StatCard label="Medium Severity" value={bySeverity.medium ?? 0} icon={AlertTriangle} colorClass="bg-amber-500/15 text-amber-500" />
              <StatCard label="Low Severity" value={bySeverity.low ?? 0} icon={Info} colorClass="bg-blue-500/15 text-blue-500" />
            </>
          )}
        </div>

        <Card>
          <CardHeader>
            <CardTitle>Threat Timeline (24h)</CardTitle>
          </CardHeader>
          <CardContent className="h-72">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={timeline ?? []}>
                <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" />
                <XAxis dataKey="time" tick={{ fontSize: 12 }} />
                <YAxis tick={{ fontSize: 12 }} allowDecimals={false} />
                <Tooltip />
                <Legend />
                <Line type="monotone" dataKey="critical" stroke="#dc2626" strokeWidth={2} dot={false} />
                <Line type="monotone" dataKey="high" stroke="#ea580c" strokeWidth={2} dot={false} />
                <Line type="monotone" dataKey="medium" stroke="#f59e0b" strokeWidth={2} dot={false} />
                <Line type="monotone" dataKey="low" stroke="#3b82f6" strokeWidth={2} dot={false} />
              </LineChart>
            </ResponsiveContainer>
          </CardContent>
        </Card>

        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
          <Card>
            <CardHeader className="pb-2"><CardTitle className="text-sm font-medium text-muted-foreground">CPU Usage</CardTitle></CardHeader>
            <CardContent className="text-2xl font-bold">{metrics?.cpu_percent?.toFixed(1) ?? '0.0'}%</CardContent>
          </Card>
          <Card>
            <CardHeader className="pb-2"><CardTitle className="text-sm font-medium text-muted-foreground">Memory Usage</CardTitle></CardHeader>
            <CardContent className="text-2xl font-bold">{metrics?.memory_percent?.toFixed(1) ?? '0.0'}%</CardContent>
          </Card>
          <Card>
            <CardHeader className="pb-2"><CardTitle className="text-sm font-medium text-muted-foreground">Network Connections</CardTitle></CardHeader>
            <CardContent className="text-2xl font-bold">{metrics?.network_connections ?? 0}</CardContent>
          </Card>
          <Card>
            <CardHeader className="pb-2"><CardTitle className="text-sm font-medium text-muted-foreground">Active Processes</CardTitle></CardHeader>
            <CardContent className="text-2xl font-bold">{metrics?.process_count ?? 0}</CardContent>
          </Card>
        </div>

        <Card>
          <CardHeader>
            <CardTitle>Recent Threats</CardTitle>
          </CardHeader>
          <CardContent>
            {threatsLoading ? <Skeleton className="h-48" /> : <ThreatTable threats={threats ?? []} />}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
