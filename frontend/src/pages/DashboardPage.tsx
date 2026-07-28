import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { Siren, TriangleAlert, CircleAlert, Info, RefreshCw, Play, Square } from 'lucide-react';
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
        <div className="grid grid-cols-1 gap-6 sm:grid-cols-2 lg:grid-cols-4">
          {statsLoading ? (
            Array.from({ length: 4 }).map((_, i) => <Skeleton key={i} className="h-28 rounded-lg" />)
          ) : (
            <>
              <StatCard
                label="Critical Threats"
                value={bySeverity.critical ?? 0}
                icon={Siren}
                colorClass="bg-danger-solid text-solid-foreground"
                helper={(bySeverity.critical ?? 0) > 0 ? 'requires action' : 'none active'}
              />
              <StatCard
                label="High Severity"
                value={bySeverity.high ?? 0}
                icon={TriangleAlert}
                colorClass="bg-warning-solid text-solid-foreground"
                helper="last 24 hours"
              />
              <StatCard
                label="Medium Severity"
                value={bySeverity.medium ?? 0}
                icon={CircleAlert}
                colorClass="bg-info-solid text-solid-foreground"
                helper="last 24 hours"
              />
              <StatCard
                label="Low Severity"
                value={bySeverity.low ?? 0}
                icon={Info}
                colorClass="bg-muted-foreground text-background"
                helper="last 24 hours"
              />
            </>
          )}
        </div>

        <Card className="border-border/60">
          <CardHeader>
            <CardTitle className="text-[1.375rem]">Threat Timeline (24h)</CardTitle>
          </CardHeader>
          <CardContent className="h-72">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={timeline ?? []}>
                <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" vertical={false} />
                <XAxis dataKey="time" tick={{ fontSize: 12, fill: 'var(--muted-foreground)' }} axisLine={false} tickLine={false} />
                <YAxis tick={{ fontSize: 12, fill: 'var(--muted-foreground)' }} allowDecimals={false} axisLine={false} tickLine={false} />
                <Tooltip
                  contentStyle={{ background: 'var(--popover)', border: '1px solid var(--border)', borderRadius: 12 }}
                  labelStyle={{ color: 'var(--foreground)' }}
                />
                <Legend wrapperStyle={{ fontSize: 12 }} />
                <Line type="monotone" dataKey="critical" stroke="var(--color-danger)" strokeWidth={2} dot={false} activeDot={{ r: 4 }} />
                <Line type="monotone" dataKey="high" stroke="var(--color-warning)" strokeWidth={2} dot={false} activeDot={{ r: 4 }} />
                <Line type="monotone" dataKey="medium" stroke="var(--color-info)" strokeWidth={2} dot={false} activeDot={{ r: 4 }} />
                <Line type="monotone" dataKey="low" stroke="var(--muted-foreground)" strokeWidth={2} dot={false} activeDot={{ r: 4 }} />
              </LineChart>
            </ResponsiveContainer>
          </CardContent>
        </Card>

        <div className="grid grid-cols-1 gap-6 sm:grid-cols-2 lg:grid-cols-4">
          <Card className="hover-lift border-border/60">
            <CardHeader className="pb-2"><CardTitle className="text-sm font-medium text-muted-foreground">CPU Usage</CardTitle></CardHeader>
            <CardContent className="data-numeral text-3xl font-semibold tracking-tight">{metrics?.cpu_percent?.toFixed(1) ?? '0.0'}%</CardContent>
          </Card>
          <Card className="hover-lift border-border/60">
            <CardHeader className="pb-2"><CardTitle className="text-sm font-medium text-muted-foreground">Memory Usage</CardTitle></CardHeader>
            <CardContent className="data-numeral text-3xl font-semibold tracking-tight">{metrics?.memory_percent?.toFixed(1) ?? '0.0'}%</CardContent>
          </Card>
          <Card className="hover-lift border-border/60">
            <CardHeader className="pb-2"><CardTitle className="text-sm font-medium text-muted-foreground">Network Connections</CardTitle></CardHeader>
            <CardContent className="data-numeral text-3xl font-semibold tracking-tight">{metrics?.network_connections ?? 0}</CardContent>
          </Card>
          <Card className="hover-lift border-border/60">
            <CardHeader className="pb-2"><CardTitle className="text-sm font-medium text-muted-foreground">Active Processes</CardTitle></CardHeader>
            <CardContent className="data-numeral text-3xl font-semibold tracking-tight">{metrics?.process_count ?? 0}</CardContent>
          </Card>
        </div>

        <Card className="border-border/60">
          <CardHeader>
            <CardTitle className="text-[1.375rem]">Recent Threats</CardTitle>
          </CardHeader>
          <CardContent>
            {threatsLoading ? <Skeleton className="h-48 rounded-xl" /> : <ThreatTable threats={threats ?? []} />}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
