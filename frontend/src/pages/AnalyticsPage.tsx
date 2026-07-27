import { useMemo, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { TopBar } from '@/components/layout/TopBar';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Skeleton } from '@/components/ui/skeleton';
import { api } from '@/lib/api';
import {
  BarChart, Bar, PieChart, Pie, Cell, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer,
} from 'recharts';

const CATEGORY_COLORS = ['#4f46e5', '#06b6d4', '#10b981', '#f59e0b', '#ef4444', '#8b5cf6'];
const RISK_COLORS: Record<string, string> = {
  Critical: '#dc2626',
  High: '#ea580c',
  Medium: '#f59e0b',
  Low: '#3b82f6',
};

const periods = [
  { label: '24 Hours', value: 1 },
  { label: '7 Days', value: 7 },
  { label: '30 Days', value: 30 },
];

export default function AnalyticsPage() {
  const [days, setDays] = useState(7);

  const { data: dailyTimeline, isLoading: timelineLoading } = useQuery({
    queryKey: ['analytics-timeline', days],
    queryFn: () => api.timeline.daily(days),
  });

  const { data: stats, isLoading: statsLoading } = useQuery({
    queryKey: ['stats', 'analytics', days],
    queryFn: () => api.stats.get(),
  });

  const categoryData = useMemo(
    () => Object.entries(stats?.by_category ?? {}).map(([name, value]) => ({ name, value })),
    [stats]
  );

  const severityData = useMemo(
    () =>
      Object.entries(stats?.by_severity ?? {}).map(([name, value]) => ({
        name: name.charAt(0).toUpperCase() + name.slice(1),
        value,
      })),
    [stats]
  );

  const mostCommonCategory = useMemo(() => {
    if (categoryData.length === 0) return '-';
    return categoryData.reduce((max, c) => (c.value > max.value ? c : max), categoryData[0]).name;
  }, [categoryData]);

  return (
    <div>
      <TopBar title="Security Analytics" description="Comprehensive threat analysis and insights" />

      <div className="space-y-6 p-8">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between">
            <CardTitle>Threat Trends Over Time</CardTitle>
            <div className="flex gap-2">
              {periods.map((p) => (
                <Button key={p.value} size="sm" variant={days === p.value ? 'default' : 'outline'} onClick={() => setDays(p.value)}>
                  {p.label}
                </Button>
              ))}
            </div>
          </CardHeader>
          <CardContent className="h-80">
            {timelineLoading ? (
              <Skeleton className="h-full" />
            ) : (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={dailyTimeline ?? []}>
                  <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" />
                  <XAxis dataKey="date" tick={{ fontSize: 12 }} />
                  <YAxis tick={{ fontSize: 12 }} allowDecimals={false} />
                  <Tooltip />
                  <Bar dataKey="count" fill="#4f46e5" radius={[4, 4, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            )}
          </CardContent>
        </Card>

        <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
          <Card>
            <CardHeader><CardTitle>Threat Categories</CardTitle></CardHeader>
            <CardContent className="h-64">
              {statsLoading ? <Skeleton className="h-full" /> : (
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie data={categoryData} dataKey="value" nameKey="name" innerRadius={50} outerRadius={80}>
                      {categoryData.map((_, i) => (
                        <Cell key={i} fill={CATEGORY_COLORS[i % CATEGORY_COLORS.length]} />
                      ))}
                    </Pie>
                    <Legend />
                    <Tooltip />
                  </PieChart>
                </ResponsiveContainer>
              )}
            </CardContent>
          </Card>

          <Card>
            <CardHeader><CardTitle>Risk Level Distribution</CardTitle></CardHeader>
            <CardContent className="h-64">
              {statsLoading ? <Skeleton className="h-full" /> : (
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie data={severityData} dataKey="value" nameKey="name" innerRadius={50} outerRadius={80}>
                      {severityData.map((entry, i) => (
                        <Cell key={i} fill={RISK_COLORS[entry.name] ?? '#94a3b8'} />
                      ))}
                    </Pie>
                    <Legend />
                    <Tooltip />
                  </PieChart>
                </ResponsiveContainer>
              )}
            </CardContent>
          </Card>
        </div>

        <Card>
          <CardHeader><CardTitle>Summary Statistics</CardTitle></CardHeader>
          <CardContent className="grid grid-cols-2 gap-6 sm:grid-cols-4">
            <div>
              <div className="text-sm text-muted-foreground">Total Threats</div>
              <div className="text-2xl font-bold">{stats?.total_threats ?? 0}</div>
            </div>
            <div>
              <div className="text-sm text-muted-foreground">Active Critical</div>
              <div className="text-2xl font-bold">{stats?.active_critical ?? 0}</div>
            </div>
            <div>
              <div className="text-sm text-muted-foreground">Most Common</div>
              <div className="text-2xl font-bold">{mostCommonCategory}</div>
            </div>
            <div>
              <div className="text-sm text-muted-foreground">Time Window</div>
              <div className="text-2xl font-bold">{stats?.time_window_hours ?? 24}h</div>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
