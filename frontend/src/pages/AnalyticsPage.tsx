import { useMemo, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { motion } from 'framer-motion';
import { TopBar } from '@/components/layout/TopBar';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Skeleton } from '@/components/ui/skeleton';
import { api } from '@/lib/api';
import {
  AreaChart, Area, PieChart, Pie, Cell, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
} from 'recharts';
import {
  TrendingUp, Download, RefreshCw, ShieldCheck, AlertOctagon, Flame, CalendarClock,
} from 'lucide-react';
import { cn } from '@/lib/utils';

const CATEGORY_COLORS = ['#4F7EFF', '#38BDF8', '#22C55E', '#FACC15', '#EF4444', '#7C5CFF'];
const RISK_COLORS: Record<string, string> = {
  Critical: '#EF4444',
  High: '#F97316',
  Medium: '#FACC15',
  Low: '#3B82F6',
};

const periods = [
  { label: '24 Hours', value: 1 },
  { label: '7 Days', value: 7 },
  { label: '30 Days', value: 30 },
];

const cardMotion = {
  initial: { opacity: 0, y: 16 },
  animate: { opacity: 1, y: 0 },
};

function AnimatedNumber({ value }: { value: number | string }) {
  return (
    <motion.span
      key={String(value)}
      initial={{ opacity: 0, y: 6 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.25 }}
      className="tabular-nums"
    >
      {value}
    </motion.span>
  );
}

function DonutLegendRow({ color, label, value, percent }: { color: string; label: string; value: number; percent: number }) {
  return (
    <div className="flex items-center justify-between gap-3 rounded-lg px-2 py-1.5 transition-colors hover:bg-accent/40">
      <div className="flex items-center gap-2">
        <span className="h-2.5 w-2.5 shrink-0 rounded-full" style={{ backgroundColor: color }} />
        <span className="text-sm text-foreground">{label}</span>
      </div>
      <div className="flex items-center gap-2 text-sm">
        <span className="font-semibold tabular-nums">{value}</span>
        <span className="w-10 text-right text-muted-foreground tabular-nums">{percent}%</span>
      </div>
    </div>
  );
}

export default function AnalyticsPage() {
  const [days, setDays] = useState(7);

  const { data: dailyTimeline, isLoading: timelineLoading, refetch: refetchTimeline, isFetching: timelineFetching } = useQuery({
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

  const mostCommonShare = useMemo(() => {
    const total = categoryData.reduce((sum, c) => sum + c.value, 0);
    if (total === 0) return 0;
    const top = categoryData.reduce((max, c) => (c.value > max.value ? c : max), categoryData[0]);
    return Math.round((top.value / total) * 100);
  }, [categoryData]);

  const categoryTotal = categoryData.reduce((sum, c) => sum + c.value, 0);
  const severityTotal = severityData.reduce((sum, c) => sum + c.value, 0);

  function handleExport() {
    const rows = [
      ['date', 'count'],
      ...(dailyTimeline ?? []).map((d) => [d.date, String(d.count)]),
    ];
    const csv = rows.map((r) => r.join(',')).join('\n');
    const blob = new Blob([csv], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `threat-analytics-${days}d.csv`;
    a.click();
    URL.revokeObjectURL(url);
  }

  return (
    <div>
      <TopBar
        title="Security Analytics"
        description="Comprehensive threat analysis and insights"
        actions={
          <>
            <Button variant="outline" size="sm" onClick={handleExport}>
              <Download className="mr-1.5 h-3.5 w-3.5" />
              Export
            </Button>
            <Button
              variant="outline"
              size="sm"
              onClick={() => refetchTimeline()}
              disabled={timelineFetching}
            >
              <RefreshCw className={cn('mr-1.5 h-3.5 w-3.5', timelineFetching && 'animate-spin')} />
              Refresh
            </Button>
          </>
        }
      />

      <div className="space-y-6 p-8">
        <motion.div {...cardMotion} transition={{ duration: 0.3 }}>
          <Card className="border-border/60 bg-linear-to-b from-card to-card/60">
            <CardHeader className="flex flex-row items-center justify-between">
              <div className="flex items-center gap-2.5">
                <div className="flex h-9 w-9 items-center justify-center rounded-xl bg-primary/15 text-primary">
                  <TrendingUp className="h-4.5 w-4.5" />
                </div>
                <CardTitle className="text-[1.375rem]">Threat Trends Over Time</CardTitle>
              </div>
              <div className="flex gap-1.5 rounded-xl border border-border/60 bg-muted/30 p-1">
                {periods.map((p) => (
                  <Button
                    key={p.value}
                    size="sm"
                    variant="ghost"
                    className={cn(
                      'h-7 rounded-lg px-3 text-xs',
                      days === p.value && 'bg-linear-to-r from-primary to-accent-purple text-primary-foreground hover:from-primary hover:to-accent-purple hover:text-primary-foreground'
                    )}
                    onClick={() => setDays(p.value)}
                  >
                    {p.label}
                  </Button>
                ))}
              </div>
            </CardHeader>
            <CardContent className="h-80">
              {timelineLoading ? (
                <Skeleton className="h-full rounded-xl" />
              ) : (dailyTimeline ?? []).length === 0 ? (
                <div className="flex h-full flex-col items-center justify-center gap-2 text-muted-foreground">
                  <ShieldCheck className="h-10 w-10" />
                  <p>No threat activity in this period.</p>
                </div>
              ) : (
                <ResponsiveContainer width="100%" height="100%">
                  <AreaChart data={dailyTimeline ?? []}>
                    <defs>
                      <linearGradient id="areaFill" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="0%" stopColor="#4F7EFF" stopOpacity={0.45} />
                        <stop offset="100%" stopColor="#7C5CFF" stopOpacity={0.02} />
                      </linearGradient>
                      <linearGradient id="areaStroke" x1="0" y1="0" x2="1" y2="0">
                        <stop offset="0%" stopColor="#4F7EFF" />
                        <stop offset="100%" stopColor="#7C5CFF" />
                      </linearGradient>
                    </defs>
                    <CartesianGrid strokeDasharray="4 6" stroke="var(--border)" vertical={false} />
                    <XAxis dataKey="date" tick={{ fontSize: 12, fill: 'var(--muted-foreground)' }} axisLine={false} tickLine={false} />
                    <YAxis tick={{ fontSize: 12, fill: 'var(--muted-foreground)' }} allowDecimals={false} axisLine={false} tickLine={false} />
                    <Tooltip
                      contentStyle={{ background: 'var(--popover)', border: '1px solid var(--border)', borderRadius: 12 }}
                      labelStyle={{ color: 'var(--foreground)' }}
                      cursor={{ stroke: 'var(--border)', strokeWidth: 1 }}
                    />
                    <Area
                      type="monotone"
                      dataKey="count"
                      stroke="url(#areaStroke)"
                      strokeWidth={2.5}
                      fill="url(#areaFill)"
                      dot={{ r: 3, fill: '#4F7EFF', strokeWidth: 0 }}
                      activeDot={{ r: 6 }}
                      animationDuration={600}
                    />
                  </AreaChart>
                </ResponsiveContainer>
              )}
            </CardContent>
          </Card>
        </motion.div>

        <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
          <motion.div {...cardMotion} transition={{ duration: 0.3, delay: 0.05 }}>
            <Card className="h-full border-border/60">
              <CardHeader>
                <CardTitle className="text-[1.375rem]">Threat Categories</CardTitle>
              </CardHeader>
              <CardContent>
                {statsLoading ? (
                  <Skeleton className="h-64 rounded-xl" />
                ) : categoryData.length === 0 ? (
                  <div className="flex h-64 flex-col items-center justify-center gap-2 text-muted-foreground">
                    <ShieldCheck className="h-10 w-10" />
                    <p>No categorized threats yet.</p>
                  </div>
                ) : (
                  <div className="grid grid-cols-1 items-center gap-4 sm:grid-cols-2">
                    <div className="relative h-56">
                      <ResponsiveContainer width="100%" height="100%">
                        <PieChart>
                          <Pie
                            data={categoryData}
                            dataKey="value"
                            nameKey="name"
                            innerRadius={62}
                            outerRadius={92}
                            paddingAngle={3}
                            cornerRadius={6}
                            animationDuration={700}
                          >
                            {categoryData.map((_, i) => (
                              <Cell key={i} fill={CATEGORY_COLORS[i % CATEGORY_COLORS.length]} stroke="none" />
                            ))}
                          </Pie>
                          <Tooltip contentStyle={{ background: 'var(--popover)', border: '1px solid var(--border)', borderRadius: 12 }} />
                        </PieChart>
                      </ResponsiveContainer>
                      <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center">
                        <span className="text-3xl font-bold tracking-tight"><AnimatedNumber value={categoryTotal} /></span>
                        <span className="text-xs text-muted-foreground">total</span>
                      </div>
                    </div>
                    <div className="space-y-0.5">
                      {categoryData.map((c, i) => (
                        <DonutLegendRow
                          key={c.name}
                          color={CATEGORY_COLORS[i % CATEGORY_COLORS.length]}
                          label={c.name}
                          value={c.value}
                          percent={categoryTotal ? Math.round((c.value / categoryTotal) * 100) : 0}
                        />
                      ))}
                    </div>
                  </div>
                )}
              </CardContent>
            </Card>
          </motion.div>

          <motion.div {...cardMotion} transition={{ duration: 0.3, delay: 0.1 }}>
            <Card className="h-full border-border/60">
              <CardHeader>
                <CardTitle className="text-[1.375rem]">Risk Level Distribution</CardTitle>
              </CardHeader>
              <CardContent>
                {statsLoading ? (
                  <Skeleton className="h-64 rounded-xl" />
                ) : severityData.length === 0 ? (
                  <div className="flex h-64 flex-col items-center justify-center gap-2 text-muted-foreground">
                    <ShieldCheck className="h-10 w-10" />
                    <p>No severity data yet.</p>
                  </div>
                ) : (
                  <div className="grid grid-cols-1 items-center gap-4 sm:grid-cols-2">
                    <div className="relative h-56">
                      <ResponsiveContainer width="100%" height="100%">
                        <PieChart>
                          <Pie
                            data={severityData}
                            dataKey="value"
                            nameKey="name"
                            innerRadius={62}
                            outerRadius={92}
                            paddingAngle={3}
                            cornerRadius={6}
                            animationDuration={700}
                          >
                            {severityData.map((entry, i) => (
                              <Cell key={i} fill={RISK_COLORS[entry.name] ?? '#94a3b8'} stroke="none" />
                            ))}
                          </Pie>
                          <Tooltip contentStyle={{ background: 'var(--popover)', border: '1px solid var(--border)', borderRadius: 12 }} />
                        </PieChart>
                      </ResponsiveContainer>
                      <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center">
                        <span className="text-3xl font-bold tracking-tight"><AnimatedNumber value={severityTotal} /></span>
                        <span className="text-xs text-muted-foreground">total</span>
                      </div>
                    </div>
                    <div className="space-y-0.5">
                      {severityData.map((s) => (
                        <DonutLegendRow
                          key={s.name}
                          color={RISK_COLORS[s.name] ?? '#94a3b8'}
                          label={s.name}
                          value={s.value}
                          percent={severityTotal ? Math.round((s.value / severityTotal) * 100) : 0}
                        />
                      ))}
                    </div>
                  </div>
                )}
              </CardContent>
            </Card>
          </motion.div>
        </div>

        <div className="grid grid-cols-1 gap-6 sm:grid-cols-2 lg:grid-cols-4">
          <motion.div {...cardMotion} transition={{ duration: 0.3, delay: 0.15 }}>
            <Card className="hover-lift relative overflow-hidden border-border/60 bg-linear-to-br from-card to-card/40">
              <div className="absolute -right-6 -top-6 h-24 w-24 rounded-full bg-info/20 opacity-30 blur-2xl" />
              <CardContent className="relative flex items-start gap-4 p-6">
                <div className="flex h-12 w-12 shrink-0 items-center justify-center rounded-2xl bg-info/15 text-info">
                  <ShieldCheck className="h-6 w-6" />
                </div>
                <div>
                  <div className="text-sm font-medium text-muted-foreground">Total Threats</div>
                  <div className="text-4xl font-bold tracking-tight"><AnimatedNumber value={stats?.total_threats ?? 0} /></div>
                  <div className="mt-1 text-xs text-muted-foreground">over the last {stats?.time_window_hours ?? 24}h</div>
                </div>
              </CardContent>
            </Card>
          </motion.div>

          <motion.div {...cardMotion} transition={{ duration: 0.3, delay: 0.2 }}>
            <Card className="hover-lift relative overflow-hidden border-border/60 bg-linear-to-br from-card to-card/40">
              <div className="absolute -right-6 -top-6 h-24 w-24 rounded-full bg-danger/20 opacity-30 blur-2xl" />
              <CardContent className="relative flex items-start gap-4 p-6">
                <div className="flex h-12 w-12 shrink-0 items-center justify-center rounded-2xl bg-danger/15 text-danger">
                  <AlertOctagon className="h-6 w-6" />
                </div>
                <div>
                  <div className="text-sm font-medium text-muted-foreground">Active Critical</div>
                  <div className="text-4xl font-bold tracking-tight"><AnimatedNumber value={stats?.active_critical ?? 0} /></div>
                  <div className="mt-1 text-xs text-muted-foreground">
                    {(stats?.active_critical ?? 0) > 0 ? 'needs attention' : 'all clear'}
                  </div>
                </div>
              </CardContent>
            </Card>
          </motion.div>

          <motion.div {...cardMotion} transition={{ duration: 0.3, delay: 0.25 }}>
            <Card className="hover-lift relative overflow-hidden border-border/60 bg-linear-to-br from-card to-card/40">
              <div className="absolute -right-6 -top-6 h-24 w-24 rounded-full bg-warning/20 opacity-30 blur-2xl" />
              <CardContent className="relative flex items-start gap-4 p-6">
                <div className="flex h-12 w-12 shrink-0 items-center justify-center rounded-2xl bg-warning/15 text-warning">
                  <Flame className="h-6 w-6" />
                </div>
                <div>
                  <div className="text-sm font-medium text-muted-foreground">Most Common</div>
                  <div className="text-2xl font-bold tracking-tight leading-tight">{mostCommonCategory}</div>
                  <div className="mt-1 text-xs text-muted-foreground">{mostCommonShare}% of all threats</div>
                </div>
              </CardContent>
            </Card>
          </motion.div>

          <motion.div {...cardMotion} transition={{ duration: 0.3, delay: 0.3 }}>
            <Card className="hover-lift relative overflow-hidden border-border/60 bg-linear-to-br from-card to-card/40">
              <div className="absolute -right-6 -top-6 h-24 w-24 rounded-full bg-accent-purple/20 opacity-30 blur-2xl" />
              <CardContent className="relative flex items-start gap-4 p-6">
                <div className="flex h-12 w-12 shrink-0 items-center justify-center rounded-2xl bg-accent-purple/15 text-accent-purple">
                  <CalendarClock className="h-6 w-6" />
                </div>
                <div>
                  <div className="text-sm font-medium text-muted-foreground">Time Window</div>
                  <div className="text-4xl font-bold tracking-tight">{stats?.time_window_hours ?? 24}h</div>
                  <div className="mt-1 text-xs text-muted-foreground">current filter</div>
                </div>
              </CardContent>
            </Card>
          </motion.div>
        </div>
      </div>
    </div>
  );
}
