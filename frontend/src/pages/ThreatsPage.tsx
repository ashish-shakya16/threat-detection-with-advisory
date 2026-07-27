import { useMemo, useState } from 'react';
import { TopBar } from '@/components/layout/TopBar';
import { ThreatTable } from '@/components/ThreatTable';
import { ThreatDetailDialog } from '@/components/ThreatDetailDialog';
import { Card, CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Skeleton } from '@/components/ui/skeleton';
import { useThreats } from '@/hooks/useThreats';
import type { Threat } from '@/types';
import { Search } from 'lucide-react';

const severityFilters = ['all', 'critical', 'high', 'medium', 'low'];

export default function ThreatsPage() {
  const [hours, setHours] = useState(24);
  const [severityFilter, setSeverityFilter] = useState('all');
  const [search, setSearch] = useState('');
  const [selectedThreat, setSelectedThreat] = useState<Threat | null>(null);

  const { data: threats, isLoading } = useThreats(hours);

  const filtered = useMemo(() => {
    if (!threats) return [];
    return threats.filter((t) => {
      const matchesSeverity = severityFilter === 'all' || t.severity.toLowerCase() === severityFilter;
      const matchesSearch = !search || t.threat_name.toLowerCase().includes(search.toLowerCase());
      return matchesSeverity && matchesSearch;
    });
  }, [threats, severityFilter, search]);

  return (
    <div>
      <TopBar
        title="Threat Management"
        description="View and manage detected security threats"
        actions={
          <div className="relative">
            <Search className="absolute left-2.5 top-2.5 h-4 w-4 text-muted-foreground" />
            <Input
              placeholder="Search threats..."
              className="w-64 pl-8"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
            />
          </div>
        }
      />

      <div className="space-y-4 p-8">
        <div className="flex flex-wrap items-center gap-4">
          <div className="flex gap-2">
            {severityFilters.map((f) => (
              <Button
                key={f}
                size="sm"
                variant={severityFilter === f ? 'default' : 'outline'}
                onClick={() => setSeverityFilter(f)}
                className="capitalize"
              >
                {f}
              </Button>
            ))}
          </div>

          <Select value={String(hours)} onValueChange={(v) => setHours(Number(v))}>
            <SelectTrigger className="w-48">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="24">Last 24 hours</SelectItem>
              <SelectItem value="168">Last 7 days</SelectItem>
              <SelectItem value="720">Last 30 days</SelectItem>
            </SelectContent>
          </Select>
        </div>

        <Card>
          <CardContent className="p-0">
            {isLoading ? (
              <div className="p-6"><Skeleton className="h-64" /></div>
            ) : (
              <ThreatTable threats={filtered} onRowClick={setSelectedThreat} />
            )}
          </CardContent>
        </Card>
      </div>

      <ThreatDetailDialog threat={selectedThreat} onClose={() => setSelectedThreat(null)} />
    </div>
  );
}
