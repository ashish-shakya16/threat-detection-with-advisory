import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { TopBar } from '@/components/layout/TopBar';
import { ResponseActionList } from '@/components/ResponseActions';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Skeleton } from '@/components/ui/skeleton';
import { api } from '@/lib/api';

const STATUS_FILTERS = ['proposed', 'all', 'executed', 'dry_run', 'rejected', 'failed', 'expired', 'resumed'];

export default function ResponsesPage() {
  const [status, setStatus] = useState('proposed');
  const { data, isLoading, isError, error } = useQuery({
    queryKey: ['responses', 'list', status],
    queryFn: () => api.responses.list({ status: status === 'all' ? '' : status }),
    refetchInterval: 15000,
  });

  return (
    <div>
      <TopBar
        title="Response Center"
        description="Review containment actions proposed for High and Critical threats"
        actions={
          <Select value={status} onValueChange={setStatus}>
            <SelectTrigger className="w-40"><SelectValue /></SelectTrigger>
            <SelectContent>
              {STATUS_FILTERS.map((value) => (
                <SelectItem key={value} value={value}>
                  {value === 'proposed' ? 'Awaiting approval' : value.replace('_', ' ')}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        }
      />
      <div className="space-y-6 p-8">
        <Card>
          <CardHeader>
            <CardTitle>How responses work</CardTitle>
            <CardDescription>
              Low risk is observed, Medium and above alerts, High proposes a reversible suspension, and Critical
              also proposes termination. Nothing runs without your approval. Before acting, SecureX re-checks that
              the process is the same one that was flagged and refuses protected system processes.
              {data && !data.execution_enabled && (
                <> Execution is currently disabled in <code>config/config.yaml</code>, so approvals are dry runs.</>
              )}
            </CardDescription>
          </CardHeader>
          <CardContent>
            {isLoading ? (
              <Skeleton className="h-32" />
            ) : isError ? (
              <p className="text-sm text-destructive">{(error as Error).message}</p>
            ) : (
              <ResponseActionList
                actions={data?.data ?? []}
                executionEnabled={Boolean(data?.execution_enabled)}
                showThreat
              />
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
