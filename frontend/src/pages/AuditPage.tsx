import { useState } from 'react';
import { useMutation, useQuery } from '@tanstack/react-query';
import { ShieldCheck, ShieldX } from 'lucide-react';
import { TopBar } from '@/components/layout/TopBar';
import { utcDate } from '@/components/ResponseActions';
import { Button } from '@/components/ui/button';
import { Card, CardContent } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Skeleton } from '@/components/ui/skeleton';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { api } from '@/lib/api';

const PAGE_SIZE = 50;

export default function AuditPage() {
  const [page, setPage] = useState(0);
  const [action, setAction] = useState('');

  const { data, isLoading, isError, error } = useQuery({
    queryKey: ['audit', page, action],
    queryFn: () => api.audit.list({ limit: PAGE_SIZE, offset: page * PAGE_SIZE, action }),
  });
  const verify = useMutation({ mutationFn: api.audit.verify });
  const total = data?.total ?? 0;

  return (
    <div>
      <TopBar
        title="Audit Log"
        description="Who did what, when, and with what outcome"
        actions={
          <div className="flex items-center gap-2">
            <Input
              className="w-56"
              placeholder="Filter by action, e.g. response."
              value={action}
              onChange={(e) => {
                setAction(e.target.value);
                setPage(0);
              }}
            />
            <Button variant="outline" onClick={() => verify.mutate()} disabled={verify.isPending}>
              Verify integrity
            </Button>
          </div>
        }
      />
      <div className="space-y-4 p-8">
        {verify.data && (
          <div
            className={`flex items-center gap-2 rounded-md border p-3 text-sm ${
              verify.data.valid ? 'border-green-500/40 bg-green-500/10' : 'border-destructive/40 bg-destructive/10'
            }`}
          >
            {verify.data.valid ? <ShieldCheck className="h-4 w-4 text-green-600" /> : <ShieldX className="h-4 w-4 text-destructive" />}
            {verify.data.valid
              ? `Hash chain intact: all ${verify.data.checked} entries verified.`
              : `Hash chain broken at entry #${verify.data.first_invalid_id}: the log was edited or entries were deleted.`}
          </div>
        )}
        <Card>
          <CardContent className="p-0">
            {isLoading ? (
              <Skeleton className="m-4 h-48" />
            ) : isError ? (
              <p className="p-4 text-sm text-destructive">{(error as Error).message}</p>
            ) : (data?.entries ?? []).length === 0 ? (
              <p className="p-6 text-sm text-muted-foreground">No audit entries yet.</p>
            ) : (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Time</TableHead>
                    <TableHead>Actor</TableHead>
                    <TableHead>Action</TableHead>
                    <TableHead>Target</TableHead>
                    <TableHead>Outcome</TableHead>
                    <TableHead>Details</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {(data?.entries ?? []).map((entry) => (
                    <TableRow key={entry.id}>
                      <TableCell className="whitespace-nowrap text-xs">{utcDate(entry.created_at.split('.')[0])}</TableCell>
                      <TableCell className="text-xs">{entry.actor}</TableCell>
                      <TableCell className="font-mono text-xs">{entry.action}</TableCell>
                      <TableCell className="text-xs">
                        {entry.target_type ? `${entry.target_type} ${entry.target_id}` : ''}
                      </TableCell>
                      <TableCell className={`text-xs ${entry.outcome === 'failure' || entry.outcome === 'failed' ? 'text-destructive' : ''}`}>
                        {entry.outcome}
                      </TableCell>
                      <TableCell className="max-w-xs truncate font-mono text-[11px] text-muted-foreground" title={JSON.stringify(entry.details)}>
                        {Object.keys(entry.details ?? {}).length ? JSON.stringify(entry.details) : ''}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            )}
          </CardContent>
        </Card>
        <div className="flex items-center justify-between text-sm text-muted-foreground">
          <span>{total} entries</span>
          <div className="flex gap-2">
            <Button variant="outline" size="sm" disabled={page === 0} onClick={() => setPage((p) => p - 1)}>
              Previous
            </Button>
            <Button
              variant="outline"
              size="sm"
              disabled={(page + 1) * PAGE_SIZE >= total}
              onClick={() => setPage((p) => p + 1)}
            >
              Next
            </Button>
          </div>
        </div>
      </div>
    </div>
  );
}
