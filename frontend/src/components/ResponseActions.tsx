import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Check, Play, ShieldAlert, X } from 'lucide-react';
import { toast } from 'sonner';
import { Button } from '@/components/ui/button';
import { api } from '@/lib/api';
import type { ResponseAction, ResponseStatus } from '@/types';

const ACTION_LABELS: Record<ResponseAction['action'], string> = {
  suspend_process: 'Suspend process (reversible)',
  terminate_process: 'Terminate process',
};

const STATUS_STYLES: Record<ResponseStatus, string> = {
  proposed: 'bg-amber-500/15 text-amber-700 dark:text-amber-300',
  approved: 'bg-blue-500/15 text-blue-700 dark:text-blue-300',
  executed: 'bg-green-500/15 text-green-700 dark:text-green-300',
  dry_run: 'bg-blue-500/15 text-blue-700 dark:text-blue-300',
  rejected: 'bg-muted text-muted-foreground',
  expired: 'bg-muted text-muted-foreground',
  resumed: 'bg-muted text-muted-foreground',
  failed: 'bg-destructive/15 text-destructive',
};

export function utcDate(value: string | null) {
  return value ? new Date(`${value.replace(' ', 'T')}Z`).toLocaleString() : '';
}

interface ResponseActionListProps {
  actions: ResponseAction[];
  executionEnabled: boolean;
  showThreat?: boolean;
}

export function ResponseActionList({ actions, executionEnabled, showThreat }: ResponseActionListProps) {
  const queryClient = useQueryClient();
  const decide = useMutation({
    mutationFn: ({ id, decision }: { id: number; decision: 'approve' | 'reject' | 'resume' }) =>
      api.responses[decision](id),
    onSuccess: (result) => {
      queryClient.invalidateQueries({ queryKey: ['responses'] });
      toast.success(`Response ${result.status.replace('_', ' ')}`, { description: result.result_message ?? undefined });
    },
    onError: (error: Error) => {
      queryClient.invalidateQueries({ queryKey: ['responses'] });
      toast.error('Response action refused', { description: error.message });
    },
  });

  if (actions.length === 0) {
    return <p className="text-xs text-muted-foreground">No containment actions proposed.</p>;
  }

  return (
    <ul className="space-y-2">
      {actions.map((action) => (
        <li key={action.id} className="rounded-md border p-2 text-xs">
          <div className="flex items-center justify-between gap-2">
            <span className="font-medium">{ACTION_LABELS[action.action]}</span>
            <span className={`rounded px-1.5 py-0.5 ${STATUS_STYLES[action.status]}`}>
              {action.status.replace('_', ' ')}
            </span>
          </div>
          <div className="mt-1 text-muted-foreground">
            {action.target_name} (PID {action.target_pid}) · {action.reason}
            {showThreat && <> · threat #{action.threat_id}</>}
          </div>
          <div className="text-muted-foreground">
            Proposed {utcDate(action.proposed_at)}
            {action.status === 'proposed' && <> · expires {utcDate(action.expires_at)}</>}
            {action.decided_by && <> · {action.status.replace('_', ' ')} by {action.decided_by}</>}
          </div>
          {action.result_message && <div className="mt-1">{action.result_message}</div>}
          {action.status === 'proposed' && (
            <div className="mt-2 flex gap-2">
              <Button
                size="sm"
                variant={action.action === 'terminate_process' ? 'destructive' : 'default'}
                disabled={decide.isPending}
                onClick={() => decide.mutate({ id: action.id, decision: 'approve' })}
              >
                <Check className="mr-1 h-3.5 w-3.5" />
                {executionEnabled ? 'Approve and run' : 'Approve (dry run)'}
              </Button>
              <Button
                size="sm"
                variant="outline"
                disabled={decide.isPending}
                onClick={() => decide.mutate({ id: action.id, decision: 'reject' })}
              >
                <X className="mr-1 h-3.5 w-3.5" /> Reject
              </Button>
            </div>
          )}
          {action.status === 'executed' && action.action === 'suspend_process' && (
            <Button
              size="sm"
              variant="outline"
              className="mt-2"
              disabled={decide.isPending}
              onClick={() => decide.mutate({ id: action.id, decision: 'resume' })}
            >
              <Play className="mr-1 h-3.5 w-3.5" /> Resume process
            </Button>
          )}
        </li>
      ))}
    </ul>
  );
}

export function ThreatResponsePanel({ threatId }: { threatId: number }) {
  const { data, isLoading } = useQuery({
    queryKey: ['responses', 'threat', threatId],
    queryFn: () => api.responses.list({ threatId }),
  });

  return (
    <div className="rounded-md border p-3">
      <div className="mb-2 flex items-center gap-1.5 text-sm font-medium">
        <ShieldAlert className="h-4 w-4" /> Response actions
      </div>
      {isLoading ? (
        <p className="text-xs text-muted-foreground">Loading...</p>
      ) : (
        <>
          {data && !data.execution_enabled && (
            <p className="mb-2 text-xs text-muted-foreground">
              Execution is disabled (<code>response.execution_enabled</code>), so approvals are recorded as dry runs.
            </p>
          )}
          <ResponseActionList actions={data?.data ?? []} executionEnabled={Boolean(data?.execution_enabled)} />
        </>
      )}
    </div>
  );
}
