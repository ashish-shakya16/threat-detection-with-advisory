import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { Mail, Plus, Trash2, Send, Database, Info } from 'lucide-react';
import { TopBar } from '@/components/layout/TopBar';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Skeleton } from '@/components/ui/skeleton';
import { toast } from 'sonner';
import { api } from '@/lib/api';

export default function SettingsPage() {
  const [newEmail, setNewEmail] = useState('');
  const queryClient = useQueryClient();

  const { data: systemInfo, isLoading: infoLoading } = useQuery({
    queryKey: ['system-info'],
    queryFn: api.system.info,
  });

  const { data: notificationStatus, isLoading: notifLoading } = useQuery({
    queryKey: ['notifications', 'status'],
    queryFn: api.notifications.status,
  });

  const addRecipientMutation = useMutation({
    mutationFn: (email: string) => api.notifications.addRecipient(email),
    onSuccess: () => {
      setNewEmail('');
      queryClient.invalidateQueries({ queryKey: ['notifications', 'status'] });
      toast.success('Recipient added');
    },
    onError: (error: Error) => toast.error('Failed to add recipient', { description: error.message }),
  });

  const removeRecipientMutation = useMutation({
    mutationFn: (email: string) => api.notifications.removeRecipient(email),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['notifications', 'status'] });
      toast.success('Recipient removed');
    },
  });

  const testNotificationMutation = useMutation({
    mutationFn: api.notifications.sendTest,
    onSuccess: () => toast.success('Test notification sent'),
    onError: (error: Error) => toast.error('Failed to send test', { description: error.message }),
  });

  return (
    <div>
      <TopBar title="System Settings" description="View system information and manage notification recipients" />

      <div className="grid grid-cols-1 gap-6 p-8 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2"><Database className="h-5 w-5" /> System Information</CardTitle>
            <CardDescription>Read-only system details</CardDescription>
          </CardHeader>
          <CardContent>
            {infoLoading ? (
              <Skeleton className="h-32" />
            ) : (
              <dl className="grid grid-cols-2 gap-4 text-sm">
                <div>
                  <dt className="text-muted-foreground">Version</dt>
                  <dd className="font-medium">{systemInfo?.version}</dd>
                </div>
                <div>
                  <dt className="text-muted-foreground">Database</dt>
                  <dd className="font-medium capitalize">{systemInfo?.database_type}</dd>
                </div>
                <div>
                  <dt className="text-muted-foreground">Rules Loaded</dt>
                  <dd className="font-medium">{systemInfo?.rules_loaded}</dd>
                </div>
              </dl>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2"><Mail className="h-5 w-5" /> Email Notifications</CardTitle>
            <CardDescription>
              Status: {notifLoading ? '...' : notificationStatus?.status === 'enabled' ? 'Enabled' : 'Disabled'}
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            {notifLoading ? (
              <Skeleton className="h-32" />
            ) : (
              <>
                <div className="space-y-2">
                  {(notificationStatus?.recipients ?? []).length === 0 && (
                    <p className="text-sm text-muted-foreground">No recipients configured</p>
                  )}
                  {(notificationStatus?.recipients ?? []).map((email) => (
                    <div key={email} className="flex items-center justify-between rounded-md border px-3 py-2 text-sm">
                      <span>{email}</span>
                      <Button
                        variant="ghost"
                        size="icon"
                        onClick={() => removeRecipientMutation.mutate(email)}
                      >
                        <Trash2 className="h-4 w-4" />
                      </Button>
                    </div>
                  ))}
                </div>

                <div className="flex gap-2">
                  <Input
                    placeholder="Enter email address..."
                    value={newEmail}
                    onChange={(e) => setNewEmail(e.target.value)}
                  />
                  <Button
                    onClick={() => newEmail && addRecipientMutation.mutate(newEmail)}
                    disabled={addRecipientMutation.isPending}
                  >
                    <Plus className="h-4 w-4" />
                  </Button>
                </div>

                <Button variant="outline" className="w-full" onClick={() => testNotificationMutation.mutate()}>
                  <Send className="mr-2 h-4 w-4" /> Send Test Notification
                </Button>
              </>
            )}
          </CardContent>
        </Card>

        <Card className="lg:col-span-2">
          <CardHeader>
            <CardTitle className="flex items-center gap-2"><Info className="h-5 w-5" /> About Monitoring Configuration</CardTitle>
          </CardHeader>
          <CardContent>
            <p className="text-sm text-muted-foreground">
              Scan intervals, CPU/memory thresholds, and detection rules are configured via{' '}
              <code className="rounded bg-muted px-1.5 py-0.5">config/config.yaml</code> and{' '}
              <code className="rounded bg-muted px-1.5 py-0.5">config/rules.json</code> on the server.
              Editing these values from the web UI is not yet supported.
            </p>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
