import { useEffect, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { Mail, Plus, Trash2, Send, Database, Info, AlertTriangle } from 'lucide-react';
import { TopBar } from '@/components/layout/TopBar';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Skeleton } from '@/components/ui/skeleton';
import { Switch } from '@/components/ui/switch';
import { toast } from 'sonner';
import { api } from '@/lib/api';

export default function SettingsPage() {
  const [newEmail, setNewEmail] = useState('');
  const [cooldownDraft, setCooldownDraft] = useState<string | null>(null);
  const [searchParams, setSearchParams] = useSearchParams();
  const queryClient = useQueryClient();

  // The verification link in the email redirects here with the outcome.
  useEffect(() => {
    const verified = searchParams.get('email_verified');
    if (verified === null) return;
    if (verified === '1') toast.success('Email address verified. It will now receive SecureX alerts.');
    else toast.error('Verification link is invalid or has expired.');
    searchParams.delete('email_verified');
    setSearchParams(searchParams, { replace: true });
  }, [searchParams, setSearchParams]);

  const { data: systemInfo, isLoading: infoLoading } = useQuery({
    queryKey: ['system-info'],
    queryFn: api.system.info,
  });

  const { data: notificationStatus, isLoading: notifLoading } = useQuery({
    queryKey: ['notifications', 'status'],
    queryFn: api.notifications.status,
  });

  const { data: deliveries } = useQuery({
    queryKey: ['notifications', 'deliveries'],
    queryFn: api.notifications.deliveries,
    refetchInterval: 30000,
  });

  const addRecipientMutation = useMutation({
    mutationFn: (email: string) => api.notifications.requestRecipientVerification(email),
    onSuccess: () => {
      setNewEmail('');
      queryClient.invalidateQueries({ queryKey: ['notifications', 'status'] });
      toast.success('Verification email sent', {
        description: 'The address is added once the link in that email is opened.',
      });
    },
    onError: (error: Error) => toast.error('Failed to add recipient', { description: error.message }),
  });

  const removeRecipientMutation = useMutation({
    mutationFn: (email: string) => api.notifications.removeRecipient(email),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['notifications', 'status'] });
      toast.success('Recipient removed');
    },
    onError: (error: Error) => toast.error('Failed to remove recipient', { description: error.message }),
  });

  const testNotificationMutation = useMutation({
    mutationFn: api.notifications.sendTest,
    onSuccess: (result) => {
      queryClient.invalidateQueries({ queryKey: ['notifications', 'deliveries'] });
      if (result?.error) toast.warning('Test sent to some recipients', { description: result.error });
      else toast.success('Test notification sent');
    },
    onError: (error: Error) => {
      queryClient.invalidateQueries({ queryKey: ['notifications', 'deliveries'] });
      toast.error('Failed to send test', { description: error.message });
    },
  });

  const updatePreferencesMutation = useMutation({
    mutationFn: (preferences: Parameters<typeof api.notifications.updatePreferences>[0]) =>
      api.notifications.updatePreferences(preferences),
    onSuccess: () => {
      setCooldownDraft(null);
      queryClient.invalidateQueries({ queryKey: ['notifications', 'status'] });
      toast.success('Notification preferences updated');
    },
    onError: (error: Error) => toast.error('Failed to update preferences', { description: error.message }),
  });

  const preferenceToggles = [
    ['enabled', 'Email alerts enabled', notificationStatus?.status === 'enabled'],
    ['critical', 'Critical alerts', notificationStatus?.notification_rules.critical],
    ['high', 'High alerts', notificationStatus?.notification_rules.high],
    ['medium', 'Medium alerts', notificationStatus?.notification_rules.medium],
    ['low', 'Low alerts', notificationStatus?.notification_rules.low],
  ] as const;

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
                {notificationStatus && !notificationStatus.smtp_configured && (
                  <div className="flex gap-2 rounded-md border border-amber-500/40 bg-amber-500/10 p-3 text-xs">
                    <AlertTriangle className="h-4 w-4 shrink-0 text-amber-500" />
                    <span>
                      SMTP credentials are not set. Set <code>SECUREX_SMTP_SENDER</code> and{' '}
                      <code>SECUREX_SMTP_PASSWORD</code> on the server and restart SecureX.
                    </span>
                  </div>
                )}

                <div className="grid gap-3 text-sm sm:grid-cols-2">
                  {preferenceToggles.map(([key, label, checked]) => (
                    <label key={key} className="flex items-center gap-2">
                      <Switch
                        checked={Boolean(checked)}
                        disabled={updatePreferencesMutation.isPending}
                        onCheckedChange={(value) => updatePreferencesMutation.mutate({ [key]: value })}
                      />
                      {label}
                    </label>
                  ))}
                </div>

                <div className="flex flex-wrap items-center gap-2 text-sm">
                  <span className="text-muted-foreground">Suppress duplicate alerts for</span>
                  <Input
                    type="number"
                    min={0}
                    max={86400}
                    className="h-8 w-24"
                    value={cooldownDraft ?? String(notificationStatus?.cooldown_seconds ?? 0)}
                    onChange={(e) => setCooldownDraft(e.target.value)}
                  />
                  <span className="text-muted-foreground">seconds</span>
                  {cooldownDraft !== null && (
                    <Button
                      size="sm"
                      variant="outline"
                      disabled={updatePreferencesMutation.isPending || cooldownDraft === ''}
                      onClick={() => updatePreferencesMutation.mutate({ cooldown_seconds: Number(cooldownDraft) })}
                    >
                      Save
                    </Button>
                  )}
                </div>

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
                    type="email"
                    placeholder="Add an address (a verification link will be sent)"
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

                <Button
                  variant="outline"
                  className="w-full"
                  onClick={() => testNotificationMutation.mutate()}
                  disabled={testNotificationMutation.isPending}
                >
                  <Send className="mr-2 h-4 w-4" />
                  {testNotificationMutation.isPending ? 'Sending...' : 'Send Test Notification'}
                </Button>

                <div>
                  <div className="mb-2 text-sm font-medium">Recent deliveries</div>
                  {(deliveries ?? []).length === 0 ? (
                    <p className="text-xs text-muted-foreground">No emails sent yet</p>
                  ) : (
                    <ul className="max-h-48 space-y-1 overflow-y-auto text-xs">
                      {(deliveries ?? []).map((delivery) => (
                        <li key={delivery.id} className="flex justify-between gap-2 rounded border px-2 py-1">
                          <span className="truncate">
                            {delivery.threat_name} ({delivery.risk_level}) to {delivery.recipient}
                          </span>
                          <span
                            className={`shrink-0 ${delivery.status === 'sent' ? 'text-green-600' : 'text-destructive'}`}
                            title={delivery.error_message || undefined}
                          >
                            {delivery.status} · {new Date(`${delivery.sent_at.replace(' ', 'T')}Z`).toLocaleString()}
                          </span>
                        </li>
                      ))}
                    </ul>
                  )}
                </div>
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
