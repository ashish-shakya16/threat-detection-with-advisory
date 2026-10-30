import { useState } from 'react';
import type { FormEvent } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Activity, FileWarning, Link2, Radar, RotateCcw, ShieldCheck } from 'lucide-react';
import { toast } from 'sonner';
import { TopBar } from '@/components/layout/TopBar';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Skeleton } from '@/components/ui/skeleton';
import { api } from '@/lib/api';
import type { PhishingResult } from '@/types';

const VERDICT_STYLES: Record<PhishingResult['verdict'], string> = {
  'High-risk URL indicators': 'bg-danger-bg text-danger',
  'Suspicious URL': 'bg-warning-bg text-warning',
  'No known phishing indicators': 'bg-success-bg text-success',
};

function EngineStatus() {
  const queryClient = useQueryClient();
  const { data, isLoading } = useQuery({
    queryKey: ['detection-status'],
    queryFn: api.detection.status,
    refetchInterval: 10000,
  });
  const reset = useMutation({
    mutationFn: api.detection.resetBaseline,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['detection-status'] });
      toast.success('Baseline cleared. SecureX will learn normal behaviour again while monitoring runs.');
    },
    onError: (error: Error) => toast.error('Reset failed', { description: error.message }),
  });

  if (isLoading || !data) return <Skeleton className="h-48" />;
  const baseline = data.anomaly_baseline;
  const ransomware = data.ransomware_monitor;

  return (
    <div className="grid gap-4 lg:grid-cols-3">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base"><ShieldCheck className="h-4 w-4" /> Behaviour rules</CardTitle>
          <CardDescription>Known suspicious patterns</CardDescription>
        </CardHeader>
        <CardContent className="text-sm text-muted-foreground">
          {data.rules} rules check processes and connections every monitoring cycle, for example look-alike
          system process names, commonly abused ports and connection floods.
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base"><FileWarning className="h-4 w-4" /> Ransomware-like behaviour</CardTitle>
          <CardDescription>
            {ransomware.running ? 'Watching for bursts of file changes' : ransomware.enabled ? 'Not running' : 'Disabled'}
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-2 text-sm text-muted-foreground">
          {ransomware.error && <p className="text-destructive">{ransomware.error}</p>}
          {ransomware.watching.length > 0 && (
            <ul className="space-y-0.5 font-mono text-xs">
              {ransomware.watching.map((path) => <li key={path} className="truncate" title={path}>{path}</li>)}
            </ul>
          )}
          <p className="text-xs">
            Alerts on mass renames to an unusual extension, ransom-note files, or {ransomware.thresholds.bulk_modification}+
            files changed within {ransomware.thresholds.window_seconds} seconds. Only file names are recorded.
          </p>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base"><Radar className="h-4 w-4" /> Unknown threats</CardTitle>
          <CardDescription>
            {baseline.state === 'active' ? 'Active: comparing processes with the learned baseline'
              : baseline.state === 'learning' ? 'Learning what is normal on this computer' : 'Disabled'}
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-3 text-sm text-muted-foreground">
          {baseline.state === 'learning' && (
            <>
              <div className="h-2 overflow-hidden rounded-full bg-muted">
                <div className="h-full bg-primary" style={{ width: `${Math.round((baseline.progress ?? 0) * 100)}%` }} />
              </div>
              <p className="text-xs">
                {Math.round((baseline.progress ?? 0) * 100)}% · {baseline.cycles}/{baseline.required_cycles} monitoring
                cycles, {baseline.samples}/{baseline.required_samples} process snapshots.
                {!data.monitoring_active && ' Start monitoring on the Dashboard to continue learning.'}
              </p>
            </>
          )}
          {baseline.state === 'active' && (
            <p className="text-xs">
              Learned from {baseline.samples} snapshots on {new Date(baseline.trained_at ?? '').toLocaleString()}.
              Tuned so about {((baseline.false_positive_target ?? 0) * 100).toFixed(1)}% of normal activity would
              still be flagged.
            </p>
          )}
          <p className="text-xs">
            Strong deviations are reported as <em>Unknown suspicious activity</em> with the measurements that stood
            out. They are not given a malware name.
          </p>
          {baseline.state !== 'disabled' && (
            <Button size="sm" variant="outline" disabled={reset.isPending} onClick={() => reset.mutate()}>
              <RotateCcw className="mr-1.5 h-3.5 w-3.5" /> Re-learn baseline
            </Button>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

function UrlChecker() {
  const [url, setUrl] = useState('');
  const analyze = useMutation({
    mutationFn: api.detection.analyzeUrl,
    onError: (error: Error) => toast.error('Could not analyse URL', { description: error.message }),
  });
  const result = analyze.data;

  function submit(event: FormEvent) {
    event.preventDefault();
    if (url.trim()) analyze.mutate(url.trim());
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2"><Link2 className="h-5 w-5" /> Phishing URL check</CardTitle>
        <CardDescription>
          Paste a link from an email or message. SecureX inspects it locally and never opens it.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <form onSubmit={submit} className="flex gap-2">
          <Input
            value={url}
            maxLength={2048}
            placeholder="https://example.com/login"
            onChange={(e) => setUrl(e.target.value)}
          />
          <Button type="submit" disabled={analyze.isPending || !url.trim()}>
            {analyze.isPending ? 'Checking…' : 'Check'}
          </Button>
        </form>

        {result && (
          <div className="space-y-4 rounded-md border p-4">
            <div className="flex flex-wrap items-center gap-3">
              <span className={`rounded px-2 py-1 text-sm font-medium ${VERDICT_STYLES[result.verdict]}`}>
                {result.verdict}
              </span>
              <span className="text-sm text-muted-foreground">Risk score {result.score}/100</span>
            </div>
            <div className="text-sm">
              <span className="text-muted-foreground">Real destination: </span>
              <span className="font-mono">{result.host}</span>
              {result.registered_domain !== result.host && (
                <span className="text-muted-foreground"> (registered domain {result.registered_domain})</span>
              )}
            </div>
            {result.evidence.length > 0 && (
              <div>
                <div className="mb-1 text-sm font-medium">Evidence</div>
                <ul className="space-y-1.5 text-sm">
                  {result.evidence.map((item) => (
                    <li key={item.indicator + item.detail}>
                      <span className="font-medium">{item.indicator}</span>
                      <span className="text-muted-foreground"> · {item.detail}</span>
                    </li>
                  ))}
                </ul>
              </div>
            )}
            <div>
              <div className="mb-1 text-sm font-medium">What to do</div>
              <ul className="list-disc space-y-1 pl-5 text-sm text-muted-foreground">
                {result.recommendations.map((item) => <li key={item}>{item}</li>)}
              </ul>
            </div>
            <p className="text-xs text-muted-foreground">{result.limitations}</p>
          </div>
        )}
      </CardContent>
    </Card>
  );
}

export default function DetectionPage() {
  return (
    <div>
      <TopBar title="Detection" description="How SecureX finds threats, and tools to check things yourself" />
      <div className="space-y-6 p-8">
        <div className="flex items-start gap-2 rounded-md border bg-muted/40 p-3 text-xs text-muted-foreground">
          <Activity className="mt-0.5 h-4 w-4 shrink-0" />
          <span>
            Every detection is classified (for example suspicious process, network anomaly, possible
            ransomware-like behaviour or unknown suspicious activity) and marked <strong>unverified</strong>: SecureX
            has no malware-signature database or threat feed, so it reports evidence and likelihood, not confirmed
            malware names.
          </span>
        </div>
        <EngineStatus />
        <UrlChecker />
      </div>
    </div>
  );
}
