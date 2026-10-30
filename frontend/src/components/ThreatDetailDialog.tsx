import { useEffect, useState } from 'react';
import { Bot } from 'lucide-react';
import type { AssistantResponse, RiskContext, Threat } from '@/types';
import { SeverityBadge } from '@/components/SeverityBadge';
import { AssistantAnswer } from '@/components/AssistantAnswer';
import { ThreatResponsePanel } from '@/components/ResponseActions';
import { Button } from '@/components/ui/button';
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription } from '@/components/ui/dialog';
import { api } from '@/lib/api';

interface ThreatDetailDialogProps {
  threat: Threat | null;
  onClose: () => void;
}

function parseEvidence(value?: string | null): string[] {
  if (!value) return [];
  try {
    const parsed = JSON.parse(value);
    return Array.isArray(parsed) ? parsed.map(String) : [];
  } catch {
    return [];
  }
}

const METHOD_LABELS: Record<string, string> = {
  rule: 'Behaviour rule',
  file_behaviour: 'File-activity monitor',
  anomaly: 'Learned-baseline anomaly',
};

function parseRiskContext(value?: string | null): RiskContext | null {
  if (!value) return null;
  try {
    return JSON.parse(value) as RiskContext;
  } catch {
    return null;
  }
}

export function ThreatDetailDialog({ threat, onClose }: ThreatDetailDialogProps) {
  const [explanation, setExplanation] = useState<AssistantResponse | null>(null);
  const [explaining, setExplaining] = useState(false);
  const [explainError, setExplainError] = useState('');

  useEffect(() => {
    setExplanation(null);
    setExplainError('');
  }, [threat?.id]);

  const riskContext = parseRiskContext(threat?.risk_context);
  const evidence = parseEvidence(threat?.evidence);

  async function explain() {
    if (!threat) return;
    setExplaining(true);
    setExplainError('');
    try {
      setExplanation(await api.assistant.explainThreat(threat.id));
    } catch (error) {
      setExplainError((error as Error).message);
    } finally {
      setExplaining(false);
    }
  }

  return (
    <Dialog open={!!threat} onOpenChange={(open) => !open && onClose()}>
      <DialogContent className="max-h-[85vh] max-w-lg overflow-y-auto">
        {threat && (
          <>
            <DialogHeader>
              <DialogTitle className="flex items-center gap-2">
                {threat.threat_name}
                <SeverityBadge severity={threat.severity} />
              </DialogTitle>
              <DialogDescription>{threat.category}</DialogDescription>
            </DialogHeader>
            <div className="space-y-3 text-sm">
              <div className="grid grid-cols-2 gap-2">
                <div>
                  <div className="text-muted-foreground">Risk Level</div>
                  <div className="font-medium">{threat.risk_level}</div>
                </div>
                <div>
                  <div className="text-muted-foreground">Risk Score</div>
                  <div className="font-medium">{threat.risk_score.toFixed(2)}</div>
                </div>
                <div>
                  <div className="text-muted-foreground">Detected</div>
                  <div className="font-medium">{new Date(threat.detected_at).toLocaleString()}</div>
                </div>
                <div>
                  <div className="text-muted-foreground">Status</div>
                  <div className="font-medium capitalize">{threat.status}</div>
                </div>
              </div>
              {threat.description && (
                <div>
                  <div className="text-muted-foreground">Description</div>
                  <p>{threat.description}</p>
                </div>
              )}
              {threat.classification && (
                <div className="rounded-md border p-3">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="font-medium">{threat.classification}</span>
                    <span className="rounded bg-warning-bg px-1.5 py-0.5 text-[11px] text-warning">
                      {threat.verification_status === 'unverified' ? 'Unverified' : threat.verification_status}
                    </span>
                  </div>
                  {threat.detection_method && (
                    <div className="mt-0.5 text-xs text-muted-foreground">
                      Detected by: {METHOD_LABELS[threat.detection_method] ?? threat.detection_method}
                    </div>
                  )}
                  {evidence.length > 0 && (
                    <ul className="mt-2 list-disc space-y-0.5 pl-4 text-xs text-muted-foreground">
                      {evidence.map((item) => <li key={item}>{item}</li>)}
                    </ul>
                  )}
                </div>
              )}
              {riskContext && (
                <div className="rounded-md border p-3">
                  <div className="mb-1 font-medium">Risk context</div>
                  <div className="grid grid-cols-2 gap-1 text-xs">
                    <span className="text-muted-foreground">Asset criticality</span>
                    <span className="capitalize">{riskContext.asset_criticality}</span>
                    <span className="text-muted-foreground">Network exposure</span>
                    <span className="capitalize">{riskContext.exposure}</span>
                    <span className="text-muted-foreground">Privileged account</span>
                    <span>{riskContext.privileged_user ? 'Yes' : 'No'}</span>
                    {riskContext.ml_anomaly_score !== undefined && (
                      <>
                        <span className="text-muted-foreground">ML anomaly score</span>
                        <span>{riskContext.ml_anomaly_score.toFixed(2)}</span>
                      </>
                    )}
                  </div>
                  {riskContext.adjustments?.length > 0 && (
                    <ul className="mt-2 list-disc pl-4 text-xs text-muted-foreground">
                      {riskContext.adjustments.map((item) => <li key={item}>{item}</li>)}
                    </ul>
                  )}
                </div>
              )}
              {threat.advisory && (
                <div className="rounded-md border bg-muted/50 p-3">
                  <div className="font-medium">{threat.advisory.title}</div>
                  <p className="mt-1 text-muted-foreground">{threat.advisory.description}</p>
                </div>
              )}
              <ThreatResponsePanel threatId={threat.id} />
              {explanation ? (
                <div className="rounded-md border p-3">
                  <AssistantAnswer
                    content={explanation.response}
                    mode={explanation.mode}
                    recommendations={explanation.recommendations}
                    evidence={explanation.evidence}
                    warning={explanation.warning}
                    uncertain={explanation.uncertain}
                  />
                </div>
              ) : (
                <Button variant="outline" className="w-full" onClick={explain} disabled={explaining}>
                  <Bot className="mr-2 h-4 w-4" />
                  {explaining ? 'Explaining...' : 'Explain with AI Assistant'}
                </Button>
              )}
              {explainError && <p className="text-xs text-destructive">{explainError}</p>}
            </div>
          </>
        )}
      </DialogContent>
    </Dialog>
  );
}
