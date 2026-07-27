import type { Threat } from '@/types';
import { SeverityBadge } from '@/components/SeverityBadge';
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription } from '@/components/ui/dialog';

interface ThreatDetailDialogProps {
  threat: Threat | null;
  onClose: () => void;
}

export function ThreatDetailDialog({ threat, onClose }: ThreatDetailDialogProps) {
  return (
    <Dialog open={!!threat} onOpenChange={(open) => !open && onClose()}>
      <DialogContent className="max-w-lg">
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
              {threat.advisory && (
                <div className="rounded-md border bg-muted/50 p-3">
                  <div className="font-medium">{threat.advisory.title}</div>
                  <p className="mt-1 text-muted-foreground">{threat.advisory.description}</p>
                </div>
              )}
            </div>
          </>
        )}
      </DialogContent>
    </Dialog>
  );
}
