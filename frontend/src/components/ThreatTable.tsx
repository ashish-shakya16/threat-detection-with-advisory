import type { Threat } from '@/types';
import { SeverityBadge } from '@/components/SeverityBadge';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { AllClearIllustration } from '@/components/GuardMark';
import { cn } from '@/lib/utils';

function formatDetectedAt(detectedAt: string): string {
  try {
    return new Date(detectedAt).toLocaleString();
  } catch {
    return detectedAt;
  }
}

function riskBarColor(score: number): string {
  if (score >= 0.75) return 'bg-danger';
  if (score >= 0.5) return 'bg-warning';
  if (score >= 0.25) return 'bg-info';
  return 'bg-muted-foreground/40';
}

interface ThreatTableProps {
  threats: Threat[];
  onRowClick?: (threat: Threat) => void;
}

export function ThreatTable({ threats, onRowClick }: ThreatTableProps) {
  if (threats.length === 0) {
    return (
      <div className="flex flex-col items-center gap-3 py-14 text-muted-foreground">
        <AllClearIllustration className="h-24 w-auto text-primary" />
        <p className="text-sm font-medium text-foreground">All clear</p>
        <p className="text-xs">No threats detected in this window.</p>
      </div>
    );
  }

  return (
    <Table>
      <TableHeader>
        <TableRow className="hover:bg-transparent">
          <TableHead className="text-xs uppercase tracking-wide text-muted-foreground">Severity</TableHead>
          <TableHead className="text-xs uppercase tracking-wide text-muted-foreground">Threat Name</TableHead>
          <TableHead className="text-xs uppercase tracking-wide text-muted-foreground">Category</TableHead>
          <TableHead className="text-xs uppercase tracking-wide text-muted-foreground">Risk Score</TableHead>
          <TableHead className="text-xs uppercase tracking-wide text-muted-foreground">Last Seen</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {threats.map((threat) => (
          <TableRow
            key={threat.id}
            className={cn('transition-colors', onRowClick && 'cursor-pointer hover:bg-accent/40')}
            onClick={() => onRowClick?.(threat)}
          >
            <TableCell className="py-3"><SeverityBadge severity={threat.severity} /></TableCell>
            <TableCell className="py-3 font-medium">
              <div className="flex items-center gap-2">
                <span>{threat.threat_name}</span>
                {!!threat.occurrence_count && threat.occurrence_count > 1 && (
                  <span className="rounded-full bg-muted px-1.5 py-0.5 text-[10px] font-semibold text-muted-foreground">
                    ×{threat.occurrence_count}
                  </span>
                )}
              </div>
            </TableCell>
            <TableCell className="py-3 text-muted-foreground">{threat.category}</TableCell>
            <TableCell className="py-3">
              <div className="flex items-center gap-2">
                <div className="h-1.5 w-16 overflow-hidden rounded-full bg-muted">
                  <div
                    className={cn('h-full rounded-full', riskBarColor(threat.risk_score))}
                    style={{ width: `${Math.min(threat.risk_score * 100, 100)}%` }}
                  />
                </div>
                <span className="data-numeral text-xs text-muted-foreground">{threat.risk_score.toFixed(2)}</span>
              </div>
            </TableCell>
            <TableCell className="py-3 text-muted-foreground">
              {formatDetectedAt(threat.last_seen_at || threat.detected_at)}
            </TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  );
}
