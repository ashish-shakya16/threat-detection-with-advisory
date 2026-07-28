import type { Threat } from '@/types';
import { SeverityBadge } from '@/components/SeverityBadge';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { ShieldCheck } from 'lucide-react';
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
  return 'bg-success';
}

interface ThreatTableProps {
  threats: Threat[];
  onRowClick?: (threat: Threat) => void;
}

export function ThreatTable({ threats, onRowClick }: ThreatTableProps) {
  if (threats.length === 0) {
    return (
      <div className="flex flex-col items-center gap-2 py-12 text-muted-foreground">
        <ShieldCheck className="h-10 w-10" />
        <p>No threats detected. System is secure.</p>
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
          <TableHead className="text-xs uppercase tracking-wide text-muted-foreground">Detected</TableHead>
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
            <TableCell className="py-3 font-medium">{threat.threat_name}</TableCell>
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
            <TableCell className="py-3 text-muted-foreground">{formatDetectedAt(threat.detected_at)}</TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  );
}
