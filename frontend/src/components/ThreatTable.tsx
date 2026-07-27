import type { Threat } from '@/types';
import { SeverityBadge } from '@/components/SeverityBadge';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { ShieldCheck } from 'lucide-react';

function formatDetectedAt(detectedAt: string): string {
  try {
    return new Date(detectedAt).toLocaleString();
  } catch {
    return detectedAt;
  }
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
        <TableRow>
          <TableHead>Severity</TableHead>
          <TableHead>Threat Name</TableHead>
          <TableHead>Category</TableHead>
          <TableHead>Risk Score</TableHead>
          <TableHead>Detected</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {threats.map((threat) => (
          <TableRow
            key={threat.id}
            className={onRowClick ? 'cursor-pointer' : undefined}
            onClick={() => onRowClick?.(threat)}
          >
            <TableCell><SeverityBadge severity={threat.severity} /></TableCell>
            <TableCell className="font-medium">{threat.threat_name}</TableCell>
            <TableCell>{threat.category}</TableCell>
            <TableCell>{threat.risk_score.toFixed(2)}</TableCell>
            <TableCell className="text-muted-foreground">{formatDetectedAt(threat.detected_at)}</TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  );
}
