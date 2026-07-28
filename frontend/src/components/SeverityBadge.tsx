import { cn } from '@/lib/utils';

const severityStyles: Record<string, string> = {
  critical: 'bg-danger/12 text-danger border-danger/30',
  high: 'bg-warning/12 text-warning border-warning/30',
  medium: 'bg-info/12 text-info border-info/30',
  low: 'bg-muted text-muted-foreground border-border',
};

export function SeverityBadge({ severity }: { severity: string }) {
  const normalized = severity.toLowerCase();
  const style = severityStyles[normalized] ?? 'bg-muted text-muted-foreground border-border';

  return (
    <span className={cn('inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-xs font-semibold capitalize', style)}>
      <span className="h-1.5 w-1.5 rounded-full bg-current" />
      {severity}
    </span>
  );
}
