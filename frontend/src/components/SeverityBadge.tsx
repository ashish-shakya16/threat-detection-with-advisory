import { cn } from '@/lib/utils';

const severityStyles: Record<string, string> = {
  critical: 'bg-red-600/15 text-red-500 border-red-600/30',
  high: 'bg-orange-600/15 text-orange-500 border-orange-600/30',
  medium: 'bg-amber-500/15 text-amber-500 border-amber-500/30',
  low: 'bg-blue-500/15 text-blue-500 border-blue-500/30',
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
