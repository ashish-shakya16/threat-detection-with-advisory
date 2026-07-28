import type { LucideIcon } from 'lucide-react';
import { Card, CardContent } from '@/components/ui/card';
import { cn } from '@/lib/utils';

interface StatCardProps {
  label: string;
  value: number | string;
  icon: LucideIcon;
  colorClass: string;
  helper?: string;
}

export function StatCard({ label, value, icon: Icon, colorClass, helper }: StatCardProps) {
  return (
    <Card className="hover-lift border-border">
      <CardContent className="flex items-start gap-4 p-5">
        <div className={cn('flex h-10 w-10 shrink-0 items-center justify-center rounded-md', colorClass)}>
          <Icon className="h-5 w-5" />
        </div>
        <div className="min-w-0 flex-1">
          <div className="text-xs font-medium uppercase tracking-wide text-muted-foreground">{label}</div>
          <div className="data-numeral mt-1 text-3xl font-semibold tracking-tight">{value}</div>
          {helper && <div className="mt-0.5 text-xs text-muted-foreground">{helper}</div>}
        </div>
      </CardContent>
    </Card>
  );
}
