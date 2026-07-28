import type { LucideIcon } from 'lucide-react';
import { Card, CardContent } from '@/components/ui/card';
import { cn } from '@/lib/utils';

interface StatCardProps {
  label: string;
  value: number | string;
  icon: LucideIcon;
  colorClass: string;
}

export function StatCard({ label, value, icon: Icon, colorClass }: StatCardProps) {
  return (
    <Card className="hover-lift relative overflow-hidden border-border/60 bg-linear-to-br from-card to-card/40">
      <div className={cn('absolute -right-6 -top-6 h-24 w-24 rounded-full opacity-20 blur-2xl', colorClass)} />
      <CardContent className="relative flex items-center gap-4 p-6">
        <div className={cn('flex h-14 w-14 shrink-0 items-center justify-center rounded-2xl', colorClass)}>
          <Icon className="h-7 w-7" />
        </div>
        <div>
          <div className="data-numeral text-4xl font-semibold tracking-tight">{value}</div>
          <div className="text-sm font-medium text-muted-foreground">{label}</div>
        </div>
      </CardContent>
    </Card>
  );
}
