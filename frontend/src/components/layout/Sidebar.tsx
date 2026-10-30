import { NavLink } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { LayoutDashboard, ShieldAlert, LineChart, Bot, Settings, ShieldCheck, ScrollText, Siren, Radar } from 'lucide-react';
import { ConnectionStatus } from '@/components/ConnectionStatus';
import { GuardMark } from '@/components/GuardMark';
import { api } from '@/lib/api';
import { cn } from '@/lib/utils';

const navItems = [
  { to: '/', label: 'Dashboard', icon: LayoutDashboard, end: true },
  { to: '/threats', label: 'Threats', icon: ShieldAlert },
  { to: '/analytics', label: 'Analytics', icon: LineChart },
  { to: '/detection', label: 'Detection', icon: Radar },
  { to: '/assistant', label: 'AI Assistant', icon: Bot },
  { to: '/responses', label: 'Response Center', icon: Siren },
  { to: '/audit', label: 'Audit Log', icon: ScrollText },
  { to: '/settings', label: 'Settings', icon: Settings },
];

export function Sidebar() {
  const { data: systemInfo } = useQuery({
    queryKey: ['system-info'],
    queryFn: api.system.info,
  });

  return (
    <nav className="fixed left-4 top-4 bottom-4 flex w-64 flex-col rounded-lg border border-sidebar-border bg-sidebar">
      <div className="flex items-center gap-2.5 border-b border-sidebar-border p-5">
        <GuardMark className="h-7 w-7 text-primary" />
        <div>
          <h2 className="text-sm font-semibold tracking-tight text-sidebar-foreground">SecureX</h2>
          <p className="text-[11px] uppercase tracking-wide text-muted-foreground">Guard Station</p>
        </div>
      </div>

      <ul className="space-y-0.5 px-3 py-3">
        {navItems.map(({ to, label, icon: Icon, end }) => (
          <li key={to}>
            <NavLink
              to={to}
              end={end}
              className={({ isActive }) =>
                cn(
                  'relative flex items-center gap-3 rounded-md px-3 py-2.5 pl-4 text-sm font-medium text-muted-foreground transition-colors duration-150 hover:bg-sidebar-accent hover:text-sidebar-accent-foreground',
                  isActive && 'bg-sidebar-accent text-sidebar-accent-foreground'
                )
              }
            >
              {({ isActive }) => (
                <>
                  {isActive && (
                    <span className="absolute inset-y-1 left-0 w-0.75 rounded-full bg-primary" />
                  )}
                  <Icon className="h-4 w-4 shrink-0" />
                  <span>{label}</span>
                </>
              )}
            </NavLink>
          </li>
        ))}
      </ul>

      <div className="mx-3 border-t border-sidebar-border pt-4">
        <div className="rounded-md border border-sidebar-border bg-muted/30 p-3.5">
          <div className="flex items-center gap-2 text-xs font-medium uppercase tracking-wide text-muted-foreground">
            <ShieldCheck className="h-3.5 w-3.5" />
            System Status
          </div>
          <dl className="mt-2.5 space-y-1.5 text-xs">
            <div className="flex items-center justify-between">
              <dt className="text-muted-foreground">Version</dt>
              <dd className="data-numeral font-medium text-sidebar-foreground">{systemInfo?.version ?? '—'}</dd>
            </div>
            <div className="flex items-center justify-between">
              <dt className="flex items-center gap-1 text-muted-foreground"><ScrollText className="h-3 w-3" /> Rules loaded</dt>
              <dd className="data-numeral font-medium text-sidebar-foreground">{systemInfo?.rules_loaded ?? '—'}</dd>
            </div>
          </dl>
        </div>
      </div>

      <div className="mt-auto p-3">
        <ConnectionStatus />
      </div>
    </nav>
  );
}
