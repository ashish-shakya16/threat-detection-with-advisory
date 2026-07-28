import { NavLink } from 'react-router-dom';
import { LayoutDashboard, ShieldAlert, LineChart, Bot, Settings } from 'lucide-react';
import { ConnectionStatus } from '@/components/ConnectionStatus';
import { cn } from '@/lib/utils';

const navItems = [
  { to: '/', label: 'Dashboard', icon: LayoutDashboard, end: true },
  { to: '/threats', label: 'Threats', icon: ShieldAlert },
  { to: '/analytics', label: 'Analytics', icon: LineChart },
  { to: '/assistant', label: 'AI Assistant', icon: Bot },
  { to: '/settings', label: 'Settings', icon: Settings },
];

export function Sidebar() {
  return (
    <nav className="fixed left-4 top-4 bottom-4 flex w-64 flex-col rounded-2xl border border-border/60 glass-panel shadow-2xl shadow-black/40">
      <div className="flex items-center gap-3 p-5">
        <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-linear-to-br from-primary to-accent-purple shadow-lg shadow-primary/30">
          <img src="/favicon.svg" alt="" className="h-5 w-5" />
        </div>
        <h2 className="text-lg font-bold tracking-tight">SecureX</h2>
      </div>

      <ul className="flex-1 space-y-1 px-3 py-2">
        {navItems.map(({ to, label, icon: Icon, end }) => (
          <li key={to}>
            <NavLink
              to={to}
              end={end}
              className={({ isActive }) =>
                cn(
                  'group relative flex items-center gap-3 rounded-xl px-3 py-2.5 text-sm font-medium text-muted-foreground transition-all duration-200 hover:bg-accent/60 hover:text-foreground',
                  isActive &&
                    'bg-linear-to-r from-primary to-accent-purple text-primary-foreground shadow-lg shadow-primary/25 hover:from-primary hover:to-accent-purple hover:text-primary-foreground'
                )
              }
            >
              {({ isActive }) => (
                <>
                  <div
                    className={cn(
                      'flex h-8 w-8 items-center justify-center rounded-lg transition-colors',
                      isActive ? 'bg-white/15' : 'bg-muted/50 group-hover:bg-muted'
                    )}
                  >
                    <Icon className="h-4 w-4" />
                  </div>
                  <span>{label}</span>
                </>
              )}
            </NavLink>
          </li>
        ))}
      </ul>

      <div className="p-3">
        <ConnectionStatus />
      </div>
    </nav>
  );
}
