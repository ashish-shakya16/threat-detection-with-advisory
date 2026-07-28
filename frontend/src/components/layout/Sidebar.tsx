import { NavLink } from 'react-router-dom';
import { LayoutDashboard, ShieldAlert, LineChart, Bot, Settings } from 'lucide-react';
import { ConnectionStatus } from '@/components/ConnectionStatus';
import { GuardMark } from '@/components/GuardMark';
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
    <nav className="fixed left-4 top-4 bottom-4 flex w-64 flex-col rounded-lg border border-sidebar-border bg-sidebar">
      <div className="flex items-center gap-2.5 border-b border-sidebar-border p-5">
        <GuardMark className="h-7 w-7 text-primary" />
        <div>
          <h2 className="text-sm font-semibold tracking-tight text-sidebar-foreground">SecureX</h2>
          <p className="text-[11px] uppercase tracking-wide text-muted-foreground">Guard Station</p>
        </div>
      </div>

      <ul className="flex-1 space-y-0.5 px-3 py-3">
        {navItems.map(({ to, label, icon: Icon, end }) => (
          <li key={to}>
            <NavLink
              to={to}
              end={end}
              className={({ isActive }) =>
                cn(
                  'relative flex items-center gap-3 rounded-md px-3 py-2 pl-4 text-sm font-medium text-muted-foreground transition-colors duration-150 hover:bg-sidebar-accent hover:text-sidebar-accent-foreground',
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

      <div className="p-3">
        <ConnectionStatus />
      </div>
    </nav>
  );
}
