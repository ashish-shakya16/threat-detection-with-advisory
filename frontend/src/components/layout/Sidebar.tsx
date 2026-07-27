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
    <nav className="fixed left-0 top-0 flex h-screen w-64 flex-col border-r bg-card">
      <div className="flex items-center gap-3 border-b p-6">
        <img src="/favicon.svg" alt="" className="h-8 w-8" />
        <h2 className="text-lg font-bold">SecureX</h2>
      </div>

      <ul className="flex-1 space-y-1 p-4">
        {navItems.map(({ to, label, icon: Icon, end }) => (
          <li key={to}>
            <NavLink
              to={to}
              end={end}
              className={({ isActive }) =>
                cn(
                  'flex items-center gap-3 rounded-md px-4 py-2.5 text-sm text-muted-foreground transition-colors hover:bg-accent hover:text-accent-foreground',
                  isActive && 'bg-primary text-primary-foreground hover:bg-primary hover:text-primary-foreground'
                )
              }
            >
              <Icon className="h-5 w-5" />
              <span>{label}</span>
            </NavLink>
          </li>
        ))}
      </ul>

      <div className="border-t p-4">
        <ConnectionStatus />
      </div>
    </nav>
  );
}
