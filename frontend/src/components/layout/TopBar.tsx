import type { ReactNode } from 'react';
import { LogOut } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { useAuth } from '@/hooks/useAuth';

interface TopBarProps {
  title: string;
  description: string;
  actions?: ReactNode;
}

export function TopBar({ title, description, actions }: TopBarProps) {
  const { user, logout } = useAuth();

  return (
    <header className="sticky top-0 z-10 flex items-center justify-between border-b border-border/60 bg-background/70 px-8 py-6 backdrop-blur-xl">
      <div>
        <h1 className="text-[2rem] font-bold tracking-tight leading-tight">{title}</h1>
        <p className="text-sm text-muted-foreground">{description}</p>
      </div>
      <div className="flex items-center gap-3">
        {actions}
        {user && (
          <div className="flex items-center gap-3 border-l border-border/60 pl-4">
            <div className="flex h-8 w-8 items-center justify-center rounded-full bg-linear-to-br from-primary to-accent-purple text-xs font-semibold text-primary-foreground">
              {user.username.slice(0, 2).toUpperCase()}
            </div>
            <span className="text-sm font-medium text-foreground">{user.username}</span>
            <Button variant="ghost" size="icon" onClick={() => logout()} title="Log out">
              <LogOut className="h-4 w-4" />
            </Button>
          </div>
        )}
      </div>
    </header>
  );
}
