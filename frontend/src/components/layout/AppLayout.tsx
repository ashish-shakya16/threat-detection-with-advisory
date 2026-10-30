import { Outlet } from 'react-router-dom';
import { Sidebar } from './Sidebar';
import { useSocket } from '@/hooks/useSocket';

export function AppLayout() {
  // One real-time connection for every authenticated page, not just the dashboard.
  useSocket();

  return (
    <div className="min-h-screen bg-background">
      <Sidebar />
      <main className="ml-70 pr-4">
        <Outlet />
      </main>
    </div>
  );
}
