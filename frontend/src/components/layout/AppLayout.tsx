import { Outlet } from 'react-router-dom';
import { Sidebar } from './Sidebar';

export function AppLayout() {
  return (
    <div className="min-h-screen bg-background">
      <Sidebar />
      <main className="ml-70 pr-4">
        <Outlet />
      </main>
    </div>
  );
}
