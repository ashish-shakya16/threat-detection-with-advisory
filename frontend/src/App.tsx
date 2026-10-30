import { Routes, Route } from 'react-router-dom';
import { ProtectedRoute } from '@/components/ProtectedRoute';
import { AppLayout } from '@/components/layout/AppLayout';
import { Toaster } from '@/components/ui/sonner';
import LoginPage from '@/pages/LoginPage';
import SignupPage from '@/pages/SignupPage';
import LandingPage from '@/pages/LandingPage';
import DashboardPage from '@/pages/DashboardPage';
import ThreatsPage from '@/pages/ThreatsPage';
import AnalyticsPage from '@/pages/AnalyticsPage';
import AssistantPage from '@/pages/AssistantPage';
import SettingsPage from '@/pages/SettingsPage';
import ResponsesPage from '@/pages/ResponsesPage';
import AuditPage from '@/pages/AuditPage';
import DetectionPage from '@/pages/DetectionPage';

function App() {
  return (
    <>
      <Routes>
        <Route path="/login" element={<LoginPage />} />
        <Route path="/signup" element={<SignupPage />} />
        {/* Public product page; no sign-in required. */}
        <Route path="/welcome" element={<LandingPage />} />
        <Route element={<ProtectedRoute />}>
          <Route element={<AppLayout />}>
            <Route path="/" element={<DashboardPage />} />
            <Route path="/threats" element={<ThreatsPage />} />
            <Route path="/analytics" element={<AnalyticsPage />} />
            <Route path="/assistant" element={<AssistantPage />} />
            <Route path="/detection" element={<DetectionPage />} />
            <Route path="/responses" element={<ResponsesPage />} />
            <Route path="/audit" element={<AuditPage />} />
            <Route path="/settings" element={<SettingsPage />} />
          </Route>
        </Route>
      </Routes>
      <Toaster />
    </>
  );
}

export default App;
