import { HashRouter, Navigate, Route, Routes, useLocation } from "react-router-dom";
import AppShell from "./components/AppShell";
import { LoadingBlock } from "./components/ui";
import { AuthProvider, useAuth } from "./lib/auth";
import Auth from "./pages/Auth";
import Dashboard from "./pages/Dashboard";
import NewScan from "./pages/NewScan";
import ScanDetail from "./pages/ScanDetail";
import History from "./pages/History";
import Compare from "./pages/Compare";
import Knowledge from "./pages/Knowledge";
import Settings from "./pages/Settings";

function Protected({ children }) {
  const { user, loading, authEnabled } = useAuth();
  const location = useLocation();
  if (loading) return <div className="boot"><LoadingBlock label="Starting CodeShield" /></div>;
  if (authEnabled && !user) return <Navigate to="/login" replace state={{ from: location.pathname }} />;
  return children;
}

export default function App() {
  return (
    <HashRouter>
      <AuthProvider>
        <Routes>
          <Route path="/login" element={<Auth />} />
          <Route element={<Protected><AppShell /></Protected>}>
            <Route path="/dashboard" element={<Dashboard />} />
            <Route path="/scan" element={<NewScan />} />
            <Route path="/scans/:id" element={<ScanDetail />} />
            <Route path="/history" element={<History />} />
            <Route path="/compare" element={<Compare />} />
            <Route path="/knowledge" element={<Knowledge />} />
            <Route path="/settings" element={<Settings />} />
          </Route>
          <Route path="*" element={<Navigate to="/dashboard" replace />} />
        </Routes>
      </AuthProvider>
    </HashRouter>
  );
}
