import { BrowserRouter, Routes, Route } from 'react-router-dom';
import { ThemeProvider } from '@/hooks/useTheme';
import { QueryClientProvider } from '@tanstack/react-query';
import { Toaster } from 'sonner';
import { queryClient } from '@/lib/queryClient';
import { useAuthStore } from '@/stores/authStore';
import { useWebSocket } from '@/hooks/useWebSocket';
import { Sidebar } from '@/components/layout/sidebar';
import { LoginPage } from '@/pages/login';
import { lazy, Suspense, useEffect } from 'react';

const DashboardPage = lazy(() => import('@/pages/dashboard').then(({ DashboardPage }) => ({ default: DashboardPage })));
const ZonesPage = lazy(() => import('@/pages/zones').then(({ ZonesPage }) => ({ default: ZonesPage })));
const ZoneDetailPage = lazy(() => import('@/pages/zone-detail').then(({ ZoneDetailPage }) => ({ default: ZoneDetailPage })));
const SettingsPage = lazy(() => import('@/pages/settings').then(({ SettingsPage }) => ({ default: SettingsPage })));
const AboutPage = lazy(() => import('@/pages/about').then(({ AboutPage }) => ({ default: AboutPage })));
const QueryLogPage = lazy(() => import('@/pages/query-log').then(({ QueryLogPage }) => ({ default: QueryLogPage })));
const TopDomainsPage = lazy(() => import('@/pages/top-domains').then(({ TopDomainsPage }) => ({ default: TopDomainsPage })));
const BlocklistPage = lazy(() => import('@/pages/blocklist').then(({ BlocklistPage }) => ({ default: BlocklistPage })));
const UpstreamsPage = lazy(() => import('@/pages/upstreams').then(({ UpstreamsPage }) => ({ default: UpstreamsPage })));
const UsersPage = lazy(() => import('@/pages/users').then(({ UsersPage }) => ({ default: UsersPage })));
const HistoricalChartsPage = lazy(() => import('@/pages/historical-charts').then(({ HistoricalChartsPage }) => ({ default: HistoricalChartsPage })));
const DNSSECPage = lazy(() => import('@/pages/dnssec').then(({ DNSSECPage }) => ({ default: DNSSECPage })));
const ClusterPage = lazy(() => import('@/pages/cluster').then(({ ClusterPage }) => ({ default: ClusterPage })));
const RPZPage = lazy(() => import('@/pages/rpz').then(({ RPZPage }) => ({ default: RPZPage })));
const ACLPage = lazy(() => import('@/pages/acl').then(({ ACLPage }) => ({ default: ACLPage })));
const GeoIPPage = lazy(() => import('@/pages/geoip').then(({ GeoIPPage }) => ({ default: GeoIPPage })));
const DNS64CookiesPage = lazy(() => import('@/pages/dns64-cookies').then(({ DNS64CookiesPage }) => ({ default: DNS64CookiesPage })));
const ZoneTransferPage = lazy(() => import('@/pages/zone-transfer').then(({ ZoneTransferPage }) => ({ default: ZoneTransferPage })));

function PageFallback() {
  return (
    <div className="space-y-4" aria-label="Loading page">
      <div className="h-8 w-48 rounded bg-muted animate-pulse" />
      <div className="grid gap-4 md:grid-cols-3">
        <div className="h-28 rounded-lg bg-muted animate-pulse" />
        <div className="h-28 rounded-lg bg-muted animate-pulse" />
        <div className="h-28 rounded-lg bg-muted animate-pulse" />
      </div>
      <div className="h-64 rounded-lg bg-muted animate-pulse" />
    </div>
  );
}

function AppContent() {
  const { isAuthenticated, token } = useAuthStore();
  const { connected } = useWebSocket('/ws');

  useEffect(() => {
    // Validate token on mount if authenticated
    if (isAuthenticated && token) {
      fetch('/api/v1/status', { headers: { Authorization: `Bearer ${token}` } })
        .then((r) => { if (!r.ok) useAuthStore.getState().clearAuth(); })
        .catch(() => {});
    }
  }, [isAuthenticated, token]);

  if (!isAuthenticated) return <LoginPage />;

  return (
    <BrowserRouter>
      <div className="flex min-h-screen bg-background text-foreground">
        <Sidebar connected={connected} />
        <main className="flex-1 overflow-y-auto h-screen">
          <div className="p-6 max-w-6xl mx-auto">
            <Suspense fallback={<PageFallback />}>
              <Routes>
                <Route path="/" element={<DashboardPage />} />
                <Route path="/zones" element={<ZonesPage />} />
                <Route path="/zones/:name" element={<ZoneDetailPage />} />
                <Route path="/settings" element={<SettingsPage />} />
                <Route path="/about" element={<AboutPage />} />
                <Route path="/query-log" element={<QueryLogPage />} />
                <Route path="/top-domains" element={<TopDomainsPage />} />
                <Route path="/blocklist" element={<BlocklistPage />} />
                <Route path="/upstreams" element={<UpstreamsPage />} />
                <Route path="/users" element={<UsersPage />} />
                <Route path="/charts" element={<HistoricalChartsPage />} />
                <Route path="/dnssec" element={<DNSSECPage />} />
                <Route path="/cluster" element={<ClusterPage />} />
                <Route path="/rpz" element={<RPZPage />} />
                <Route path="/acl" element={<ACLPage />} />
                <Route path="/geoip" element={<GeoIPPage />} />
                <Route path="/dns64-cookies" element={<DNS64CookiesPage />} />
                <Route path="/zone-transfer" element={<ZoneTransferPage />} />
              </Routes>
            </Suspense>
          </div>
        </main>
      </div>
    </BrowserRouter>
  );
}

export default function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <ThemeProvider>
        <AppContent />
        <Toaster position="bottom-right" richColors closeButton />
      </ThemeProvider>
    </QueryClientProvider>
  );
}
