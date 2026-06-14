import { Toaster } from "@/components/ui/toaster";
import { Toaster as Sonner } from "@/components/ui/sonner";
import { TooltipProvider } from "@/components/ui/tooltip";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter, Routes, Route } from "react-router-dom";
import { AuthProvider, useAuth } from "@/hooks/useAuth";
import { OrganizationProvider } from "@/components/OrganizationProvider";
import ProtectedRoute from "@/components/ProtectedRoute";
import SecurityHeaders from "@/components/security/SecurityHeaders";
import ErrorBoundary from "@/components/ErrorBoundary";
import CommandPalette from "@/components/CommandPalette";

// Core MVP Pages
import NewHomepage from "./pages/NewHomepage";
import BlogList from "./pages/Blog";
import Episode1 from "./pages/blog/Episode1";
import Episode2 from "./pages/blog/Episode2";
import Episode3 from "./pages/blog/Episode3";
import Episode4 from "./pages/blog/Episode4";
import BuildingCyberImmunity from "./pages/blog/BuildingCyberImmunity";
import LaunchingVDP from "./pages/blog/LaunchingVDP";
import Vdp from "./pages/VDP";
import HallOfFame from "./pages/HallOfFame";
import Auth from "./pages/Auth";
import AuthCallback from "./pages/AuthCallback";
import ResetPassword from "./pages/ResetPassword";
import Onboarding from "./pages/Onboarding";
import STIGDashboard from "./pages/STIGDashboard";
import AssetScanning from "./pages/AssetScanning";
import ComplianceReports from "./pages/ComplianceReports";
import EvidenceCollectionMVP from "./pages/EvidenceCollectionMVP";
import SimpleBilling from "./pages/SimpleBilling";
import DoD from "./pages/DoD";
import MasterAdmin from "./pages/MasterAdmin";
import ClientPortal from "./pages/ClientPortal";
import UltimateDashboard from "./pages/UltimateDashboard";
import CommandCenter from "./pages/CommandCenter";
import NotFound from "./pages/NotFound";
import LegalPage from "./pages/LegalPage";
import { ThreatHuntingDashboard } from "./pages/ThreatHuntingDashboard";
import GlobalIntelligenceDashboard from "./pages/GlobalIntelligenceDashboard";
import { useDocumentTitle } from "@/hooks/useDocumentTitle";
import NLChatPanel from "@/components/NLChatPanel";
import Advisory from "./pages/Advisory";

/**
 * Invisible component that sets document.title per route.
 * Must be inside <BrowserRouter> to access useLocation.
 */
const DocumentTitle = () => {
  useDocumentTitle();
  return null;
};

/**
 * CommandPalette wrapper that reads auth state.
 */
const AuthAwareCommandPalette = () => {
  const { user } = useAuth();
  return <CommandPalette isAuthenticated={!!user} />;
};

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: 1,
      refetchOnWindowFocus: false,
    },
  },
});

const App = () => {
  return (
    <BrowserRouter>
      <QueryClientProvider client={queryClient}>
        <AuthProvider>
          <SecurityHeaders>
            <TooltipProvider>
              <OrganizationProvider>
                <ErrorBoundary>
                  <DocumentTitle />
                  <AuthAwareCommandPalette />
                  <Toaster />
                  <Sonner />
                  <Routes>
                    {/* Public Routes */}
                    <Route path="/" element={<NewHomepage />} />
                    <Route path="/advisory" element={<Advisory />} />
                    <Route path="/contact-sales" element={<Advisory />} />
                    <Route path="/blog" element={<BlogList />} />
                    <Route path="/blog/episode-1-blood-moon-philosopher-api" element={<Episode1 />} />
                    <Route path="/blog/episode-2-autonomous-ai-deepfakes-leadership" element={<Episode2 />} />
                    <Route path="/blog/episode-3-founder-inception-story" element={<Episode3 />} />
                    <Route path="/blog/episode-4-rising-through-ranks" element={<Episode4 />} />
                    <Route path="/blog/building-cyber-immunity-cmmc-stig-database" element={<BuildingCyberImmunity />} />
                    <Route path="/blog/launching-vdp" element={<LaunchingVDP />} />
                    <Route path="/vdp" element={<Vdp />} />
                    <Route path="/hall-of-fame" element={<HallOfFame />} />
                    <Route path="/auth" element={<Auth />} />
                    <Route path="/auth/callback" element={<AuthCallback />} />
                    <Route path="/auth/reset-password" element={<ResetPassword />} />
                    <Route path="/onboarding" element={<Onboarding />} />

                    {/* Legal Pages */}
                    <Route path="/privacy" element={<LegalPage />} />
                    <Route path="/terms" element={<LegalPage />} />
                    <Route path="/security" element={<LegalPage />} />
                    <Route path="/compliance" element={<LegalPage />} />

                    {/* STIG-First MVP Routes */}
                    <Route path="/stig-dashboard" element={<ProtectedRoute><STIGDashboard /></ProtectedRoute>} />
                    <Route path="/dashboard" element={<ProtectedRoute><STIGDashboard /></ProtectedRoute>} />
                    <Route path="/asset-scanning" element={<ProtectedRoute><AssetScanning /></ProtectedRoute>} />
                    <Route path="/compliance-reports" element={<ProtectedRoute><ComplianceReports /></ProtectedRoute>} />
                    <Route path="/evidence-collection" element={<ProtectedRoute><EvidenceCollectionMVP /></ProtectedRoute>} />
                    <Route path="/billing" element={<SimpleBilling />} />
                    <Route path="/ultimate" element={<ProtectedRoute><UltimateDashboard /></ProtectedRoute>} />
                    <Route path="/command-center" element={<ProtectedRoute><CommandCenter /></ProtectedRoute>} />
                    <Route path="/threat-hunting" element={<ProtectedRoute><ThreatHuntingDashboard /></ProtectedRoute>} />
                    <Route path="/intelligence" element={<ProtectedRoute><GlobalIntelligenceDashboard /></ProtectedRoute>} />

                    {/* DoD Solutions (public marketing page) */}
                    <Route path="/dod" element={<DoD />} />

                    {/* Admin Routes */}
                    <Route path="/admin" element={<ProtectedRoute><MasterAdmin /></ProtectedRoute>} />

                    {/* Khepra Client Portal */}
                    <Route path="/clients/:org_id/overview" element={<ProtectedRoute><ClientPortal /></ProtectedRoute>} />
                    <Route path="/clients/:org_id" element={<ProtectedRoute><ClientPortal /></ProtectedRoute>} />

                    {/* Catch-all */}
                    <Route path="*" element={<NotFound />} />
                  </Routes>
                </ErrorBoundary>
              </OrganizationProvider>
            </TooltipProvider>
          </SecurityHeaders>
        </AuthProvider>
      </QueryClientProvider>
      <NLChatPanel />
    </BrowserRouter>
  );
};

export default App;
