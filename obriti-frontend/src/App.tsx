import { Toaster } from "@/components/ui/toaster";
import { Toaster as Sonner } from "@/components/ui/sonner";
import { TooltipProvider } from "@/components/ui/tooltip";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter, Routes, Route } from "react-router-dom";
import Index from "./pages/Index";
import Integrations from "./pages/Integrations";
import Assets from "./pages/Assets";
import Vulnerabilities from "./pages/Vulnerabilities";
import VulnerabilityByOwner from "./pages/VulnerabilityByOwner";
import VulnerabilityByHosts from "./pages/VulnerabilityByHosts";
import ClosedVulnerabilitiesPage from "./pages/ClosedVulnerabilitiesPage";
import Exceptions from "./pages/Exceptions";
import RescanReadyHostsPage from "./pages/RescanReadyHosts";
import HostDetails from "./pages/HostDetails";
import OwnerDetails from "./pages/OwnerDetails";
import ScanManagement from "./pages/ScanManagement";
import Settings from "./pages/Settings";
import UserManagementPage from "./pages/UserManagementPage";
import NotFound from "./pages/NotFound";
import ScanHistory from "./pages/ScanHistory";
import Login from "./pages/Login";
import Register from "./pages/Register";
import MicrosoftCallback from "./pages/MicrosoftCallback";
import { AuthProvider } from "@/components/AuthProvider";
import ProtectedRoute from "@/components/ProtectedRoute";
import AdminRoute from "@/components/AdminRoute";
import PermissionRoute from "@/components/PermissionRoute";
import ErrorBoundary from "@/components/ErrorBoundary";

const queryClient = new QueryClient();

const App = () => (
  <QueryClientProvider client={queryClient}>
    <TooltipProvider>
      <Toaster />
      <Sonner />
      <BrowserRouter>
        <AuthProvider>
          <ErrorBoundary>
            <Routes>
              <Route path="/login" element={<Login />} />
              <Route path="/register" element={<Register />} />
              <Route path="/auth/microsoft/callback" element={<MicrosoftCallback />} />
              <Route
                path="/*"
                element={
                  <ProtectedRoute>
                    <Routes>
                      {/* Dashboard - accessible by org_team */}
                      <Route path="/" element={<Index />} />
                      
                      {/* Vulnerabilities - accessible by org_team */}
                      <Route path="/vulnerabilities" element={<Vulnerabilities />} />
                      <Route path="/vulnerabilities/by-owner" element={<VulnerabilityByOwner />} />
                      <Route path="/vulnerabilities/by-hosts" element={<VulnerabilityByHosts />} />
                      <Route path="/vulnerabilities/closed" element={<ClosedVulnerabilitiesPage />} />
                      <Route path="/exceptions" element={<Exceptions />} />
                      
                      {/* Host and Owner details - accessible by org_team (part of vulnerability analysis) */}
                      <Route path="/hosts/:hostId" element={<HostDetails />} />
                      <Route path="/owners/:ownerName" element={<OwnerDetails />} />
                      
                      {/* Admin-only routes */}
                      <Route 
                        path="/rescan-ready" 
                        element={
                          <AdminRoute>
                            <RescanReadyHostsPage />
                          </AdminRoute>
                        } 
                      />
                      <Route 
                        path="/user-management" 
                        element={
                          <AdminRoute>
                            <UserManagementPage />
                          </AdminRoute>
                        } 
                      />
                      
                      {/* Permission-based routes for org_team restrictions */}
                      <Route 
                        path="/integrations" 
                        element={
                          <PermissionRoute requiredPermission="integrations">
                            <Integrations />
                          </PermissionRoute>
                        } 
                      />
                      <Route 
                        path="/assets" 
                        element={
                          <PermissionRoute requiredPermission="asset_management">
                            <Assets />
                          </PermissionRoute>
                        } 
                      />
                      <Route 
                        path="/scans" 
                        element={
                          <PermissionRoute requiredPermission="scan_management">
                            <ScanManagement />
                          </PermissionRoute>
                        } 
                      />
                      <Route 
                        path="/history" 
                        element={
                          <PermissionRoute requiredPermission="scan_management">
                            <ScanHistory />
                          </PermissionRoute>
                        } 
                      />
                      <Route 
                        path="/settings" 
                        element={
                          <PermissionRoute requiredPermission="settings">
                            <Settings />
                          </PermissionRoute>
                        } 
                      />
                      <Route path="*" element={<NotFound />} />
                    </Routes>
                  </ProtectedRoute>
                }
              />
            </Routes>
          </ErrorBoundary>
        </AuthProvider>
      </BrowserRouter>
    </TooltipProvider>
  </QueryClientProvider>
);

export default App;
