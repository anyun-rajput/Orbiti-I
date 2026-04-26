import { ReactNode } from "react";
import { Navigate, useLocation } from "react-router-dom";
import { useAuth } from "./AuthProvider";

interface PermissionRouteProps {
  children: ReactNode;
  requiredPermission: string;
  fallbackPath?: string;
}

export default function PermissionRoute({ 
  children, 
  requiredPermission, 
  fallbackPath = "/" 
}: PermissionRouteProps) {
  const { userInfo, loading, hasPermission } = useAuth();
  const location = useLocation();

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-screen">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
      </div>
    );
  }

  // Check if user has the required permission
  if (!userInfo || !hasPermission(requiredPermission)) {
    // Redirect to fallback path (default: dashboard) if user doesn't have permission
    return <Navigate to={fallbackPath} replace />;
  }

  return <>{children}</>;
}
