import { Navigate } from "react-router-dom";
import { useAuth } from "./AuthProvider";

interface AdminRouteProps {
  children: React.ReactNode;
}

export default function AdminRoute({ children }: AdminRouteProps) {
  const { userInfo, loading, isAdmin } = useAuth();

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-screen">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
      </div>
    );
  }

  // Check if user has admin role
  if (!userInfo || !isAdmin()) {
    return <Navigate to="/" replace />;
  }

  return <>{children}</>;
}
