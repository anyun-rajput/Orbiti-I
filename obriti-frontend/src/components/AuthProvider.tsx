import React, { createContext, useContext, useState, useEffect, ReactNode, useCallback, useMemo } from "react";
import { useNavigate } from "react-router-dom";
import SecureTokenManager from "../utils/tokenManager";
import config from "../config/environment";

interface UserInfo {
  id: number;
  username: string;
  first_name?: string;
  last_name?: string;
  email: string;
  role_name: string;
  permissions: string[];
}

interface AuthContextType {
  isAuthenticated: boolean;
  token: string | null;
  userInfo: UserInfo | null;
  login: (token: string) => void;
  logout: () => void;
  getToken: () => string | null;
  loading: boolean;
  hasPermission: (permission: string) => boolean;
  isAdmin: () => boolean;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [token, setToken] = useState<string | null>(null);
  const [userInfo, setUserInfo] = useState<UserInfo | null>(null);
  const [loading, setLoading] = useState(true);
  const navigate = useNavigate();

  // Fetch user info when token is available
  useEffect(() => {
    const fetchUserInfo = async () => {
      const storedToken = SecureTokenManager.getToken();
      if (storedToken && SecureTokenManager.isTokenValid()) {
        try {
          const response = await fetch(`${config.apiUrl}/api/users/me`, {
            headers: {
              Authorization: `Bearer ${storedToken}`,
            },
          });
          
          if (response.ok) {
            const userData: UserInfo = await response.json();
            setUserInfo(userData);
            setIsAuthenticated(true);
            setToken(storedToken);
          } else {
            // Token is invalid, clear it
            SecureTokenManager.clearToken();
            setIsAuthenticated(false);
            setToken(null);
            setUserInfo(null);
          }
        } catch (error) {
          console.error("Error fetching user info:", error);
          SecureTokenManager.clearToken();
          setIsAuthenticated(false);
          setToken(null);
          setUserInfo(null);
        }
      } else {
        // No valid token
        SecureTokenManager.clearToken();
        setIsAuthenticated(false);
        setToken(null);
        setUserInfo(null);
      }
      setLoading(false);
    };

    fetchUserInfo();
  }, []);

  const login = async (token: string) => {
    // Store token securely with 1 hour expiry
    SecureTokenManager.setToken(token, 3600);
    setToken(token);
    
    try {
      // Fetch user info immediately after login
      const response = await fetch(`${config.apiUrl}/api/users/me`, {
        headers: {
          Authorization: `Bearer ${token}`,
        },
      });
      
      if (response.ok) {
        const userData: UserInfo = await response.json();
        setUserInfo(userData);
        setIsAuthenticated(true);
        navigate("/");
      } else {
        throw new Error("Failed to fetch user info");
      }
    } catch (error) {
      console.error("Error during login:", error);
      SecureTokenManager.clearToken();
      setToken(null);
      setUserInfo(null);
      setIsAuthenticated(false);
    }
  };

  const logout = () => {
    SecureTokenManager.clearToken();
    setToken(null);
    setUserInfo(null);
    setIsAuthenticated(false);
    navigate("/login");
  };

  const getToken = () => SecureTokenManager.getToken();

  const hasPermission = useCallback((permission: string): boolean => {
    return userInfo?.permissions.includes(permission) || false;
  }, [userInfo?.permissions]);

  const isAdmin = useCallback((): boolean => {
    return userInfo?.role_name === "admin" || false;
  }, [userInfo?.role_name]);

  // Memoize the context value to prevent unnecessary re-renders
  const contextValue = useMemo(() => ({
    isAuthenticated,
    token,
    userInfo,
    login,
    logout,
    getToken,
    loading,
    hasPermission,
    isAdmin
  }), [isAuthenticated, token, userInfo, loading, hasPermission, isAdmin]);

  return (
    <AuthContext.Provider value={contextValue}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) throw new Error("useAuth must be used within an AuthProvider");
  return context;
} 