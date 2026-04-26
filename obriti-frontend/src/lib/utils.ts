import { clsx, type ClassValue } from "clsx"
import { twMerge } from "tailwind-merge"
import { useAuth } from "@/components/AuthProvider";
import { toast } from "@/hooks/use-toast";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs))
}

import config from '../config/environment';

// This function must be called inside a React component or hook
export function useApiFetch() {
  const { getToken, logout } = useAuth();

  return async function apiFetch(input: RequestInfo, init: RequestInit = {}) {
    const token = getToken();
    const headers = new Headers(init.headers || {});
    if (token) {
      headers.set("Authorization", `Bearer ${token}`);
    }
    
    // Add security headers
    headers.set("X-Requested-With", "XMLHttpRequest");
    
    // Only set Content-Type for non-FormData requests
    // FormData will automatically set the correct Content-Type with boundary
    if (!(init.body instanceof FormData)) {
      headers.set("Content-Type", "application/json");
    }
    
    try {
      // Ensure we're using the configured API URL
      const url = typeof input === 'string' && input.startsWith('http') 
        ? input 
        : `${config.apiUrl}${input}`;
        
      const response = await fetch(url, { ...init, headers });
      
      // Handle 401 Unauthorized responses
      if (response.status === 401) {
        console.log("Unauthorized access detected, redirecting to login...");
        
        // Show toast notification
        toast({
          title: "Session Expired",
          description: "Your session has expired. Please log in again.",
          variant: "destructive",
        });
        
        logout(); // This will clear the token and redirect to login
        return response;
      }
      
      // Handle other error responses
      if (!response.ok && response.status !== 401) {
        console.error(`API request failed: ${response.status} ${response.statusText}`);
        
        // Try to parse error message from response
        try {
          const errorData = await response.json();
          toast({
            title: "Request Failed",
            description: errorData.detail || `Request failed with status ${response.status}`,
            variant: "destructive",
          });
        } catch {
          toast({
            title: "Request Failed",
            description: `Request failed with status ${response.status}`,
            variant: "destructive",
          });
        }
      }
      
      return response;
    } catch (error) {
      console.error("Network error:", error);
      toast({
        title: "Network Error",
        description: "Failed to connect to the server. Please check your connection.",
        variant: "destructive",
      });
      throw error;
    }
  };
}
