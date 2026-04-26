/**
 * Secure token management utilities
 * Implements secure storage and retrieval of authentication tokens
 */

interface TokenData {
  token: string;
  expiresAt: number;
  refreshToken?: string;
}

class SecureTokenManager {
  private static readonly TOKEN_KEY = 'vmt_auth_token';
  private static readonly REFRESH_KEY = 'vmt_refresh_token';
  private static readonly TOKEN_EXPIRY_KEY = 'vmt_token_expiry';
  
  /**
   * Store authentication token securely
   */
  static setToken(token: string, expiresIn: number = 3600): void {
    try {
      const expiresAt = Date.now() + (expiresIn * 1000);
      const tokenData: TokenData = {
        token,
        expiresAt
      };
      
      // Store in sessionStorage (more secure than localStorage)
      sessionStorage.setItem(this.TOKEN_KEY, token);
      sessionStorage.setItem(this.TOKEN_EXPIRY_KEY, expiresAt.toString());
      
      // Also store in memory for quick access
      (window as any).__vmt_token_data = tokenData;
    } catch (error) {
      console.error('Failed to store token:', error);
    }
  }
  
  /**
   * Get current authentication token
   */
  static getToken(): string | null {
    try {
      // Check if token exists and is not expired
      const token = sessionStorage.getItem(this.TOKEN_KEY);
      const expiry = sessionStorage.getItem(this.TOKEN_EXPIRY_KEY);
      
      if (!token || !expiry) {
        return null;
      }
      
      const expiresAt = parseInt(expiry, 10);
      if (Date.now() >= expiresAt) {
        // Token expired, clean up
        this.clearToken();
        return null;
      }
      
      return token;
    } catch (error) {
      console.error('Failed to retrieve token:', error);
      return null;
    }
  }
  
  /**
   * Check if token is valid and not expired
   */
  static isTokenValid(): boolean {
    const token = this.getToken();
    return token !== null;
  }
  
  /**
   * Clear all stored tokens
   */
  static clearToken(): void {
    try {
      sessionStorage.removeItem(this.TOKEN_KEY);
      sessionStorage.removeItem(this.REFRESH_KEY);
      sessionStorage.removeItem(this.TOKEN_EXPIRY_KEY);
      delete (window as any).__vmt_token_data;
    } catch (error) {
      console.error('Failed to clear token:', error);
    }
  }
  
  /**
   * Get token expiry time
   */
  static getTokenExpiry(): number | null {
    try {
      const expiry = sessionStorage.getItem(this.TOKEN_EXPIRY_KEY);
      return expiry ? parseInt(expiry, 10) : null;
    } catch (error) {
      console.error('Failed to get token expiry:', error);
      return null;
    }
  }
  
  /**
   * Check if token needs refresh (within 5 minutes of expiry)
   */
  static needsRefresh(): boolean {
    const expiry = this.getTokenExpiry();
    if (!expiry) return false;
    
    const fiveMinutes = 5 * 60 * 1000; // 5 minutes in milliseconds
    return Date.now() >= (expiry - fiveMinutes);
  }
  
  /**
   * Set refresh token
   */
  static setRefreshToken(refreshToken: string): void {
    try {
      sessionStorage.setItem(this.REFRESH_KEY, refreshToken);
    } catch (error) {
      console.error('Failed to store refresh token:', error);
    }
  }
  
  /**
   * Get refresh token
   */
  static getRefreshToken(): string | null {
    try {
      return sessionStorage.getItem(this.REFRESH_KEY);
    } catch (error) {
      console.error('Failed to retrieve refresh token:', error);
      return null;
    }
  }
  
  /**
   * Sanitize input to prevent XSS
   */
  private static sanitizeInput(input: string): string {
    return input
      .replace(/[<>\"'&]/g, '') // Remove potentially dangerous characters
      .trim()
      .substring(0, 1000); // Limit length
  }
}

export default SecureTokenManager;
