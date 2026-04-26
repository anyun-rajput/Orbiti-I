/**
 * Environment configuration for the application
 * Centralizes all environment variables and provides type safety
 */

interface EnvironmentConfig {
  apiUrl: string;
  enableHttps: boolean;
  tokenExpiry: number;
  enableDebug: boolean;
  enableAnalytics: boolean;
  devMode: boolean;
}

const getEnvironmentConfig = (): EnvironmentConfig => {
  return {
    apiUrl: import.meta.env.VITE_API_URL || 'http://orbiti.fareportal.com:7000',
    enableHttps: import.meta.env.VITE_ENABLE_HTTPS === 'true',
    tokenExpiry: parseInt(import.meta.env.VITE_TOKEN_EXPIRY || '3600', 10),
    enableDebug: import.meta.env.VITE_ENABLE_DEBUG === 'true',
    enableAnalytics: import.meta.env.VITE_ENABLE_ANALYTICS === 'true',
    devMode: import.meta.env.VITE_DEV_MODE === 'true' || import.meta.env.DEV
  };
};

export const config = getEnvironmentConfig();

// Validate configuration
if (!config.apiUrl) {
  throw new Error('VITE_API_URL is required');
}

if (config.tokenExpiry < 300) { // Minimum 5 minutes
  console.warn('Token expiry is very short, consider increasing VITE_TOKEN_EXPIRY');
}

export default config;
