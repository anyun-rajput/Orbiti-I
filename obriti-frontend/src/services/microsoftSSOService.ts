interface MicrosoftSSOConfig {
  enabled: boolean;
  client_id: string | null;
  redirect_uri: string;
}

interface MicrosoftAuthResponse {
  access_token: string;
  token_type: string;
  user: {
    id: number;
    username: string;
    email: string;
    first_name: string;
    last_name: string;
    role: string;
    auth_provider: string;
  };
}

class MicrosoftSSOService {
  private baseUrl = "https://orbiti.fareportal.com:7000/api/auth";

  async getConfig(): Promise<MicrosoftSSOConfig> {
    try {
      const response = await fetch(`${this.baseUrl}/microsoft/config`);
      if (!response.ok) {
        throw new Error('Failed to fetch Microsoft SSO config');
      }
      return await response.json();
    } catch (error) {
      console.error('Error fetching Microsoft SSO config:', error);
      return { enabled: false, client_id: null, redirect_uri: '' };
    }
  }

  async getLoginUrl(state?: string): Promise<string | null> {
    try {
      const url = new URL(`${this.baseUrl}/microsoft/login`);
      if (state) {
        url.searchParams.append('state', state);
      }
      
      const response = await fetch(url.toString());
      if (!response.ok) {
        throw new Error('Failed to get Microsoft login URL');
      }
      
      const data = await response.json();
      return data.auth_url;
    } catch (error) {
      console.error('Error getting Microsoft login URL:', error);
      return null;
    }
  }

  async handleCallback(code: string, state?: string): Promise<MicrosoftAuthResponse | null> {
    try {
      const response = await fetch(`${this.baseUrl}/microsoft/callback`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ code, state }),
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.detail || 'Microsoft authentication failed');
      }

      return await response.json();
    } catch (error) {
      console.error('Error handling Microsoft callback:', error);
      return null;
    }
  }

  // Generate a random state parameter for CSRF protection
  generateState(): string {
    return Math.random().toString(36).substring(2, 15) + 
           Math.random().toString(36).substring(2, 15);
  }

  // Store state in sessionStorage for validation
  storeState(state: string): void {
    sessionStorage.setItem('microsoft_sso_state', state);
  }

  // Validate state parameter
  validateState(state: string): boolean {
    const storedState = sessionStorage.getItem('microsoft_sso_state');
    sessionStorage.removeItem('microsoft_sso_state');
    return storedState === state;
  }

  // Initiate Microsoft SSO login
  async initiateLogin(): Promise<void> {
    const config = await this.getConfig();
    if (!config.enabled) {
      throw new Error('Microsoft SSO is not configured');
    }

    const state = this.generateState();
    this.storeState(state);

    const loginUrl = await this.getLoginUrl(state);
    if (!loginUrl) {
      throw new Error('Failed to generate Microsoft login URL');
    }

    // Redirect to Microsoft login
    window.location.href = loginUrl;
  }
}

export const microsoftSSOService = new MicrosoftSSOService();
export type { MicrosoftSSOConfig, MicrosoftAuthResponse };
