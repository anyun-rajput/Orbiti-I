/**
 * Integration service for managing Microsoft SSO and Nessus configurations
 */

const API_BASE_URL = 'https://orbiti.fareportal.com:7000/api';

export interface IntegrationConfig {
  id: number;
  integration_type: string;
  enabled: boolean;
  config_data: Record<string, any>;
  status: string;
  last_tested?: string;
  last_sync?: string;
  extra_metadata?: Record<string, any>;
  created_at: string;
  updated_at: string;
}

export interface IntegrationConfigRequest {
  integration_type: string;
  enabled: boolean;
  config_data: Record<string, any>;
}

export interface IntegrationTestRequest {
  integration_type: string;
  config_data: Record<string, any>;
}

class IntegrationService {
  private getAuthHeaders(): HeadersInit {
    const token = localStorage.getItem('token');
    return {
      'Content-Type': 'application/json',
      ...(token && { 'Authorization': `Bearer ${token}` })
    };
  }

  async getAllIntegrations(): Promise<IntegrationConfig[]> {
    const response = await fetch(`${API_BASE_URL}/integrations/`, {
      method: 'GET',
      headers: this.getAuthHeaders()
    });

    if (!response.ok) {
      throw new Error(`Failed to fetch integrations: ${response.statusText}`);
    }

    return response.json();
  }

  async getIntegration(integrationType: string): Promise<IntegrationConfig | null> {
    const response = await fetch(`${API_BASE_URL}/integrations/${integrationType}`, {
      method: 'GET',
      headers: this.getAuthHeaders()
    });

    if (response.status === 404) {
      return null; // Integration not configured yet
    }

    if (!response.ok) {
      throw new Error(`Failed to fetch integration: ${response.statusText}`);
    }

    return response.json();
  }

  async createOrUpdateIntegration(config: IntegrationConfigRequest): Promise<IntegrationConfig> {
    const response = await fetch(`${API_BASE_URL}/integrations/`, {
      method: 'POST',
      headers: this.getAuthHeaders(),
      body: JSON.stringify(config)
    });

    if (!response.ok) {
      throw new Error(`Failed to save integration: ${response.statusText}`);
    }

    return response.json();
  }

  async testIntegration(testRequest: IntegrationTestRequest): Promise<{ status: string; message: string }> {
    const response = await fetch(`${API_BASE_URL}/integrations/test`, {
      method: 'POST',
      headers: this.getAuthHeaders(),
      body: JSON.stringify(testRequest)
    });

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({ detail: response.statusText }));
      throw new Error(errorData.detail || `Test failed: ${response.statusText}`);
    }

    return response.json();
  }

  async deleteIntegration(integrationType: string): Promise<{ message: string }> {
    const response = await fetch(`${API_BASE_URL}/integrations/${integrationType}`, {
      method: 'DELETE',
      headers: this.getAuthHeaders()
    });

    if (!response.ok) {
      throw new Error(`Failed to delete integration: ${response.statusText}`);
    }

    return response.json();
  }

  // Helper methods for specific integration types
  async getMicrosoftSSOConfig(): Promise<IntegrationConfig | null> {
    return this.getIntegration('microsoft_sso');
  }

  async getNessusConfig(): Promise<IntegrationConfig | null> {
    return this.getIntegration('nessus');
  }

  async saveMicrosoftSSOConfig(config: {
    enabled: boolean;
    clientId: string;
    clientSecret: string;
    tenantId: string;
    redirectUri: string;
  }): Promise<IntegrationConfig> {
    return this.createOrUpdateIntegration({
      integration_type: 'microsoft_sso',
      enabled: config.enabled,
      config_data: {
        clientId: config.clientId,
        clientSecret: config.clientSecret,
        tenantId: config.tenantId,
        redirectUri: config.redirectUri
      }
    });
  }

  async saveNessusConfig(config: {
    enabled: boolean;
    serverUrl: string;
    username: string;
    password: string;
  }): Promise<IntegrationConfig> {
    return this.createOrUpdateIntegration({
      integration_type: 'nessus',
      enabled: config.enabled,
      config_data: {
        serverUrl: config.serverUrl,
        username: config.username,
        password: config.password
      }
    });
  }

  async testMicrosoftSSO(config: {
    clientId: string;
    clientSecret: string;
    tenantId: string;
    redirectUri: string;
  }): Promise<{ status: string; message: string }> {
    return this.testIntegration({
      integration_type: 'microsoft_sso',
      config_data: config
    });
  }

  async testNessus(config: {
    serverUrl: string;
    username: string;
    password: string;
  }): Promise<{ status: string; message: string }> {
    return this.testIntegration({
      integration_type: 'nessus',
      config_data: config
    });
  }
}

export const integrationService = new IntegrationService();
