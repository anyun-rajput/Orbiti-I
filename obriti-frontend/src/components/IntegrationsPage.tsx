
import { useState, useEffect } from "react";
import { Settings, Shield, Users, CheckCircle, XCircle, AlertCircle, Save, TestTube, Eye, EyeOff, Trash2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { integrationService, IntegrationConfig } from "@/services/integrationService";
import { toast } from "sonner";

interface MicrosoftSSOConfig {
  enabled: boolean;
  clientId: string;
  clientSecret: string;
  tenantId: string;
  redirectUri: string;
  status: "configured" | "not_configured" | "error" | "connected";
  lastTest: string;
  isConfigured: boolean; // Whether integration exists in database
}

interface NessusConfig {
  enabled: boolean;
  serverUrl: string;
  username: string;
  password: string;
  status: "connected" | "disconnected" | "error" | "configured";
  lastScan: string;
  vulnerabilityCount: number;
  isConfigured: boolean; // Whether integration exists in database
}

export function IntegrationsPage() {
  const [microsoftSSO, setMicrosoftSSO] = useState<MicrosoftSSOConfig>({
    enabled: false,
    clientId: "",
    clientSecret: "",
    tenantId: "common",
    redirectUri: "https://orbiti.fareportal.com:7000/microsoft/callback",
    status: "not_configured",
    lastTest: "Never",
    isConfigured: false
  });

  const [nessus, setNessus] = useState<NessusConfig>({
    enabled: false,
    serverUrl: "",
    username: "",
    password: "",
    status: "disconnected",
    lastScan: "Never",
    vulnerabilityCount: 0,
    isConfigured: false
  });

  const [showSecrets, setShowSecrets] = useState({
    nessusSecret: false,
    microsoftSecret: false
  });

  const [loading, setLoading] = useState({
    microsoftSSO: false,
    nessus: false,
    testMicrosoft: false,
    testNessus: false
  });

  // Load configurations from backend on component mount
  useEffect(() => {
    loadConfigurations();
  }, []);

  const loadConfigurations = async () => {
    try {
      setLoading(prev => ({ ...prev, microsoftSSO: true, nessus: true }));
      
      // Load Microsoft SSO config
      const microsoftConfig = await integrationService.getMicrosoftSSOConfig();
      if (microsoftConfig && microsoftConfig.id > 0) {
        setMicrosoftSSO({
          enabled: microsoftConfig.enabled,
          clientId: microsoftConfig.config_data?.clientId || "",
          clientSecret: "", // Don't populate sensitive fields from backend
          tenantId: microsoftConfig.config_data?.tenantId || "common",
          redirectUri: microsoftConfig.config_data?.redirectUri || "https://orbiti.fareportal.com:7000/microsoft/callback",
          status: microsoftConfig.status as "configured" | "not_configured" | "error" | "connected",
          lastTest: microsoftConfig.last_tested ? new Date(microsoftConfig.last_tested).toLocaleString() : "Never",
          isConfigured: true
        });
      }

      // Load Nessus config
      const nessusConfig = await integrationService.getNessusConfig();
      if (nessusConfig && nessusConfig.id > 0) {
        setNessus({
          enabled: nessusConfig.enabled,
          serverUrl: nessusConfig.config_data?.serverUrl || "",
          username: "", // Don't populate sensitive fields from backend
          password: "", // Don't populate sensitive fields from backend
          status: nessusConfig.status as "connected" | "disconnected" | "error" | "configured",
          lastScan: nessusConfig.last_sync ? new Date(nessusConfig.last_sync).toLocaleString() : "Never",
          vulnerabilityCount: nessusConfig.extra_metadata?.vulnerabilityCount || 0,
          isConfigured: true
        });
      }
      
    } catch (error) {
      console.error("Failed to load configurations:", error);
      toast.error("Failed to load integration configurations");
    } finally {
      setLoading(prev => ({ ...prev, microsoftSSO: false, nessus: false }));
    }
  };

  const saveMicrosoftSSOConfig = async () => {
    try {
      setLoading(prev => ({ ...prev, microsoftSSO: true }));
      
      const savedConfig = await integrationService.saveMicrosoftSSOConfig({
        enabled: microsoftSSO.enabled,
        clientId: microsoftSSO.clientId,
        clientSecret: microsoftSSO.clientSecret,
        tenantId: microsoftSSO.tenantId,
        redirectUri: microsoftSSO.redirectUri
      });
      
      setMicrosoftSSO(prev => ({
        ...prev,
        status: savedConfig.status as "configured" | "not_configured" | "error" | "connected",
        isConfigured: true
      }));
      
      toast.success("Microsoft SSO configuration saved successfully");
    } catch (error) {
      console.error("Failed to save Microsoft SSO config:", error);
      toast.error("Failed to save Microsoft SSO configuration");
    } finally {
      setLoading(prev => ({ ...prev, microsoftSSO: false }));
    }
  };

  const saveNessusConfig = async () => {
    try {
      setLoading(prev => ({ ...prev, nessus: true }));
      
      const savedConfig = await integrationService.saveNessusConfig({
        enabled: nessus.enabled,
        serverUrl: nessus.serverUrl,
        username: nessus.username,
        password: nessus.password
      });
      
      setNessus(prev => ({
        ...prev,
        status: savedConfig.status as "connected" | "disconnected" | "error" | "configured",
        vulnerabilityCount: savedConfig.extra_metadata?.vulnerabilityCount || 0,
        isConfigured: true
      }));
      
      toast.success("Nessus configuration saved successfully");
    } catch (error) {
      console.error("Failed to save Nessus config:", error);
      toast.error("Failed to save Nessus configuration");
    } finally {
      setLoading(prev => ({ ...prev, nessus: false }));
    }
  };

  const testMicrosoftSSOConnection = async () => {
    try {
      setLoading(prev => ({ ...prev, testMicrosoft: true }));
      
      const result = await integrationService.testMicrosoftSSO({
        clientId: microsoftSSO.clientId,
        clientSecret: microsoftSSO.clientSecret,
        tenantId: microsoftSSO.tenantId,
        redirectUri: microsoftSSO.redirectUri
      });
      
      setMicrosoftSSO(prev => ({ 
        ...prev, 
        status: "configured", 
        lastTest: new Date().toLocaleString() 
      }));
      
      toast.success(result.message);
    } catch (error) {
      setMicrosoftSSO(prev => ({ 
        ...prev, 
        status: "error", 
        lastTest: new Date().toLocaleString() 
      }));
      
      toast.error(error instanceof Error ? error.message : "Microsoft SSO test failed");
    } finally {
      setLoading(prev => ({ ...prev, testMicrosoft: false }));
    }
  };

  const testNessusConnection = async () => {
    try {
      setLoading(prev => ({ ...prev, testNessus: true }));
      
      const result = await integrationService.testNessus({
        serverUrl: nessus.serverUrl,
        username: nessus.username,
        password: nessus.password
      });
      
      setNessus(prev => ({ 
        ...prev, 
        status: "connected", 
        lastScan: new Date().toLocaleString(),
        vulnerabilityCount: 1547 // This would come from the actual test result
      }));
      
      toast.success(result.message);
    } catch (error) {
      setNessus(prev => ({ 
        ...prev, 
        status: "error", 
        lastScan: new Date().toLocaleString() 
      }));
      
      toast.error(error instanceof Error ? error.message : "Nessus connection test failed");
    } finally {
      setLoading(prev => ({ ...prev, testNessus: false }));
    }
  };

  const deleteMicrosoftSSOConfig = async () => {
    try {
      setLoading(prev => ({ ...prev, microsoftSSO: true }));
      
      await integrationService.deleteIntegration('microsoft_sso');
      
      setMicrosoftSSO({
        enabled: false,
        clientId: "",
        clientSecret: "",
        tenantId: "common",
        redirectUri: "https://orbiti.fareportal.com:7000/microsoft/callback",
        status: "not_configured",
        lastTest: "Never",
        isConfigured: false
      });
      
      toast.success("Microsoft SSO integration deleted successfully");
    } catch (error) {
      console.error("Failed to delete Microsoft SSO config:", error);
      toast.error("Failed to delete Microsoft SSO integration");
    } finally {
      setLoading(prev => ({ ...prev, microsoftSSO: false }));
    }
  };

  const deleteNessusConfig = async () => {
    try {
      setLoading(prev => ({ ...prev, nessus: true }));
      
      await integrationService.deleteIntegration('nessus');
      
      setNessus({
        enabled: false,
        serverUrl: "",
        username: "",
        password: "",
        status: "disconnected",
        lastScan: "Never",
        vulnerabilityCount: 0,
        isConfigured: false
      });
      
      toast.success("Nessus integration deleted successfully");
    } catch (error) {
      console.error("Failed to delete Nessus config:", error);
      toast.error("Failed to delete Nessus integration");
    } finally {
      setLoading(prev => ({ ...prev, nessus: false }));
    }
  };

  const getStatusBadge = (status: string) => {
    switch (status) {
      case "configured":
      case "connected":
        return <Badge className="bg-green-500 text-white"><CheckCircle className="h-3 w-3 mr-1" />Connected</Badge>;
      case "error":
        return <Badge className="bg-red-500 text-white"><XCircle className="h-3 w-3 mr-1" />Error</Badge>;
      default:
        return <Badge className="bg-gray-500 text-white"><AlertCircle className="h-3 w-3 mr-1" />Not Configured</Badge>;
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-3xl font-bold">Integrations</h1>
          <p className="text-muted-foreground">
            Configure Microsoft SSO authentication and Nessus vulnerability scanning for the Orbit-I security platform
          </p>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Microsoft SSO Integration Card */}
        <Card>
          <CardHeader>
            <div className="flex items-center justify-between">
              <div className="flex items-center space-x-2">
                <Users className="h-5 w-5 text-blue-600" />
                <CardTitle>Microsoft SSO Authentication</CardTitle>
              </div>
              {getStatusBadge(microsoftSSO.status)}
            </div>
            <CardDescription>
              Configure Microsoft Single Sign-On for user authentication
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="flex items-center justify-between">
              <Label htmlFor="microsoft-enabled">Enable Microsoft SSO</Label>
              <Switch
                id="microsoft-enabled"
                checked={microsoftSSO.enabled}
                onCheckedChange={(checked) => 
                  setMicrosoftSSO(prev => ({ ...prev, enabled: checked }))
                }
              />
            </div>

            {microsoftSSO.enabled && (
              <div className="space-y-4 pt-4 border-t">
                {microsoftSSO.isConfigured && (
                  <Alert className="mb-4">
                    <AlertCircle className="h-4 w-4" />
                    <AlertDescription>
                      Integration is configured and active. You can update the configuration or delete the integration.
                    </AlertDescription>
                  </Alert>
                )}
                
                <div className="grid gap-2">
                  <Label htmlFor="client-id">Client ID</Label>
                  <Input
                    id="client-id"
                    value={microsoftSSO.clientId}
                    onChange={(e) => setMicrosoftSSO(prev => ({ ...prev, clientId: e.target.value }))}
                    placeholder="Enter Azure AD Application Client ID"
                  />
                </div>

                <div className="grid gap-2">
                  <Label htmlFor="client-secret">Client Secret</Label>
                  <div className="relative">
                    <Input
                      id="client-secret"
                      type={showSecrets.microsoftSecret ? "text" : "password"}
                      value={microsoftSSO.clientSecret}
                      onChange={(e) => setMicrosoftSSO(prev => ({ ...prev, clientSecret: e.target.value }))}
                      placeholder={microsoftSSO.isConfigured ? "Enter new client secret to update" : "Enter Azure AD Application Client Secret"}
                      className="pr-10"
                    />
                    <Button
                      type="button"
                      variant="ghost"
                      size="sm"
                      className="absolute right-0 top-0 h-full px-3 py-2 hover:bg-transparent"
                      onClick={() => setShowSecrets(prev => ({ ...prev, microsoftSecret: !prev.microsoftSecret }))}
                    >
                      {showSecrets.microsoftSecret ? (
                        <EyeOff className="h-4 w-4" />
                      ) : (
                        <Eye className="h-4 w-4" />
                      )}
                    </Button>
                  </div>
                </div>

                <div className="grid gap-2">
                  <Label htmlFor="tenant-id">Tenant ID</Label>
                  <Input
                    id="tenant-id"
                    value={microsoftSSO.tenantId}
                    onChange={(e) => setMicrosoftSSO(prev => ({ ...prev, tenantId: e.target.value }))}
                    placeholder="common (for multi-tenant) or specific tenant ID"
                  />
                </div>

                <div className="grid gap-2">
                  <Label htmlFor="redirect-uri">Redirect URI</Label>
                  <Input
                    id="redirect-uri"
                    value={microsoftSSO.redirectUri}
                    onChange={(e) => setMicrosoftSSO(prev => ({ ...prev, redirectUri: e.target.value }))}
                    placeholder="https://orbiti.fareportal.com:7000/microsoft/callback"
                  />
                </div>

                <div className="flex space-x-2 pt-4">
                  <Button onClick={saveMicrosoftSSOConfig} className="flex-1">
                    <Save className="h-4 w-4 mr-2" />
                    Save Configuration
                  </Button>
                  <Button variant="outline" onClick={testMicrosoftSSOConnection}>
                    <TestTube className="h-4 w-4 mr-2" />
                    Test Connection
                  </Button>
                  {microsoftSSO.isConfigured && (
                    <Button variant="destructive" onClick={deleteMicrosoftSSOConfig}>
                      <Trash2 className="h-4 w-4 mr-2" />
                      Delete
                    </Button>
                  )}
                </div>

                {microsoftSSO.lastTest !== "Never" && (
                  <div className="text-sm text-muted-foreground">
                    Last tested: {microsoftSSO.lastTest}
                  </div>
                )}
              </div>
            )}
          </CardContent>
        </Card>

        {/* Nessus Integration Card */}
        <Card>
          <CardHeader>
            <div className="flex items-center justify-between">
              <div className="flex items-center space-x-2">
                <Shield className="h-5 w-5 text-red-600" />
                <CardTitle>Nessus Vulnerability Scanner</CardTitle>
              </div>
              {getStatusBadge(nessus.status)}
            </div>
            <CardDescription>
              Configure Nessus for vulnerability scanning and data import
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="flex items-center justify-between">
              <Label htmlFor="nessus-enabled">Enable Nessus Integration</Label>
              <Switch
                id="nessus-enabled"
                checked={nessus.enabled}
                onCheckedChange={(checked) => 
                  setNessus(prev => ({ ...prev, enabled: checked }))
                }
              />
            </div>

            {nessus.enabled && (
              <div className="space-y-4 pt-4 border-t">
                {nessus.isConfigured && (
                  <Alert className="mb-4">
                    <AlertCircle className="h-4 w-4" />
                    <AlertDescription>
                      Integration is configured. For security, credentials are not displayed. 
                      Enter new credentials to update or use the delete button to remove the integration.
                    </AlertDescription>
                  </Alert>
                )}
                
                <div className="space-y-4">
                  <div>
                    <Label htmlFor="nessus-url">Server URL</Label>
                    <Input
                      id="nessus-url"
                      type="url"
                      placeholder="https://nessus.company.com:8834"
                      value={nessus.serverUrl}
                      onChange={(e) => setNessus(prev => ({ ...prev, serverUrl: e.target.value }))}
                    />
                  </div>

                  <div>
                    <Label htmlFor="nessus-username">Username</Label>
                    <Input
                      id="nessus-username"
                      type="text"
                      placeholder={nessus.isConfigured ? "Enter new username to update" : "Enter Nessus username"}
                      value={nessus.username}
                      onChange={(e) => setNessus(prev => ({ ...prev, username: e.target.value }))}
                    />
                  </div>

                  <div>
                    <Label htmlFor="nessus-password">Password</Label>
                    <div className="relative">
                      <Input
                        id="nessus-password"
                        type={showSecrets.nessusSecret ? "text" : "password"}
                        placeholder={nessus.isConfigured ? "Enter new password to update" : "Enter Nessus password"}
                        value={nessus.password}
                        onChange={(e) => setNessus(prev => ({ ...prev, password: e.target.value }))}
                        className="pr-10"
                      />
                      <Button
                        type="button"
                        variant="ghost"
                        size="sm"
                        className="absolute right-0 top-0 h-full px-3 py-2 hover:bg-transparent"
                        onClick={() => setShowSecrets(prev => ({ ...prev, nessusSecret: !prev.nessusSecret }))}
                      >
                        {showSecrets.nessusSecret ? (
                          <EyeOff className="h-4 w-4" />
                        ) : (
                          <Eye className="h-4 w-4" />
                        )}
                      </Button>
                    </div>
                  </div>
                </div>
                <div className="flex space-x-2 pt-4">
                  <Button 
                    onClick={saveNessusConfig} 
                    disabled={loading.nessus}
                    className="flex-1"
                  >
                    <Save className="h-4 w-4 mr-2" />
                    {loading.nessus ? "Saving..." : "Save Configuration"}
                  </Button>
                  <Button 
                    onClick={testNessusConnection}
                    disabled={loading.testNessus}
                    variant="outline"
                    className="border-blue-200 text-blue-700 hover:bg-blue-50"
                  >
                    <TestTube className="h-4 w-4 mr-2" />
                    {loading.testNessus ? "Testing..." : "Test Connection"}
                  </Button>
                  {nessus.isConfigured && (
                    <Button variant="destructive" onClick={deleteNessusConfig}>
                      <Trash2 className="h-4 w-4 mr-2" />
                      Delete
                    </Button>
                  )}
                </div>

                <div className="grid grid-cols-2 gap-4 pt-4 text-sm">
                  <div>
                    <span className="text-muted-foreground">Last Scan:</span>
                    <div className="font-medium">{nessus.lastScan}</div>
                  </div>
                  <div>
                    <span className="text-muted-foreground">Vulnerabilities:</span>
                    <div className="font-medium">{nessus.vulnerabilityCount.toLocaleString()}</div>
                  </div>
                </div>
              </div>
            )}
          </CardContent>
        </Card>
      </div>

      {/* Integration Status Summary */}
      <Card>
        <CardHeader>
          <CardTitle>Integration Status</CardTitle>
          <CardDescription>Overview of your configured integrations</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="flex items-center justify-between p-4 border rounded-lg">
              <div className="flex items-center space-x-3">
                <Users className="h-5 w-5 text-blue-600" />
                <div>
                  <div className="font-medium">Microsoft SSO</div>
                  <div className="text-sm text-muted-foreground">Authentication Provider</div>
                </div>
              </div>
              {getStatusBadge(microsoftSSO.status)}
            </div>
            
            <div className="flex items-center justify-between p-4 border rounded-lg">
              <div className="flex items-center space-x-3">
                <Shield className="h-5 w-5 text-red-600" />
                <div>
                  <div className="font-medium">Nessus Scanner</div>
                  <div className="text-sm text-muted-foreground">Vulnerability Assessment</div>
                </div>
              </div>
              {getStatusBadge(nessus.status)}
            </div>
          </div>

          {(microsoftSSO.enabled || nessus.enabled) && (
            <Alert className="mt-4">
              <AlertCircle className="h-4 w-4" />
              <AlertDescription>
                Integration settings are stored securely on the server. Sensitive credentials are not displayed 
                for security reasons. Use the delete button to remove integrations if needed.
              </AlertDescription>
            </Alert>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
