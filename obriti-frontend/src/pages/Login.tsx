import { useState, useEffect } from "react";
import { useSearchParams } from "react-router-dom";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { Separator } from "@/components/ui/separator";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { AlertCircle } from "lucide-react";
import { toast } from "sonner";
import { useAuth } from "@/components/AuthProvider";
import { microsoftSSOService, type MicrosoftSSOConfig } from "@/services/microsoftSSOService";
import config from "../config/environment";

export default function Login() {
  const [searchParams] = useSearchParams();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const [microsoftSSOLoading, setMicrosoftSSOLoading] = useState(false);
  const [microsoftConfig, setMicrosoftConfig] = useState<MicrosoftSSOConfig>({ enabled: false, client_id: null, redirect_uri: '' });
  const { login } = useAuth();

  // Check for authentication errors from URL parameters
  const authError = searchParams.get('error');
  const authErrorDescription = searchParams.get('error_description');

  // Load Microsoft SSO configuration on component mount
  useEffect(() => {
    const loadMicrosoftConfig = async () => {
      try {
        const config = await microsoftSSOService.getConfig();
        console.log('Microsoft SSO Config:', config); // Debug log
        setMicrosoftConfig(config);
      } catch (error) {
        console.error('Failed to load Microsoft SSO config:', error);
        // Set default config if fetch fails
        setMicrosoftConfig({ enabled: false, client_id: null, redirect_uri: '' });
      }
    };
    loadMicrosoftConfig();
  }, []);

  // Show toast notification for authentication errors
  useEffect(() => {
    if (authError && authErrorDescription) {
      toast.error(`Authentication Failed: ${decodeURIComponent(authErrorDescription)}`);
    }
  }, [authError, authErrorDescription]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    try {
      const params = new URLSearchParams();
      params.append("grant_type", "password");
      params.append("username", username);
      params.append("password", password);
      params.append("scope", "");
      params.append("client_id", "string");
      params.append("client_secret", "string");
      // Use fetch directly for login (no Authorization header needed)
      const res = await fetch(`${config.apiUrl}/api/auth/login`, {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
          "accept": "application/json"
        },
        body: params.toString(),
      });
      const data = await res.json();
      if (res.ok && data.access_token) {
        toast.success("Login successful");
        await login(data.access_token);
      } else {
        toast.error(data.detail || "Login failed");
      }
    } catch (err) {
      toast.error("Network error");
    } finally {
      setLoading(false);
    }
  };

  const handleMicrosoftLogin = async () => {
    setMicrosoftSSOLoading(true);
    try {
      await microsoftSSOService.initiateLogin();
    } catch (error) {
      console.error('Microsoft SSO login error:', error);
      toast.error(error instanceof Error ? error.message : 'Failed to initiate Microsoft login');
      setMicrosoftSSOLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-background to-muted/40 text-foreground relative overflow-hidden">
      {/* Subtle Cybersecurity Glow Effect */}
      <div className="absolute inset-0 pointer-events-none z-0">
        <div className="absolute -top-32 -left-32 w-[400px] h-[400px] bg-primary/20 rounded-full blur-2xl animate-pulse" />
        <div className="absolute bottom-0 right-0 w-[300px] h-[300px] bg-secondary/30 rounded-full blur-2xl animate-pulse" />
      </div>
      <Card className="w-full max-w-md z-10 shadow-2xl border border-border/60 bg-card/90 backdrop-blur-md rounded-2xl">
        <CardHeader className="flex flex-col items-center gap-1">
          <img src="/icon.png" alt="Orbit-I Logo" className="h-16 mb-3 drop-shadow-lg" />
          <div className="text-muted-foreground text-center text-sm">Sign in to continue</div>
        </CardHeader>
        <CardContent>
          {/* Authentication Error Display */}
          {authError && authErrorDescription && (
            <Alert className="mb-6 border-red-200 bg-red-50 dark:border-red-800 dark:bg-red-950">
              <AlertCircle className="h-4 w-4 text-red-600 dark:text-red-400" />
              <AlertDescription className="text-red-800 dark:text-red-200">
                <strong>Authentication Failed:</strong> {decodeURIComponent(authErrorDescription)}
              </AlertDescription>
            </Alert>
          )}

          {/* Microsoft SSO Login */}
          {microsoftConfig.enabled && (
            <>
              <div className="space-y-4 mb-6">
                <Button
                  type="button"
                  onClick={handleMicrosoftLogin}
                  disabled={microsoftSSOLoading}
                  className="w-full text-lg font-semibold tracking-wide shadow-md hover:scale-[1.02] transition-transform duration-150 bg-[#0078d4] hover:bg-[#106ebe] text-white border-0"
                >
                  {microsoftSSOLoading ? (
                    <>
                      <svg className="animate-spin -ml-1 mr-3 h-5 w-5 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                        <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                        <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                      </svg>
                      Signing in with Microsoft...
                    </>
                  ) : (
                    <>
                      <svg className="mr-2 h-5 w-5" viewBox="0 0 23 23" fill="currentColor">
                        <path d="M1 1h10v10H1z" fill="#f25022"/>
                        <path d="M12 1h10v10H12z" fill="#00a4ef"/>
                        <path d="M1 12h10v10H1z" fill="#ffb900"/>
                        <path d="M12 12h10v10H12z" fill="#7fba00"/>
                      </svg>
                      Continue with Microsoft
                    </>
                  )}
                </Button>
              </div>
              
              <div className="relative">
                <div className="absolute inset-0 flex items-center">
                  <Separator className="w-full" />
                </div>
                <div className="relative flex justify-center text-xs uppercase">
                  <span className="bg-card px-2 text-muted-foreground">Or continue with local account</span>
                </div>
              </div>
            </>
          )}

          {/* Local Login Form */}
          <form onSubmit={handleSubmit} className={`space-y-6 ${microsoftConfig.enabled ? 'mt-6' : ''}`}>
            <div>
              <Label htmlFor="username" className="text-lg">Username</Label>
              <Input
                id="username"
                value={username}
                onChange={e => setUsername(e.target.value)}
                required
                autoFocus={!microsoftConfig.enabled}
                placeholder="Enter your username"
                className="mt-1 bg-background/80 border border-border focus:ring-primary text-lg"
              />
            </div>
            <div>
              <Label htmlFor="password" className="text-lg">Password</Label>
              <Input
                id="password"
                type="password"
                value={password}
                onChange={e => setPassword(e.target.value)}
                required
                placeholder="Enter your password"
                className="mt-1 bg-background/80 border border-border focus:ring-primary text-lg"
              />
            </div>
            <Button type="submit" className="w-full text-lg font-semibold tracking-wide shadow-md hover:scale-[1.02] transition-transform duration-150 ring-1 ring-primary/20" disabled={loading}>
              {loading ? "Logging in..." : "Login"}
            </Button>
          </form>
        </CardContent>
      </Card>
    </div>
  );
} 