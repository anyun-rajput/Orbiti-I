import { useEffect, useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { toast } from "sonner";
import { useAuth } from "@/components/AuthProvider";
import { microsoftSSOService } from "@/services/microsoftSSOService";
import { Loader2 } from "lucide-react";

export default function MicrosoftCallback() {
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();
  const { login } = useAuth();
  const [status, setStatus] = useState<'processing' | 'success' | 'error'>('processing');
  const [errorMessage, setErrorMessage] = useState<string>('');

  useEffect(() => {
    const handleCallback = async () => {
      try {
        const token = searchParams.get('token');
        const username = searchParams.get('user');
        const success = searchParams.get('success');
        const error = searchParams.get('error');
        const errorDescription = searchParams.get('error_description');

        // Check for OAuth errors
        if (error) {
          throw new Error(errorDescription || `OAuth error: ${error}`);
        }

        // Check if we have a successful authentication with token
        if (success === 'true' && token) {
          // Login with the received token
          await login(token);
          
          setStatus('success');
          toast.success(`Welcome ${username}! Microsoft SSO authentication successful.`);
          
          // Navigate to dashboard after a brief delay
          setTimeout(() => {
            navigate('/');
          }, 1500);
          return;
        }

        // If we have a code (old flow), handle it
        const code = searchParams.get('code');
        const state = searchParams.get('state');

        if (code) {
          // Validate state parameter for CSRF protection
          if (state && !microsoftSSOService.validateState(state)) {
            throw new Error('Invalid state parameter - possible CSRF attack');
          }

          // Exchange code for token
          const authResponse = await microsoftSSOService.handleCallback(code, state || undefined);
          
          if (!authResponse) {
            throw new Error('Failed to authenticate with Microsoft');
          }

          // Login with the received token
          await login(authResponse.access_token);
          
          setStatus('success');
          toast.success(`Welcome ${authResponse.user.first_name || authResponse.user.username}!`);
          
          // Navigate to dashboard after a brief delay
          setTimeout(() => {
            navigate('/');
          }, 1500);
          return;
        }

        // If we reach here, no valid authentication data was found
        throw new Error('No valid authentication data received');

      } catch (error) {
        console.error('Microsoft SSO callback error:', error);
        setStatus('error');
        const message = error instanceof Error ? error.message : 'Authentication failed';
        setErrorMessage(message);
        toast.error(message);
        
        // Navigate back to login after a delay
        setTimeout(() => {
          navigate('/login');
        }, 3000);
      }
    };

    handleCallback();
  }, [searchParams, navigate, login]);

  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-background to-muted/40 text-foreground">
      <Card className="w-full max-w-md shadow-2xl border border-border/60 bg-card/90 backdrop-blur-md rounded-2xl">
        <CardHeader className="flex flex-col items-center gap-1">
          <img src="/icon.png" alt="Orbit-I Logo" className="h-16 mb-3 drop-shadow-lg" />
          <CardTitle className="text-center">
            {status === 'processing' && 'Authenticating...'}
            {status === 'success' && 'Authentication Successful'}
            {status === 'error' && 'Authentication Failed'}
          </CardTitle>
        </CardHeader>
        <CardContent className="text-center">
          {status === 'processing' && (
            <div className="flex flex-col items-center gap-4">
              <Loader2 className="h-8 w-8 animate-spin text-primary" />
              <p className="text-muted-foreground">
                Processing Microsoft authentication...
              </p>
            </div>
          )}
          
          {status === 'success' && (
            <div className="flex flex-col items-center gap-4">
              <div className="h-8 w-8 rounded-full bg-green-500 flex items-center justify-center">
                <svg className="h-5 w-5 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                </svg>
              </div>
              <p className="text-muted-foreground">
                Redirecting to dashboard...
              </p>
            </div>
          )}
          
          {status === 'error' && (
            <div className="flex flex-col items-center gap-4">
              <div className="h-8 w-8 rounded-full bg-red-500 flex items-center justify-center">
                <svg className="h-5 w-5 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                </svg>
              </div>
              <p className="text-red-600 text-sm">
                {errorMessage}
              </p>
              <p className="text-muted-foreground text-sm">
                Redirecting to login page...
              </p>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
