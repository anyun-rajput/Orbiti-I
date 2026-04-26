import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { toast } from "sonner";
import { Layout } from "@/components/Layout";
import { useAuth } from "@/components/AuthProvider";
import { useApiFetch } from "@/lib/utils";
import { Eye, EyeOff } from "lucide-react";

export default function Register() {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [firstName, setFirstName] = useState("");
  const [lastName, setLastName] = useState("");
  const [email, setEmail] = useState("");
  const [loading, setLoading] = useState(false);
  const [passwordVisible, setPasswordVisible] = useState(false);
  const [confirmPassword, setConfirmPassword] = useState("");
  const [confirmPasswordVisible, setConfirmPasswordVisible] = useState(false);
  const navigate = useNavigate();
  const { login } = useAuth();
  const apiFetch = useApiFetch();

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (password !== confirmPassword) {
      toast.error("Passwords do not match");
      return;
    }
    setLoading(true);
    try {
      const res = await fetch("https://orbiti.fareportal.com:7000/api/auth/register", {
        method: "POST",
        headers: { "Content-Type": "application/json", "accept": "application/json" },
        body: JSON.stringify({
          username,
          password,
          first_name: firstName,
          last_name: lastName,
          email,
        }),
      });
      const data = await res.json();
      if (res.ok && data.access_token) {
        toast.success("Registration successful");
        login(data.access_token);
      } else {
        toast.error(data.detail || "Registration failed");
      }
    } catch (err) {
      toast.error("Network error");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-background text-foreground relative overflow-hidden">
      {/* Subtle Cybersecurity Glow Effect */}
      <div className="absolute inset-0 pointer-events-none z-0">
        <div className="absolute -top-32 -left-32 w-[400px] h-[400px] bg-primary/20 rounded-full blur-2xl animate-pulse" />
        <div className="absolute bottom-0 right-0 w-[300px] h-[300px] bg-secondary/30 rounded-full blur-2xl animate-pulse" />
      </div>
      <Card className="w-full max-w-md z-10 shadow-2xl border border-border bg-card/90 backdrop-blur-md">
        <CardHeader className="flex flex-col items-center gap-2">
          <img src="/icon.png" alt="Orbit-I Logo" className="w-20 h-20 mb-2 drop-shadow-lg" />
          <CardTitle className="text-3xl font-bold text-primary text-center">Register for VMT</CardTitle>
          <div className="text-muted-foreground text-center text-base font-medium mt-2">
            Create your account to secure your assets.
          </div>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleSubmit} className="space-y-6">
            <div>
              <Label htmlFor="username" className="text-lg">Username</Label>
              <Input
                id="username"
                value={username}
                onChange={e => setUsername(e.target.value)}
                required
                autoFocus
                className="mt-1 bg-background/80 border border-border focus:ring-primary text-lg"
              />
            </div>
            <div>
              <Label htmlFor="password" className="text-lg">Password</Label>
              <div className="relative">
                <Input
                  id="password"
                  type={passwordVisible ? "text" : "password"}
                  value={password}
                  onChange={e => setPassword(e.target.value)}
                  required
                  className="mt-1 bg-background/80 border border-border focus:ring-primary text-lg pr-10"
                />
                <button
                  type="button"
                  tabIndex={-1}
                  className="absolute right-2 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-primary focus:outline-none"
                  onClick={() => setPasswordVisible(v => !v)}
                  aria-label={passwordVisible ? "Hide password" : "Show password"}
                >
                  {passwordVisible ? <EyeOff size={20} /> : <Eye size={20} />}
                </button>
              </div>
            </div>
            <div>
              <Label htmlFor="confirmPassword" className="text-lg">Confirm Password</Label>
              <div className="relative">
                <Input
                  id="confirmPassword"
                  type={confirmPasswordVisible ? "text" : "password"}
                  value={confirmPassword}
                  onChange={e => setConfirmPassword(e.target.value)}
                  required
                  className="mt-1 bg-background/80 border border-border focus:ring-primary text-lg pr-10"
                />
                <button
                  type="button"
                  tabIndex={-1}
                  className="absolute right-2 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-primary focus:outline-none"
                  onClick={() => setConfirmPasswordVisible(v => !v)}
                  aria-label={confirmPasswordVisible ? "Hide password" : "Show password"}
                >
                  {confirmPasswordVisible ? <EyeOff size={20} /> : <Eye size={20} />}
                </button>
              </div>
            </div>
            <div>
              <Label htmlFor="firstName" className="text-lg">First Name</Label>
              <Input
                id="firstName"
                value={firstName}
                onChange={e => setFirstName(e.target.value)}
                required
                className="mt-1 bg-background/80 border border-border focus:ring-primary text-lg"
              />
            </div>
            <div>
              <Label htmlFor="lastName" className="text-lg">Last Name</Label>
              <Input
                id="lastName"
                value={lastName}
                onChange={e => setLastName(e.target.value)}
                required
                className="mt-1 bg-background/80 border border-border focus:ring-primary text-lg"
              />
            </div>
            <div>
              <Label htmlFor="email" className="text-lg">Email</Label>
              <Input
                id="email"
                type="email"
                value={email}
                onChange={e => setEmail(e.target.value)}
                required
                className="mt-1 bg-background/80 border border-border focus:ring-primary text-lg"
              />
            </div>
            <Button type="submit" className="w-full text-lg font-semibold tracking-wide shadow-md hover:scale-[1.02] transition-transform duration-150" disabled={loading}>
              {loading ? "Registering..." : "Register"}
            </Button>
            <div className="text-center text-sm mt-2 text-muted-foreground">
              Already have an account? <a href="/login" className="text-primary underline hover:text-primary/80">Login</a>
            </div>
          </form>
        </CardContent>
      </Card>
    </div>
  );
} 