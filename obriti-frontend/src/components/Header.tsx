import { SidebarTrigger } from "@/components/ui/sidebar";
import { Button } from "@/components/ui/button";
import { Scan, Bell, LogOut } from "lucide-react";
import { useAuth } from "@/components/AuthProvider";

export function Header() {
  const { logout } = useAuth();
  return (
    <header className="h-16 border-b border-border bg-card flex items-center justify-between px-6">
      <div className="flex items-center gap-4">
        <SidebarTrigger />
        <div>
          <h1 className="text-xl font-semibold">Vulnerability Management Platform</h1>
          <p className="text-sm text-muted-foreground">Advanced security management platform</p>
        </div>
      </div>
      <div className="flex items-center gap-3">
        <Button variant="ghost" size="sm">
          <Bell className="h-4 w-4" />
        </Button>
        <Button variant="secondary" size="sm" className="gap-2" onClick={logout}>
          <LogOut className="h-4 w-4" />
          Logout
        </Button>
      </div>
    </header>
  );
}
