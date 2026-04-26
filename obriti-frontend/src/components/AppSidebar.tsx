import { NavLink, useLocation } from "react-router-dom";
import { useMemo, memo, useCallback } from "react";
import {
  Scan,
  Monitor,
  AlertTriangle,
  History,
  Settings,
  BarChart3,
  Users,
  Server,
  CheckCircle,
  Zap,
  ShieldX,
} from "lucide-react";
import {
  Sidebar,
  SidebarContent,
  SidebarGroup,
  SidebarGroupContent,
  SidebarGroupLabel,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
  useSidebar,
} from "@/components/ui/sidebar";
import { useAuth } from "./AuthProvider";

const allNavItems = [
  { title: "Dashboard", url: "/", icon: BarChart3, permission: "dashboard" },
  { title: "Scan Management", url: "/scans", icon: Scan, permission: "scan_management" },
  { title: "Asset Management", url: "/assets", icon: Monitor, permission: "asset_management" },
  { title: "Vulnerabilities", url: "/vulnerabilities", icon: AlertTriangle, permission: "vulnerabilities" },
  { title: "Vuln by Owner", url: "/vulnerabilities/by-owner", icon: Users, permission: "vuln_by_owner" },
  { title: "Vuln by Hosts", url: "/vulnerabilities/by-hosts", icon: Server, permission: "vuln_by_hosts" },
  { title: "Closed Vulnerabilities", url: "/vulnerabilities/closed", icon: CheckCircle, permission: "closed_vulnerabilities" },
  { title: "Exceptions", url: "/exceptions", icon: ShieldX, permission: "exceptions" },
  { title: "Rescan Ready Hosts", url: "/rescan-ready", icon: Zap, permission: "scan_management" },
  { title: "Settings", url: "/settings", icon: Settings, permission: "settings" },
];

// Custom comparison function to prevent unnecessary re-renders
const AppSidebarComponent = function AppSidebar() {
  const { state } = useSidebar();
  const location = useLocation();
  const currentPath = location.pathname;
  const isCollapsed = state === "collapsed";
  const { userInfo, loading, hasPermission } = useAuth();

  const isActive = useCallback((path: string) => currentPath === path, [currentPath]);

  // Memoize user permissions array to prevent hasPermission function changes
  const userPermissions = useMemo(() => userInfo?.permissions || [], [userInfo?.permissions]);
  
  // Memoize filtered navigation items based on stable user permissions
  const navItems = useMemo(() => {
    if (userInfo && userPermissions.length > 0) {
      return allNavItems.filter(item => 
        userPermissions.includes(item.permission)
      );
    } else if (!loading) {
      // Fallback to org_team permissions if no user info
      return allNavItems.filter(item => 
        ["dashboard", "vulnerabilities", "vuln_by_owner", "vuln_by_hosts", "closed_vulnerabilities", "exceptions"].includes(item.permission)
      );
    }
    return [];
  }, [userInfo, userPermissions, loading]);

  // Show loading state while checking user privileges
  if (loading) {
    return (
      <Sidebar className={`${isCollapsed ? "w-20" : "w-64"} border-r bg-card`} collapsible="icon">
        <SidebarContent>
          <div className="flex items-center justify-center h-full">
            <div className="animate-spin rounded-full h-6 w-6 border-b-2 border-primary"></div>
          </div>
        </SidebarContent>
      </Sidebar>
    );
  }

  return (
    <Sidebar className={`${isCollapsed ? "w-20" : "w-64"} border-r bg-card`} collapsible="icon">
      <SidebarContent>
        {/* Header */}
        <div className={`${isCollapsed ? "p-3" : "p-4"} border-b`}>
          <div className={`flex ${isCollapsed ? "justify-center" : "items-center gap-3"}`}>
            <img 
              src={isCollapsed ? "/icon_favicon.png" : "/icon.png"} 
              alt="Orbit-I Logo" 
              className="h-8" 
            />
            {!isCollapsed && (
              <div>
                <p className="text-xs text-muted-foreground">Security Platform</p>
              </div>
            )}
          </div>
        </div>

        {/* Navigation */}
        <div className="flex-1 py-2">
          <SidebarGroup>
            <SidebarGroupLabel className={`${isCollapsed ? "sr-only" : "px-4 text-xs font-medium text-muted-foreground uppercase tracking-wide"}`}>
              Navigation
            </SidebarGroupLabel>
            <SidebarGroupContent className="px-2">
              <SidebarMenu className="space-y-1">
                {navItems.map((item) => {
                  const isItemActive = isActive(item.url);
                  return (
                    <SidebarMenuItem key={item.title}>
                      <SidebarMenuButton asChild>
                        <NavLink
                          to={item.url}
                          end
                          className={`flex items-center gap-3 px-3 py-2 rounded-md transition-colors ${
                            isItemActive
                              ? "bg-accent text-accent-foreground font-medium"
                              : "text-muted-foreground hover:text-foreground hover:bg-accent/50"
                          }`}
                        >
                          <item.icon className="h-4 w-4 flex-shrink-0" />
                          {!isCollapsed && <span className="text-sm">{item.title}</span>}
                        </NavLink>
                      </SidebarMenuButton>
                    </SidebarMenuItem>
                  );
                })}
              </SidebarMenu>
            </SidebarGroupContent>
          </SidebarGroup>
        </div>

        {/* User Info */}
        {!isCollapsed && userInfo && (
          <div className="p-4 border-t">
            <div className="flex items-center gap-3 p-2 rounded-md bg-muted/50">
              <div className="flex items-center justify-center w-8 h-8 bg-primary/10 rounded-full">
                <div className="w-2 h-2 bg-primary rounded-full"></div>
              </div>
              <div className="flex-1 min-w-0">
                <p className="text-sm font-medium text-foreground truncate">{userInfo.username}</p>
                <p className="text-xs text-muted-foreground capitalize">
                  {userInfo.role_name.replace('_', ' ')}
                </p>
              </div>
            </div>
          </div>
        )}
      </SidebarContent>
    </Sidebar>
  );
};

// Export with memo and custom comparison
export const AppSidebar = memo(AppSidebarComponent, (prevProps, nextProps) => {
  // Since this component has no props, it should only re-render when internal hooks change
  // The memo will prevent re-renders when parent components re-render
  return true; // Always consider props equal since there are no props
});
