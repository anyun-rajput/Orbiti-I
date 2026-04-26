
import { useEffect, useState, useRef, useMemo, useCallback } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { Button } from "@/components/ui/button";
import { 
  Shield, 
  AlertTriangle, 
  CheckCircle, 
  Clock,
  Activity,
  Monitor,
  Scan,
  TrendingUp,
  RefreshCw,
  Zap,
  ShieldX
} from "lucide-react";
import { useApiFetch } from "@/lib/utils";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";
import { useNavigate } from "react-router-dom";
import { useAuth } from "./AuthProvider";
import { TopOwnersChart } from "./TopOwnersChart";
import { VulnerabilityPieChart } from "./VulnerabilityPieChart";
import { VulnerabilityTrendChart } from "./VulnerabilityTrendChart";
import config from "@/config/environment";

// TypeScript interfaces for clarity
interface Vulnerability {
  id: string;
  name: string;
  severity: "critical" | "high" | "medium" | "low";
  hostCount: number;
  description: string;
  solution: string;
  cve?: string;
  comment?: string;
}

export function Dashboard() {
  const apiFetch = useApiFetch();
  const navigate = useNavigate();
  const { isAdmin } = useAuth();

  // State for dashboard data
  const [totalAssets, setTotalAssets] = useState<number | null>(null);
  const [vulnCounts, setVulnCounts] = useState<any>({});
  const [exceptionsCount, setExceptionsCount] = useState<number>(0);
  const [activeScans, setActiveScans] = useState<any[]>([]);
  const [topVulns, setTopVulns] = useState<Vulnerability[]>([]);
  const [lastScanTime, setLastScanTime] = useState<string | null>(null);
  const [readyHostsCount, setReadyHostsCount] = useState<number>(0);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [refreshInterval, setRefreshInterval] = useState<number>(0); // ms, 0 = never
  const intervalRef = useRef<NodeJS.Timeout | null>(null);
  const [hasLoaded, setHasLoaded] = useState(false);
  const lastFetchRef = useRef<number>(0);
  const CACHE_DURATION = 30000; // 30 seconds cache

  // Memoize last scan time for performance
  const memoizedLastScanTime = useMemo(() => lastScanTime, [lastScanTime]);

  const fetchDashboardData = useCallback(async (forceRefresh = false) => {
    const now = Date.now();
    
    // Check cache unless force refresh is requested
    if (!forceRefresh && now - lastFetchRef.current < CACHE_DURATION && hasLoaded) {
      return;
    }
    
    setLoading(true);
    setError(null);
    try {
      // Fetch all dashboard data in a single optimized request
      const dashboardRes = await apiFetch(`${config.apiUrl}/api/dashboard`);
      const dashboardData = await dashboardRes.json();
      
      setTotalAssets(dashboardData.total_assets || 0);
      setLastScanTime(dashboardData.last_scan_time ? new Date(dashboardData.last_scan_time).toLocaleString() : "-");
      setVulnCounts(dashboardData.vuln_counts || {});
      setExceptionsCount(dashboardData.exceptions_count || 0);
      setActiveScans(dashboardData.active_scans || []);
      setTopVulns(dashboardData.top_vulnerabilities || []);
      
      // Fetch ready hosts count (only for admin users)
      if (isAdmin()) {
        try {
          const readyHostsRes = await apiFetch(`${config.apiUrl}/api/hosts/ready-for-rescan`);
          if (readyHostsRes.ok) {
            const readyHostsData = await readyHostsRes.json();
            setReadyHostsCount(readyHostsData.count || 0);
          }
        } catch (e) {
          console.error("Failed to fetch ready hosts count:", e);
        }
      }
      
      setHasLoaded(true);
      lastFetchRef.current = now;
    } catch (e) {
      setError("Failed to load dashboard data");
    } finally {
      setLoading(false);
    }
  }, [apiFetch, hasLoaded]);

  // Auto-refresh logic
  useEffect(() => {
    if (intervalRef.current) {
      clearInterval(intervalRef.current);
      intervalRef.current = null;
    }
    if (refreshInterval > 0) {
      intervalRef.current = setInterval(() => {
        fetchDashboardData(false); // Use cache for auto-refresh
      }, refreshInterval);
    }
    return () => {
      if (intervalRef.current) {
        clearInterval(intervalRef.current);
        intervalRef.current = null;
      }
    };
  }, [refreshInterval]);

  // Fetch data on mount
  useEffect(() => {
    fetchDashboardData();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const getSeverityBadge = (severity: string) => {
    const configs = {
      critical: { variant: "destructive", className: "vulnerability-critical" },
      high: { variant: "secondary", className: "vulnerability-high" },
      medium: { variant: "secondary", className: "vulnerability-medium" },
      low: { variant: "secondary", className: "vulnerability-low" },
      info: { variant: "secondary", className: "vulnerability-info" }
    };
    const config = configs[severity as keyof typeof configs] || configs.info;
    return (
      <Badge variant={config.variant as any} className={config.className}>
        {severity.toUpperCase()}
      </Badge>
    );
  };

  // Subcomponent for Top Vulnerabilities
  function TopVulnerabilityCard() {
    return (
      <Card aria-label="Top Vulnerabilities" className="p-4">
        <CardHeader className="pb-3">
          <CardTitle className="flex items-center gap-2 text-base">
            <AlertTriangle className="h-4 w-4" />
            Top Vulnerabilities
          </CardTitle>
          <CardDescription className="text-xs">
            Most impactful vulnerabilities by severity and affected hosts
          </CardDescription>
        </CardHeader>
        <CardContent className="pt-0">
          <div className="space-y-2">
            {loading && !hasLoaded ? (
              <>
                {[...Array(3)].map((_, i) => (
                  <Skeleton key={i} className="h-6 w-full mb-1" />
                ))}
              </>
            ) : topVulns.length === 0 ? (
              <div className="text-center text-muted-foreground text-sm">No top vulnerabilities</div>
            ) : topVulns.map((vuln) => (
              <button
                key={vuln.id}
                className="flex items-center justify-between p-2 border rounded-md w-full hover:bg-muted/30 transition"
                onClick={() => navigate(`/vulnerabilities/${vuln.id}`)}
                aria-label={`View details for vulnerability ${vuln.name}`}
                tabIndex={0}
              >
                <div className="flex items-center gap-2 min-w-0">
                  <TooltipProvider>
                    <Tooltip>
                      <TooltipTrigger asChild>
                        <span>{getSeverityBadge(vuln.severity)}</span>
                      </TooltipTrigger>
                      <TooltipContent>{vuln.severity.charAt(0).toUpperCase() + vuln.severity.slice(1)} severity</TooltipContent>
                    </Tooltip>
                  </TooltipProvider>
                  <div className="min-w-0">
                    <p className="font-mono font-semibold text-sm text-left" title={vuln.cve || vuln.id}>{vuln.cve || vuln.id}</p>
                    <p className="text-xs text-muted-foreground text-left truncate" title={vuln.name}>{vuln.name}</p>
                  </div>
                </div>
                <div className="text-right min-w-[50px]">
                  <span className="text-sm font-bold" title="Number of affected hosts">{vuln.hostCount}</span>
                  <span className="block text-xs text-muted-foreground">Hosts</span>
                </div>
              </button>
            ))}
          </div>
          <div className="flex justify-end mt-3">
            <Button variant="outline" size="sm" onClick={() => navigate("/vulnerabilities")}>View All</Button>
          </div>
        </CardContent>
      </Card>
    );
  }

  return (
    <div className="space-y-4">
      {error && (
        <div className="bg-red-100 text-red-700 px-4 py-2 rounded mb-4" role="alert">
          {error}
        </div>
      )}
      <div className="flex items-center justify-end mb-2">
        <div className="flex items-center gap-2">
          <TooltipProvider>
            <Tooltip>
              <TooltipTrigger asChild>
                <button
                  className="p-2 rounded-full hover:bg-muted transition-colors text-muted-foreground focus:outline-none focus:ring-2 focus:ring-primary/30"
                  onClick={() => fetchDashboardData(true)}
                  disabled={loading}
                  aria-label="Refresh dashboard"
                  style={{ fontSize: 18 }}
                >
                  <RefreshCw className={loading ? "animate-spin" : ""} size={18} />
                </button>
              </TooltipTrigger>
              <TooltipContent side="bottom">Refresh</TooltipContent>
            </Tooltip>
            <Tooltip>
              <TooltipTrigger asChild>
                <div className="flex items-center gap-1 text-xs text-muted-foreground">
                  <Clock size={14} className="mr-1" />
                  <select
                    className="bg-transparent border-none outline-none text-xs text-muted-foreground cursor-pointer"
                    value={refreshInterval}
                    onChange={e => setRefreshInterval(Number(e.target.value))}
                    aria-label="Auto-refresh interval"
                  >
                    <option value={0}>Never</option>
                    <option value={30000}>30s</option>
                    <option value={60000}>1m</option>
                    <option value={300000}>5m</option>
                  </select>
                </div>
              </TooltipTrigger>
              <TooltipContent side="bottom">Auto-refresh interval</TooltipContent>
            </Tooltip>
          </TooltipProvider>
        </div>
      </div>
      {/* Overview Cards */}
      <div className={`grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-4 ${isAdmin() ? 'lg:grid-cols-5 xl:grid-cols-5' : 'lg:grid-cols-4 xl:grid-cols-4'}`}>
        <Card className="p-3">
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-1">
            <CardTitle className="text-xs font-medium">Total Assets</CardTitle>
            <Monitor className="h-3 w-3 text-muted-foreground" />
          </CardHeader>
          <CardContent className="pt-2">
            {loading && !hasLoaded ? (
              <Skeleton className="h-6 w-16 mb-1" />
            ) : (
              <div className="text-xl font-bold">{totalAssets}</div>
            )}
            <p className="text-xs text-muted-foreground">
              <TrendingUp className="inline h-2 w-2 mr-1" />
              {/* No trend data from API */}
            </p>
          </CardContent>
        </Card>

        <Card className="p-3">
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-1">
            <CardTitle className="text-xs font-medium">Critical Vulnerabilities</CardTitle>
            <AlertTriangle className="h-3 w-3 text-red-500" />
          </CardHeader>
          <CardContent className="pt-2">
            {loading && !hasLoaded ? (
              <Skeleton className="h-6 w-16 mb-1" />
            ) : (
              <div className="text-xl font-bold text-red-500">{vulnCounts.critical ?? 0}</div>
            )}
            <p className="text-xs text-muted-foreground">
              Requires immediate attention
            </p>
          </CardContent>
        </Card>

        <Card className="p-3">
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-1">
            <CardTitle className="text-xs font-medium">Active Scans</CardTitle>
            <Activity className="h-3 w-3 text-green-500" />
          </CardHeader>
          <CardContent className="pt-2">
            {loading && !hasLoaded ? (
              <Skeleton className="h-6 w-16 mb-1" />
            ) : (
              <div className="text-xl font-bold text-green-500">{activeScans.length}</div>
            )}
            <p className="text-xs text-muted-foreground">
              Currently running
            </p>
          </CardContent>
        </Card>

        <Card className="p-3">
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-1">
            <CardTitle className="text-xs font-medium">Last Scan</CardTitle>
            <Clock className="h-3 w-3 text-muted-foreground" />
          </CardHeader>
          <CardContent className="pt-2">
            {loading && !hasLoaded ? (
              <Skeleton className="h-6 w-24 mb-1" />
            ) : (
              <div className="text-lg font-bold">{lastScanTime}</div>
            )}
            <p className="text-xs text-muted-foreground">
              Last Batch Scan
            </p>
          </CardContent>
        </Card>

        <Card className="p-3 cursor-pointer hover:shadow-md transition-shadow" onClick={() => navigate('/exceptions')}>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-1">
            <CardTitle className="text-xs font-medium">Exceptions</CardTitle>
            <ShieldX className="h-3 w-3 text-purple-500" />
          </CardHeader>
          <CardContent className="pt-2">
            {loading && !hasLoaded ? (
              <Skeleton className="h-6 w-16 mb-1" />
            ) : (
              <div className="text-xl font-bold text-purple-500">{exceptionsCount}</div>
            )}
            <p className="text-xs text-muted-foreground">
              Click to manage
            </p>
          </CardContent>
        </Card>

        {isAdmin() && (
          <Card className="p-3 cursor-pointer hover:shadow-md transition-shadow" onClick={() => navigate('/rescan-ready')}>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-1">
              <CardTitle className="text-xs font-medium">Ready for Rescan</CardTitle>
              <Zap className="h-3 w-3 text-orange-500" />
            </CardHeader>
            <CardContent className="pt-2">
              {loading && !hasLoaded ? (
                <Skeleton className="h-6 w-16 mb-1" />
              ) : (
                <div className="text-xl font-bold text-orange-500">{readyHostsCount}</div>
              )}
              <p className="text-xs text-muted-foreground">
                Click to manage
              </p>
            </CardContent>
          </Card>
        )}
      </div>

      {/* Vulnerability Trend Chart - Moved to top */}
      <VulnerabilityTrendChart />

      {/* Vulnerability Pie Chart and Top Owners - Side by Side */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Vulnerability Pie Chart */}
        <VulnerabilityPieChart />

        {/* Top Owners Chart */}
        <TopOwnersChart />
      </div>

      {/* Top Vulnerabilities and Active Scans - Side by Side */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Top Vulnerabilities */}
        <TopVulnerabilityCard />

        {/* Active Scans */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Scan className="h-5 w-5" />
              Active Scans
            </CardTitle>
            <CardDescription>
              Monitor real-time scan progress
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            {loading && !hasLoaded ? (
              <>
                <Skeleton className="h-8 w-full mb-2" />
                <Skeleton className="h-2 w-full mb-2" />
                <Skeleton className="h-8 w-full mb-2" />
              </>
            ) : activeScans.length === 0 ? (
              <div className="text-center text-muted-foreground">No active scans</div>
            ) : activeScans.map((scan: any) => (
              <div key={scan.id} className="space-y-2">
                <div className="flex justify-between items-center">
                  <span className="text-sm font-medium">{scan.name || scan.target || scan.id}</span>
                  <Badge className="scan-running">
                    {scan.status}
                  </Badge>
                </div>
                <Progress value={scan.progress || 0} className="h-2" />
                <p className="text-xs text-muted-foreground">
                  {scan.progress ? `${scan.progress}% complete • ` : ''}Scan ID: {scan.id}
                </p>
              </div>
            ))}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
