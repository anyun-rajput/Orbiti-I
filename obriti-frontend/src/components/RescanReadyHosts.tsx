import { useState, useEffect } from "react";
import { RefreshCw, Play, Pause, AlertTriangle, CheckCircle, Clock, Server, Zap } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { useApiFetch } from "@/lib/utils";
import { useToast } from "@/hooks/use-toast";

interface ReadyHost {
  id: number;
  hostname: string;
  host_ip: string;
  server_owner: string;
  application_dependent: string;
  os_name: string;
  status: string;
  last_scan_date: string | null;
  ready_for_rescan: boolean;
}

interface ScanStatus {
  is_running: boolean;
  current_scan_id?: string;
  estimated_completion?: string;
}

export function RescanReadyHosts() {
  const [readyHosts, setReadyHosts] = useState<ReadyHost[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [isScanning, setIsScanning] = useState(false);
  const [scanStatus, setScanStatus] = useState<ScanStatus>({ is_running: false });
  const [refreshing, setRefreshing] = useState(false);
  const apiFetch = useApiFetch();
  const { toast } = useToast();

  // Fetch ready hosts
  const fetchReadyHosts = async () => {
    setIsLoading(true);
    try {
      const response = await apiFetch("https://orbiti.fareportal.com:7000/api/hosts/ready-for-rescan");
      if (response.ok) {
        const data = await response.json();
        setReadyHosts(data.hosts || []);
      } else {
        toast({
          title: "Error",
          description: "Failed to fetch ready hosts",
          variant: "destructive",
        });
      }
    } catch (error) {
      console.error("Error fetching ready hosts:", error);
      toast({
        title: "Error",
        description: "Failed to fetch ready hosts",
        variant: "destructive",
      });
    } finally {
      setIsLoading(false);
    }
  };

  // Check scan status
  const checkScanStatus = async () => {
    try {
      const response = await apiFetch("https://orbiti.fareportal.com:7000/api/scans/running");
      if (response.ok) {
        const data = await response.json();
        setScanStatus({
          is_running: data.length > 0,
          current_scan_id: data.length > 0 ? data[0].id : undefined,
          estimated_completion: data.length > 0 ? data[0].estimated_completion : undefined
        });
      }
    } catch (error) {
      console.error("Error checking scan status:", error);
    }
  };

  // Start immediate scan for ready hosts
  const startImmediateScan = async () => {
    if (scanStatus.is_running) {
      toast({
        title: "Scan Already Running",
        description: "A scan is currently in progress. Ready hosts will be scanned after the current scan completes.",
        variant: "destructive",
      });
      return;
    }

    if (readyHosts.length === 0) {
      toast({
        title: "No Ready Hosts",
        description: "There are no hosts marked as ready for rescan.",
        variant: "destructive",
      });
      return;
    }

    setIsScanning(true);
    try {
      // Get host IPs for scanning
      const hostIPs = readyHosts.map(host => host.host_ip);
      
      const response = await apiFetch("https://orbiti.fareportal.com:7000/api/scans/immediate", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          host_ips: hostIPs,
          scan_type: "ready_hosts_rescan"
        }),
      });

      if (response.ok) {
        const data = await response.json();
        toast({
          title: "Scan Started",
          description: `Immediate scan started for ${readyHosts.length} ready hosts.`,
        });
        
        // Refresh scan status
        await checkScanStatus();
        
        // Clear ready hosts after scan starts
        setReadyHosts([]);
      } else {
        const error = await response.json();
        toast({
          title: "Scan Failed",
          description: error.detail || "Failed to start immediate scan",
          variant: "destructive",
        });
      }
    } catch (error) {
      console.error("Error starting immediate scan:", error);
      toast({
        title: "Error",
        description: "Failed to start immediate scan",
        variant: "destructive",
      });
    } finally {
      setIsScanning(false);
    }
  };

  // Refresh data
  const handleRefresh = async () => {
    setRefreshing(true);
    await Promise.all([fetchReadyHosts(), checkScanStatus()]);
    setRefreshing(false);
  };

  // Toggle host ready status
  const handleToggleReady = async (hostId: number) => {
    try {
      const response = await apiFetch(`https://orbiti.fareportal.com:7000/api/hosts/${hostId}/toggle-rescan`, {
        method: "PATCH",
      });
      
      if (response.ok) {
        const result = await response.json();
        // Remove host from ready list
        setReadyHosts(prev => prev.filter(host => host.id !== hostId));
        toast({
          title: "Success",
          description: result.message,
        });
      } else {
        const error = await response.json();
        toast({
          title: "Error",
          description: error.detail || "Failed to toggle rescan status",
          variant: "destructive",
        });
      }
    } catch (error) {
      console.error("Error toggling rescan status:", error);
      toast({
        title: "Error",
        description: "Failed to toggle rescan status",
        variant: "destructive",
      });
    }
  };

  // Get status badge
  const getStatusBadge = (status: string) => {
    const configs = {
      active: { className: "bg-green-500", label: "Active" },
      inactive: { className: "bg-gray-500", label: "Inactive" },
      pending: { className: "bg-yellow-500", label: "Pending" },
      error: { className: "bg-red-500", label: "Error" },
    };
    const config = configs[status as keyof typeof configs] || { className: "bg-gray-500", label: status };
    return <Badge className={`text-white ${config.className}`}>{config.label}</Badge>;
  };

  useEffect(() => {
    fetchReadyHosts();
    checkScanStatus();
    
    // Check scan status every 30 seconds
    const interval = setInterval(checkScanStatus, 30000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Rescan Ready Hosts</h1>
          <p className="text-muted-foreground">
            Manage hosts marked as ready for immediate rescanning
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button
            variant="outline"
            onClick={handleRefresh}
            disabled={refreshing}
            className="flex items-center gap-2"
          >
            <RefreshCw className={`h-4 w-4 ${refreshing ? "animate-spin" : ""}`} />
            Refresh
          </Button>
          <Button
            onClick={startImmediateScan}
            disabled={isScanning || readyHosts.length === 0 || scanStatus.is_running}
            className="flex items-center gap-2 bg-orange-500 hover:bg-orange-600"
          >
            {isScanning ? (
              <>
                <RefreshCw className="h-4 w-4 animate-spin" />
                Starting Scan...
              </>
            ) : (
              <>
                <Play className="h-4 w-4" />
                Start Immediate Scan
              </>
            )}
          </Button>
        </div>
      </div>

      {/* Scan Status Alert */}
      {scanStatus.is_running && (
        <Alert>
          <AlertTriangle className="h-4 w-4" />
          <AlertDescription>
            A scan is currently running. Ready hosts will be automatically scanned after the current scan completes.
            {scanStatus.estimated_completion && (
              <span className="ml-2 text-sm text-muted-foreground">
                Estimated completion: {scanStatus.estimated_completion}
              </span>
            )}
          </AlertDescription>
        </Alert>
      )}

      {/* Ready Hosts Count */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Ready Hosts</CardTitle>
            <Zap className="h-4 w-4 text-orange-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{readyHosts.length}</div>
            <p className="text-xs text-muted-foreground">
              Hosts ready for immediate rescan
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Scan Status</CardTitle>
            {scanStatus.is_running ? (
              <RefreshCw className="h-4 w-4 text-blue-500 animate-spin" />
            ) : (
              <CheckCircle className="h-4 w-4 text-green-500" />
            )}
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {scanStatus.is_running ? "Running" : "Idle"}
            </div>
            <p className="text-xs text-muted-foreground">
              {scanStatus.is_running ? "Scan in progress" : "Ready to scan"}
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Last Updated</CardTitle>
            <Clock className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {new Date().toLocaleTimeString()}
            </div>
            <p className="text-xs text-muted-foreground">
              Auto-refreshes every 30s
            </p>
          </CardContent>
        </Card>
      </div>

      {/* Ready Hosts Table */}
      <Card>
        <CardHeader>
          <CardTitle>Ready for Rescan</CardTitle>
          <CardDescription>
            Hosts marked as ready for immediate vulnerability scanning
          </CardDescription>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <div className="flex items-center justify-center py-8">
              <RefreshCw className="h-6 w-6 animate-spin mr-2" />
              Loading ready hosts...
            </div>
          ) : readyHosts.length === 0 ? (
            <div className="text-center py-8">
              <Server className="h-12 w-12 text-muted-foreground mx-auto mb-4" />
              <h3 className="text-lg font-semibold mb-2">No Ready Hosts</h3>
              <p className="text-muted-foreground">
                No hosts are currently marked as ready for rescan.
              </p>
            </div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Hostname</TableHead>
                  <TableHead>IP Address</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Owner</TableHead>
                  <TableHead>OS</TableHead>
                  <TableHead>Last Scan</TableHead>
                  <TableHead>Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {readyHosts.map((host) => (
                  <TableRow key={host.id}>
                    <TableCell className="font-medium">{host.hostname}</TableCell>
                    <TableCell className="font-mono">{host.host_ip}</TableCell>
                    <TableCell>{getStatusBadge(host.status)}</TableCell>
                    <TableCell>{host.server_owner || "—"}</TableCell>
                    <TableCell>{host.os_name || "Unknown"}</TableCell>
                    <TableCell>
                      {host.last_scan_date 
                        ? new Date(host.last_scan_date).toLocaleDateString()
                        : "Never"
                      }
                    </TableCell>
                    <TableCell>
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => handleToggleReady(host.id)}
                        className="text-orange-600 hover:text-orange-700 hover:bg-orange-50"
                      >
                        <Zap className="h-4 w-4 mr-1" />
                        Remove from Ready
                      </Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
