import { useState, useEffect } from "react";
import { Eye, X, Users, Shield, AlertTriangle, Calendar, Server, Building } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Separator } from "@/components/ui/separator";
import { Progress } from "@/components/ui/progress";
import { useApiFetch } from "@/lib/utils";
import { useToast } from "@/hooks/use-toast";

interface OwnerDetails {
  owner: string;
  total_hosts: number;
  total_vulnerabilities: number;
  total_instances: number;
  severity_breakdown: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
  risk_score: number;
  hosts: HostSummary[];
  top_vulnerabilities: VulnerabilitySummary[];
}

interface HostSummary {
  id: number;
  hostname: string;
  host_ip: string;
  os_name: string;
  status: string;
  vulnerability_count: number;
  risk_score: number;
  last_scan_date: string | null;
}

interface VulnerabilitySummary {
  id: string;
  name: string;
  severity: "critical" | "high" | "medium" | "low";
  affected_hosts: number;
  cve?: string;
}

interface OwnerDetailsModalProps {
  ownerName: string | null;
  isOpen: boolean;
  onClose: () => void;
  onViewHost?: (hostId: number) => void;
}

export function OwnerDetailsModal({ ownerName, isOpen, onClose, onViewHost }: OwnerDetailsModalProps) {
  const { toast } = useToast();
  const [ownerDetails, setOwnerDetails] = useState<OwnerDetails | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const apiFetch = useApiFetch();

  const fetchOwnerDetails = async (owner: string) => {
    setIsLoading(true);
    try {
      const response = await apiFetch(`https://orbiti.fareportal.com:7000/api/vulnerabilities/owner/${encodeURIComponent(owner)}/details`, {
        headers: { accept: "application/json" }
      });
      const data = await response.json();
      setOwnerDetails(data);
    } catch (error) {
      console.error('Error fetching owner details:', error);
      toast({
        title: "Error",
        description: "Failed to fetch owner details",
        variant: "destructive",
      });
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    if (ownerName && isOpen) {
      fetchOwnerDetails(ownerName);
    }
  }, [ownerName, isOpen]);

  const getSeverityBadgeVariant = (severity: string) => {
    switch (severity) {
      case "critical": return "destructive";
      case "high": return "destructive";
      case "medium": return "default";
      case "low": return "secondary";
      default: return "outline";
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case "critical": return "text-red-600";
      case "high": return "text-orange-600";
      case "medium": return "text-yellow-600";
      case "low": return "text-blue-600";
      default: return "text-gray-600";
    }
  };

  const getStatusBadgeVariant = (status: string) => {
    switch (status.toLowerCase()) {
      case "active": return "default";
      case "inactive": return "secondary";
      default: return "outline";
    }
  };

  if (!isOpen) return null;

  return (
    <Dialog open={isOpen} onOpenChange={onClose}>
      <DialogContent className="max-w-5xl max-h-[90vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Building className="h-5 w-5" />
            Owner Details: {ownerName}
          </DialogTitle>
          <DialogDescription>
            Detailed vulnerability analysis for all hosts owned by {ownerName}
          </DialogDescription>
        </DialogHeader>

        {isLoading ? (
          <div className="flex items-center justify-center py-8">
            <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary"></div>
            <span className="ml-2">Loading owner details...</span>
          </div>
        ) : ownerDetails ? (
          <div className="space-y-6">
            {/* Owner Summary */}
            <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
              <Card>
                <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                  <CardTitle className="text-sm font-medium">Total Hosts</CardTitle>
                  <Server className="h-4 w-4 text-muted-foreground" />
                </CardHeader>
                <CardContent>
                  <div className="text-2xl font-bold">{ownerDetails.total_hosts}</div>
                </CardContent>
              </Card>
              <Card>
                <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                  <CardTitle className="text-sm font-medium">Vulnerabilities</CardTitle>
                  <Shield className="h-4 w-4 text-muted-foreground" />
                </CardHeader>
                <CardContent>
                  <div className="text-2xl font-bold">{ownerDetails.total_vulnerabilities}</div>
                  <p className="text-xs text-muted-foreground">
                    {ownerDetails.total_instances} instances
                  </p>
                </CardContent>
              </Card>
              <Card>
                <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                  <CardTitle className="text-sm font-medium">Risk Score</CardTitle>
                  <AlertTriangle className="h-4 w-4 text-muted-foreground" />
                </CardHeader>
                <CardContent>
                  <div className="text-2xl font-bold">{ownerDetails.risk_score}</div>
                  <Progress 
                    value={Math.min((ownerDetails.risk_score / 100) * 100, 100)} 
                    className="mt-2"
                  />
                </CardContent>
              </Card>
              <Card>
                <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                  <CardTitle className="text-sm font-medium">Severity Breakdown</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="flex gap-1 flex-wrap">
                    {ownerDetails.severity_breakdown.critical > 0 && (
                      <Badge variant="destructive" className="text-xs">
                        C: {ownerDetails.severity_breakdown.critical}
                      </Badge>
                    )}
                    {ownerDetails.severity_breakdown.high > 0 && (
                      <Badge variant="destructive" className="text-xs bg-orange-500">
                        H: {ownerDetails.severity_breakdown.high}
                      </Badge>
                    )}
                    {ownerDetails.severity_breakdown.medium > 0 && (
                      <Badge variant="default" className="text-xs">
                        M: {ownerDetails.severity_breakdown.medium}
                      </Badge>
                    )}
                    {ownerDetails.severity_breakdown.low > 0 && (
                      <Badge variant="secondary" className="text-xs">
                        L: {ownerDetails.severity_breakdown.low}
                      </Badge>
                    )}
                  </div>
                </CardContent>
              </Card>
            </div>

            {/* Hosts Table */}
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Server className="h-4 w-4" />
                  Hosts ({ownerDetails.hosts?.length || 0})
                </CardTitle>
                <CardDescription>
                  All hosts owned by {ownerName}
                </CardDescription>
              </CardHeader>
              <CardContent>
                {!ownerDetails.hosts || ownerDetails.hosts.length === 0 ? (
                  <div className="text-center py-8 text-muted-foreground">
                    <Server className="h-12 w-12 mx-auto mb-4 opacity-50" />
                    <p>No hosts found for this owner</p>
                  </div>
                ) : (
                  <div className="rounded-md border">
                    <Table>
                      <TableHeader>
                        <TableRow>
                          <TableHead>Host</TableHead>
                          <TableHead>OS</TableHead>
                          <TableHead>Status</TableHead>
                          <TableHead>Vulnerabilities</TableHead>
                          <TableHead>Risk Score</TableHead>
                          <TableHead>Last Scan</TableHead>
                          <TableHead>Actions</TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {ownerDetails.hosts.map((host) => (
                          <TableRow key={host.id}>
                            <TableCell>
                              <div className="space-y-1">
                                <p className="font-medium">{host.hostname}</p>
                                <p className="text-sm text-muted-foreground font-mono">{host.host_ip}</p>
                              </div>
                            </TableCell>
                            <TableCell>
                              <Badge variant="secondary" className="text-xs">
                                {host.os_name || "Unknown"}
                              </Badge>
                            </TableCell>
                            <TableCell>
                              <Badge variant={getStatusBadgeVariant(host.status)} className="text-xs">
                                {host.status}
                              </Badge>
                            </TableCell>
                            <TableCell>
                              <Badge variant="outline">{host.vulnerability_count}</Badge>
                            </TableCell>
                            <TableCell>
                              <div className="flex items-center gap-2">
                                <Badge 
                                  variant={host.risk_score > 50 ? "destructive" : host.risk_score > 20 ? "default" : "secondary"}
                                >
                                  {host.risk_score}
                                </Badge>
                                <Progress 
                                  value={Math.min((host.risk_score / 100) * 100, 100)} 
                                  className="w-16 h-2"
                                />
                              </div>
                            </TableCell>
                            <TableCell className="text-sm text-muted-foreground">
                              {host.last_scan_date ? new Date(host.last_scan_date).toLocaleDateString() : "Never"}
                            </TableCell>
                            <TableCell>
                              <Button
                                variant="outline"
                                size="sm"
                                onClick={() => onViewHost?.(host.id)}
                              >
                                <Eye className="h-4 w-4 mr-1" />
                                Details
                              </Button>
                            </TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </div>
                )}
              </CardContent>
            </Card>

            {/* Top Vulnerabilities */}
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Shield className="h-4 w-4" />
                  Top Vulnerabilities ({ownerDetails.top_vulnerabilities?.length || 0})
                </CardTitle>
                <CardDescription>
                  Most common vulnerabilities affecting {ownerName}'s hosts
                </CardDescription>
              </CardHeader>
              <CardContent>
                {!ownerDetails.top_vulnerabilities || ownerDetails.top_vulnerabilities.length === 0 ? (
                  <div className="text-center py-8 text-muted-foreground">
                    <Shield className="h-12 w-12 mx-auto mb-4 opacity-50" />
                    <p>No vulnerabilities found</p>
                  </div>
                ) : (
                  <div className="rounded-md border">
                    <Table>
                      <TableHeader>
                        <TableRow>
                          <TableHead>Vulnerability</TableHead>
                          <TableHead>Severity</TableHead>
                          <TableHead>Affected Hosts</TableHead>
                          <TableHead>CVE</TableHead>
                          <TableHead>Actions</TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {ownerDetails.top_vulnerabilities.map((vuln) => (
                          <TableRow key={vuln.id}>
                            <TableCell>
                              <p className="font-medium">{vuln.name}</p>
                            </TableCell>
                            <TableCell>
                              <Badge 
                                variant={getSeverityBadgeVariant(vuln.severity)}
                                className={getSeverityColor(vuln.severity)}
                              >
                                {vuln.severity.toUpperCase()}
                              </Badge>
                            </TableCell>
                            <TableCell>
                              <Badge variant="outline">{vuln.affected_hosts} hosts</Badge>
                            </TableCell>
                            <TableCell>
                              {vuln.cve ? (
                                <Badge variant="outline" className="font-mono text-xs">
                                  {vuln.cve}
                                </Badge>
                              ) : (
                                <span className="text-muted-foreground">-</span>
                              )}
                            </TableCell>
                            <TableCell>
                              <Button
                                variant="outline"
                                size="sm"
                                onClick={() => {
                                  // This would open vulnerability details modal
                                  console.log("View vulnerability details:", vuln.id);
                                }}
                              >
                                <Eye className="h-4 w-4 mr-1" />
                                Details
                              </Button>
                            </TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </div>
                )}
              </CardContent>
            </Card>
          </div>
        ) : (
          <div className="text-center py-8 text-muted-foreground">
            <AlertTriangle className="h-12 w-12 mx-auto mb-4 opacity-50" />
            <p>Failed to load owner details</p>
          </div>
        )}
      </DialogContent>
    </Dialog>
  );
}
