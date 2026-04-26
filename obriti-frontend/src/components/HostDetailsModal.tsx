import { useState, useEffect } from "react";
import { Eye, X, Monitor, Shield, AlertTriangle, Calendar, Server, User, Package, Copy, Download, TrendingUp, MessageSquare } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Separator } from "@/components/ui/separator";
import { useApiFetch } from "@/lib/utils";
import { useToast } from "@/hooks/use-toast";
import { CommentSystem } from "@/components/CommentSystem";

interface HostDetails {
  id: number;
  hostname: string;
  host_ip: string;
  server_owner: string;
  application_dependent: string;
  os_name: string;
  status: string;
  last_scan_date: string | null;
  vulnerabilities: VulnerabilityInstance[];
}

interface VulnerabilityInstance {
  id: string;
  name: string;
  severity: "critical" | "high" | "medium" | "low";
  description: string;
  solution: string;
  cve?: string;
  plugin_output?: string;
  vuln_status: string;
}

interface HostDetailsModalProps {
  hostId: number | null;
  isOpen: boolean;
  onClose: () => void;
}

export function HostDetailsModal({ hostId, isOpen, onClose }: HostDetailsModalProps) {
  const { toast } = useToast();
  const [hostDetails, setHostDetails] = useState<HostDetails | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [isExporting, setIsExporting] = useState(false);
  const [showComments, setShowComments] = useState(false);
  const apiFetch = useApiFetch();

  const fetchHostDetails = async (id: number) => {
    setIsLoading(true);
    try {
      const response = await apiFetch(`https://orbiti.fareportal.com:7000/api/hosts/${id}/details`, {
        headers: { accept: "application/json" }
      });
      const data = await response.json();
      setHostDetails(data);
    } catch (error) {
      console.error('Error fetching host details:', error);
      toast({
        title: "Error",
        description: "Failed to fetch host details",
        variant: "destructive",
      });
    } finally {
      setIsLoading(false);
    }
  };

  const handleExportReport = async () => {
    if (!hostDetails || !hostId) return;
    
    setIsExporting(true);
    try {
      const response = await apiFetch(`https://orbiti.fareportal.com:7000/api/hosts/${hostId}/export_csv`, {
        headers: { accept: "text/csv" }
      });
      const csvData = await response.text();
      
      const blob = new Blob([csvData], { type: "text/csv" });
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `host_${hostDetails.hostname}_vulnerabilities.csv`;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);
      
      toast({
        title: "Success",
        description: "Host report exported successfully",
      });
    } catch (error) {
      console.error("Error exporting report:", error);
      toast({
        title: "Error",
        description: "Failed to export host report",
        variant: "destructive",
      });
    } finally {
      setIsExporting(false);
    }
  };

  const copyToClipboard = async (text: string) => {
    try {
      await navigator.clipboard.writeText(text);
      toast({
        title: "Copied to clipboard",
        description: "Text has been copied to your clipboard.",
      });
    } catch (err) {
      toast({
        title: "Failed to copy",
        description: "Could not copy text to clipboard.",
        variant: "destructive",
      });
    }
  };

  useEffect(() => {
    if (hostId && isOpen) {
      fetchHostDetails(hostId);
    }
  }, [hostId, isOpen]);

  const getSeverityBadgeClass = (severity: string) => {
    switch (severity) {
      case 'critical': return "bg-red-500/20 text-red-400 border border-red-500/30";
      case 'high': return "bg-orange-500/20 text-orange-400 border border-orange-500/30";
      case 'medium': return "bg-yellow-500/20 text-yellow-400 border border-yellow-500/30";
      case 'low': return "bg-blue-500/20 text-blue-400 border border-blue-500/30";
      default: return "bg-gray-500/20 text-gray-400 border border-gray-500/30";
    }
  };

  const getSeverityText = (severity: string) => {
    switch (severity) {
      case 'critical': return "Critical";
      case 'high': return "High";
      case 'medium': return "Medium";
      case 'low': return "Low";
      default: return "Info";
    }
  };

  const getStatusBadgeClass = (status: string) => {
    switch (status.toLowerCase()) {
      case "active": return "bg-green-500/20 text-green-400 border border-green-500/30";
      case "inactive": return "bg-gray-500/20 text-gray-400 border border-gray-500/30";
      default: return "bg-gray-500/20 text-gray-400 border border-gray-500/30";
    }
  };

  if (!isOpen) return null;

  const criticalCount = hostDetails?.vulnerabilities.filter(v => v.severity === 'critical').length || 0;
  const highCount = hostDetails?.vulnerabilities.filter(v => v.severity === 'high').length || 0;
  const mediumCount = hostDetails?.vulnerabilities.filter(v => v.severity === 'medium').length || 0;
  const lowCount = hostDetails?.vulnerabilities.filter(v => v.severity === 'low').length || 0;

  return (
    <Dialog open={isOpen} onOpenChange={onClose}>
      <DialogContent className="max-w-6xl max-h-[95vh] overflow-hidden p-0">
        {/* Modern Header with Gradient */}
        <div className="bg-gradient-to-r from-blue-600 via-purple-600 to-indigo-600 p-6 text-white">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="p-2 bg-white/20 rounded-lg backdrop-blur-sm">
                <Monitor className="h-6 w-6" />
              </div>
              <div>
                <DialogTitle className="text-xl font-semibold text-white">
                  {hostDetails ? hostDetails.hostname : "Host Details"}
                </DialogTitle>
                <DialogDescription className="text-blue-100 mt-1">
                  Comprehensive vulnerability analysis and host information
                </DialogDescription>
              </div>
            </div>
            <div className="flex items-center gap-2">
              <Button
                onClick={() => setShowComments(true)}
                disabled={!hostDetails}
                variant="secondary"
                size="sm"
                className="bg-white/20 hover:bg-white/30 text-white border-white/30"
              >
                <MessageSquare className="h-4 w-4 mr-2" />
                Comments
              </Button>
              <Button 
                onClick={handleExportReport} 
                disabled={isExporting || !hostDetails}
                variant="secondary"
                size="sm"
                className="bg-white/20 hover:bg-white/30 text-white border-white/30"
              >
                <Download className={`h-4 w-4 mr-2 ${isExporting ? "animate-spin" : ""}`} />
                {isExporting ? "Exporting..." : "Export"}
              </Button>
              <Button
                onClick={onClose}
                variant="ghost"
                size="sm"
                className="text-white hover:bg-white/20"
              >
                <X className="h-4 w-4" />
              </Button>
            </div>
          </div>
        </div>

        {/* Content Area */}
        <div className="flex-1 overflow-y-auto p-6">
          {isLoading ? (
            <div className="flex items-center justify-center py-12">
              <div className="text-center">
                <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600 mx-auto mb-4"></div>
                <p className="text-muted-foreground">Loading host details...</p>
              </div>
            </div>
          ) : hostDetails ? (
            <div className="space-y-6">
              {/* Host Summary Card */}
              <Card className="shadow-lg border-0 bg-gradient-to-br from-card to-card/50">
                <CardHeader className="pb-4">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-3">
                      <div className="p-2 bg-blue-500/20 rounded-lg">
                        <Server className="h-5 w-5 text-blue-400" />
                      </div>
                      <div>
                        <CardTitle className="text-lg">Host Information</CardTitle>
                        <CardDescription>System details and configuration</CardDescription>
                      </div>
                    </div>
                    <span className={`inline-flex items-center px-3 py-1 rounded-full text-sm font-medium ${
                      hostDetails.vulnerabilities.length > 0 
                        ? "bg-red-500/20 text-red-400 border border-red-500/30" 
                        : "bg-green-500/20 text-green-400 border border-green-500/30"
                    }`}>
                      {hostDetails.vulnerabilities.length > 0 ? "Vulnerable" : "Secure"}
                    </span>
                  </div>
                </CardHeader>
                <CardContent>
                  <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                    <div className="space-y-4">
                      <div className="p-4 bg-muted/30 rounded-lg border">
                        <label className="text-sm font-medium text-muted-foreground block mb-2">Hostname</label>
                        <div className="flex items-center gap-2">
                          <span className="font-semibold text-foreground">{hostDetails.hostname}</span>
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => copyToClipboard(hostDetails.hostname)}
                            className="h-6 w-6 p-0"
                          >
                            <Copy className="h-3 w-3" />
                          </Button>
                        </div>
                      </div>
                      <div className="p-4 bg-muted/30 rounded-lg border">
                        <label className="text-sm font-medium text-muted-foreground block mb-2">IP Address</label>
                        <div className="flex items-center gap-2">
                          <span className="font-mono font-semibold text-foreground">{hostDetails.host_ip}</span>
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => copyToClipboard(hostDetails.host_ip)}
                            className="h-6 w-6 p-0"
                          >
                            <Copy className="h-3 w-3" />
                          </Button>
                        </div>
                      </div>
                    </div>
                    
                    <div className="space-y-4">
                      <div className="p-4 bg-muted/30 rounded-lg border">
                        <label className="text-sm font-medium text-muted-foreground block mb-2">Server Owner</label>
                        <div className="flex items-center gap-2">
                          <User className="h-4 w-4 text-muted-foreground" />
                          <span className="font-semibold">{hostDetails.server_owner || "Unknown"}</span>
                        </div>
                      </div>
                      <div className="p-4 bg-muted/30 rounded-lg border">
                        <label className="text-sm font-medium text-muted-foreground block mb-2">Application</label>
                        <div className="flex items-center gap-2">
                          <Package className="h-4 w-4 text-muted-foreground" />
                          <span className="font-semibold">{hostDetails.application_dependent || "Not specified"}</span>
                        </div>
                      </div>
                    </div>

                    <div className="space-y-4">
                      <div className="p-4 bg-muted/30 rounded-lg border">
                        <label className="text-sm font-medium text-muted-foreground block mb-2">Operating System</label>
                        <span className={`inline-flex items-center px-2 py-1 rounded text-sm font-medium ${getStatusBadgeClass("active")}`}>
                          {hostDetails.os_name || "Unknown"}
                        </span>
                      </div>
                      <div className="p-4 bg-muted/30 rounded-lg border">
                        <label className="text-sm font-medium text-muted-foreground block mb-2">Last Scan</label>
                        <div className="flex items-center gap-2">
                          <Calendar className="h-4 w-4 text-muted-foreground" />
                          <span className="font-semibold">
                            {hostDetails.last_scan_date 
                              ? new Date(hostDetails.last_scan_date).toLocaleDateString()
                              : "Never"
                            }
                          </span>
                        </div>
                      </div>
                    </div>
                  </div>
                </CardContent>
              </Card>

              {/* Vulnerability Statistics */}
              <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                <Card className="shadow-md border-0 bg-gradient-to-br from-card to-muted/20">
                  <CardContent className="p-4">
                    <div className="flex items-center justify-between">
                      <div>
                        <p className="text-sm font-medium text-muted-foreground">Total</p>
                        <p className="text-2xl font-bold">{hostDetails.vulnerabilities.length}</p>
                      </div>
                      <div className="p-2 bg-blue-500/20 rounded-lg">
                        <Shield className="h-5 w-5 text-blue-400" />
                      </div>
                    </div>
                  </CardContent>
                </Card>
                
                <Card className="shadow-md border-0 bg-gradient-to-br from-red-500/10 to-red-500/5">
                  <CardContent className="p-4">
                    <div className="flex items-center justify-between">
                      <div>
                        <p className="text-sm font-medium text-muted-foreground">Critical</p>
                        <p className="text-2xl font-bold text-red-400">{criticalCount}</p>
                      </div>
                      <div className="p-2 bg-red-500/20 rounded-lg">
                        <AlertTriangle className="h-5 w-5 text-red-400" />
                      </div>
                    </div>
                  </CardContent>
                </Card>
                
                <Card className="shadow-md border-0 bg-gradient-to-br from-orange-500/10 to-orange-500/5">
                  <CardContent className="p-4">
                    <div className="flex items-center justify-between">
                      <div>
                        <p className="text-sm font-medium text-muted-foreground">High</p>
                        <p className="text-2xl font-bold text-orange-400">{highCount}</p>
                      </div>
                      <div className="p-2 bg-orange-500/20 rounded-lg">
                        <TrendingUp className="h-5 w-5 text-orange-400" />
                      </div>
                    </div>
                  </CardContent>
                </Card>
                
                <Card className="shadow-md border-0 bg-gradient-to-br from-yellow-500/10 to-yellow-500/5">
                  <CardContent className="p-4">
                    <div className="flex items-center justify-between">
                      <div>
                        <p className="text-sm font-medium text-muted-foreground">Med & Low</p>
                        <p className="text-2xl font-bold text-yellow-400">{mediumCount + lowCount}</p>
                      </div>
                      <div className="p-2 bg-yellow-500/20 rounded-lg">
                        <TrendingUp className="h-5 w-5 text-yellow-400" />
                      </div>
                    </div>
                  </CardContent>
                </Card>
              </div>

              {/* Vulnerabilities Table */}
              <Card className="shadow-lg border-0">
                <CardHeader className="bg-gradient-to-r from-muted/50 to-muted/30 rounded-t-lg">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-3">
                      <div className="p-2 bg-primary/20 rounded-lg">
                        <Shield className="h-5 w-5 text-primary" />
                      </div>
                      <div>
                        <CardTitle>Vulnerabilities ({hostDetails.vulnerabilities?.length || 0})</CardTitle>
                        <CardDescription>Active security findings on this host</CardDescription>
                      </div>
                    </div>
                  </div>
                </CardHeader>
                <CardContent className="p-0">
                  {!hostDetails.vulnerabilities || hostDetails.vulnerabilities.length === 0 ? (
                    <div className="text-center py-12">
                      <div className="p-4 bg-green-500/20 rounded-full w-16 h-16 mx-auto mb-4 flex items-center justify-center">
                        <Shield className="h-8 w-8 text-green-400" />
                      </div>
                      <h3 className="text-lg font-semibold mb-2">No Vulnerabilities Found</h3>
                      <p className="text-muted-foreground">This host appears to be secure with no active vulnerabilities.</p>
                    </div>
                  ) : (
                    <div className="overflow-x-auto">
                      <Table>
                        <TableHeader>
                          <TableRow className="bg-muted/30">
                            <TableHead className="font-semibold">Vulnerability</TableHead>
                            <TableHead className="font-semibold">Severity</TableHead>
                            <TableHead className="font-semibold">CVE</TableHead>
                            <TableHead className="font-semibold">Status</TableHead>
                            <TableHead className="font-semibold">Actions</TableHead>
                          </TableRow>
                        </TableHeader>
                        <TableBody>
                          {hostDetails.vulnerabilities.map((vuln) => (
                            <TableRow key={vuln.id} className="hover:bg-muted/20">
                              <TableCell className="max-w-md">
                                <div className="space-y-1">
                                  <div className="flex items-center gap-2">
                                    <p className="font-medium truncate">{vuln.name}</p>
                                    <Button
                                      variant="ghost"
                                      size="sm"
                                      onClick={() => copyToClipboard(vuln.name)}
                                      className="h-6 w-6 p-0 flex-shrink-0"
                                    >
                                      <Copy className="h-3 w-3" />
                                    </Button>
                                  </div>
                                  <p className="text-sm text-muted-foreground line-clamp-2">
                                    {vuln.description}
                                  </p>
                                </div>
                              </TableCell>
                              <TableCell>
                                <span className={`inline-flex items-center px-2 py-1 rounded text-sm font-medium ${getSeverityBadgeClass(vuln.severity)}`}>
                                  {getSeverityText(vuln.severity)}
                                </span>
                              </TableCell>
                              <TableCell>
                                {vuln.cve ? (
                                  <div className="flex items-center gap-2">
                                    <span className="font-mono text-sm bg-muted px-2 py-1 rounded">
                                      {vuln.cve}
                                    </span>
                                    <Button
                                      variant="ghost"
                                      size="sm"
                                      onClick={() => copyToClipboard(vuln.cve)}
                                      className="h-6 w-6 p-0"
                                    >
                                      <Copy className="h-3 w-3" />
                                    </Button>
                                  </div>
                                ) : (
                                  <span className="text-muted-foreground">-</span>
                                )}
                              </TableCell>
                              <TableCell>
                                <span className={`inline-flex items-center px-2 py-1 rounded text-sm font-medium ${
                                  vuln.vuln_status === "active" 
                                    ? "bg-red-500/20 text-red-400 border border-red-500/30"
                                    : "bg-green-500/20 text-green-400 border border-green-500/30"
                                }`}>
                                  {vuln.vuln_status}
                                </span>
                              </TableCell>
                              <TableCell>
                                <Button
                                  variant="outline"
                                  size="sm"
                                  onClick={() => {
                                    const details = `Vulnerability: ${vuln.name}\nSeverity: ${vuln.severity}\nDescription: ${vuln.description}\nSolution: ${vuln.solution || 'N/A'}\nCVE: ${vuln.cve || 'N/A'}`;
                                    copyToClipboard(details);
                                  }}
                                  className="gap-2"
                                >
                                  <Eye className="h-4 w-4" />
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
            <div className="text-center py-12">
              <div className="p-4 bg-red-500/20 rounded-full w-16 h-16 mx-auto mb-4 flex items-center justify-center">
                <AlertTriangle className="h-8 w-8 text-red-400" />
              </div>
              <h3 className="text-lg font-semibold mb-2">Failed to Load Host Details</h3>
              <p className="text-muted-foreground">Unable to retrieve information for this host.</p>
            </div>
          )}
        </div>
      </DialogContent>
      
      {/* Comments Dialog - Separate from main dialog to avoid nesting issues */}
      <Dialog open={showComments} onOpenChange={setShowComments}>
        <DialogContent className="max-w-4xl">
          <DialogHeader>
            <DialogTitle>
              Comments for {hostDetails?.hostname || 'Host'}
            </DialogTitle>
            <DialogDescription>
              View and manage comments for this host ({hostDetails?.host_ip}).
            </DialogDescription>
          </DialogHeader>
          <CommentSystem
            hostId={hostId || undefined}
            onCommentChange={() => {
              // Refresh host details if needed
              if (hostId) {
                fetchHostDetails(hostId);
              }
            }}
          />
        </DialogContent>
      </Dialog>
    </Dialog>
  );
}
