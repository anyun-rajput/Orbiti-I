import { useState, useEffect } from "react";
import { useParams, useNavigate, useLocation } from "react-router-dom";
import { 
  ArrowLeft, 
  Download, 
  Copy, 
  Shield, 
  AlertTriangle, 
  TrendingUp, 
  RefreshCw,
  X,
  MessageSquare,
  Eye,
  EyeOff,
  Server,
  User,
  Package,
  Calendar,
  Monitor
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Separator } from "@/components/ui/separator";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Textarea } from "@/components/ui/textarea";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";
import { Layout } from "@/components/Layout";
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
  vulnerabilities: Vulnerability[];
}

interface Vulnerability {
  id: string;
  name: string;
  severity: string;
  description: string;
  solution: string;
  cve: string;
  vuln_status: string;
  plugin_output: string;
  comment?: string;
}

export default function HostDetailsPage() {
  const { hostId } = useParams<{ hostId: string }>();
  const navigate = useNavigate();
  const location = useLocation();
  const { toast } = useToast();
  const [hostDetails, setHostDetails] = useState<HostDetails | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [isExporting, setIsExporting] = useState(false);
  const [closeDialogOpen, setCloseDialogOpen] = useState(false);
  const [selectedVuln, setSelectedVuln] = useState<any>(null);
  const [closeComment, setCloseComment] = useState("");
  const [isClosing, setIsClosing] = useState(false);
  const [showComments, setShowComments] = useState(false);
  const apiFetch = useApiFetch();

  const fetchHostDetails = async (id: string) => {
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
    if (!hostDetails) return;
    
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

  const handleBack = () => {
    if (location.state?.from) {
      navigate(location.state.from);
    } else {
      navigate('/vulnerabilities/by-hosts');
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

  const getStatusBadgeVariant = (status: string) => {
    switch (status.toLowerCase()) {
      case "active": return "default";
      case "inactive": return "secondary";
      default: return "outline";
    }
  };

  const handleCloseVulnerability = (vuln: any) => {
    setSelectedVuln(vuln);
    setCloseComment("");
    setCloseDialogOpen(true);
  };

  const handleViewDetails = (vuln: any) => {
    // For now, just copy the vulnerability details to clipboard
    const details = `Vulnerability: ${vuln.name}\nSeverity: ${vuln.severity}\nDescription: ${vuln.description}\nSolution: ${vuln.solution || 'N/A'}\nCVE: ${vuln.cve || 'N/A'}`;
    copyToClipboard(details);
  };

  const handleConfirmClose = async () => {
    if (!selectedVuln || !closeComment.trim()) {
      toast({
        title: "Comment required",
        description: "Please provide a comment before closing the vulnerability.",
        variant: "destructive",
      });
      return;
    }

    setIsClosing(true);
    try {
      // TODO: Implement API call to close vulnerability
      // const response = await apiFetch(`/api/vulnerabilities/${selectedVuln.id}/close`, {
      //   method: 'POST',
      //   headers: { 'Content-Type': 'application/json' },
      //   body: JSON.stringify({ comment: closeComment.trim() })
      // });
      
      // For now, just update the local state
      setHostDetails(prev => {
        if (!prev) return prev;
        return {
          ...prev,
          vulnerabilities: prev.vulnerabilities.map(v => 
            v.id === selectedVuln.id 
              ? { ...v, vuln_status: 'closed', comment: closeComment.trim() }
              : v
          )
        };
      });

      toast({
        title: "Vulnerability closed",
        description: "The vulnerability has been successfully closed.",
      });

      setCloseDialogOpen(false);
      setSelectedVuln(null);
      setCloseComment("");
    } catch (error) {
      console.error("Error closing vulnerability:", error);
      toast({
        title: "Error",
        description: "Failed to close vulnerability. Please try again.",
        variant: "destructive",
      });
    } finally {
      setIsClosing(false);
    }
  };

  useEffect(() => {
    if (hostId) {
      fetchHostDetails(hostId);
    }
  }, [hostId]);

  const criticalCount = hostDetails?.vulnerabilities.filter(v => v.severity === 'critical').length || 0;
  const highCount = hostDetails?.vulnerabilities.filter(v => v.severity === 'high').length || 0;
  const mediumCount = hostDetails?.vulnerabilities.filter(v => v.severity === 'medium').length || 0;
  const lowCount = hostDetails?.vulnerabilities.filter(v => v.severity === 'low').length || 0;

  // Sort vulnerabilities by severity (critical to low)
  const getSeverityOrder = (severity: string) => {
    switch (severity) {
      case 'critical': return 1;
      case 'high': return 2;
      case 'medium': return 3;
      case 'low': return 4;
      default: return 5;
    }
  };

  const sortedVulnerabilities = hostDetails?.vulnerabilities.sort((a, b) => 
    getSeverityOrder(a.severity) - getSeverityOrder(b.severity)
  ) || [];

  if (isLoading) {
    return (
      <Layout>
        <div className="flex items-center justify-center min-h-96">
          <div className="text-center">
            <RefreshCw className="h-12 w-12 animate-spin mx-auto mb-4 text-blue-600" />
            <p className="text-muted-foreground">Loading host details...</p>
          </div>
        </div>
      </Layout>
    );
  }

  if (!hostDetails) {
    return (
      <Layout>
        <div className="text-center py-12">
          <div className="p-4 bg-red-500/20 rounded-full w-16 h-16 mx-auto mb-4 flex items-center justify-center">
            <Shield className="h-8 w-8 text-red-400" />
          </div>
          <h2 className="text-xl font-semibold mb-2">Host Not Found</h2>
          <p className="text-muted-foreground mb-4">The requested host could not be found.</p>
          <Button onClick={() => navigate('/vulnerabilities/by-hosts')} variant="outline">
            <ArrowLeft className="h-4 w-4 mr-2" />
            Go Back
          </Button>
        </div>
      </Layout>
    );
  }

  return (
    <Layout>
      <div className="space-y-6">
        {/* Header */}
        <div className="flex justify-between items-center mb-6">
            <div className="flex items-center space-x-4">
              <Button 
                onClick={handleBack}
                variant="ghost"
                size="sm"
              className="p-2"
              >
              <ArrowLeft className="h-4 w-4" />
              </Button>
                <div>
              <h1 className="text-2xl font-semibold text-foreground">Host Details</h1>
              <p className="text-muted-foreground mt-1">Detailed vulnerability analysis</p>
              </div>
            </div>
            <div className="flex items-center gap-2">
              <Button
                onClick={() => setShowComments(true)}
                disabled={!hostDetails}
                variant="outline"
                className="gap-2"
              >
                <MessageSquare className="h-4 w-4" />
                Comments
              </Button>
              <Button 
                onClick={handleExportReport} 
                disabled={isExporting || !hostDetails}
              variant="outline"
              className="gap-2"
              >
                <Download className={`h-4 w-4 ${isExporting ? "animate-spin" : ""}`} />
                {isExporting ? "Exporting..." : "Export Report"}
              </Button>
            </div>
        </div>

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
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
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
              
              <div className="p-4 bg-muted/30 rounded-lg border">
                <label className="text-sm font-medium text-muted-foreground block mb-2">Server Owner</label>
                <div className="flex items-center gap-2">
                  <User className="h-4 w-4 text-muted-foreground" />
                  <span className="font-semibold">{hostDetails.server_owner || "Unknown"}</span>
                </div>
              </div>

              <div className="p-4 bg-muted/30 rounded-lg border">
                <label className="text-sm font-medium text-muted-foreground block mb-2">Operating System</label>
                <div className="flex items-center gap-2">
                  <Package className="h-4 w-4 text-muted-foreground" />
                  <span className="font-semibold">{hostDetails.os_name || "Unknown"}</span>
                </div>
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
            <div className="flex items-center gap-3">
              <div className="p-2 bg-primary/20 rounded-lg">
                <Shield className="h-5 w-5 text-primary" />
              </div>
              <div>
                <CardTitle>Vulnerabilities ({hostDetails.vulnerabilities?.length || 0})</CardTitle>
                <CardDescription>Active security findings on this host</CardDescription>
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
                <TooltipProvider>
                  <Table>
                    <TableHeader>
                      <TableRow className="bg-muted/30">
                        <TableHead className="font-semibold">Vulnerability Name</TableHead>
                        <TableHead className="font-semibold">Severity</TableHead>
                        <TableHead className="font-semibold">CVE</TableHead>
                        <TableHead className="font-semibold">Status</TableHead>
                        <TableHead className="font-semibold">Comment</TableHead>
                        <TableHead className="font-semibold">Actions</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {sortedVulnerabilities.map((vuln) => (
                        <TableRow key={vuln.id} className="hover:bg-muted/20">
                          <TableCell className="max-w-xs">
                            <Tooltip>
                              <TooltipTrigger asChild>
                                <div className="flex items-center gap-2">
                                  <span className="font-medium truncate cursor-help">{vuln.name}</span>
                                  <Button
                                    variant="ghost"
                                    size="sm"
                                    onClick={() => copyToClipboard(vuln.name)}
                                    className="h-6 w-6 p-0 flex-shrink-0"
                                  >
                                    <Copy className="h-3 w-3" />
                                  </Button>
                                </div>
                              </TooltipTrigger>
                              <TooltipContent side="top" className="max-w-md">
                                <div className="space-y-2">
                                  <p className="font-semibold">{vuln.name}</p>
                                  <p className="text-sm">{vuln.description || 'No description available'}</p>
                                  {vuln.solution && (
                                    <div>
                                      <p className="font-medium text-xs">Solution:</p>
                                      <p className="text-xs">{vuln.solution}</p>
                                    </div>
                                  )}
                                </div>
                              </TooltipContent>
                            </Tooltip>
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
                              vuln.vuln_status === 'active' ? 'bg-red-500/20 text-red-400 border border-red-500/30' :
                              vuln.vuln_status === 'closed' ? 'bg-green-500/20 text-green-400 border border-green-500/30' :
                              'bg-gray-500/20 text-gray-400 border border-gray-500/30'
                            }`}>
                              {vuln.vuln_status === 'active' ? 'Active' : 
                               vuln.vuln_status === 'closed' ? 'Closed' : 'Unknown'}
                            </span>
                          </TableCell>
                          <TableCell className="max-w-xs">
                            {vuln.comment ? (
                              <Tooltip>
                                <TooltipTrigger asChild>
                                  <span className="text-sm text-muted-foreground truncate cursor-help block">
                                    {vuln.comment}
                                  </span>
                                </TooltipTrigger>
                                <TooltipContent side="top" className="max-w-md">
                                  <p>{vuln.comment}</p>
                                </TooltipContent>
                              </Tooltip>
                            ) : (
                              <span className="text-muted-foreground">-</span>
                            )}
                          </TableCell>
                          <TableCell>
                            <div className="flex items-center gap-1">
                              {vuln.vuln_status === 'active' && (
                                <Button
                                  onClick={() => handleCloseVulnerability(vuln)}
                                  variant="ghost"
                                  size="sm"
                                  className="h-8 px-2 text-xs"
                                  title="Close vulnerability"
                                >
                                  <X className="h-3 w-3" />
                                </Button>
                              )}
                              <Button
                                onClick={() => handleViewDetails(vuln)}
                                variant="ghost"
                                size="sm"
                                className="h-8 px-2 text-xs"
                                title="View details"
                              >
                                <Eye className="h-3 w-3" />
                              </Button>
                            </div>
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </TooltipProvider>
              </div>
            )}
          </CardContent>
        </Card>

        {/* Close Vulnerability Dialog */}
        <Dialog open={closeDialogOpen} onOpenChange={setCloseDialogOpen}>
          <DialogContent className="sm:max-w-[425px]">
            <DialogHeader>
              <DialogTitle>Close Vulnerability</DialogTitle>
              <DialogDescription>
                Please provide a comment explaining why this vulnerability is being closed.
              </DialogDescription>
            </DialogHeader>
            <div className="grid gap-4 py-4">
              <div className="space-y-2">
                <label className="text-sm font-medium">Vulnerability:</label>
                <p className="text-sm text-muted-foreground">{selectedVuln?.name}</p>
              </div>
              <div className="space-y-2">
                <label className="text-sm font-medium">Comment *</label>
                <Textarea
                  placeholder="Enter reason for closing this vulnerability..."
                  value={closeComment}
                  onChange={(e) => setCloseComment(e.target.value)}
                  className="min-h-[100px]"
                />
              </div>
            </div>
            <DialogFooter>
              <Button
                variant="outline"
                onClick={() => {
                  setCloseDialogOpen(false);
                  setSelectedVuln(null);
                  setCloseComment("");
                }}
              >
                Cancel
              </Button>
              <Button
                onClick={handleConfirmClose}
                disabled={!closeComment.trim() || isClosing}
              >
                {isClosing ? "Closing..." : "Close Vulnerability"}
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>

        {/* Comments Dialog */}
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
              hostId={hostId ? parseInt(hostId) : undefined}
              onCommentChange={() => {
                // Refresh host details if needed
                if (hostId) {
                  fetchHostDetails(hostId);
                }
              }}
            />
          </DialogContent>
        </Dialog>
      </div>
    </Layout>
  );
}
