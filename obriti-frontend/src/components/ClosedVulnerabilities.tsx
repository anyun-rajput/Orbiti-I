import { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { Search, RefreshCw, Download, Eye, Shield, CheckCircle, Calendar, MessageSquare, AlertTriangle, TrendingUp } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { CommentSystem } from "@/components/CommentSystem";
import { InlineCommentDisplay } from "@/components/InlineCommentDisplay";
import { useApiFetch } from "@/lib/utils";
import { useToast } from "@/hooks/use-toast";

interface ClosedVulnerability {
  vulnerability_id: string;
  vulnerability_name: string;
  severity: string;
  description: string;
  solution: string;
  cve: string;
  cvss_base_score: number;
  host_id: number;
  hostname: string;
  host_ip: string;
  server_owner: string;
  application_dependent: string;
  os_name: string;
  plugin_output: string;
  closed_date: string | null;
}

interface ClosedVulnSummary {
  unique_vulnerabilities: number;
  total_instances: number;
  affected_hosts: number;
  affected_owners: number;
  severity_breakdown: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
}

interface OwnerSummary {
  name: string;
  total_hosts: number;
  unique_vulnerabilities: number;
  total_instances: number;
  severity_counts: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
}

export function ClosedVulnerabilities() {
  const { toast } = useToast();
  const navigate = useNavigate();
  const [closedVulns, setClosedVulns] = useState<ClosedVulnerability[]>([]);
  const [summary, setSummary] = useState<ClosedVulnSummary | null>(null);
  const [ownerSummary, setOwnerSummary] = useState<OwnerSummary[]>([]);
  const [searchTerm, setSearchTerm] = useState("");
  const [severityFilter, setSeverityFilter] = useState("all");
  const [ownerFilter, setOwnerFilter] = useState("all");
  const [sortBy, setSortBy] = useState("closed_date");
  const [isLoading, setIsLoading] = useState(false);
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(20);
  const [totalCount, setTotalCount] = useState(0);
  const [totalPages, setTotalPages] = useState(1);
  const [isExporting, setIsExporting] = useState(false);
  const [showComments, setShowComments] = useState(false);
  const [selectedVulnForComments, setSelectedVulnForComments] = useState<ClosedVulnerability | null>(null);
  const apiFetch = useApiFetch();

  const fetchClosedVulnerabilities = async (pageNum = page, pageSizeNum = pageSize, search = searchTerm, severity = severityFilter, owner = ownerFilter, sort = sortBy) => {
    setIsLoading(true);
    try {
      const params = new URLSearchParams({
        page: pageNum.toString(),
        page_size: pageSizeNum.toString(),
        search: search,
        severity: severity,
        owner: owner,
        sort_by: sort,
      });
      const response = await apiFetch(`https://orbiti.fareportal.com:7000/api/vulnerabilities/closed?${params.toString()}`, {
        headers: { accept: "application/json" }
      });
      const data = await response.json();
      setClosedVulns(data.closed_vulnerabilities || []);
      setTotalCount(data.total || 0);
      setTotalPages(data.total_pages || 1);
    } catch (error) {
      console.error('Error fetching closed vulnerabilities:', error);
      toast({
        title: "Error",
        description: "Failed to fetch closed vulnerabilities",
        variant: "destructive",
      });
    } finally {
      setIsLoading(false);
    }
  };

  const fetchSummary = async () => {
    try {
      const response = await apiFetch('https://orbiti.fareportal.com:7000/api/vulnerabilities/closed/summary', {
        headers: { accept: "application/json" }
      });
      const data = await response.json();
      setSummary(data);
    } catch (error) {
      console.error('Error fetching closed vulnerabilities summary:', error);
    }
  };

  const fetchOwnerSummary = async () => {
    try {
      const response = await apiFetch('https://orbiti.fareportal.com:7000/api/vulnerabilities/owner_summary', {
        headers: { accept: "application/json" }
      });
      const data = await response.json();
      setOwnerSummary(data.owners || []);
    } catch (error) {
      console.error('Error fetching owner summary:', error);
    }
  };

  const handleExport = async () => {
    setIsExporting(true);
    try {
      const response = await apiFetch('https://orbiti.fareportal.com:7000/api/closed_vulnerabilities/export_csv', {
        headers: { accept: "text/csv" }
      });
      const blob = await response.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.style.display = 'none';
      a.href = url;
      a.download = 'closed_vulnerabilities.csv';
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);
      toast({
        title: "Success",
        description: "Closed vulnerabilities exported successfully",
      });
    } catch (error) {
      console.error('Error exporting closed vulnerabilities:', error);
      toast({
        title: "Error",
        description: "Failed to export closed vulnerabilities",
        variant: "destructive",
      });
    } finally {
      setIsExporting(false);
    }
  };

  const handleSearch = () => {
    setPage(1);
    fetchClosedVulnerabilities(1, pageSize, searchTerm, severityFilter, ownerFilter, sortBy);
  };

  const handleReset = () => {
    setSearchTerm("");
    setSeverityFilter("all");
    setOwnerFilter("all");
    setSortBy("closed_date");
    setPage(1);
    fetchClosedVulnerabilities(1, pageSize, "", "all", "all", "closed_date");
  };

  const handleKeyPress = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter') {
      handleSearch();
    }
  };

  const handleRefresh = () => {
    fetchClosedVulnerabilities();
    fetchSummary();
    fetchOwnerSummary();
  };

  const getSeverityBadge = (severity: string) => {
    const configs: Record<string, { className: string }> = {
      critical: { className: "vulnerability-critical" },
      high: { className: "vulnerability-high" },
      medium: { className: "vulnerability-medium" },
      low: { className: "vulnerability-low" }
    };
    const config = configs[severity.toLowerCase()] || configs.medium;
    return (
      <Badge className={config.className}>
        {severity.toUpperCase()}
      </Badge>
    );
  };

  const formatDate = (dateString: string | null) => {
    if (!dateString) return 'N/A';
    return new Date(dateString).toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric'
    });
  };

  const openCommentDialog = (vuln: ClosedVulnerability) => {
    setSelectedVulnForComments(vuln);
    setShowComments(true);
  };

  useEffect(() => {
    fetchClosedVulnerabilities();
    fetchSummary();
    fetchOwnerSummary();
  }, []);

  useEffect(() => {
    if (page > 1) {
      fetchClosedVulnerabilities();
    }
  }, [page, pageSize]);

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-3xl font-bold">Closed Vulnerabilities</h1>
          <p className="text-muted-foreground">
            Track vulnerabilities that have been resolved and closed across your infrastructure
          </p>
        </div>
        <div className="flex gap-2">
          <Button onClick={handleRefresh} disabled={isLoading}>
            <RefreshCw className={`h-4 w-4 mr-2 ${isLoading ? "animate-spin" : ""}`} />
            Refresh
          </Button>
          <Button
            onClick={handleExport}
            disabled={isExporting}
            variant="outline"
          >
            <Download className={`h-4 w-4 mr-2 ${isExporting ? "animate-spin" : ""}`} />
            {isExporting ? "Exporting..." : "Export CSV"}
          </Button>
        </div>
      </div>

      {/* Summary Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Closed Vulnerabilities</CardTitle>
            <CheckCircle className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{summary?.unique_vulnerabilities || 0}</div>
            <p className="text-xs text-muted-foreground">
              {summary?.total_instances || 0} total instances
            </p>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Critical</CardTitle>
            <AlertTriangle className="h-4 w-4 text-red-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-red-500">{summary?.severity_breakdown.critical || 0}</div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">High</CardTitle>
            <TrendingUp className="h-4 w-4 text-orange-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-orange-500">{summary?.severity_breakdown.high || 0}</div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Medium</CardTitle>
            <TrendingUp className="h-4 w-4 text-yellow-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-yellow-500">{summary?.severity_breakdown.medium || 0}</div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Low</CardTitle>
            <TrendingUp className="h-4 w-4 text-green-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-green-500">{summary?.severity_breakdown.low || 0}</div>
          </CardContent>
        </Card>
      </div>

      {/* Filters */}
      <div className="space-y-4">
        <div className="flex gap-4">
          <div className="relative flex-1">
            <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-muted-foreground" />
            <Input
              placeholder="Search by vulnerability name, hostname, IP, or owner..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              onKeyPress={handleKeyPress}
              className="pl-10"
            />
          </div>
          <Select value={severityFilter} onValueChange={setSeverityFilter}>
            <SelectTrigger className="w-[180px]">
              <SelectValue placeholder="All severities" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All Severities</SelectItem>
              <SelectItem value="critical">Critical</SelectItem>
              <SelectItem value="high">High</SelectItem>
              <SelectItem value="medium">Medium</SelectItem>
              <SelectItem value="low">Low</SelectItem>
            </SelectContent>
          </Select>
          <Select value={ownerFilter} onValueChange={setOwnerFilter}>
            <SelectTrigger className="w-[180px]">
              <SelectValue placeholder="All owners" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All Owners</SelectItem>
              {ownerSummary.map((owner) => (
                <SelectItem key={owner.name} value={owner.name}>
                  {owner.name}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
          <Select value={sortBy} onValueChange={setSortBy}>
            <SelectTrigger className="w-[180px]">
              <SelectValue placeholder="Sort by" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="closed_date">Closed Date</SelectItem>
              <SelectItem value="hostname">Hostname</SelectItem>
              <SelectItem value="vulnerability_name">Vulnerability Name</SelectItem>
            </SelectContent>
          </Select>
          <Button onClick={handleSearch} disabled={isLoading}>
            <Search className="h-4 w-4 mr-2" />
            Search
          </Button>
          <Button onClick={handleReset} variant="outline" disabled={isLoading}>
            Reset
          </Button>
        </div>
      </div>

      {/* Results Table */}
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <div>
              <CardTitle>Closed Vulnerabilities ({totalCount})</CardTitle>
              <CardDescription>
                Showing {closedVulns.length} of {totalCount} closed vulnerabilities
              </CardDescription>
            </div>
            <div className="flex items-center gap-2">
              <span className="text-sm text-muted-foreground">
                Page {page} of {totalPages}
              </span>
              <div className="flex gap-1">
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => setPage(Math.max(1, page - 1))}
                  disabled={page === 1 || isLoading}
                >
                  Previous
                </Button>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => setPage(Math.min(totalPages, page + 1))}
                  disabled={page === totalPages || isLoading}
                >
                  Next
                </Button>
              </div>
            </div>
          </div>
        </CardHeader>
        <CardContent>
          <div className="rounded-md border">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Vulnerability</TableHead>
                  <TableHead>Severity</TableHead>
                  <TableHead>Host</TableHead>
                  <TableHead>Owner</TableHead>
                  <TableHead>OS</TableHead>
                  <TableHead>Closed Date</TableHead>
                  <TableHead>Comments</TableHead>
                  <TableHead>Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {isLoading ? (
                  <TableRow>
                    <TableCell colSpan={8} className="text-center py-8">
                      <div className="flex items-center justify-center">
                        <RefreshCw className="h-4 w-4 animate-spin mr-2" />
                        Loading closed vulnerabilities...
                      </div>
                    </TableCell>
                  </TableRow>
                ) : closedVulns.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={8} className="text-center py-8 text-muted-foreground">
                      No closed vulnerabilities found
                    </TableCell>
                  </TableRow>
                ) : (
                  closedVulns.map((vuln) => (
                    <TableRow key={`${vuln.vulnerability_id}-${vuln.host_id}`}>
                      <TableCell>
                        <div className="space-y-1">
                          <div className="font-medium text-sm">{vuln.vulnerability_name}</div>
                          <div className="text-xs text-muted-foreground">ID: {vuln.vulnerability_id}</div>
                          {vuln.cve && (
                            <div className="text-xs text-blue-600 dark:text-blue-400">{vuln.cve}</div>
                          )}
                        </div>
                      </TableCell>
                      <TableCell>
                        {getSeverityBadge(vuln.severity)}
                      </TableCell>
                      <TableCell>
                        <div className="space-y-1">
                          <div className="font-medium text-sm">{vuln.hostname}</div>
                          <div className="text-xs text-muted-foreground">{vuln.host_ip}</div>
                        </div>
                      </TableCell>
                      <TableCell>
                        <div className="text-sm">{vuln.server_owner || 'N/A'}</div>
                      </TableCell>
                      <TableCell>
                        <div className="text-sm">{vuln.os_name}</div>
                      </TableCell>
                      <TableCell>
                        <div className="text-sm">{formatDate(vuln.closed_date)}</div>
                      </TableCell>
                      <TableCell>
                        <InlineCommentDisplay
                          hostId={vuln.host_id}
                          vulnerabilityId={parseInt(vuln.vulnerability_id)}
                        />
                      </TableCell>
                      <TableCell>
                        <div className="flex gap-1">
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => navigate(`/hosts/${vuln.host_id}`)}
                            title="View host details"
                          >
                            <Eye className="h-4 w-4" />
                          </Button>
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => openCommentDialog(vuln)}
                            title="View comments"
                          >
                            <MessageSquare className="h-4 w-4" />
                          </Button>
                        </div>
                      </TableCell>
                    </TableRow>
                  ))
                )}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>

      {/* Comments Dialog */}
      <Dialog open={showComments} onOpenChange={setShowComments}>
        <DialogContent className="max-w-4xl max-h-[80vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle>Comments - {selectedVulnForComments?.vulnerability_name}</DialogTitle>
            <DialogDescription>
              Host: {selectedVulnForComments?.hostname} ({selectedVulnForComments?.host_ip})
            </DialogDescription>
          </DialogHeader>
          {selectedVulnForComments && (
            <CommentSystem
              hostId={selectedVulnForComments.host_id}
              vulnerabilityId={parseInt(selectedVulnForComments.vulnerability_id)}
            />
          )}
        </DialogContent>
      </Dialog>
    </div>
  );
}
