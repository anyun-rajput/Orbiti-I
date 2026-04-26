import React, { useState, useEffect } from "react";
import { useParams, useNavigate, useLocation } from "react-router-dom";
import { Layout } from "../components/Layout";
import { Button } from "../components/ui/button";
import { useToast } from "../hooks/use-toast";
import { useApiFetch } from "../lib/utils";
import { InlineCommentDisplay } from "../components/InlineCommentDisplay";
import { 
  ArrowLeft, 
  Download, 
  Eye, 
  Server, 
  Shield, 
  AlertTriangle, 
  TrendingUp, 
  RefreshCw,
  MessageSquare
} from "lucide-react";

interface OwnerDetails {
  owner_name: string;
  total_vulnerabilities: number;
  total_instances: number;
  affected_hosts: number;
  severity_breakdown: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
  hosts: {
    id: number;
    hostname: string;
    host_ip: string;
    os_name?: string;
    status?: string;
    vulnerability_count?: number;
    severity_breakdown?: {
      critical: number;
      high: number;
      medium: number;
      low: number;
    };
  }[];
}

interface HostSummary {
  id: number;
  hostname: string;
  host_ip: string;
  os_name: string;
  status: string;
  vulnerability_count: number;
  last_scan_date: string | null;
  severity_breakdown: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
}

export default function OwnerDetailsPage() {
  const { ownerName } = useParams<{ ownerName: string }>();
  const navigate = useNavigate();
  const location = useLocation();
  const { toast } = useToast();
  const [ownerDetails, setOwnerDetails] = useState<OwnerDetails | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [isExporting, setIsExporting] = useState(false);
  const apiFetch = useApiFetch();

  const fetchOwnerDetails = async (owner: string) => {
    setIsLoading(true);
    try {
      const response = await apiFetch(`https://orbiti.fareportal.com:7000/api/owners/${encodeURIComponent(owner)}/details`, {
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

  const handleExportReport = async () => {
    if (!ownerDetails) return;
    
    setIsExporting(true);
    try {
      const response = await apiFetch(`https://orbiti.fareportal.com:7000/api/owners/${encodeURIComponent(ownerName)}/export_csv`, {
        headers: { accept: "text/csv" }
      });
      const csvData = await response.text();
      
      const blob = new Blob([csvData], { type: "text/csv" });
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `owner_${ownerDetails.owner_name}_vulnerabilities.csv`;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);
      
      toast({
        title: "Success",
        description: "Owner report exported successfully",
      });
    } catch (error) {
      console.error("Error exporting report:", error);
      toast({
        title: "Error",
        description: "Failed to export owner report",
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
      navigate('/vulnerabilities/by-owner');
    }
  };

  const handleViewHostDetails = (hostId: number) => {
    navigate(`/hosts/${hostId}`);
  };

  useEffect(() => {
    if (ownerName) {
      fetchOwnerDetails(ownerName);
    }
  }, [ownerName]);

  if (isLoading) {
    return (
      <Layout>
        <div className="flex items-center justify-center min-h-[400px]">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary"></div>
          <span className="ml-4 text-lg">Loading owner details...</span>
        </div>
      </Layout>
    );
  }

  if (!ownerDetails) {
    return (
      <Layout>
        <div className="text-center py-12">
          <AlertTriangle className="h-16 w-16 mx-auto mb-4 text-muted-foreground opacity-50" />
          <h2 className="text-2xl font-semibold mb-2">Owner Not Found</h2>
          <p className="text-muted-foreground mb-6">The requested owner details could not be loaded.</p>
          <Button onClick={() => navigate(-1)} variant="outline">
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
              <h1 className="text-2xl font-semibold text-foreground">Owner Details</h1>
              <p className="text-muted-foreground mt-1">Detailed vulnerability analysis by owner</p>
            </div>
          </div>
          <Button 
            onClick={handleExportReport} 
            disabled={isExporting || !ownerDetails}
            variant="outline"
            className="gap-2"
          >
            <Download className={`h-4 w-4 ${isExporting ? "animate-spin" : ""}`} />
            {isExporting ? "Exporting..." : "Export Report"}
          </Button>
        </div>

        {/* Owner Summary */}
        <div className="bg-card border rounded-lg p-6 mb-6">
          <div className="flex justify-between items-start mb-4">
            <div>
              <h2 className="text-xl font-semibold mb-3">{ownerDetails.owner_name}</h2>
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
                <div>
                  <span className="text-muted-foreground block mb-1">Managed Hosts</span>
                  <span className="font-medium">{ownerDetails.hosts.length}</span>
                </div>
                <div>
                  <span className="text-muted-foreground block mb-1">Total Vulnerabilities</span>
                  <span className="font-medium">{ownerDetails.total_vulnerabilities}</span>
                </div>
                <div>
                  <span className="text-muted-foreground block mb-1">Critical Issues</span>
                  <span className="font-medium text-red-400">{ownerDetails.severity_breakdown.critical}</span>
                </div>
                <div>
                  <span className="text-muted-foreground block mb-1">High Priority</span>
                  <span className="font-medium text-orange-400">{ownerDetails.severity_breakdown.high}</span>
                </div>
              </div>
            </div>
            <span className={`inline-flex items-center px-3 py-1 rounded text-sm font-medium ${
              ownerDetails.total_vulnerabilities > 0 
                ? "bg-red-500/20 text-red-400 border border-red-500/30" 
                : "bg-green-500/20 text-green-400 border border-green-500/30"
            }`}>
              {ownerDetails.total_vulnerabilities > 0 ? "Has Vulnerabilities" : "Secure"}
            </span>
          </div>
        </div>

        {/* Vulnerability Statistics */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
          <div className="bg-card border rounded-lg p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-muted-foreground">Total Hosts</p>
                <p className="text-xl font-semibold">{ownerDetails.hosts.length}</p>
              </div>
              <Server className="h-5 w-5 text-muted-foreground" />
            </div>
          </div>
          
          <div className="bg-card border rounded-lg p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-muted-foreground">Critical</p>
                <p className="text-xl font-semibold text-red-400">{ownerDetails.severity_breakdown.critical}</p>
              </div>
              <AlertTriangle className="h-5 w-5 text-red-400" />
            </div>
          </div>
          
          <div className="bg-card border rounded-lg p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-muted-foreground">High</p>
                <p className="text-xl font-semibold text-orange-400">{ownerDetails.severity_breakdown.high}</p>
              </div>
              <TrendingUp className="h-5 w-5 text-orange-400" />
            </div>
          </div>
          
          <div className="bg-card border rounded-lg p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-muted-foreground">Medium & Low</p>
                <p className="text-xl font-semibold text-yellow-400">{ownerDetails.severity_breakdown.medium + ownerDetails.severity_breakdown.low}</p>
              </div>
              <TrendingUp className="h-5 w-5 text-yellow-400" />
            </div>
          </div>
        </div>

        {/* Hosts List */}
        <div className="border rounded-lg">
          <div className="p-4 border-b">
            <h3 className="font-medium">Managed Hosts ({ownerDetails.hosts.length})</h3>
            <p className="text-sm text-muted-foreground mt-1">Click on hosts to view details or add comments</p>
          </div>
          <div className="overflow-x-auto">
            {!ownerDetails.hosts || ownerDetails.hosts.length === 0 ? (
              <div className="text-center py-12 text-muted-foreground">
                No hosts found for this owner
              </div>
            ) : (
              <div>
                {ownerDetails.hosts.map((host, index) => (
                  <div key={host.id} className="p-4 hover:bg-muted/30 border-b last:border-b-0">
                    <div className="space-y-3">
                      {/* Host Header */}
                      <div className="flex items-center justify-between">
                        <div className="flex-1">
                          <div className="flex items-center gap-3 mb-2">
                            <h4 className="font-medium text-sm">{host.hostname}</h4>
                            <span className={`inline-flex items-center px-2 py-1 rounded text-xs font-medium ${
                              host.status === 'active' 
                                ? 'bg-green-500/20 text-green-400 border border-green-500/30' 
                                : 'bg-gray-500/20 text-gray-400 border border-gray-500/30'
                            }`}>
                              {host.status || 'Unknown'}
                            </span>
                          </div>
                          
                          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs text-muted-foreground">
                            <div>IP: {host.host_ip}</div>
                            <div>OS: {host.os_name || 'Unknown'}</div>
                            <div className="flex items-center gap-2">
                              <span>Vulnerabilities: {host.vulnerability_count || 0}</span>
                              {host.severity_breakdown && (
                                <div className="flex gap-1">
                                  {host.severity_breakdown.critical > 0 && (
                                    <span className="inline-flex items-center px-1 py-0.5 rounded text-xs bg-red-500/20 text-red-400">
                                      {host.severity_breakdown.critical}C
                                    </span>
                                  )}
                                  {host.severity_breakdown.high > 0 && (
                                    <span className="inline-flex items-center px-1 py-0.5 rounded text-xs bg-orange-500/20 text-orange-400">
                                      {host.severity_breakdown.high}H
                                    </span>
                                  )}
                                  {host.severity_breakdown.medium > 0 && (
                                    <span className="inline-flex items-center px-1 py-0.5 rounded text-xs bg-yellow-500/20 text-yellow-400">
                                      {host.severity_breakdown.medium}M
                                    </span>
                                  )}
                                  {host.severity_breakdown.low > 0 && (
                                    <span className="inline-flex items-center px-1 py-0.5 rounded text-xs bg-blue-500/20 text-blue-400">
                                      {host.severity_breakdown.low}L
                                    </span>
                                  )}
                                </div>
                              )}
                            </div>
                          </div>
                        </div>
                        
                        <Button
                          onClick={() => navigate(`/hosts/${host.id}`, { 
                            state: { from: `/owners/${ownerName}` } 
                          })}
                          variant="ghost"
                          size="sm"
                          className="h-8 px-2 text-xs"
                        >
                          <Eye className="h-3 w-3" />
                        </Button>
                      </div>

                      {/* Host Comments */}
                      <div className="mt-3 pt-3 border-t border-muted/30">
                        <div className="flex items-center gap-2 mb-2">
                          <MessageSquare className="h-3 w-3 text-muted-foreground" />
                          <span className="text-xs font-medium text-muted-foreground">Comments</span>
                        </div>
                        <InlineCommentDisplay 
                          hostId={host.id}
                          maxDisplay={1}
                        />
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>
    </Layout>
  );
}
