import { useState, useEffect, useMemo } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Cell } from "recharts";
import { Users, TrendingUp, AlertTriangle } from "lucide-react";
import { useApiFetch } from "@/lib/utils";

interface OwnerData {
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

interface TopOwnersChartProps {
  className?: string;
}

export function TopOwnersChart({ className }: TopOwnersChartProps) {
  const [owners, setOwners] = useState<OwnerData[]>([]);
  const [severityFilter, setSeverityFilter] = useState("total");
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const apiFetch = useApiFetch();

  const fetchTopOwners = async () => {
    setIsLoading(true);
    setError(null);
    try {
      const response = await apiFetch("https://orbiti.fareportal.com:7000/api/vulnerabilities/owner_summary", {
        headers: { accept: "application/json" }
      });
      const data = await response.json();
      setOwners(data.owners || []);
    } catch (err) {
      console.error('Error fetching top owners:', err);
      setError("Failed to load owner data");
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchTopOwners();
  }, []);

  const chartData = useMemo(() => {
    if (!owners.length) return [];

    // Sort by selected severity and take top 10
    const sortedOwners = [...owners].sort((a, b) => {
      if (severityFilter === "total") {
        return (b.severity_counts.critical + b.severity_counts.high + b.severity_counts.medium + b.severity_counts.low) - 
               (a.severity_counts.critical + a.severity_counts.high + a.severity_counts.medium + a.severity_counts.low);
      }
      return (b.severity_counts[severityFilter as keyof typeof b.severity_counts] || 0) - 
             (a.severity_counts[severityFilter as keyof typeof a.severity_counts] || 0);
    });

    return sortedOwners.slice(0, 10).map(owner => ({
      name: owner.name.length > 15 ? `${owner.name.substring(0, 15)}...` : owner.name,
      fullName: owner.name,
      value: severityFilter === "total" 
        ? owner.severity_counts.critical + owner.severity_counts.high + owner.severity_counts.medium + owner.severity_counts.low
        : owner.severity_counts[severityFilter as keyof typeof owner.severity_counts] || 0,
      critical: owner.severity_counts.critical,
      high: owner.severity_counts.high,
      medium: owner.severity_counts.medium,
      low: owner.severity_counts.low,
      totalHosts: owner.total_hosts,
      uniqueVulns: owner.unique_vulnerabilities
    }));
  }, [owners, severityFilter]);

  const getBarColor = (entry: any, index: number) => {
    if (severityFilter === "critical") return "#ef4444";
    if (severityFilter === "high") return "#f97316";
    if (severityFilter === "medium") return "#eab308";
    if (severityFilter === "low") return "#3b82f6";
    
    // For total, use gradient based on critical/high ratio
    const criticalRatio = entry.critical / (entry.value || 1);
    if (criticalRatio > 0.3) return "#ef4444";
    if (criticalRatio > 0.1) return "#f97316";
    return "#3b82f6";
  };

  const CustomTooltip = ({ active, payload, label }: any) => {
    if (active && payload && payload.length) {
      const data = payload[0].payload;
      return (
        <div className="bg-card border border-border rounded-lg shadow-lg p-4">
          <p className="font-semibold text-foreground mb-2">{data.fullName}</p>
          <div className="space-y-1 text-sm">
            <div className="flex items-center gap-2">
              <div className="w-3 h-3 rounded-full bg-red-500"></div>
              <span>Critical: {data.critical}</span>
            </div>
            <div className="flex items-center gap-2">
              <div className="w-3 h-3 rounded-full bg-orange-500"></div>
              <span>High: {data.high}</span>
            </div>
            <div className="flex items-center gap-2">
              <div className="w-3 h-3 rounded-full bg-yellow-500"></div>
              <span>Medium: {data.medium}</span>
            </div>
            <div className="flex items-center gap-2">
              <div className="w-3 h-3 rounded-full bg-blue-500"></div>
              <span>Low: {data.low}</span>
            </div>
            <div className="pt-2 border-t border-border">
              <p className="text-muted-foreground">Total Hosts: {data.totalHosts}</p>
              <p className="text-muted-foreground">Unique Vulns: {data.uniqueVulns}</p>
            </div>
          </div>
        </div>
      );
    }
    return null;
  };

  if (error) {
    return (
      <Card className={className}>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Users className="h-5 w-5" />
            Top 10 Owners
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="text-center text-destructive py-8">
            <AlertTriangle className="h-8 w-8 mx-auto mb-2" />
            <p>{error}</p>
          </div>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card className={`${className} chart-gradient-bg`}>
      <CardHeader>
        <div className="flex items-center justify-between">
          <div>
            <CardTitle className="flex items-center gap-2">
              <Users className="h-5 w-5" />
              Top 10 Owners
            </CardTitle>
            <CardDescription>
              Owners with highest vulnerability counts
            </CardDescription>
          </div>
          <div className="flex items-center gap-2">
            <Select value={severityFilter} onValueChange={setSeverityFilter}>
              <SelectTrigger className="w-32">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="total">
                  <div className="flex items-center gap-2">
                    <TrendingUp className="h-4 w-4" />
                    Total
                  </div>
                </SelectItem>
                <SelectItem value="critical">
                  <div className="flex items-center gap-2">
                    <div className="w-3 h-3 rounded-full bg-red-500"></div>
                    Critical
                  </div>
                </SelectItem>
                <SelectItem value="high">
                  <div className="flex items-center gap-2">
                    <div className="w-3 h-3 rounded-full bg-orange-500"></div>
                    High
                  </div>
                </SelectItem>
                <SelectItem value="medium">
                  <div className="flex items-center gap-2">
                    <div className="w-3 h-3 rounded-full bg-yellow-500"></div>
                    Medium
                  </div>
                </SelectItem>
                <SelectItem value="low">
                  <div className="flex items-center gap-2">
                    <div className="w-3 h-3 rounded-full bg-blue-500"></div>
                    Low
                  </div>
                </SelectItem>
              </SelectContent>
            </Select>
          </div>
        </div>
      </CardHeader>
      <CardContent>
        {isLoading ? (
          <div className="space-y-4">
            <Skeleton className="h-8 w-full" />
            <Skeleton className="h-64 w-full" />
            <Skeleton className="h-8 w-full" />
          </div>
        ) : chartData.length === 0 ? (
          <div className="text-center text-muted-foreground py-8">
            No owner data available
          </div>
        ) : (
          <div className="space-y-4">
            <div className="h-80 chart-container">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart
                  data={chartData}
                  margin={{
                    top: 20,
                    right: 30,
                    left: 20,
                    bottom: 60,
                  }}
                >
                  <CartesianGrid strokeDasharray="3 3" className="opacity-30" />
                  <XAxis 
                    dataKey="name" 
                    angle={-45}
                    textAnchor="end"
                    height={80}
                    fontSize={12}
                    className="text-muted-foreground"
                  />
                  <YAxis 
                    fontSize={12}
                    className="text-muted-foreground"
                  />
                  <Tooltip content={<CustomTooltip />} />
                  <Bar 
                    dataKey="value" 
                    radius={[4, 4, 0, 0]}
                    className="hover:opacity-80 transition-opacity"
                  >
                    {chartData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={getBarColor(entry, index)} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
            
            {/* Summary Stats */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4 pt-4 border-t border-border">
              <div className="text-center">
                <div className="text-2xl font-bold text-red-500">
                  {chartData.reduce((sum, item) => sum + item.critical, 0)}
                </div>
                <div className="text-xs text-muted-foreground">Critical</div>
              </div>
              <div className="text-center">
                <div className="text-2xl font-bold text-orange-500">
                  {chartData.reduce((sum, item) => sum + item.high, 0)}
                </div>
                <div className="text-xs text-muted-foreground">High</div>
              </div>
              <div className="text-center">
                <div className="text-2xl font-bold text-yellow-500">
                  {chartData.reduce((sum, item) => sum + item.medium, 0)}
                </div>
                <div className="text-xs text-muted-foreground">Medium</div>
              </div>
              <div className="text-center">
                <div className="text-2xl font-bold text-blue-500">
                  {chartData.reduce((sum, item) => sum + item.low, 0)}
                </div>
                <div className="text-xs text-muted-foreground">Low</div>
              </div>
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
