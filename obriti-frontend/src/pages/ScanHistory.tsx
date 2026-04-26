import { Layout } from "@/components/Layout";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import { History, CheckCircle, XCircle } from "lucide-react";
import { useEffect, useState } from "react";

interface ScanHistoryItem {
  id: string;
  name: string;
  status: "completed" | "failed";
  targets: string;
  finished: string;
}

export default function ScanHistoryPage() {
  // Replace with real API call
  const [history, setHistory] = useState<ScanHistoryItem[]>([]);

  useEffect(() => {
    // Example data, replace with fetch from your backend
    setHistory([
      {
        id: "scan_001",
        name: "Production Network Scan",
        status: "completed",
        targets: "192.168.1.0/24",
        finished: "2024-06-30T14:30:00Z",
      },
      {
        id: "scan_002",
        name: "Web Application Scan",
        status: "failed",
        targets: "app.example.com",
        finished: "2024-06-29T10:15:00Z",
      },
    ]);
  }, []);

  const getStatusBadge = (status: string) => {
    if (status === "completed")
      return (
        <Badge className="bg-green-500/20 text-green-400 border border-green-500/30 flex items-center gap-1">
          <CheckCircle className="h-4 w-4" /> Completed
        </Badge>
      );
    if (status === "failed")
      return (
        <Badge className="bg-red-500/20 text-red-400 border border-red-500/30 flex items-center gap-1">
          <XCircle className="h-4 w-4" /> Failed
        </Badge>
      );
    return null;
  };

  return (
    <Layout>
      <div className="space-y-6">
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <History className="h-5 w-5" />
              Scan History
            </CardTitle>
            <CardDescription>
              View completed and archived scans
            </CardDescription>
          </CardHeader>
          <CardContent>
            {history.length === 0 ? (
              <div className="text-center py-8 text-muted-foreground">
                <History className="h-12 w-12 mx-auto mb-4 opacity-50" />
                <p>No scan history available.</p>
              </div>
            ) : (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Scan ID</TableHead>
                    <TableHead>Name</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead>Targets</TableHead>
                    <TableHead>Finished</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {history.map((scan) => (
                    <TableRow key={scan.id}>
                      <TableCell className="font-mono text-sm">{scan.id}</TableCell>
                      <TableCell>{scan.name}</TableCell>
                      <TableCell>{getStatusBadge(scan.status)}</TableCell>
                      <TableCell>{scan.targets}</TableCell>
                      <TableCell>
                        {new Date(scan.finished).toLocaleString()}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            )}
          </CardContent>
        </Card>
      </div>
    </Layout>
  );
}