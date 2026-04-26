import { useState, useEffect, useRef } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Textarea } from "@/components/ui/textarea";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { CalendarIcon, Plus, Play, Pause, Settings, History, Layers } from "lucide-react";
import { toast } from "sonner";
import { useApiFetch } from "@/lib/utils";

interface Scan {
  id: string;
  name: string;
  status: 'running' | 'completed' | 'failed' | 'scheduled' | 'paused';
  targets: string;
  created: string;
  lastRun?: string;
  progress?: number;
  batchId?: string;
}

interface Batch {
  id: number;
  batch_name: string;
  batch_size: number;
  batch_job: string;
  job_start_time: string;
  job_end_time: string;
  week_day: string;
  created_at?: string;
}

export function ScanManagement() {
  const [scans, setScans] = useState<any[]>([]);
  const [loadingScans, setLoadingScans] = useState(true);
  const [batches, setBatches] = useState<Batch[]>([]);
  const [loadingBatches, setLoadingBatches] = useState(true);
  const [isCreateScanOpen, setIsCreateScanOpen] = useState(false);
  const [isCreateBatchOpen, setIsCreateBatchOpen] = useState(false);
  const [isImportOpen, setIsImportOpen] = useState(false);
  const [importScanId, setImportScanId] = useState("");
  const [isImporting, setIsImporting] = useState(false);
  const [isCreatingBatch, setIsCreatingBatch] = useState(false);
  const [deletingBatchId, setDeletingBatchId] = useState<number | null>(null);
  const [scanForm, setScanForm] = useState({
    id: '',
    name: '',
    targets: '',
    overwrite: false
  });
  const [batchForm, setBatchForm] = useState({
    batch_name: '',
    batch_size: 1,
    batch_job: 'vuln_scan',
    job_start_time: '',
    job_end_time: '',
    week_day: ''
  });
  const [activeTab, setActiveTab] = useState("scans");
  const batchesFetchedRef = useRef(false);

  const apiFetch = useApiFetch();

  const fetchRunningScans = async () => {
    setLoadingScans(true);
    try {
      const res = await apiFetch("https://orbiti.fareportal.com:7000/api/scans/running");
      const data = await res.json();
      setScans(data.running_scans || []);
    } catch (e) {
      setScans([]);
    } finally {
      setLoadingScans(false);
    }
  };

  useEffect(() => {
    fetchRunningScans();
  }, []); // Only run once on mount

  const fetchBatches = async () => {
    setLoadingBatches(true);
    try {
      const res = await apiFetch("https://orbiti.fareportal.com:7000/api/batch-scan/all");
      const data = await res.json();
      setBatches(Array.isArray(data) ? data : []);
    } catch (e) {
      setBatches([]);
    } finally {
      setLoadingBatches(false);
    }
  };

  // Fetch batches only when the tab is selected for the first time
  useEffect(() => {
    if (activeTab === "batches" && !batchesFetchedRef.current) {
      fetchBatches();
      batchesFetchedRef.current = true;
    }
  }, [activeTab]);

  const handleCreateScan = async () => {
    try {
      // API call would go here
      console.log('Creating scan:', scanForm);
      
      const newScan: Scan = {
        id: scanForm.id || `scan_${Date.now()}`,
        name: scanForm.name,
        status: 'scheduled',
        targets: scanForm.targets,
        created: new Date().toISOString()
      };

      if (scanForm.overwrite && scanForm.id) {
        setScans(prev => prev.map(scan => 
          scan.id === scanForm.id ? { ...newScan, id: scanForm.id } : scan
        ));
        toast.success(`Scan ${scanForm.id} overwritten successfully`);
      } else {
        setScans(prev => [...prev, newScan]);
        toast.success("New scan created successfully");
      }

      setScanForm({ id: '', name: '', targets: '', overwrite: false });
      setIsCreateScanOpen(false);
    } catch (error) {
      toast.error("Failed to create scan");
    }
  };

  function formatTimeTo12Hour(time: string): string {
    if (!time) return '';
    const [hour, minute] = time.split(":");
    const date = new Date();
    date.setHours(Number(hour));
    date.setMinutes(Number(minute));
    return date.toLocaleTimeString([], { hour: 'numeric', minute: '2-digit', hour12: true });
  }

  const handleCreateBatch = async () => {
    setIsCreatingBatch(true);
    try {
      // Format time as 'h:mm AM/PM'
      const start = formatTimeTo12Hour(batchForm.job_start_time);
      const end = formatTimeTo12Hour(batchForm.job_end_time);
      const payload = {
        batch_name: batchForm.batch_name,
        batch_size: batchForm.batch_size,
        batch_job: batchForm.batch_job,
        job_start_time: start,
        job_end_time: end,
        week_day: batchForm.week_day
      };
      const res = await apiFetch("https://orbiti.fareportal.com:7000/api/batch-scan/schedule", {
        method: "POST",
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
      if (!res.ok) throw new Error("Failed to create batch");
      toast.success("Batch created successfully");
      setBatchForm({
        batch_name: '',
        batch_size: 1,
        batch_job: 'vuln_scan',
        job_start_time: '',
        job_end_time: '',
        week_day: ''
      });
      setIsCreateBatchOpen(false);
      // Refresh batches after creation
      await fetchBatches();
    } catch (error) {
      toast.error("Failed to create batch");
    } finally {
      setIsCreatingBatch(false);
    }
  };

  const handleScanAction = async (scanId: string, action: 'start' | 'pause' | 'stop') => {
    try {
      console.log(`${action} scan:`, scanId);
      
      setScans(prev => prev.map(scan => 
        scan.id === scanId 
          ? { 
              ...scan, 
              status: action === 'start' ? 'running' : action === 'pause' ? 'paused' : 'completed'
            }
          : scan
      ));
      
      toast.success(`Scan ${action}ed successfully`);
    } catch (error) {
      toast.error(`Failed to ${action} scan`);
    }
  };

  const handleImportScan = async () => {
    if (!importScanId) {
      toast.error("Please enter a Scan ID");
      return;
    }
    setIsImporting(true);
    try {
      toast.info("Starting scan import... This may take several minutes for large scans.");
      
      const res = await apiFetch(`https://orbiti.fareportal.com:7000/api/scans/${importScanId}?isinventoryscan=false`, {
        method: "GET"
      });
      
      if (!res.ok) {
        const errorText = await res.text();
        throw new Error(`Import failed: ${errorText}`);
      }
      
      toast.success("Scan imported successfully");
      setIsImportOpen(false);
      setImportScanId("");
      // Optionally refresh scans here
    } catch (e) {
      console.error("Import error:", e);
      toast.error(`Failed to import scan: ${e.message}`);
    } finally {
      setIsImporting(false);
    }
  };

  const handleDeleteBatch = async (batchId: number) => {
    if (!window.confirm(`Are you sure you want to delete batch with ID ${batchId}? This action cannot be undone.`)) {
      return;
    }
    setDeletingBatchId(batchId);
    try {
      const res = await apiFetch(`https://orbiti.fareportal.com:7000/api/batch-scan/${batchId}`, {
        method: "DELETE"
      });
      if (!res.ok) throw new Error("Failed to delete batch");
      toast.success("Batch deleted successfully");
      setBatches(prev => prev.filter(batch => batch.id !== batchId));
    } catch (e) {
      toast.error("Failed to delete batch");
    } finally {
      setDeletingBatchId(null);
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'running': return 'bg-blue-500';
      case 'completed': return 'bg-green-500';
      case 'failed': return 'bg-red-500';
      case 'paused': return 'bg-yellow-500';
      case 'pending': return 'bg-gray-500';
      default: return 'bg-gray-500';
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-3xl font-bold">Scan Management</h1>
          <p className="text-muted-foreground">Create, manage, and monitor security scans</p>
        </div>
        <div className="flex gap-2">
          <Dialog open={isCreateBatchOpen} onOpenChange={setIsCreateBatchOpen}>
            <DialogTrigger asChild>
              <Button variant="outline" className="gap-2">
                <Layers className="h-4 w-4" />
                Create Batch
              </Button>
            </DialogTrigger>
            <DialogContent className="max-w-2xl">
              <DialogHeader>
                <DialogTitle>Create New Batch</DialogTitle>
                <DialogDescription>
                  Configure batch settings for running multiple scans
                </DialogDescription>
              </DialogHeader>
              <div className="space-y-4">
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <Label htmlFor="batchName">Batch Name</Label>
                    <Input
                      id="batchName"
                      value={batchForm.batch_name}
                      onChange={(e) => setBatchForm(prev => ({ ...prev, batch_name: e.target.value }))}
                      placeholder="Enter batch name"
                    />
                  </div>
                  <div>
                    <Label htmlFor="batchSize">Batch Size</Label>
                    <Input
                      id="batchSize"
                      type="number"
                      value={batchForm.batch_size}
                      onChange={(e) => setBatchForm(prev => ({ ...prev, batch_size: parseInt(e.target.value) } ))}
                      placeholder="1"
                      min={1}
                    />
                  </div>
                </div>
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <Label htmlFor="startTime">Start Time</Label>
                    <Input
                      id="startTime"
                      type="time"
                      value={batchForm.job_start_time}
                      onChange={(e) => setBatchForm(prev => ({ ...prev, job_start_time: e.target.value }))}
                      step="60"
                    />
                  </div>
                  <div>
                    <Label htmlFor="endTime">End Time</Label>
                    <Input
                      id="endTime"
                      type="time"
                      value={batchForm.job_end_time}
                      onChange={(e) => setBatchForm(prev => ({ ...prev, job_end_time: e.target.value }))}
                      step="60"
                    />
                  </div>
                </div>
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <Label htmlFor="batchJob">Batch Job Type</Label>
                    <Select value={batchForm.batch_job} onValueChange={(value) => setBatchForm(prev => ({ ...prev, batch_job: value }))}>
                      <SelectTrigger id="batchJob">
                        <SelectValue placeholder="Select job type" />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="vuln_scan">Vulnerability Scan</SelectItem>
                        <SelectItem value="compliance_scan">Compliance Scan</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                  <div>
                    <Label htmlFor="weekDay">Week Day(s)</Label>
                    <Input
                      id="weekDay"
                      value={batchForm.week_day}
                      onChange={(e) => setBatchForm(prev => ({ ...prev, week_day: e.target.value }))}
                      placeholder="e.g. 2-5"
                    />
                  </div>
                </div>
                <Button onClick={handleCreateBatch} className="w-full" disabled={isCreatingBatch}>
                  {isCreatingBatch ? (
                    <>
                      <span className="animate-spin mr-2">⏳</span>
                      Creating Batch...
                    </>
                  ) : (
                    "Create Batch"
                  )}
                </Button>
              </div>
            </DialogContent>
          </Dialog>

          
          <Dialog open={isImportOpen} onOpenChange={setIsImportOpen}>
            <DialogTrigger asChild>
              <Button variant="outline" className="gap-2">
                <Plus className="h-4 w-4" />
                Import Scan from Nessus
              </Button>
            </DialogTrigger>
            <DialogContent>
              <DialogHeader>
                <DialogTitle>Import Scan from Nessus</DialogTitle>
                <DialogDescription>
                  Enter the Nessus Scan ID to import as inventory scan.
                </DialogDescription>
              </DialogHeader>
              <div className="space-y-4">
                <Input
                  id="importScanId"
                  value={importScanId}
                  onChange={e => setImportScanId(e.target.value)}
                  placeholder="Enter Nessus Scan ID"
                  disabled={isImporting}
                />
                <Button 
                  onClick={handleImportScan} 
                  className="w-full"
                  disabled={isImporting}
                >
                  {isImporting ? (
                    <>
                      <span className="animate-spin mr-2">⏳</span>
                      Importing...
                    </>
                  ) : (
                    "Import Scan"
                  )}
                </Button>
              </div>
            </DialogContent>
          </Dialog>
        </div>
      </div>

      <Tabs defaultValue="scans" className="space-y-4" value={activeTab} onValueChange={setActiveTab}>
        <TabsList>
          <TabsTrigger value="scans">Active Scans</TabsTrigger>
          <TabsTrigger value="batches">Batch Management</TabsTrigger>
        </TabsList>

        <TabsContent value="scans">
          <Card>
            <CardHeader className="flex flex-row items-center justify-between">
              <div>
                <CardTitle>Active Scans</CardTitle>
                <CardDescription>Manage and monitor your security scans</CardDescription>
              </div>
              <Button variant="outline" size="sm" onClick={fetchRunningScans} disabled={loadingScans}>
                {loadingScans ? "Refreshing..." : "Refresh"}
              </Button>
            </CardHeader>
            <CardContent>
              {loadingScans ? (
                <div className="text-center py-8 text-muted-foreground">Loading scans...</div>
              ) : scans.length === 0 ? (
                <div className="text-center py-8 text-muted-foreground">No scan is running</div>
              ) : (
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Scan ID</TableHead>
                      <TableHead>Name</TableHead>
                      <TableHead>Status</TableHead>
                      <TableHead>Type</TableHead>
                      <TableHead>Owner</TableHead>
                      <TableHead>Created</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {scans.map((scan) => (
                      <TableRow key={scan.id}>
                        <TableCell className="font-mono text-sm">{scan.id}</TableCell>
                        <TableCell>{scan.name}</TableCell>
                        <TableCell>
                          <Badge className={getStatusColor(scan.status)}>
                            {scan.status}
                          </Badge>
                        </TableCell>
                        <TableCell>{scan.scan_type}</TableCell>
                        <TableCell>{scan.owner}</TableCell>
                        <TableCell>
                          {scan.creation_date
                            ? new Date(scan.creation_date * 1000).toLocaleString()
                            : "-"}
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="batches">
          <Card>
            <CardHeader className="flex flex-row items-center justify-between">
              <div>
                <CardTitle>Batch Management</CardTitle>
                <CardDescription>Manage scan batches and scheduling</CardDescription>
              </div>
              <Button variant="outline" size="sm" onClick={fetchBatches} disabled={loadingBatches}>
                {loadingBatches ? "Refreshing..." : "Refresh"}
              </Button>
            </CardHeader>
            <CardContent>
              {loadingBatches ? (
                <div className="text-center py-8 text-muted-foreground">Loading batches...</div>
              ) : batches.length === 0 ? (
                <div className="text-center py-8 text-muted-foreground">No batches found</div>
              ) : (
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Batch ID</TableHead>
                      <TableHead>Name</TableHead>
                      <TableHead>Size</TableHead>
                      <TableHead>Job Type</TableHead>
                      <TableHead>Start Time</TableHead>
                      <TableHead>End Time</TableHead>
                      <TableHead>Week Day</TableHead>
                      <TableHead>Created At</TableHead>
                      <TableHead>Actions</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {batches.map((batch) => (
                      <TableRow key={batch.id}>
                        <TableCell className="font-mono text-sm">{batch.id}</TableCell>
                        <TableCell>{batch.batch_name}</TableCell>
                        <TableCell>{batch.batch_size}</TableCell>
                        <TableCell>{batch.batch_job}</TableCell>
                        <TableCell>{batch.job_start_time}</TableCell>
                        <TableCell>{batch.job_end_time}</TableCell>
                        <TableCell>{batch.week_day}</TableCell>
                        <TableCell>{batch.created_at ? new Date(batch.created_at).toLocaleString() : '-'}</TableCell>
                        <TableCell>
                          <Button 
                            variant="outline" 
                            size="sm" 
                            onClick={() => handleDeleteBatch(batch.id)}
                            disabled={deletingBatchId === batch.id}
                          >
                            {deletingBatchId === batch.id ? (
                              <>
                                <span className="animate-spin mr-1">⏳</span>
                                Deleting...
                              </>
                            ) : (
                              "Delete"
                            )}
                          </Button>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              )}
            </CardContent>
          </Card>
        </TabsContent>

      </Tabs>
    </div>
  );
}
