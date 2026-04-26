
import React, { useState, useEffect } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Badge } from "@/components/ui/badge";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Skeleton } from "@/components/ui/skeleton";
import { useToast } from "@/hooks/use-toast";
import { useApiFetch } from "@/lib/utils";
import config from "@/config/environment";
import { 
  Plus, 
  Search, 
  Filter, 
  Edit, 
  Trash2, 
  ShieldX, 
  AlertTriangle,
  Calendar,
  User,
  Shield,
  Server,
  Eye,
  EyeOff,
  RefreshCw
} from "lucide-react";
import { format } from "date-fns";

interface Exception {
  id: number;
  exception_id: string;
  vulnerability_id?: number;
  host_id?: number;
  exception_type: 'vulnerability' | 'host' | 'vulnerability_host';
  reason: string;
  expiry_date: string;
  created_by: string;
  created_at: string;
  updated_at: string;
  is_active: boolean;
  is_expired: boolean;
  vulnerability_name?: string;
  hostname?: string;
  host_ip?: string;
}

interface ExceptionSummary {
  total_active: number;
  expired: number;
  expiring_soon: number;
  by_type: Record<string, number>;
}

export function ExceptionsManagement() {
  const { toast } = useToast();
  const apiFetch = useApiFetch();
  
  // State
  const [exceptions, setExceptions] = useState<Exception[]>([]);
  const [summary, setSummary] = useState<ExceptionSummary | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [isCreating, setIsCreating] = useState(false);
  const [isUpdating, setIsUpdating] = useState(false);
  const [isDeleting, setIsDeleting] = useState(false);
  
  // Pagination
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(20);
  const [totalPages, setTotalPages] = useState(1);
  const [totalCount, setTotalCount] = useState(0);
  
  // Filters
  const [search, setSearch] = useState("");
  const [exceptionType, setExceptionType] = useState("all");
  const [isActive, setIsActive] = useState<boolean | null>(null);
  const [isExpired, setIsExpired] = useState<boolean | null>(null);
  
  // Create/Edit dialog
  const [isCreateDialogOpen, setIsCreateDialogOpen] = useState(false);
  const [isEditDialogOpen, setIsEditDialogOpen] = useState(false);
  const [editingException, setEditingException] = useState<Exception | null>(null);
  
  // Form data
  const [formData, setFormData] = useState({
    exception_id: "",
    vulnerability_id: "",
    host_id: "",
    exception_type: "vulnerability" as "vulnerability" | "host" | "vulnerability_host",
    reason: "",
    expiry_date: "",
    created_by: ""
  });

  // Fetch exceptions
  const fetchExceptions = async () => {
    setLoading(true);
    setError(null);
    try {
      const params = new URLSearchParams({
        page: page.toString(),
        page_size: pageSize.toString(),
        search,
        exception_type: exceptionType,
        ...(isActive !== null && { is_active: isActive.toString() }),
        ...(isExpired !== null && { is_expired: isExpired.toString() })
      });

      const response = await apiFetch(`https://orbiti.fareportal.com:7000/api/exceptions?${params}`);
      if (!response.ok) {
        throw new Error('Failed to fetch exceptions');
      }
      
      const data = await response.json();
      console.log('Raw API response:', data);
      console.log('Response type:', typeof data);
      console.log('Is array:', Array.isArray(data));
      
      // Handle the paginated API response format
      if (Array.isArray(data)) {
        // Fallback for old format - treat as plain array
        console.log('Received array format, using fallback');
        setExceptions(data);
        setTotalCount(data.length);
        setTotalPages(Math.ceil(data.length / pageSize));
      } else {
        // New paginated format
        console.log('Received paginated format');
        setExceptions(data.exceptions || []);
        setTotalCount(data.total || 0);
        setTotalPages(data.total_pages || 1);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to fetch exceptions');
    } finally {
      setLoading(false);
    }
  };

  // Fetch summary
  const fetchSummary = async () => {
    try {
      const response = await apiFetch(`https://orbiti.fareportal.com:7000/api/exceptions/summary`);
      if (response.ok) {
        const data = await response.json();
        setSummary(data);
      }
    } catch (err) {
      console.error('Failed to fetch summary:', err);
    }
  };

  // Create exception
  const createException = async () => {
    // Basic form validation
    if (!formData.exception_id.trim()) {
      toast({
        title: "Validation Error",
        description: "Exception ID is required",
        variant: "destructive"
      });
      return;
    }

    if (!formData.reason.trim()) {
      toast({
        title: "Validation Error",
        description: "Reason is required",
        variant: "destructive"
      });
      return;
    }

    if (!formData.expiry_date) {
      toast({
        title: "Validation Error",
        description: "Expiry date is required",
        variant: "destructive"
      });
      return;
    }

    if (!formData.created_by.trim()) {
      toast({
        title: "Validation Error",
        description: "Created by is required",
        variant: "destructive"
      });
      return;
    }

    // Validate based on exception type
    if ((formData.exception_type === 'vulnerability' || formData.exception_type === 'vulnerability_host') && !formData.vulnerability_id.trim()) {
      toast({
        title: "Validation Error",
        description: "Vulnerability ID is required for this exception type",
        variant: "destructive"
      });
      return;
    }

    if ((formData.exception_type === 'host' || formData.exception_type === 'vulnerability_host') && !formData.host_id.trim()) {
      toast({
        title: "Validation Error",
        description: "Host ID is required for this exception type",
        variant: "destructive"
      });
      return;
    }

    setIsCreating(true);
    console.log('Starting exception creation, loading state set to true');
    
    try {
      const payload = {
        ...formData,
        vulnerability_id: formData.vulnerability_id ? parseInt(formData.vulnerability_id) : null,
        host_id: formData.host_id ? parseInt(formData.host_id) : null,
        expiry_date: formData.expiry_date
      };

      console.log('Sending API request with payload:', payload);

      // Add timeout to prevent hanging
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 30000); // 30 second timeout

      const response = await apiFetch(`https://orbiti.fareportal.com:7000/api/exceptions`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
        signal: controller.signal
      });

      clearTimeout(timeoutId);
      console.log('API response received:', response.status);

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.detail || 'Failed to create exception');
      }

      toast({
        title: "Success",
        description: "Exception created successfully",
      });

      // Close dialog and reset form immediately
      setIsCreateDialogOpen(false);
      resetForm();
      
      // Refresh data in background (don't wait for these)
      fetchExceptions();
      fetchSummary();
    } catch (err) {
      console.error('Exception creation error:', err);
      
      let errorMessage = 'Failed to create exception';
      if (err instanceof Error) {
        if (err.name === 'AbortError') {
          errorMessage = 'Request timed out. Please try again.';
        } else {
          errorMessage = err.message;
        }
      }
      
      toast({
        title: "Error",
        description: errorMessage,
        variant: "destructive"
      });
    } finally {
      console.log('Exception creation completed, setting loading state to false');
      setIsCreating(false);
    }
  };

  // Update exception
  const updateException = async () => {
    if (!editingException) return;

    setIsUpdating(true);
    try {
      const payload = {
        reason: formData.reason,
        expiry_date: formData.expiry_date,
        is_active: editingException.is_active
      };

      const response = await apiFetch(`https://orbiti.fareportal.com:7000/api/exceptions/${editingException.exception_id}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.detail || 'Failed to update exception');
      }

      toast({
        title: "Success",
        description: "Exception updated successfully",
      });

      setIsEditDialogOpen(false);
      setEditingException(null);
      resetForm();
      fetchExceptions();
      fetchSummary();
    } catch (err) {
      toast({
        title: "Error",
        description: err instanceof Error ? err.message : 'Failed to update exception',
        variant: "destructive"
      });
    } finally {
      setIsUpdating(false);
    }
  };

  // Delete exception
  const deleteException = async (exceptionId: string) => {
    if (!confirm('Are you sure you want to delete this exception?')) return;

    setIsDeleting(true);
    try {
      const response = await apiFetch(`https://orbiti.fareportal.com:7000/api/exceptions/${exceptionId}`, {
        method: 'DELETE'
      });

      if (!response.ok) {
        throw new Error('Failed to delete exception');
      }

      toast({
        title: "Success",
        description: "Exception deleted successfully",
      });

      fetchExceptions();
      fetchSummary();
    } catch (err) {
      toast({
        title: "Error",
        description: err instanceof Error ? err.message : 'Failed to delete exception',
        variant: "destructive"
      });
    } finally {
      setIsDeleting(false);
    }
  };

  // Reset form
  const resetForm = () => {
    setFormData({
      exception_id: "",
      vulnerability_id: "",
      host_id: "",
      exception_type: "vulnerability",
      reason: "",
      expiry_date: "",
      created_by: ""
    });
  };

  // Open edit dialog
  const openEditDialog = (exception: Exception) => {
    setEditingException(exception);
    setFormData({
      exception_id: exception.exception_id,
      vulnerability_id: exception.vulnerability_id?.toString() || "",
      host_id: exception.host_id?.toString() || "",
      exception_type: exception.exception_type,
      reason: exception.reason,
      expiry_date: exception.expiry_date,
      created_by: exception.created_by
    });
    setIsEditDialogOpen(true);
  };

  // Effects
  useEffect(() => {
    fetchExceptions();
    fetchSummary();
  }, [page, pageSize, search, exceptionType, isActive, isExpired]);

  const getSeverityColor = (type: string) => {
    switch (type) {
      case 'vulnerability': return 'bg-blue-100 text-blue-800';
      case 'host': return 'bg-green-100 text-green-800';
      case 'vulnerability_host': return 'bg-purple-100 text-purple-800';
      default: return 'bg-gray-100 text-gray-800';
    }
  };

  const getStatusColor = (isActive: boolean, isExpired: boolean) => {
    if (!isActive) return 'bg-gray-100 text-gray-800';
    if (isExpired) return 'bg-red-100 text-red-800';
    return 'bg-green-100 text-green-800';
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-3xl font-bold">Exception Management</h1>
          <p className="text-muted-foreground">Manage vulnerability exceptions and accepted risks</p>
        </div>
        <div className="flex items-center gap-2">
          <Button 
            variant="outline" 
            onClick={() => {
              fetchExceptions();
              fetchSummary();
            }}
            disabled={loading}
          >
            <RefreshCw className={`h-4 w-4 mr-2 ${loading ? "animate-spin" : ""}`} />
            Refresh
          </Button>
          <Dialog open={isCreateDialogOpen} onOpenChange={setIsCreateDialogOpen}>
            <DialogTrigger asChild>
              <Button onClick={() => resetForm()}>
                <Plus className="h-4 w-4 mr-2" />
                Create Exception
              </Button>
            </DialogTrigger>
          </Dialog>
        </div>
      </div>

      {/* Summary Cards */}
      {summary && (
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Total Active</CardTitle>
              <ShieldX className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{summary.total_active}</div>
              <p className="text-xs text-muted-foreground">Active exceptions</p>
            </CardContent>
          </Card>
          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Expired</CardTitle>
              <AlertTriangle className="h-4 w-4 text-red-500" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-red-500">{summary.expired}</div>
              <p className="text-xs text-muted-foreground">Expired exceptions</p>
            </CardContent>
          </Card>
          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Expiring Soon</CardTitle>
              <Calendar className="h-4 w-4 text-orange-500" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-orange-500">{summary.expiring_soon}</div>
              <p className="text-xs text-muted-foreground">Within 7 days</p>
            </CardContent>
          </Card>
          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">By Type</CardTitle>
              <Shield className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="space-y-1">
                {Object.entries(summary.by_type).map(([type, count]) => (
                  <div key={type} className="flex justify-between text-sm">
                    <span className="capitalize">{type.replace('_', ' ')}</span>
                    <span className="font-medium">{count}</span>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </div>
      )}

      {/* Filters */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Filter className="h-5 w-5" />
            Filters
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            <div>
              <Label htmlFor="search">Search</Label>
              <div className="relative">
                <Search className="absolute left-2 top-2.5 h-4 w-4 text-muted-foreground" />
                <Input
                  id="search"
                  placeholder="Search exceptions..."
                  value={search}
                  onChange={(e) => setSearch(e.target.value)}
                  className="pl-8"
                />
              </div>
            </div>
            <div>
              <Label htmlFor="type">Exception Type</Label>
              <Select value={exceptionType} onValueChange={setExceptionType}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All Types</SelectItem>
                  <SelectItem value="vulnerability">Vulnerability Only</SelectItem>
                  <SelectItem value="host">Host Only</SelectItem>
                  <SelectItem value="vulnerability_host">Specific Vulnerability-Host</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div>
              <Label htmlFor="status">Status</Label>
              <Select 
                value={isActive === null ? "all" : isActive.toString()} 
                onValueChange={(value) => setIsActive(value === "all" ? null : value === "true")}
              >
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All Status</SelectItem>
                  <SelectItem value="true">Active</SelectItem>
                  <SelectItem value="false">Inactive</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div>
              <Label htmlFor="expiry">Expiry Status</Label>
              <Select 
                value={isExpired === null ? "all" : isExpired.toString()} 
                onValueChange={(value) => setIsExpired(value === "all" ? null : value === "true")}
              >
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All</SelectItem>
                  <SelectItem value="true">Expired</SelectItem>
                  <SelectItem value="false">Not Expired</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Exceptions Table */}
      <Card>
        <CardHeader>
          <CardTitle>Exceptions</CardTitle>
          <CardDescription>
            Manage vulnerability exceptions and accepted risks
          </CardDescription>
        </CardHeader>
        <CardContent>
          {loading ? (
            <div className="space-y-2">
              {[...Array(5)].map((_, i) => (
                <Skeleton key={i} className="h-12 w-full" />
              ))}
            </div>
          ) : error ? (
            <Alert variant="destructive">
              <AlertTriangle className="h-4 w-4" />
              <AlertDescription>{error}</AlertDescription>
            </Alert>
          ) : exceptions.length === 0 ? (
            <div className="text-center py-8 text-muted-foreground">
              No exceptions found
            </div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Exception ID</TableHead>
                  <TableHead>Type</TableHead>
                  <TableHead>Vulnerability</TableHead>
                  <TableHead>Host</TableHead>
                  <TableHead>Reason</TableHead>
                  <TableHead>Expiry Date</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Created By</TableHead>
                  <TableHead>Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {exceptions.map((exception) => (
                  <TableRow key={exception.id}>
                    <TableCell className="font-medium">{exception.exception_id}</TableCell>
                    <TableCell>
                      <Badge className={getSeverityColor(exception.exception_type)}>
                        {exception.exception_type.replace('_', ' ')}
                      </Badge>
                    </TableCell>
                    <TableCell>
                      {exception.vulnerability_name ? (
                        <div>
                          <div className="font-medium">{exception.vulnerability_name}</div>
                          <div className="text-sm text-muted-foreground">ID: {exception.vulnerability_id}</div>
                        </div>
                      ) : (
                        <span className="text-muted-foreground">-</span>
                      )}
                    </TableCell>
                    <TableCell>
                      {exception.hostname ? (
                        <div>
                          <div className="font-medium">{exception.hostname}</div>
                          <div className="text-sm text-muted-foreground">{exception.host_ip}</div>
                        </div>
                      ) : (
                        <span className="text-muted-foreground">-</span>
                      )}
                    </TableCell>
                    <TableCell className="max-w-xs truncate">{exception.reason}</TableCell>
                    <TableCell>
                      <div className="flex items-center gap-1">
                        <Calendar className="h-3 w-3" />
                        {format(new Date(exception.expiry_date), 'MMM dd, yyyy')}
                      </div>
                    </TableCell>
                    <TableCell>
                      <Badge className={getStatusColor(exception.is_active, exception.is_expired)}>
                        {!exception.is_active ? 'Inactive' : exception.is_expired ? 'Expired' : 'Active'}
                      </Badge>
                    </TableCell>
                    <TableCell>
                      <div className="flex items-center gap-1">
                        <User className="h-3 w-3" />
                        {exception.created_by}
                      </div>
                    </TableCell>
                    <TableCell>
                      <div className="flex items-center gap-2">
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => openEditDialog(exception)}
                        >
                          <Edit className="h-4 w-4" />
                        </Button>
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => deleteException(exception.exception_id)}
                          disabled={isDeleting}
                        >
                          {isDeleting ? (
                            <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-current"></div>
                          ) : (
                            <Trash2 className="h-4 w-4" />
                          )}
                        </Button>
                      </div>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
        
        {/* Pagination */}
        {totalCount > 0 && (
          <CardContent>
            <div className="flex justify-between items-center px-6 py-4">
              <div className="text-sm text-muted-foreground">
                Showing {((page - 1) * pageSize) + 1} to {Math.min(page * pageSize, totalCount)} of {totalCount} exceptions
              </div>
              <div className="flex items-center space-x-2">
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => setPage(page - 1)}
                  disabled={page === 1 || loading}
                >
                  Previous
                </Button>
                <span className="text-sm">
                  Page {page} of {totalPages}
                </span>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => setPage(page + 1)}
                  disabled={page === totalPages || loading}
                >
                  Next
                </Button>
                <Select value={pageSize.toString()} onValueChange={(value) => {
                  setPageSize(parseInt(value));
                  setPage(1);
                }}>
                  <SelectTrigger className="w-20">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="10">10</SelectItem>
                    <SelectItem value="20">20</SelectItem>
                    <SelectItem value="50">50</SelectItem>
                    <SelectItem value="100">100</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </div>
          </CardContent>
        )}
      </Card>

      {/* Create Exception Dialog */}
      <Dialog 
        open={isCreateDialogOpen} 
        onOpenChange={(open) => {
          if (!isCreating) {
            setIsCreateDialogOpen(open);
            if (!open) {
              resetForm();
            }
          }
        }}
      >
        <DialogContent className="max-w-2xl relative">
          {isCreating && (
            <div className="absolute inset-0 bg-white/50 flex items-center justify-center z-10 rounded-lg">
              <div className="flex items-center space-x-2 bg-white p-4 rounded-lg shadow-lg">
                <div className="animate-spin rounded-full h-6 w-6 border-b-2 border-blue-600"></div>
                <span className="text-blue-600 font-medium">Creating exception...</span>
              </div>
            </div>
          )}
            <DialogHeader>
              <DialogTitle>Create New Exception</DialogTitle>
              <DialogDescription>
                Create a new vulnerability exception to exclude it from counts and reports.
                {isCreating && <span className="text-blue-600 font-medium"> (Creating...)</span>}
              </DialogDescription>
            </DialogHeader>
            <div className="space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <Label htmlFor="exception_id">Exception ID *</Label>
                  <Input
                    id="exception_id"
                    value={formData.exception_id}
                    onChange={(e) => setFormData({ ...formData, exception_id: e.target.value })}
                    placeholder="e.g., EXC-2024-001"
                    disabled={isCreating}
                  />
                </div>
                <div>
                  <Label htmlFor="exception_type">Exception Type *</Label>
                  <Select
                    value={formData.exception_type}
                    onValueChange={(value: any) => setFormData({ ...formData, exception_type: value })}
                    disabled={isCreating}
                  >
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="vulnerability">Vulnerability Only</SelectItem>
                      <SelectItem value="host">Host Only</SelectItem>
                      <SelectItem value="vulnerability_host">Specific Vulnerability-Host</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
              </div>
              
              {(formData.exception_type === 'vulnerability' || formData.exception_type === 'vulnerability_host') ? (
                <div>
                  <Label htmlFor="vulnerability_id">Vulnerability ID *</Label>
                  <Input
                    id="vulnerability_id"
                    type="number"
                    value={formData.vulnerability_id}
                    onChange={(e) => setFormData({ ...formData, vulnerability_id: e.target.value })}
                    placeholder="Enter vulnerability plugin ID"
                    disabled={isCreating}
                  />
                </div>
              ) : null}
              
              {(formData.exception_type === 'host' || formData.exception_type === 'vulnerability_host') ? (
                <div>
                  <Label htmlFor="host_id">Host ID *</Label>
                  <Input
                    id="host_id"
                    type="number"
                    value={formData.host_id}
                    onChange={(e) => setFormData({ ...formData, host_id: e.target.value })}
                    placeholder="Enter host ID"
                    disabled={isCreating}
                  />
                </div>
              ) : null}
              
              <div>
                <Label htmlFor="reason">Reason *</Label>
                <Textarea
                  id="reason"
                  value={formData.reason}
                  onChange={(e) => setFormData({ ...formData, reason: e.target.value })}
                  placeholder="Explain why this exception is needed"
                  rows={3}
                  disabled={isCreating}
                />
              </div>
              
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <Label htmlFor="expiry_date">Expiry Date *</Label>
                  <Input
                    id="expiry_date"
                    type="date"
                    value={formData.expiry_date}
                    onChange={(e) => setFormData({ ...formData, expiry_date: e.target.value })}
                    disabled={isCreating}
                  />
                </div>
                <div>
                  <Label htmlFor="created_by">Created By *</Label>
                  <Input
                    id="created_by"
                    value={formData.created_by}
                    onChange={(e) => setFormData({ ...formData, created_by: e.target.value })}
                    placeholder="Your name or username"
                    disabled={isCreating}
                  />
                </div>
              </div>
            </div>
            <DialogFooter>
              <Button 
                variant="outline" 
                onClick={() => {
                  if (!isCreating) {
                    setIsCreateDialogOpen(false);
                    resetForm();
                  }
                }}
                disabled={isCreating}
              >
                {isCreating ? "Creating..." : "Cancel"}
              </Button>
              <Button 
                onClick={createException} 
                disabled={isCreating}
                className={isCreating ? "opacity-75 cursor-not-allowed" : ""}
              >
                {isCreating ? (
                  <>
                    <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white mr-2"></div>
                    Creating...
                  </>
                ) : (
                  "Create Exception"
                )}
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>

      {/* Edit Dialog */}
      <Dialog open={isEditDialogOpen} onOpenChange={setIsEditDialogOpen}>
        <DialogContent className="max-w-2xl">
          <DialogHeader>
            <DialogTitle>Edit Exception</DialogTitle>
            <DialogDescription>
              Update the exception details. Some fields cannot be changed after creation.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            <div className="grid grid-cols-2 gap-4">
              <div>
                <Label htmlFor="edit_exception_id">Exception ID</Label>
                <Input
                  id="edit_exception_id"
                  value={formData.exception_id}
                  disabled
                  className="bg-muted"
                />
              </div>
              <div>
                <Label htmlFor="edit_exception_type">Exception Type</Label>
                <Input
                  id="edit_exception_type"
                  value={formData.exception_type.replace('_', ' ')}
                  disabled
                  className="bg-muted"
                />
              </div>
            </div>
            
            <div>
              <Label htmlFor="edit_reason">Reason *</Label>
              <Textarea
                id="edit_reason"
                value={formData.reason}
                onChange={(e) => setFormData({ ...formData, reason: e.target.value })}
                placeholder="Explain why this exception is needed"
                rows={3}
              />
            </div>
            
            <div className="grid grid-cols-2 gap-4">
              <div>
                <Label htmlFor="edit_expiry_date">Expiry Date *</Label>
                <Input
                  id="edit_expiry_date"
                  type="date"
                  value={formData.expiry_date}
                  onChange={(e) => setFormData({ ...formData, expiry_date: e.target.value })}
                />
              </div>
              <div>
                <Label htmlFor="edit_created_by">Created By</Label>
                <Input
                  id="edit_created_by"
                  value={formData.created_by}
                  disabled
                  className="bg-muted"
                />
              </div>
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setIsEditDialogOpen(false)} disabled={isUpdating}>
              Cancel
            </Button>
            <Button onClick={updateException} disabled={isUpdating}>
              {isUpdating ? (
                <>
                  <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white mr-2"></div>
                  Updating...
                </>
              ) : (
                "Update Exception"
              )}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
