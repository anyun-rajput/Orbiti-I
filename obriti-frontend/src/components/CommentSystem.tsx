import { useState, useEffect } from "react";
import { MessageSquare, Plus, Edit2, Trash2, User, Clock } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Textarea } from "@/components/ui/textarea";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { useApiFetch } from "@/lib/utils";
import { useToast } from "@/hooks/use-toast";
import { useAuth } from "@/components/AuthProvider";

export type CommentType = "vulnerability" | "host" | "host_vulnerability";

export interface Comment {
  id: number;
  comment_type: CommentType;
  content: string;
  created_at: string;
  updated_at: string;
  created_by: string;
  vulnerability_id?: number;
  host_id?: number;
}

interface CommentSystemProps {
  vulnerabilityId?: number;
  hostId?: number;
  ownerName?: string;
  onCommentChange?: () => void;
}

export function CommentSystem({ vulnerabilityId, hostId, ownerName, onCommentChange }: CommentSystemProps) {
  const { toast } = useToast();
  const { userInfo, isAdmin } = useAuth();
  const [comments, setComments] = useState<Comment[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [dialogOpen, setDialogOpen] = useState(false);
  const [editingComment, setEditingComment] = useState<Comment | null>(null);
  const [newCommentContent, setNewCommentContent] = useState("");
  const [newCommentType, setNewCommentType] = useState<CommentType>("vulnerability");
  const apiFetch = useApiFetch();


  // Determine available comment types based on props
  const getAvailableCommentTypes = (): CommentType[] => {
    if (vulnerabilityId && hostId) {
      return ["vulnerability", "host", "host_vulnerability"];
    } else if (vulnerabilityId) {
      return ["vulnerability"];
    } else if (hostId) {
      return ["host"];
    } else if (ownerName) {
      // For owner context, we'll show general comments
      return ["vulnerability"];
    }
    return ["vulnerability"]; // Default fallback
  };

  // Set default comment type based on available options
  useEffect(() => {
    const availableTypes = getAvailableCommentTypes();
    if (availableTypes.length > 0 && !availableTypes.includes(newCommentType)) {
      setNewCommentType(availableTypes[0]);
    }
  }, [vulnerabilityId, hostId]);

  // Optimized fetch using batch endpoint
  const fetchComments = async () => {
    setIsLoading(true);
    try {
      const requestBody = {
        vulnerability_id: vulnerabilityId || null,
        host_id: hostId || null,
        owner_name: ownerName || null
      };

      const response = await apiFetch('https://orbiti.fareportal.com:7000/api/comments/batch', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(requestBody),
      });

      if (response.ok) {
        const batchData = await response.json();
        
        // Combine all comments and sort by type priority and date
        const allComments = [
          ...batchData.host_vulnerability_comments,
          ...batchData.host_comments,
          ...batchData.vulnerability_comments
        ];
        
        // Sort by comment type priority and creation date
        const sortedComments = allComments.sort((a, b) => {
          const typeOrder = { 'host_vulnerability': 0, 'host': 1, 'vulnerability': 2 };
          const aOrder = typeOrder[a.comment_type] || 3;
          const bOrder = typeOrder[b.comment_type] || 3;
          
          if (aOrder !== bOrder) {
            return aOrder - bOrder;
          }
          return new Date(b.created_at).getTime() - new Date(a.created_at).getTime();
        });
        
        setComments(sortedComments);
      } else {
        console.error('Failed to fetch comments:', response.statusText);
        setComments([]);
      }
    } catch (error) {
      console.error('Error fetching comments:', error);
      toast({
        title: "Error",
        description: "Failed to fetch comments",
        variant: "destructive",
      });
    } finally {
      setIsLoading(false);
    }
  };

  // Create a new comment
  const createComment = async () => {
    if (!newCommentContent.trim()) return;


    // Check if we have any valid context (be more specific about undefined/null vs 0)
    if ((vulnerabilityId === undefined || vulnerabilityId === null) && 
        (hostId === undefined || hostId === null) && 
        (!ownerName || ownerName.trim() === '')) {
      toast({
        title: "Error",
        description: "Comments require a specific vulnerability, host, or owner context",
        variant: "destructive",
      });
      return;
    }

    try {
      const commentData = {
        comment_type: newCommentType,
        content: newCommentContent,
        vulnerability_id: (newCommentType === "vulnerability" || newCommentType === "host_vulnerability") && vulnerabilityId ? vulnerabilityId : null,
        host_id: (newCommentType === "host" || newCommentType === "host_vulnerability") && hostId ? hostId : null,
      };

      const response = await apiFetch("https://orbiti.fareportal.com:7000/api/comments", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify(commentData),
      });

      if (response.ok) {
        toast({
          title: "Success",
          description: "Comment added successfully",
        });
        setNewCommentContent("");
        setDialogOpen(false);
        fetchComments();
        onCommentChange?.();
      } else {
        throw new Error("Failed to create comment");
      }
    } catch (error) {
      console.error('Error creating comment:', error);
      toast({
        title: "Error",
        description: "Failed to add comment",
        variant: "destructive",
      });
    }
  };

  // Update an existing comment
  const updateComment = async (commentId: number, content: string) => {
    try {
      const response = await apiFetch(`https://orbiti.fareportal.com:7000/api/comments/${commentId}`, {
        method: "PUT",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ content }),
      });

      if (response.ok) {
        toast({
          title: "Success",
          description: "Comment updated successfully",
        });
        setEditingComment(null);
        fetchComments();
        onCommentChange?.();
      } else {
        throw new Error("Failed to update comment");
      }
    } catch (error) {
      console.error('Error updating comment:', error);
      toast({
        title: "Error",
        description: "Failed to update comment",
        variant: "destructive",
      });
    }
  };

  // Delete a comment
  const deleteComment = async (commentId: number) => {
    try {
      const response = await apiFetch(`https://orbiti.fareportal.com:7000/api/comments/${commentId}`, {
        method: "DELETE",
      });

      if (response.ok) {
        toast({
          title: "Success",
          description: "Comment deleted successfully",
        });
        fetchComments();
        onCommentChange?.();
      } else {
        throw new Error("Failed to delete comment");
      }
    } catch (error) {
      console.error('Error deleting comment:', error);
      toast({
        title: "Error",
        description: "Failed to delete comment",
        variant: "destructive",
      });
    }
  };

  // Check if user can edit/delete a comment
  const canEditComment = (comment: Comment): boolean => {
    // Admins can edit any comment
    if (isAdmin()) return true;
    // Users can edit their own comments
    return comment.created_by === userInfo?.username;
  };

  // Get comment type badge
  const getCommentTypeBadge = (type: CommentType) => {
    const configs = {
      vulnerability: { label: "Vulnerability", className: "bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-300" },
      host: { label: "Host", className: "bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-300" },
      host_vulnerability: { label: "Host-Vuln", className: "bg-purple-100 text-purple-800 dark:bg-purple-900 dark:text-purple-300" },
    };
    const config = configs[type];
    return <Badge className={config.className}>{config.label}</Badge>;
  };

  // Format date
  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleString();
  };

  useEffect(() => {
    // Add debouncing to prevent excessive API calls
    const timeoutId = setTimeout(() => {
      fetchComments();
    }, 200);
    
    return () => clearTimeout(timeoutId);
  }, [vulnerabilityId, hostId, ownerName]);

  const availableTypes = getAvailableCommentTypes();

  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-4">
        <CardTitle className="flex items-center gap-2">
          <MessageSquare className="h-5 w-5" />
          Comments ({comments.length})
        </CardTitle>
        {availableTypes.length > 0 && (
          <Dialog open={dialogOpen} onOpenChange={setDialogOpen}>
            <DialogTrigger asChild>
              <Button size="sm">
                <Plus className="h-4 w-4 mr-2" />
                Add Comment
              </Button>
            </DialogTrigger>
            <DialogContent>
              <DialogHeader>
                <DialogTitle>Add New Comment</DialogTitle>
                <DialogDescription>
                  Add a comment that will be visible across relevant sections.
                </DialogDescription>
              </DialogHeader>
              <div className="space-y-4">
                {availableTypes.length > 1 && (
                  <div>
                    <label className="text-sm font-medium mb-2 block">Comment Type</label>
                    <Select value={newCommentType} onValueChange={(value: CommentType) => setNewCommentType(value)}>
                      <SelectTrigger>
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        {availableTypes.includes("vulnerability") && (
                          <SelectItem value="vulnerability">Vulnerability Comment</SelectItem>
                        )}
                        {availableTypes.includes("host") && (
                          <SelectItem value="host">Host Comment</SelectItem>
                        )}
                        {availableTypes.includes("host_vulnerability") && (
                          <SelectItem value="host_vulnerability">Host-Vulnerability Specific</SelectItem>
                        )}
                      </SelectContent>
                    </Select>
                  </div>
                )}
                <div>
                  <label className="text-sm font-medium mb-2 block">Comment</label>
                  <Textarea
                    placeholder="Enter your comment..."
                    value={newCommentContent}
                    onChange={(e) => setNewCommentContent(e.target.value)}
                    rows={4}
                  />
                </div>
                <div className="flex justify-end gap-2">
                  <Button variant="outline" onClick={() => setDialogOpen(false)}>
                    Cancel
                  </Button>
                  <Button onClick={createComment} disabled={!newCommentContent.trim()}>
                    Add Comment
                  </Button>
                </div>
              </div>
            </DialogContent>
          </Dialog>
        )}
      </CardHeader>
      <CardContent>
        {isLoading ? (
          <div className="text-center py-4 text-muted-foreground">Loading comments...</div>
        ) : comments.length === 0 ? (
          <div className="text-center py-4 text-muted-foreground">No comments yet</div>
        ) : (
          <div className="space-y-4">
            {comments.map((comment) => (
              <div key={comment.id} className="border rounded-lg p-4 space-y-3">
                <div className="flex items-start justify-between">
                  <div className="flex items-center gap-2">
                    {getCommentTypeBadge(comment.comment_type)}
                    <div className="flex items-center gap-1 text-sm text-muted-foreground">
                      <User className="h-3 w-3" />
                      {comment.created_by}
                    </div>
                    <div className="flex items-center gap-1 text-sm text-muted-foreground">
                      <Clock className="h-3 w-3" />
                      {formatDate(comment.created_at)}
                    </div>
                  </div>
                  {canEditComment(comment) && (
                    <div className="flex gap-1">
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => {
                          setEditingComment(comment);
                          setNewCommentContent(comment.content);
                        }}
                        title="Edit comment"
                      >
                        <Edit2 className="h-3 w-3" />
                      </Button>
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => deleteComment(comment.id)}
                        title="Delete comment"
                      >
                        <Trash2 className="h-3 w-3" />
                      </Button>
                    </div>
                  )}
                </div>
                <div className="text-sm">
                  {editingComment?.id === comment.id ? (
                    <div className="space-y-2">
                      <Textarea
                        value={newCommentContent}
                        onChange={(e) => setNewCommentContent(e.target.value)}
                        rows={3}
                      />
                      <div className="flex gap-2">
                        <Button
                          size="sm"
                          onClick={() => updateComment(comment.id, newCommentContent)}
                        >
                          Save
                        </Button>
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => {
                            setEditingComment(null);
                            setNewCommentContent("");
                          }}
                        >
                          Cancel
                        </Button>
                      </div>
                    </div>
                  ) : (
                    <p className="whitespace-pre-wrap">{comment.content}</p>
                  )}
                </div>
              </div>
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  );
}
