import { useState, useEffect, useMemo, useCallback, useRef } from "react";
import { MessageSquare, Plus } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Textarea } from "@/components/ui/textarea";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { useApiFetch } from "@/lib/utils";
import { useToast } from "@/hooks/use-toast";
import { CommentType, Comment, CommentSystem } from "@/components/CommentSystem";

// Simple cache for comments
const commentCache = new Map<string, { comment: Comment | null, timestamp: number }>();
const CACHE_DURATION = 60000; // 1 minute cache

interface InlineCommentDisplayProps {
  vulnerabilityId?: number;
  hostId?: number;
  ownerName?: string;
  refreshTrigger?: number;
}

export function InlineCommentDisplay({ vulnerabilityId, hostId, ownerName, refreshTrigger }: InlineCommentDisplayProps) {
  const { toast } = useToast();
  const [latestComment, setLatestComment] = useState<Comment | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [dialogOpen, setDialogOpen] = useState(false);
  const [newCommentContent, setNewCommentContent] = useState("");
  const [newCommentType, setNewCommentType] = useState<CommentType>("host_vulnerability");
  const [hasFetched, setHasFetched] = useState(false);
  const [isVisible, setIsVisible] = useState(false);
  const isMountedRef = useRef(true);
  const elementRef = useRef<HTMLDivElement>(null);
  const observerRef = useRef<IntersectionObserver | null>(null);
  const lastRefreshTriggerRef = useRef(0);
  const apiFetch = useApiFetch();

  // Generate cache key for this context
  const cacheKey = useMemo(() => {
    return `comment-${vulnerabilityId || 'null'}-${hostId || 'null'}-${ownerName || 'null'}`;
  }, [vulnerabilityId, hostId, ownerName]);

  // Determine available comment types
  const getAvailableCommentTypes = (): CommentType[] => {
    if (vulnerabilityId && hostId) {
      return ["host_vulnerability", "host", "vulnerability"];
    } else if (hostId) {
      return ["host"];
    } else if (vulnerabilityId) {
      return ["host_vulnerability", "vulnerability"];
    } else if (ownerName) {
      return ["vulnerability"];
    }
    return ["vulnerability"];
  };

  // Fetch the first comment only when visible
  const fetchFirstComment = useCallback(async () => {
    if (!isMountedRef.current || hasFetched || isLoading || !isVisible) return;
    
    setIsLoading(true);
    
    try {
      // Check cache first
      if (commentCache.has(cacheKey)) {
        const cached = commentCache.get(cacheKey);
        if (cached && Date.now() - cached.timestamp < CACHE_DURATION) {
          if (isMountedRef.current) {
            setLatestComment(cached.comment);
            setHasFetched(true);
            setIsLoading(false);
          }
          return;
        }
      }

      const context: any = {};
      if (vulnerabilityId) context.vulnerability_id = vulnerabilityId;
      if (hostId) context.host_id = hostId;
      if (ownerName) context.owner_name = ownerName;

      const response = await apiFetch('https://orbiti.fareportal.com:7000/api/comments/latest', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(context)
      });

      if (!isMountedRef.current) return;

      if (response.ok) {
        const data = await response.json();
        const comment = data && data.content ? data : null;
        
        if (isMountedRef.current) {
          setLatestComment(comment);
          setHasFetched(true);
          
          // Cache the result
          commentCache.set(cacheKey, {
            comment,
            timestamp: Date.now()
          });
        }
      } else {
        if (isMountedRef.current) {
          setLatestComment(null);
          setHasFetched(true);
        }
      }
    } catch (error) {
      console.error('Error fetching comment:', error);
      if (isMountedRef.current) {
        setLatestComment(null);
        setHasFetched(true);
      }
    } finally {
      if (isMountedRef.current) {
        setIsLoading(false);
      }
    }
  }, [vulnerabilityId, hostId, ownerName, cacheKey, hasFetched, isLoading, isVisible, apiFetch]);

  // Create a new comment
  const createComment = async () => {
    if (!newCommentContent.trim()) return;

    if (!vulnerabilityId && !hostId && !ownerName) {
      toast({
        title: "Error",
        description: "Comments require a specific context",
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
        
        // Clear cache and refetch
        commentCache.delete(cacheKey);
        setHasFetched(false);
        fetchFirstComment();
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

  // Get comment type badge
  const getCommentTypeBadge = (type: CommentType) => {
    const configs = {
      vulnerability: { label: "V", className: "bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-300" },
      host: { label: "H", className: "bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-300" },
      host_vulnerability: { label: "HV", className: "bg-purple-100 text-purple-800 dark:bg-purple-900 dark:text-purple-300" },
    };
    const config = configs[type];
    return <Badge className={`${config.className} text-xs px-1 py-0`}>{config.label}</Badge>;
  };

  // Set up intersection observer to detect when component is visible
  useEffect(() => {
    if (!elementRef.current) return;

    observerRef.current = new IntersectionObserver(
      (entries) => {
        const [entry] = entries;
        if (entry.isIntersecting) {
          setIsVisible(true);
        } else {
          setIsVisible(false);
        }
      },
      {
        threshold: 0.1, // Trigger when 10% of the component is visible
        rootMargin: '0px'
      }
    );

    observerRef.current.observe(elementRef.current);

    return () => {
      if (observerRef.current) {
        observerRef.current.disconnect();
      }
    };
  }, []);

  // Fetch comment only when component becomes visible
  useEffect(() => {
    if (isVisible && !hasFetched && isMountedRef.current) {
      fetchFirstComment();
    }
  }, [isVisible, hasFetched, fetchFirstComment]);

  // Respond to refresh trigger from parent component
  useEffect(() => {
    if (refreshTrigger && refreshTrigger > 0 && refreshTrigger !== lastRefreshTriggerRef.current) {
      lastRefreshTriggerRef.current = refreshTrigger;
      
      // Clear cache and reset state to force refresh
      commentCache.delete(cacheKey);
      setHasFetched(false);
      setLatestComment(null);
      
      // Fetch new comment if visible
      if (isVisible) {
        fetchFirstComment();
      }
    }
  }, [refreshTrigger]);

  // Set default comment type
  useEffect(() => {
    const availableTypes = getAvailableCommentTypes();
    if (availableTypes.length > 0 && !availableTypes.includes(newCommentType)) {
      setNewCommentType(availableTypes[0]);
    }
  }, [vulnerabilityId, hostId, newCommentType]);

  // Cleanup on unmount
  useEffect(() => {
    return () => {
      isMountedRef.current = false;
      if (observerRef.current) {
        observerRef.current.disconnect();
      }
    };
  }, []);

  const availableTypes = getAvailableCommentTypes();

  // Show loading state
  if (isLoading) {
    return (
      <div ref={elementRef} className="flex items-center gap-2 text-xs text-muted-foreground">
        <MessageSquare className="h-3 w-3 animate-pulse" />
        <span>Loading...</span>
      </div>
    );
  }

  // Show placeholder if no comment exists
  if (!latestComment) {
    return (
      <div ref={elementRef} className="flex items-center gap-1 text-xs text-muted-foreground">
        <MessageSquare className="h-3 w-3" />
        <span>No comments</span>
      </div>
    );
  }

  // Show the first comment
  return (
    <div ref={elementRef} className="flex items-center gap-2">
      <div className="flex items-center gap-2 text-xs">
        {getCommentTypeBadge(latestComment.comment_type)}
        <span className="truncate max-w-32 text-muted-foreground" title={latestComment.content}>
          {latestComment.content}
        </span>
      </div>
      
      {/* Full comment dialog */}
      <Dialog open={dialogOpen} onOpenChange={setDialogOpen}>
        <DialogTrigger asChild>
          <Button variant="ghost" size="sm" className="h-6 w-6 p-0">
            <MessageSquare className="h-3 w-3" />
          </Button>
        </DialogTrigger>
        <DialogContent className="max-w-4xl">
          <DialogHeader>
            <DialogTitle>Comments</DialogTitle>
            <DialogDescription>
              View all comments and add new ones.
            </DialogDescription>
          </DialogHeader>
          <div className="mt-4">
            <CommentSystem
              vulnerabilityId={vulnerabilityId}
              hostId={hostId}
              ownerName={ownerName}
              onCommentChange={() => {
                // Clear cache and refetch when comments change
                commentCache.delete(cacheKey);
                setHasFetched(false);
                fetchFirstComment();
              }}
            />
          </div>
        </DialogContent>
      </Dialog>
    </div>
  );
}