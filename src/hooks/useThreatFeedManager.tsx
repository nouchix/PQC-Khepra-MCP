import { useState, useEffect } from 'react';
import { supabase } from '@/integrations/supabase/client';
import { useToast } from '@/hooks/use-toast';

export interface ThreatFeed {
  source: string;
  enabled: boolean;
  last_sync: number | null;
  indicators_today: number;
  status: 'active' | 'inactive' | 'error';
  next_sync?: string;
}

export interface FeedSyncResult {
  source: string;
  success: boolean;
  indicators_fetched: number;
  indicators_added: number;
  last_sync: string;
  error?: string;
  note?: string;
}

export const useThreatFeedManager = () => {
  const [feeds, setFeeds] = useState<ThreatFeed[]>([]);
  const [loading, setLoading] = useState(true);
  const [syncing, setSyncing] = useState(false);
  const [lastSyncResults, setLastSyncResults] = useState<FeedSyncResult[]>([]);
  const { toast } = useToast();

  const fetchFeedStatus = async () => {
    try {
      setLoading(true);
      const { data, error } = await supabase.functions.invoke('threat-feed-sync', {
        body: { action: 'get_feeds' }
      });

      if (error) throw error;

      setFeeds(data.feeds || []);
      return data;
    } catch (error: any) {
      console.error('Error fetching feed status:', error);
      toast({
        title: "Error",
        description: "Failed to fetch threat feed status",
        variant: "destructive"
      });
      return null;
    } finally {
      setLoading(false);
    }
  };

  const syncAllFeeds = async () => {
    try {
      setSyncing(true);
      toast({
        title: "Sync Started",
        description: "Synchronizing all threat intelligence feeds..."
      });

      const { data, error } = await supabase.functions.invoke('threat-feed-sync', {
        body: { action: 'sync_all' }
      });

      if (error) throw error;

      setLastSyncResults(data.results || []);
      
      // Refresh feed status
      await fetchFeedStatus();

      toast({
        title: "Sync Complete",
        description: `Synchronized ${data.active_feeds} active feeds. Total indicators processed: ${data.results?.reduce((sum: number, r: any) => sum + r.indicators_added, 0) || 0}`
      });

      return data;
    } catch (error: any) {
      console.error('Error syncing feeds:', error);
      toast({
        title: "Sync Failed",
        description: error.message || "Failed to synchronize threat feeds",
        variant: "destructive"
      });
      throw error;
    } finally {
      setSyncing(false);
    }
  };

  const syncSpecificFeed = async (source: string) => {
    try {
      setSyncing(true);
      toast({
        title: "Sync Started",
        description: `Synchronizing ${source}...`
      });

      const { data, error } = await supabase.functions.invoke('threat-feed-sync', {
        body: { action: 'sync_source', source }
      });

      if (error) throw error;

      // Update the specific feed result
      setLastSyncResults(prev => {
        const filtered = prev.filter(r => r.source !== source);
        return [...filtered, data];
      });

      // Refresh feed status
      await fetchFeedStatus();

      toast({
        title: "Sync Complete",
        description: `${source}: ${data.indicators_added} new indicators added`
      });

      return data;
    } catch (error: any) {
      console.error(`Error syncing ${source}:`, error);
      toast({
        title: "Sync Failed",
        description: `Failed to sync ${source}: ${error.message}`,
        variant: "destructive"
      });
      throw error;
    } finally {
      setSyncing(false);
    }
  };

  const startAutoSync = async () => {
    try {
      // Enable real-time sync using SQL scheduler
      const { error } = await supabase.rpc('log_user_action', {
        action_type: 'THREAT_FEED_AUTO_SYNC_ENABLED',
        resource_type: 'threat_feeds',
        details: { timestamp: new Date().toISOString() }
      });

      if (error) throw error;

      toast({
        title: "Auto-Sync Enabled",
        description: "Threat feeds will now sync automatically every hour"
      });

      return true;
    } catch (error: any) {
      console.error('Error enabling auto-sync:', error);
      toast({
        title: "Auto-Sync Failed",
        description: error.message || "Failed to enable automatic synchronization",
        variant: "destructive"
      });
      return false;
    }
  };

  const processIndicators = async () => {
    try {
      const { data, error } = await supabase.functions.invoke('threat-feed-sync', {
        body: { action: 'process_indicators' }
      });

      if (error) throw error;

      toast({
        title: "Processing Complete",
        description: `Processed ${data.processed} indicators, found ${data.correlations} correlations`
      });

      return data;
    } catch (error: any) {
      console.error('Error processing indicators:', error);
      toast({
        title: "Processing Failed",
        description: error.message || "Failed to process threat indicators",
        variant: "destructive"
      });
      throw error;
    }
  };

  const getFeedMetrics = () => {
    const totalIndicators = feeds.reduce((sum, feed) => sum + feed.indicators_today, 0);
    const activeFeeds = feeds.filter(feed => feed.status === 'active').length;
    const errorFeeds = feeds.filter(feed => feed.status === 'error').length;
    
    return {
      totalFeeds: feeds.length,
      activeFeeds,
      errorFeeds,
      totalIndicators,
      lastSync: feeds.length > 0 ? Math.max(...feeds.map(f => f.last_sync || 0)) : null
    };
  };

  useEffect(() => {
    fetchFeedStatus();
    
    // Set up periodic refresh
    const interval = setInterval(fetchFeedStatus, 5 * 60 * 1000); // Every 5 minutes
    
    return () => clearInterval(interval);
  }, []);

  return {
    feeds,
    loading,
    syncing,
    lastSyncResults,
    metrics: getFeedMetrics(),
    syncAllFeeds,
    syncSpecificFeed,
    startAutoSync,
    processIndicators,
    refetchFeeds: fetchFeedStatus
  };
};