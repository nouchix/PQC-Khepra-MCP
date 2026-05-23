import { useState, useEffect } from 'react';
import { cacheManager } from '@/lib/cacheManager';
import { toast } from 'sonner';

export const useCacheManager = () => {
  const [isUpdateAvailable, setIsUpdateAvailable] = useState(false);
  const [lastCheck, setLastCheck] = useState<Date | null>(null);

  useEffect(() => {
    // Listen for update notifications
    const handleUpdateAvailable = () => {
      setIsUpdateAvailable(true);
      toast.info('New version available!', {
        description: 'Click to update to the latest version',
        action: {
          label: 'Update Now',
          onClick: () => handleForceUpdate()
        },
        duration: 10000
      });
    };

    // Check for updates on mount
    checkForUpdates();

    // Set up periodic checks (every 2 minutes in production)
    const checkInterval = process.env.NODE_ENV === 'production' ? 120000 : 0;
    let intervalId: NodeJS.Timeout;

    if (checkInterval > 0) {
      intervalId = setInterval(checkForUpdates, checkInterval);
    }

    return () => {
      if (intervalId) {
        clearInterval(intervalId);
      }
    };
  }, []);

  const checkForUpdates = async () => {
    try {
      setLastCheck(new Date());
      
      // In a real app, you'd check against your deployment service API
      // For now, we'll simulate version checking
      const currentVersion = localStorage.getItem('app-version');
      const buildTime = document.querySelector('meta[name="version"]')?.getAttribute('content');
      
      if (currentVersion && buildTime && currentVersion !== buildTime) {
        setIsUpdateAvailable(true);
        return true;
      }
      
      // Store current version
      if (buildTime) {
        localStorage.setItem('app-version', buildTime);
      }
      
      return false;
    } catch (error) {
      console.error('Failed to check for updates:', error);
      return false;
    }
  };

  const handleForceUpdate = async () => {
    try {
      toast.loading('Updating application...', { id: 'cache-update' });
      await cacheManager.forceUpdate();
      setIsUpdateAvailable(false);
      toast.success('Application updated successfully!', { id: 'cache-update' });
    } catch (error) {
      console.error('Failed to force update:', error);
      toast.error('Failed to update application', { id: 'cache-update' });
    }
  };

  const clearCache = async () => {
    try {
      toast.loading('Clearing cache...', { id: 'cache-clear' });
      await cacheManager.clearAllCaches();
      toast.success('Cache cleared successfully!', { id: 'cache-clear' });
      globalThis.location.reload();
    } catch (error) {
      console.error('Failed to clear cache:', error);
      toast.error('Failed to clear cache', { id: 'cache-clear' });
    }
  };

  return {
    isUpdateAvailable,
    lastCheck,
    checkForUpdates,
    forceUpdate: handleForceUpdate,
    clearCache
  };
};