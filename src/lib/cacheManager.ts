// Cache Management Utilities
export class CacheManager {
  private static instance: CacheManager;
  private version: string = '';
  private checkInterval: number = 30000; // Check every 30 seconds

  private constructor() {
    this.version = this.getCurrentVersion();
    this.startVersionCheck();
    this.registerServiceWorker();
  }

  static getInstance(): CacheManager {
    if (!CacheManager.instance) {
      CacheManager.instance = new CacheManager();
    }
    return CacheManager.instance;
  }

  private getCurrentVersion(): string {
    // Get version from build timestamp or package.json
    return process.env.NODE_ENV === 'production' 
      ? `v${Date.now()}` 
      : `dev-${Date.now()}`;
  }

  private async registerServiceWorker(): Promise<void> {
    if ('serviceWorker' in navigator) {
      try {
        const registration = await navigator.serviceWorker.register('/sw.js');
        console.log('[Cache Manager] Service Worker registered:', registration);

        // Listen for service worker messages
        navigator.serviceWorker.addEventListener('message', (event) => {
          if (event.data && event.data.type === 'RELOAD_PAGE') {
            globalThis.location.reload();
          }
        });

        // Update service worker when new version is available
        registration.addEventListener('updatefound', () => {
          const newWorker = registration.installing;
          if (newWorker) {
            newWorker.addEventListener('statechange', () => {
              if (newWorker.state === 'installed' && navigator.serviceWorker.controller) {
                // New version available
                this.showUpdateNotification();
              }
            });
          }
        });

      } catch (error) {
        console.error('[Cache Manager] Service Worker registration failed:', error);
      }
    }
  }

  private startVersionCheck(): void {
    // Disable version checking since we don't have a version endpoint
    // Version checking is not needed for this static application
  }

  private async checkForUpdates(): Promise<void> {
    // Version checking disabled - not needed for this static application
    return Promise.resolve();
  }

  public async forceUpdate(): Promise<void> {
    console.log('[Cache Manager] Forcing cache update');
    
    if ('serviceWorker' in navigator && navigator.serviceWorker.controller) {
      // Tell service worker to clear caches
      navigator.serviceWorker.controller.postMessage({
        type: 'FORCE_UPDATE'
      });
    } else {
      // Fallback: clear browser caches manually
      if ('caches' in window) {
        const cacheNames = await caches.keys();
        await Promise.all(
          cacheNames.map(cacheName => caches.delete(cacheName))
        );
      }
      
      // Force reload with cache bypass
      globalThis.location.reload();
    }
  }

  public async clearAllCaches(): Promise<void> {
    if ('caches' in window) {
      const cacheNames = await caches.keys();
      await Promise.all(
        cacheNames.map(cacheName => caches.delete(cacheName))
      );
      console.log('[Cache Manager] All caches cleared');
    }
  }

  private showUpdateNotification(): void {
    // You can integrate this with your toast system
    const updateButton = document.createElement('div');
    updateButton.style.cssText = `
      position: fixed;
      top: 20px;
      right: 20px;
      background: #007bff;
      color: white;
      padding: 12px 20px;
      border-radius: 8px;
      cursor: pointer;
      z-index: 10000;
      box-shadow: 0 4px 12px rgba(0,0,0,0.3);
      font-family: -apple-system, BlinkMacSystemFont, sans-serif;
    `;
    updateButton.textContent = 'New version available - Click to update';
    updateButton.onclick = () => {
      this.forceUpdate();
      document.body.removeChild(updateButton);
    };
    
    document.body.appendChild(updateButton);
    
    // Auto-hide after 10 seconds
    setTimeout(() => {
      if (document.body.contains(updateButton)) {
        document.body.removeChild(updateButton);
      }
    }, 10000);
  }

  // Method to add cache-busting query params to requests
  public addCacheBuster(url: string): string {
    const separator = url.includes('?') ? '&' : '?';
    return `${url}${separator}_cb=${Date.now()}`;
  }

  // Method to set no-cache headers for critical requests
  public getNoCacheHeaders(): HeadersInit {
    return {
      'Cache-Control': 'no-cache, no-store, must-revalidate, max-age=0',
      'Pragma': 'no-cache',
      'Expires': '0'
    };
  }
}

// Initialize cache manager
export const cacheManager = CacheManager.getInstance();