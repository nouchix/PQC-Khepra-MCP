// Cache prevention utilities for development mode

export const clearAllCaches = async (): Promise<void> => {
  if (typeof window === 'undefined') return;

  try {
    // Clear localStorage
    localStorage.clear();
    
    // Clear sessionStorage
    sessionStorage.clear();
    
    // Clear IndexedDB
    if ('indexedDB' in window && indexedDB.databases) {
      const databases = await indexedDB.databases();
      await Promise.all(
        databases.map(db => {
          if (db.name) {
            return new Promise<void>((resolve) => {
              const deleteReq = indexedDB.deleteDatabase(db.name!);
              deleteReq.onsuccess = () => resolve();
              deleteReq.onerror = () => resolve();
            });
          }
          return Promise.resolve();
        })
      );
    }
    
    // Clear service worker caches
    if ('serviceWorker' in navigator && 'caches' in window) {
      const cacheNames = await caches.keys();
      await Promise.all(
        cacheNames.map(cacheName => caches.delete(cacheName))
      );
    }
    
    console.log('All caches cleared successfully');
  } catch (error) {
    console.log('Cache clearing completed with minor issues');
  }
};

export const addCacheBustingToAssets = (): void => {
  if (process.env.NODE_ENV !== 'development') return;
  
  const timestamp = Date.now();
  
  // Add timestamp to all script tags
  const scripts = document.querySelectorAll('script[src]');
  scripts.forEach(script => {
    const src = script.getAttribute('src');
    if (src && !src.includes('?')) {
      script.setAttribute('src', `${src}?v=${timestamp}`);
    }
  });
  
  // Add timestamp to all link tags (CSS)
  const links = document.querySelectorAll('link[rel="stylesheet"]');
  links.forEach(link => {
    const href = link.getAttribute('href');
    if (href && !href.includes('?')) {
      link.setAttribute('href', `${href}?v=${timestamp}`);
    }
  });
};

export const preventBrowserCache = (): void => {
  if (process.env.NODE_ENV !== 'development') return;
  
  // Override fetch to add cache busting
  const originalFetch = globalThis.fetch;
  globalThis.fetch = (input: RequestInfo | URL, init?: RequestInit) => {
    if (typeof input === 'string' && !input.includes('?v=')) {
      input = `${input}?v=${Date.now()}`;
    } else if (input instanceof Request && !input.url.includes('?v=')) {
      input = new Request(`${input.url}?v=${Date.now()}`, input);
    }
    
    const headers = new Headers(init?.headers);
    headers.set('Cache-Control', 'no-cache, no-store, must-revalidate');
    headers.set('Pragma', 'no-cache');
    headers.set('Expires', '0');
    
    return originalFetch(input, { ...init, headers });
  };
};

export const disableServiceWorker = async (): Promise<void> => {
  if ('serviceWorker' in navigator) {
    const registrations = await navigator.serviceWorker.getRegistrations();
    await Promise.all(
      registrations.map(registration => registration.unregister())
    );
  }
};