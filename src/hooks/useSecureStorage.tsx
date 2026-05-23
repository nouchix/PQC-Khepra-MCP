/**
 * Secure storage hook to replace direct localStorage usage for sensitive data
 * Uses sessionStorage for temporary data and localStorage only for non-sensitive app state
 */
import { useCallback } from 'react';

export const useSecureStorage = () => {
  // For sensitive temporary data (like form inputs, auth state)
  const setSecureItem = useCallback((key: string, value: string) => {
    try {
      sessionStorage.setItem(key, value);
    } catch (error) {
      console.warn('Failed to store secure item:', error);
    }
  }, []);

  const getSecureItem = useCallback((key: string): string | null => {
    try {
      return sessionStorage.getItem(key);
    } catch (error) {
      console.warn('Failed to retrieve secure item:', error);
      return null;
    }
  }, []);

  const removeSecureItem = useCallback((key: string) => {
    try {
      sessionStorage.removeItem(key);
    } catch (error) {
      console.warn('Failed to remove secure item:', error);
    }
  }, []);

  // For non-sensitive app preferences
  const setAppPreference = useCallback((key: string, value: string) => {
    try {
      localStorage.setItem(key, value);
    } catch (error) {
      console.warn('Failed to store app preference:', error);
    }
  }, []);

  const getAppPreference = useCallback((key: string): string | null => {
    try {
      return localStorage.getItem(key);
    } catch (error) {
      console.warn('Failed to retrieve app preference:', error);
      return null;
    }
  }, []);

  const removeAppPreference = useCallback((key: string) => {
    try {
      localStorage.removeItem(key);
    } catch (error) {
      console.warn('Failed to remove app preference:', error);
    }
  }, []);

  // Clear all secure data (sessionStorage)
  const clearSecureData = useCallback(() => {
    try {
      sessionStorage.clear();
    } catch (error) {
      console.warn('Failed to clear secure data:', error);
    }
  }, []);

  // Clear sensitive localStorage data while preserving necessary app state
  const clearSensitiveLocalData = useCallback(() => {
    try {
      const keysToKeep = [
        'app-version',
        'has_seen_onboarding',
        'currentOrganizationId'
      ];
      
      const allKeys = Object.keys(localStorage);
      allKeys.forEach(key => {
        if (!keysToKeep.includes(key)) {
          localStorage.removeItem(key);
        }
      });
    } catch (error) {
      console.warn('Failed to clear sensitive local data:', error);
    }
  }, []);

  return {
    // Secure (session) storage
    setSecureItem,
    getSecureItem,
    removeSecureItem,
    clearSecureData,
    
    // App preferences (local) storage
    setAppPreference,
    getAppPreference,
    removeAppPreference,
    clearSensitiveLocalData
  };
};