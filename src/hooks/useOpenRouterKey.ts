import { useState, useCallback } from 'react';

const STORAGE_KEY = 'asaf_openrouter_key';

export interface OpenRouterKeyState {
  apiKey: string;
  hasKey: boolean;
  setApiKey: (key: string) => void;
  clearApiKey: () => void;
}

export const useOpenRouterKey = (): OpenRouterKeyState => {
  const [apiKey, setApiKeyState] = useState<string>(
    () => (typeof window !== 'undefined' ? localStorage.getItem(STORAGE_KEY) ?? '' : '')
  );

  const setApiKey = useCallback((key: string) => {
    const trimmed = key.trim();
    if (typeof window !== 'undefined') {
      if (trimmed) {
        localStorage.setItem(STORAGE_KEY, trimmed);
      } else {
        localStorage.removeItem(STORAGE_KEY);
      }
    }
    setApiKeyState(trimmed);
  }, []);

  const clearApiKey = useCallback(() => {
    if (typeof window !== 'undefined') {
      localStorage.removeItem(STORAGE_KEY);
    }
    setApiKeyState('');
  }, []);

  return { apiKey, hasKey: apiKey.length > 0, setApiKey, clearApiKey };
};
