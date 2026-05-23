import { useState, useEffect, useCallback, useRef } from 'react';

export type WebSocketChannel = 'scans' | 'dag' | 'license';

export interface WebSocketMessage {
  type: 'scan_update' | 'dag_update' | 'license_update';
  timestamp: string;
  data: Record<string, unknown>;
}

export interface ScanUpdate {
  scan_id: string;
  status: 'queued' | 'running' | 'completed' | 'failed';
  progress?: number;
  target_url?: string;
  scan_type?: string;
  results?: {
    vulnerabilities_found?: number;
    crypto_issues?: number;
    stig_violations?: number;
  };
}

export interface DAGUpdate {
  node_id: string;
  type: string;
  timestamp: string;
  action?: string;
  parents?: string[];
}

export interface LicenseUpdate {
  machine_id: string;
  status: 'valid' | 'expiring' | 'expired' | 'revoked';
  days_remaining?: number;
  message?: string;
}

interface UseKhepraWebSocketOptions {
  deploymentUrl: string;
  channel: WebSocketChannel;
  onMessage?: (message: WebSocketMessage) => void;
  onError?: (error: Event) => void;
  onOpen?: () => void;
  onClose?: () => void;
  reconnectAttempts?: number;
  reconnectInterval?: number;
}

interface UseKhepraWebSocketReturn {
  isConnected: boolean;
  lastMessage: WebSocketMessage | null;
  scanUpdates: ScanUpdate[];
  dagUpdates: DAGUpdate[];
  licenseUpdates: LicenseUpdate[];
  connect: () => void;
  disconnect: () => void;
  connectionError: string | null;
}

export function useKhepraWebSocket({
  deploymentUrl,
  channel,
  onMessage,
  onError,
  onOpen,
  onClose,
  reconnectAttempts = 5,
  reconnectInterval = 5000,
}: UseKhepraWebSocketOptions): UseKhepraWebSocketReturn {
  const [isConnected, setIsConnected] = useState(false);
  const [lastMessage, setLastMessage] = useState<WebSocketMessage | null>(null);
  const [scanUpdates, setScanUpdates] = useState<ScanUpdate[]>([]);
  const [dagUpdates, setDagUpdates] = useState<DAGUpdate[]>([]);
  const [licenseUpdates, setLicenseUpdates] = useState<LicenseUpdate[]>([]);
  const [connectionError, setConnectionError] = useState<string | null>(null);

  const wsRef = useRef<WebSocket | null>(null);
  const reconnectCountRef = useRef(0);
  const reconnectTimeoutRef = useRef<NodeJS.Timeout | null>(null);

  const getWebSocketUrl = useCallback(() => {
    // Ensure proper protocol (ws:// or wss://)
    const protocol = deploymentUrl.startsWith('https') ? 'wss' : 'ws';
    const host = deploymentUrl.replace(/^https?:\/\//, '');
    return `${protocol}://${host}/ws/${channel}`;
  }, [deploymentUrl, channel]);

  const connect = useCallback(() => {
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      return;
    }

    try {
      const url = getWebSocketUrl();
      console.log(`[Khepra WS] Connecting to ${url}`);

      wsRef.current = new WebSocket(url);

      wsRef.current.onopen = () => {
        console.log(`[Khepra WS] Connected to ${channel}`);
        setIsConnected(true);
        setConnectionError(null);
        reconnectCountRef.current = 0;
        onOpen?.();
      };

      wsRef.current.onmessage = (event) => {
        try {
          const message: WebSocketMessage = JSON.parse(event.data);
          setLastMessage(message);
          onMessage?.(message);

          // Route message to appropriate state
          switch (message.type) {
            case 'scan_update':
              setScanUpdates(prev => [...prev.slice(-99), message.data as unknown as ScanUpdate]);
              break;
            case 'dag_update':
              setDagUpdates(prev => [...prev.slice(-99), message.data as unknown as DAGUpdate]);
              break;
            case 'license_update':
              setLicenseUpdates(prev => [...prev.slice(-9), message.data as unknown as LicenseUpdate]);
              break;
          }
        } catch (err) {
          console.error('[Khepra WS] Failed to parse message:', err);
        }
      };

      wsRef.current.onerror = (error) => {
        console.error('[Khepra WS] Error:', error);
        setConnectionError('WebSocket connection error');
        onError?.(error);
      };

      wsRef.current.onclose = () => {
        console.log('[Khepra WS] Disconnected');
        setIsConnected(false);
        onClose?.();

        // Attempt reconnection
        if (reconnectCountRef.current < reconnectAttempts) {
          reconnectCountRef.current++;
          console.log(`[Khepra WS] Reconnecting (${reconnectCountRef.current}/${reconnectAttempts})...`);

          reconnectTimeoutRef.current = setTimeout(() => {
            connect();
          }, reconnectInterval);
        } else {
          setConnectionError('Max reconnection attempts reached');
        }
      };
    } catch (err) {
      console.error('[Khepra WS] Connection failed:', err);
      setConnectionError('Failed to establish WebSocket connection');
    }
  }, [getWebSocketUrl, channel, onMessage, onError, onOpen, onClose, reconnectAttempts, reconnectInterval]);

  const disconnect = useCallback(() => {
    if (reconnectTimeoutRef.current) {
      clearTimeout(reconnectTimeoutRef.current);
      reconnectTimeoutRef.current = null;
    }

    if (wsRef.current) {
      wsRef.current.close();
      wsRef.current = null;
    }

    setIsConnected(false);
    reconnectCountRef.current = reconnectAttempts; // Prevent reconnection
  }, [reconnectAttempts]);

  // Auto-connect on mount
  useEffect(() => {
    connect();

    return () => {
      disconnect();
    };
  }, [connect, disconnect]);

  return {
    isConnected,
    lastMessage,
    scanUpdates,
    dagUpdates,
    licenseUpdates,
    connect,
    disconnect,
    connectionError,
  };
}

// Convenience hooks for specific channels
export function useKhepraScanUpdates(deploymentUrl: string) {
  return useKhepraWebSocket({
    deploymentUrl,
    channel: 'scans',
  });
}

export function useKhepraDAGUpdates(deploymentUrl: string) {
  return useKhepraWebSocket({
    deploymentUrl,
    channel: 'dag',
  });
}

export function useKhepraLicenseUpdates(deploymentUrl: string) {
  return useKhepraWebSocket({
    deploymentUrl,
    channel: 'license',
  });
}
