import { useState, useEffect } from 'react';
import { systemService } from '../services';
import { SystemInfo } from '../types';

export const useSystemInfo = () => {
  const [systemInfo, setSystemInfo] = useState<SystemInfo | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const loadSystemInfo = async () => {
    try {
      setLoading(true);
      setError(null);
      const data = await systemService.getSystemInfo();
      setSystemInfo(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load system info');
      console.error('Failed to load system info:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadSystemInfo();
  }, []);

  return {
    systemInfo,
    loading,
    error,
    refetch: loadSystemInfo,
  };
};
