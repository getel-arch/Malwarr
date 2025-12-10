import { useState, useEffect } from 'react';
import { statsService } from '../services';
import { FileTypeStats, FamilyStats } from '../types';

export const useFileTypeStats = () => {
  const [stats, setStats] = useState<FileTypeStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const loadStats = async () => {
    try {
      setLoading(true);
      setError(null);
      const data = await statsService.getFileTypeStats();
      setStats(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load file type stats');
      console.error('Failed to load file type stats:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadStats();
  }, []);

  return {
    stats,
    loading,
    error,
    refetch: loadStats,
  };
};

export const useFamilyStats = () => {
  const [stats, setStats] = useState<FamilyStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const loadStats = async () => {
    try {
      setLoading(true);
      setError(null);
      const data = await statsService.getFamilyStats();
      setStats(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load family stats');
      console.error('Failed to load family stats:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadStats();
  }, []);

  return {
    stats,
    loading,
    error,
    refetch: loadStats,
  };
};
