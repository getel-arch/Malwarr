import { useState, useEffect } from 'react';
import { samplesService } from '../services';
import { MalwareSample } from '../types';

interface UseSamplesOptions {
  skip?: number;
  limit?: number;
  file_type?: string;
  family?: string;
  tag?: string;
  autoLoad?: boolean;
}

export const useSamples = (options: UseSamplesOptions = {}) => {
  const [samples, setSamples] = useState<MalwareSample[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const loadSamples = async () => {
    try {
      setLoading(true);
      setError(null);
      const data = await samplesService.getSamples({
        skip: options.skip,
        limit: options.limit || 100,
        file_type: options.file_type,
        family: options.family,
        tag: options.tag,
      });
      setSamples(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load samples');
      console.error('Failed to load samples:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (options.autoLoad !== false) {
      loadSamples();
    }
  }, [options.file_type, options.family, options.tag, options.skip, options.limit]);

  return {
    samples,
    loading,
    error,
    refetch: loadSamples,
  };
};

export const useSample = (sha512: string) => {
  const [sample, setSample] = useState<MalwareSample | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const loadSample = async () => {
      try {
        setLoading(true);
        setError(null);
        const data = await samplesService.getSample(sha512);
        setSample(data);
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Failed to load sample');
        console.error('Failed to load sample:', err);
      } finally {
        setLoading(false);
      }
    };

    if (sha512) {
      loadSample();
    }
  }, [sha512]);

  return {
    sample,
    loading,
    error,
  };
};
