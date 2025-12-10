import api from './apiClient';
import { MalwareSample } from '../types';

export const searchService = {
  searchSamples: async (
    query: string, 
    limit: number = 100, 
    offset: number = 0
  ): Promise<MalwareSample[]> => {
    const response = await api.get('/api/v1/search/query', {
      params: { q: query, limit, offset }
    });
    return response.data;
  },

  getSearchFields: async (): Promise<string[]> => {
    const response = await api.get('/api/v1/search/fields');
    return response.data;
  },
};
