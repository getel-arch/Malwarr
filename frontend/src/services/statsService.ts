import api from './apiClient';
import { FileTypeStats, FamilyStats } from '../types';

export const statsService = {
  getFileTypeStats: async (): Promise<FileTypeStats> => {
    const response = await api.get('/api/v1/stats/types');
    return response.data;
  },

  getFamilyStats: async (): Promise<FamilyStats> => {
    const response = await api.get('/api/v1/stats/families');
    return response.data;
  },
};
