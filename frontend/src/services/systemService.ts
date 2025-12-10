import api from './apiClient';
import { SystemInfo, VersionInfo } from '../types';

export const systemService = {
  getSystemInfo: async (): Promise<SystemInfo> => {
    const response = await api.get('/api/v1/system');
    return response.data;
  },

  getVersion: async (): Promise<VersionInfo> => {
    const response = await api.get('/api/v1/version');
    return response.data;
  },

  getHealth: async () => {
    const response = await api.get('/health');
    return response.data;
  },
};
