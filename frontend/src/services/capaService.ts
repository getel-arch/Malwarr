import api from './apiClient';

export const capaService = {
  // CAPA Rules Management
  getRulesStatus: async () => {
    const response = await api.get('/api/v1/capa/rules/status');
    return response.data;
  },

  downloadRules: async (version: string = 'latest') => {
    const response = await api.post('/api/v1/capa/rules/download', null, {
      params: { version }
    });
    return response.data;
  },

  uploadRules: async (file: File) => {
    const formData = new FormData();
    formData.append('file', file);
    
    const response = await api.post('/api/v1/capa/rules/upload', formData, {
      headers: {
        'Content-Type': 'multipart/form-data',
      },
    });
    return response.data;
  },

  deleteRules: async () => {
    const response = await api.delete('/api/v1/capa/rules');
    return response.data;
  },

  // CAPA Explorer Management
  getExplorerStatus: async () => {
    const response = await api.get('/api/v1/capa/explorer/status');
    return response.data;
  },

  downloadExplorer: async (version: string = 'latest') => {
    const response = await api.post('/api/v1/capa/explorer/download', null, {
      params: { version }
    });
    return response.data;
  },

  deleteExplorer: async () => {
    const response = await api.delete('/api/v1/capa/explorer');
    return response.data;
  },
};
