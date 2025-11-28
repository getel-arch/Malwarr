import axios, { InternalAxiosRequestConfig } from 'axios';

const API_BASE_URL = process.env.REACT_APP_API_URL || 'http://localhost:8686';

const api = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Interceptor to add API key to all requests
api.interceptors.request.use((config: InternalAxiosRequestConfig) => {
  const apiKey = localStorage.getItem('malwarr_api_key');
  if (apiKey) {
    config.headers['X-API-Key'] = apiKey;
  }
  return config;
});

export const setApiKey = (key: string) => {
  localStorage.setItem('malwarr_api_key', key);
};

export const clearApiKey = () => {
  localStorage.removeItem('malwarr_api_key');
  delete api.defaults.headers.common['X-API-Key'];
};

export interface MalwareSample {
  sha512: string;
  sha256: string;
  sha1: string;
  md5: string;
  filename: string;
  file_size: number;
  file_type: string;
  mime_type?: string;
  pe_imphash?: string;
  pe_compilation_timestamp?: string;
  pe_entry_point?: string;
  pe_sections?: string;
  pe_imports?: string;
  pe_exports?: string;
  elf_machine?: string;
  elf_entry_point?: string;
  elf_sections?: string;
  magic_description?: string;
  strings_count?: number;
  entropy?: string;
  tags?: string[];
  family?: string;
  classification?: string;
  virustotal_link?: string;
  malwarebazaar_link?: string;
  notes?: string;
  // CAPA analysis fields
  capa_capabilities?: string;
  capa_attack?: string;
  capa_mbc?: string;
  capa_analysis_date?: string;
  capa_total_capabilities?: number;
  analysis_status?: string;
  analysis_task_id?: string;
  first_seen: string;
  last_updated: string;
  upload_date: string;
  storage_path: string;
}

export interface SystemInfo {
  app_name: string;
  version: string;
  total_samples: number;
  storage_used: number;
  database_status: string;
}

export interface FileTypeStats {
  file_types: Array<{ type: string; count: number }>;
}

export interface FamilyStats {
  top_families: Array<{ family: string; count: number }>;
}

export const malwarrApi = {
  // System
  getSystemInfo: async (): Promise<SystemInfo> => {
    const response = await api.get('/api/v1/system');
    return response.data;
  },

  getHealth: async () => {
    const response = await api.get('/health');
    return response.data;
  },

  // Samples
  getSamples: async (params?: {
    skip?: number;
    limit?: number;
    file_type?: string;
    family?: string;
    tag?: string;
  }): Promise<MalwareSample[]> => {
    const response = await api.get('/api/v1/samples', { params });
    return response.data;
  },

  getSample: async (sha512: string): Promise<MalwareSample> => {
    const response = await api.get(`/api/v1/samples/${sha512}`);
    return response.data;
  },

  uploadSample: async (file: File, metadata?: {
    tags?: string;
    family?: string;
    classification?: string;
    notes?: string;
  }): Promise<MalwareSample> => {
    const formData = new FormData();
    formData.append('file', file);
    if (metadata?.tags) formData.append('tags', metadata.tags);
    if (metadata?.family) formData.append('family', metadata.family);
    if (metadata?.classification) formData.append('classification', metadata.classification);
    if (metadata?.notes) formData.append('notes', metadata.notes);

    const response = await api.post('/api/v1/samples', formData, {
      headers: {
        'Content-Type': 'multipart/form-data',
      },
    });
    return response.data;
  },

  uploadSampleFromUrl: async (data: {
    url: string;
    filename?: string;
    tags?: string[];
    family?: string;
    classification?: string;
    notes?: string;
  }): Promise<MalwareSample> => {
    const response = await api.post('/api/v1/samples/from-url', data);
    return response.data;
  },

  updateSample: async (sha512: string, data: {
    tags?: string[];
    family?: string;
    classification?: string;
    notes?: string;
    virustotal_link?: string;
    malwarebazaar_link?: string;
  }): Promise<MalwareSample> => {
    const response = await api.patch(`/api/v1/samples/${sha512}`, data);
    return response.data;
  },

  deleteSample: async (sha512: string): Promise<void> => {
    await api.delete(`/api/v1/samples/${sha512}`);
  },

  downloadSample: async (sha512: string, filename: string): Promise<void> => {
    const response = await api.get(`/api/v1/samples/${sha512}/download`, {
      responseType: 'blob',
    });
    
    const url = window.URL.createObjectURL(new Blob([response.data]));
    const link = document.createElement('a');
    link.href = url;
    link.setAttribute('download', filename);
    document.body.appendChild(link);
    link.click();
    link.remove();
  },

  searchSamples: async (query: string): Promise<MalwareSample[]> => {
    const response = await api.get('/api/v1/samples/search', {
      params: { q: query },
    });
    return response.data;
  },

  // CAPA Analysis
  runCapaAnalysis: async (sha512: string): Promise<{ status: string; sha512: string; total_capabilities: number; analysis_date: string }> => {
    const response = await api.post(`/api/v1/samples/${sha512}/analyze/capa`);
    return response.data;
  },

  getCapaResults: async (sha512: string): Promise<any> => {
    const response = await api.get(`/api/v1/samples/${sha512}/capa`);
    return response.data;
  },

  // Statistics
  getFileTypeStats: async (): Promise<FileTypeStats> => {
    const response = await api.get('/api/v1/stats/types');
    return response.data;
  },

  getFamilyStats: async (): Promise<FamilyStats> => {
    const response = await api.get('/api/v1/stats/families');
    return response.data;
  },
};

// CAPA Rules Management
export const getCapaRulesStatus = async () => {
  const response = await api.get('/api/v1/capa/rules/status');
  return response.data;
};

export const downloadCapaRules = async (version: string = 'latest') => {
  const response = await api.post('/api/v1/capa/rules/download', null, {
    params: { version }
  });
  return response.data;
};

export const uploadCapaRules = async (file: File) => {
  const formData = new FormData();
  formData.append('file', file);
  
  const response = await api.post('/api/v1/capa/rules/upload', formData, {
    headers: {
      'Content-Type': 'multipart/form-data',
    },
  });
  return response.data;
};

export const deleteCapaRules = async () => {
  const response = await api.delete('/api/v1/capa/rules');
  return response.data;
};

// CAPA Explorer Management
export const getCapaExplorerStatus = async () => {
  const response = await api.get('/api/v1/capa/explorer/status');
  return response.data;
};

export const downloadCapaExplorer = async (version: string = 'latest') => {
  const response = await api.post('/api/v1/capa/explorer/download', null, {
    params: { version }
  });
  return response.data;
};

export const deleteCapaExplorer = async () => {
  const response = await api.delete('/api/v1/capa/explorer');
  return response.data;
};

export default api;
