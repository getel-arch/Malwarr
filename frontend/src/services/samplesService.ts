import api from './apiClient';
import { 
  MalwareSample, 
  SampleMetadata, 
  SampleUpdateData,
  UrlUploadData,
  TaskResponse,
  BulkUploadResponse
} from '../types';

interface GetSamplesParams {
  skip?: number;
  limit?: number;
  file_type?: string;
  family?: string;
  tag?: string;
}

export const samplesService = {
  getSamples: async (params?: GetSamplesParams): Promise<MalwareSample[]> => {
    const response = await api.get('/api/v1/samples', { params });
    return response.data;
  },

  getSample: async (sha512: string): Promise<MalwareSample> => {
    const response = await api.get(`/api/v1/samples/${sha512}`);
    return response.data;
  },

  uploadSample: async (
    file: File, 
    metadata?: SampleMetadata
  ): Promise<TaskResponse> => {
    const formData = new FormData();
    formData.append('file', file);
    if (metadata?.tags) formData.append('tags', metadata.tags);
    if (metadata?.family) formData.append('family', metadata.family);
    if (metadata?.classification) formData.append('classification', metadata.classification);
    if (metadata?.notes) formData.append('notes', metadata.notes);
    if (metadata?.archive_password) formData.append('archive_password', metadata.archive_password);

    const response = await api.post('/api/v1/samples', formData, {
      headers: {
        'Content-Type': 'multipart/form-data',
      },
    });
    return response.data;
  },

  uploadBulkSamples: async (
    files: File[], 
    metadata?: SampleMetadata
  ): Promise<BulkUploadResponse> => {
    const formData = new FormData();
    files.forEach(file => formData.append('files', file));
    if (metadata?.tags) formData.append('tags', metadata.tags);
    if (metadata?.family) formData.append('family', metadata.family);
    if (metadata?.classification) formData.append('classification', metadata.classification);
    if (metadata?.notes) formData.append('notes', metadata.notes);
    if (metadata?.archive_password) formData.append('archive_password', metadata.archive_password);

    const response = await api.post('/api/v1/samples/bulk', formData, {
      headers: {
        'Content-Type': 'multipart/form-data',
      },
    });
    return response.data;
  },

  uploadSampleFromUrl: async (data: UrlUploadData): Promise<TaskResponse> => {
    const response = await api.post('/api/v1/samples/from-url', data);
    return response.data;
  },

  updateSample: async (
    sha512: string, 
    data: SampleUpdateData
  ): Promise<MalwareSample> => {
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
};
