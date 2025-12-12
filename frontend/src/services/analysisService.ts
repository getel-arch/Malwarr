import api from './apiClient';
import { 
  PEAnalysis, 
  ELFAnalysis, 
  MagikaAnalysis, 
  CAPAAnalysis,
  VirusTotalAnalysis,
  StringsAnalysis 
} from '../types';

export const analysisService = {
  getCapaResults: async (sha512: string): Promise<any> => {
    const response = await api.get(`/api/v1/samples/${sha512}/capa`);
    return response.data;
  },

  getPEAnalysis: async (sha512: string): Promise<PEAnalysis | null> => {
    const response = await api.get(`/api/v1/samples/${sha512}/analysis/pe`);
    return response.data;
  },

  getELFAnalysis: async (sha512: string): Promise<ELFAnalysis | null> => {
    const response = await api.get(`/api/v1/samples/${sha512}/analysis/elf`);
    return response.data;
  },

  getMagikaAnalysis: async (sha512: string): Promise<MagikaAnalysis | null> => {
    const response = await api.get(`/api/v1/samples/${sha512}/analysis/magika`);
    return response.data;
  },

  getVirusTotalAnalysis: async (sha512: string): Promise<VirusTotalAnalysis | null> => {
    const response = await api.get(`/api/v1/samples/${sha512}/analysis/virustotal`);
    return response.data;
  },

  getStringsAnalysis: async (sha512: string): Promise<StringsAnalysis | null> => {
    const response = await api.get(`/api/v1/samples/${sha512}/analysis/strings`);
    return response.data;
  },
};
