import axios, { InternalAxiosRequestConfig } from 'axios';

// Determine API base URL
// Priority: 1) Environment variable, 2) Same origin (for production), 3) localhost fallback
const getApiBaseUrl = (): string => {
  // Use environment variable if set
  if (process.env.REACT_APP_API_URL) {
    return process.env.REACT_APP_API_URL;
  }
  
  // In production (served from backend), use empty string for relative URLs
  // This allows the frontend to work with any domain/port
  if (process.env.NODE_ENV === 'production') {
    return '';
  }
  
  // Development fallback
  return 'http://localhost:8686';
};

const API_BASE_URL = getApiBaseUrl();

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

// Analyzer result interfaces (must be declared before MalwareSample)
export interface PEAnalysis {
  imphash?: string;
  compilation_timestamp?: string;
  entry_point?: string;
  sections?: string;
  imports?: string;
  exports?: string;
  machine?: string;
  number_of_sections?: number;
  characteristics?: string;
  magic?: string;
  image_base?: string;
  subsystem?: string;
  dll_characteristics?: string;
  checksum?: string;
  size_of_image?: number;
  size_of_headers?: number;
  base_of_code?: string;
  linker_version?: string;
  os_version?: string;
  image_version?: string;
  subsystem_version?: string;
  import_dll_count?: number;
  imported_functions_count?: number;
  export_count?: number;
  resources?: string;
  resource_count?: number;
  version_info?: string;
  debug_info?: string;
  tls_info?: string;
  rich_header?: string;
  is_signed?: boolean;
  signature_info?: string;
  analysis_date: string;
}

export interface ELFAnalysis {
  machine?: string;
  entry_point?: string;
  file_class?: string;
  data_encoding?: string;
  os_abi?: string;
  abi_version?: number;
  elf_type?: string;
  version?: string;
  flags?: string;
  header_size?: number;
  program_header_offset?: string;
  section_header_offset?: string;
  program_header_entry_size?: number;
  program_header_count?: number;
  section_header_entry_size?: number;
  section_header_count?: number;
  sections?: string;
  section_count?: number;
  segments?: string;
  segment_count?: number;
  interpreter?: string;
  dynamic_tags?: string;
  shared_libraries?: string;
  shared_library_count?: number;
  symbols?: string;
  symbol_count?: number;
  relocations?: string;
  relocation_count?: number;
  analysis_date: string;
}

export interface MagikaAnalysis {
  label?: string;
  score?: string;
  mime_type?: string;
  group?: string;
  description?: string;
  is_text?: boolean;
  analysis_date: string;
}

export interface CAPAAnalysis {
  capabilities?: string;
  attack?: string;
  mbc?: string;
  result_document?: string;
  total_capabilities?: number;
  analysis_date: string;
}

export interface VirusTotalAnalysis {
  positives?: number;
  total?: number;
  scan_date?: string;
  permalink?: string;
  scans?: string;
  detection_ratio?: string;
  scan_id?: string;
  verbose_msg?: string;
  analysis_date: string;
}

export interface StringsAnalysis {
  ascii_strings?: string;
  unicode_strings?: string;
  ascii_count?: number;
  unicode_count?: number;
  total_count?: number;
  min_length?: number;
  longest_string_length?: number;
  average_string_length?: string;
  urls?: string;
  ip_addresses?: string;
  file_paths?: string;
  registry_keys?: string;
  email_addresses?: string;
  url_count?: number;
  ip_count?: number;
  file_path_count?: number;
  registry_key_count?: number;
  email_count?: number;
  analysis_date: string;
}

export interface MalwareSample {
  sha512: string;
  sha256: string;
  sha1: string;
  md5: string;
  filename: string;
  file_size: number;
  file_type: string;
  mime_type?: string;
  // Archive fields
  is_archive?: string;
  parent_archive_sha512?: string;
  extracted_file_count?: number;
  // Source information
  source_url?: string;
  // PE basic metadata
  pe_imphash?: string;
  pe_compilation_timestamp?: string;
  pe_entry_point?: string;
  pe_sections?: string;
  pe_imports?: string;
  pe_exports?: string;
  // PE Header information
  pe_machine?: string;
  pe_number_of_sections?: number;
  pe_characteristics?: string;
  pe_magic?: string;
  pe_image_base?: string;
  pe_subsystem?: string;
  pe_dll_characteristics?: string;
  pe_checksum?: string;
  pe_size_of_image?: number;
  pe_size_of_headers?: number;
  pe_base_of_code?: string;
  // PE Version information
  pe_linker_version?: string;
  pe_os_version?: string;
  pe_image_version?: string;
  pe_subsystem_version?: string;
  // PE Import/Export counts
  pe_import_dll_count?: number;
  pe_imported_functions_count?: number;
  pe_export_count?: number;
  // PE Resources
  pe_resources?: string;
  pe_resource_count?: number;
  // PE Version info
  pe_version_info?: string;
  // PE Debug info
  pe_debug_info?: string;
  // PE TLS
  pe_tls_info?: string;
  // PE Rich header
  pe_rich_header?: string;
  // PE Digital signature
  pe_is_signed?: boolean;
  pe_signature_info?: string;
  // ELF metadata
  elf_machine?: string;
  elf_entry_point?: string;
  elf_file_class?: string;
  elf_data_encoding?: string;
  elf_os_abi?: string;
  elf_abi_version?: number;
  elf_type?: string;
  elf_version?: string;
  elf_flags?: string;
  elf_header_size?: number;
  elf_program_header_offset?: string;
  elf_section_header_offset?: string;
  elf_program_header_entry_size?: number;
  elf_program_header_count?: number;
  elf_section_header_entry_size?: number;
  elf_section_header_count?: number;
  elf_sections?: string;
  elf_section_count?: number;
  elf_segments?: string;
  elf_segment_count?: number;
  elf_interpreter?: string;
  elf_dynamic_tags?: string;
  elf_shared_libraries?: string;
  elf_shared_library_count?: number;
  elf_symbols?: string;
  elf_symbol_count?: number;
  elf_relocations?: string;
  elf_relocation_count?: number;
  // Magika AI file type detection
  magika_label?: string;
  magika_score?: string;
  magika_mime_type?: string;
  magika_group?: string;
  magika_description?: string;
  magika_is_text?: boolean;
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
  // VirusTotal fields
  vt_positives?: number;
  vt_total?: number;
  vt_scan_date?: string;
  vt_permalink?: string;
  vt_scans?: string;
  vt_detection_ratio?: string;
  vt_scan_id?: string;
  vt_verbose_msg?: string;
  vt_analysis_date?: string;
  first_seen: string;
  last_updated: string;
  upload_date: string;
  storage_path: string;
  // Analyzer relationships
  pe_analysis?: PEAnalysis;
  elf_analysis?: ELFAnalysis;
  magika_analysis?: MagikaAnalysis;
  capa_analysis?: CAPAAnalysis;
  virustotal_analysis?: VirusTotalAnalysis;
  strings_analysis?: StringsAnalysis;
}

export interface UploadResponse {
  sample: MalwareSample;
  extracted_samples: MalwareSample[];
  is_archive: boolean;
  extraction_count: number;
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

export interface VersionInfo {
  version: string;
  app_name: string;
  full_version: string;
}

export const malwarrApi = {
  // System
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
    archive_password?: string;
  }): Promise<{ task_id: string; filename: string; status: string; message: string }> => {
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

  uploadBulkSamples: async (files: File[], metadata?: {
    tags?: string;
    family?: string;
    classification?: string;
    notes?: string;
    archive_password?: string;
  }): Promise<{ total_files: number; status: string; message: string; files: Array<{ task_id: string; filename: string; size: number }> }> => {
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

  uploadSampleFromUrl: async (data: {
    url: string;
    filename?: string;
    tags?: string[];
    family?: string;
    classification?: string;
    notes?: string;
    archive_password?: string;
  }): Promise<{ task_id: string; filename: string; status: string; message: string }> => {
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

  // Rescan (run all relevant analyzers for a sample)
  rescanSample: async (sha512: string): Promise<any> => {
    const response = await api.post(`/api/v1/samples/${sha512}/rescan`);
    return response.data;
  },

  // VirusTotal upload
  uploadToVirusTotal: async (sha512: string): Promise<{ status: string; sha512: string; analysis_id: string; message: string; sha256: string }> => {
    const response = await api.post(`/api/v1/samples/${sha512}/virustotal/upload`);
    return response.data;
  },

  // Bulk VirusTotal upload
  uploadToVirusTotalBulk: async (sha512List: string[]): Promise<{
    total: number;
    success: number;
    errors: number;
    results: Array<{
      sha512: string;
      status: string;
      analysis_id?: string;
      message: string;
      sha256?: string;
    }>;
  }> => {
    const response = await api.post(`/api/v1/samples/virustotal/upload/bulk`, sha512List);
    return response.data;
  },

  getCapaResults: async (sha512: string): Promise<any> => {
    const response = await api.get(`/api/v1/samples/${sha512}/capa`);
    return response.data;
  },

  // Individual Analyzer Results
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

  // Statistics
  getFileTypeStats: async (): Promise<FileTypeStats> => {
    const response = await api.get('/api/v1/stats/types');
    return response.data;
  },

  getFamilyStats: async (): Promise<FamilyStats> => {
    const response = await api.get('/api/v1/stats/families');
    return response.data;
  },

  // Tasks / Queue
  getRunningTasks: async (): Promise<any[]> => {
    const response = await api.get('/api/v1/tasks/running');
    return response.data;
  },

  getTaskQueue: async (): Promise<any[]> => {
    const response = await api.get('/api/v1/tasks/queue');
    return response.data;
  },

  getTaskStatus: async (taskId: string): Promise<{
    task_id: string;
    state: string;
    status: string;
    result?: any;
    error?: string;
    info?: any;
  }> => {
    const response = await api.get(`/api/v1/tasks/${taskId}`);
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

// Search
export const searchSamples = async (query: string, limit: number = 100, offset: number = 0) => {
  const response = await api.get('/api/v1/search/query', {
    params: { q: query, limit, offset }
  });
  return response.data;
};

export const getSearchFields = async () => {
  const response = await api.get('/api/v1/search/fields');
  return response.data;
};

// Tasks
export const getTaskStatus = async (taskId: string) => {
  const response = await api.get(`/api/v1/tasks/${taskId}`);
  return response.data;
};

// Bulk VirusTotal upload (exported for easy access)
export const uploadToVirusTotalBulk = async (sha512List: string[]): Promise<{
  total: number;
  success: number;
  errors: number;
  results: Array<{
    sha512: string;
    status: string;
    analysis_id?: string;
    message: string;
    sha256?: string;
  }>;
}> => {
  const response = await api.post(`/api/v1/samples/virustotal/upload/bulk`, sha512List);
  return response.data;
};

export default api;
