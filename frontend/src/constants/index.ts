// API Configuration
export const API_CONFIG = {
  DEFAULT_LIMIT: 100,
  DEFAULT_SKIP: 0,
  REFRESH_INTERVAL: 5000, // 5 seconds
  REQUEST_TIMEOUT: 30000, // 30 seconds
} as const;

// File Type Options
export const FILE_TYPES = [
  { value: '', label: 'All Types' },
  { value: 'pe', label: 'PE' },
  { value: 'elf', label: 'ELF' },
  { value: 'macho', label: 'Mach-O' },
  { value: 'script', label: 'Script' },
  { value: 'archive', label: 'Archive' },
  { value: 'document', label: 'Document' },
  { value: 'other', label: 'Other' },
] as const;

// Classification Options
export const CLASSIFICATIONS = [
  'Malware',
  'Trojan',
  'Virus',
  'Worm',
  'Ransomware',
  'Backdoor',
  'Spyware',
  'Adware',
  'Rootkit',
  'Botnet',
  'PUP',
  'Clean',
  'Unknown',
] as const;

// Task States
export const TASK_STATES = {
  PENDING: 'PENDING',
  STARTED: 'STARTED',
  SUCCESS: 'SUCCESS',
  FAILURE: 'FAILURE',
  RETRY: 'RETRY',
  REVOKED: 'REVOKED',
} as const;

// Chart Colors
export const CHART_COLORS = {
  primary: '#f4511e',
  secondary: '#ff6f00',
  tertiary: '#ffab00',
  quaternary: '#ffd600',
  quinary: '#aeea00',
  senary: '#00c853',
  background: '#1a1a1a',
  border: 'rgba(255, 255, 255, 0.1)',
} as const;

// Routes
export const ROUTES = {
  HOME: '/',
  SAMPLES: '/samples',
  SAMPLE_DETAIL: '/samples/:sha512',
  CAPA_EXPLORER: '/samples/:sha512/capa',
  SEARCH: '/search',
  TASKS: '/tasks',
  UPLOAD: '/upload',
  SETTINGS: '/settings',
} as const;

// Local Storage Keys
export const STORAGE_KEYS = {
  API_KEY: 'malwarr_api_key',
  THEME: 'malwarr_theme',
  PREFERENCES: 'malwarr_preferences',
} as const;

// Pagination
export const PAGINATION = {
  DEFAULT_PAGE_SIZE: 25,
  PAGE_SIZE_OPTIONS: [10, 25, 50, 100],
} as const;

// Hash Types
export const HASH_TYPES = {
  MD5: 'md5',
  SHA1: 'sha1',
  SHA256: 'sha256',
  SHA512: 'sha512',
} as const;

// Analysis Types
export const ANALYSIS_TYPES = {
  PE: 'pe',
  ELF: 'elf',
  MAGIKA: 'magika',
  CAPA: 'capa',
  VIRUSTOTAL: 'virustotal',
  STRINGS: 'strings',
} as const;

// Status Messages
export const STATUS_MESSAGES = {
  UPLOAD_SUCCESS: 'File uploaded successfully',
  UPLOAD_ERROR: 'Failed to upload file',
  DELETE_SUCCESS: 'Sample deleted successfully',
  DELETE_ERROR: 'Failed to delete sample',
  UPDATE_SUCCESS: 'Sample updated successfully',
  UPDATE_ERROR: 'Failed to update sample',
  ANALYSIS_STARTED: 'Analysis started',
  ANALYSIS_ERROR: 'Failed to start analysis',
} as const;
