import api from './apiClient';

export const getApiBaseUrl = (): string => {
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

export const setApiKey = (key: string): void => {
  localStorage.setItem('malwarr_api_key', key);
};

export const clearApiKey = (): void => {
  localStorage.removeItem('malwarr_api_key');
  delete api.defaults.headers.common['X-API-Key'];
};

export const getApiKey = (): string | null => {
  return localStorage.getItem('malwarr_api_key');
};
