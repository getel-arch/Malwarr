import React, { createContext, useContext, useState, useEffect, ReactNode } from 'react';
import { malwarrApi, VersionInfo } from '../services/api';

interface AppContextType {
  appName: string;
  version: string;
  fullVersion: string;
  isLoading: boolean;
}

const AppContext = createContext<AppContextType | undefined>(undefined);

export const useApp = () => {
  const context = useContext(AppContext);
  if (!context) {
    throw new Error('useApp must be used within an AppProvider');
  }
  return context;
};

interface AppProviderProps {
  children: ReactNode;
}

export const AppProvider: React.FC<AppProviderProps> = ({ children }) => {
  const [appName, setAppName] = useState('Malwarr');
  const [version, setVersion] = useState('...');
  const [fullVersion, setFullVersion] = useState('Malwarr v...');
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    const fetchVersionInfo = async () => {
      try {
        const versionInfo: VersionInfo = await malwarrApi.getVersion();
        setAppName(versionInfo.app_name);
        setVersion(versionInfo.version);
        setFullVersion(versionInfo.full_version);
      } catch (error) {
        console.error('Failed to fetch version info:', error);
        // Keep default values on error
      } finally {
        setIsLoading(false);
      }
    };

    fetchVersionInfo();
  }, []);

  return (
    <AppContext.Provider value={{ appName, version, fullVersion, isLoading }}>
      {children}
    </AppContext.Provider>
  );
};
