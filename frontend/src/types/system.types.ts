export interface SystemInfo {
  app_name: string;
  version: string;
  total_samples: number;
  storage_used: number;
  database_status: string;
}

export interface VersionInfo {
  version: string;
  app_name: string;
  full_version: string;
}

export interface FileTypeStats {
  file_types: Array<{ type: string; count: number }>;
}

export interface FamilyStats {
  top_families: Array<{ family: string; count: number }>;
}
