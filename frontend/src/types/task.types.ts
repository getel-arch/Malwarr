export interface TaskStatus {
  task_id: string;
  state: string;
  status: string;
  result?: any;
  error?: string;
  info?: any;
}

export interface TaskResponse {
  task_id: string;
  filename: string;
  status: string;
  message: string;
}

export interface BulkUploadResponse {
  total_files: number;
  status: string;
  message: string;
  files: Array<{ 
    task_id: string; 
    filename: string; 
    size: number;
  }>;
}
