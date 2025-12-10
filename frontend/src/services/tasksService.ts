import api from './apiClient';
import { TaskStatus } from '../types';

export const tasksService = {
  getRunningTasks: async (): Promise<any[]> => {
    const response = await api.get('/api/v1/tasks/running');
    return response.data;
  },

  getTaskQueue: async (): Promise<any[]> => {
    const response = await api.get('/api/v1/tasks/queue');
    return response.data;
  },

  getTaskStatus: async (taskId: string): Promise<TaskStatus> => {
    const response = await api.get(`/api/v1/tasks/${taskId}`);
    return response.data;
  },
};
