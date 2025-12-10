import { useState, useEffect } from 'react';
import { tasksService } from '../services';
import { TaskStatus } from '../types';

export const useTaskStatus = (taskId: string | null) => {
  const [task, setTask] = useState<TaskStatus | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const loadTaskStatus = async () => {
    if (!taskId) return;

    try {
      setLoading(true);
      setError(null);
      const data = await tasksService.getTaskStatus(taskId);
      setTask(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load task status');
      console.error('Failed to load task status:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (taskId) {
      loadTaskStatus();
    }
  }, [taskId]);

  return {
    task,
    loading,
    error,
    refetch: loadTaskStatus,
  };
};

export const useRunningTasks = (autoRefresh: boolean = false, interval: number = 5000) => {
  const [tasks, setTasks] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const loadTasks = async () => {
    try {
      setLoading(true);
      setError(null);
      const data = await tasksService.getRunningTasks();
      setTasks(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load running tasks');
      console.error('Failed to load running tasks:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadTasks();

    if (autoRefresh) {
      const intervalId = setInterval(loadTasks, interval);
      return () => clearInterval(intervalId);
    }
  }, [autoRefresh, interval]);

  return {
    tasks,
    loading,
    error,
    refetch: loadTasks,
  };
};

export const useTaskQueue = () => {
  const [queue, setQueue] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const loadQueue = async () => {
    try {
      setLoading(true);
      setError(null);
      const data = await tasksService.getTaskQueue();
      setQueue(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load task queue');
      console.error('Failed to load task queue:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadQueue();
  }, []);

  return {
    queue,
    loading,
    error,
    refetch: loadQueue,
  };
};
