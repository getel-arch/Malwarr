import React, { useEffect, useState, useRef } from 'react';
import { malwarrApi } from '../services/api';
import './Tasks.css';

const POLL_INTERVAL = 5000;

const Tasks: React.FC = () => {
  const [running, setRunning] = useState<any[]>([]);
  const [queue, setQueue] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const mounted = useRef(true);

  useEffect(() => {
    mounted.current = true;
    loadData();
    const iv = setInterval(loadData, POLL_INTERVAL);
    return () => { mounted.current = false; clearInterval(iv); };
  }, []);

  const loadData = async () => {
    try {
      const [r, q] = await Promise.all([
        malwarrApi.getRunningTasks(),
        malwarrApi.getTaskQueue(),
      ]);
      if (!mounted.current) return;

      // Backend inspector responses might be returned as an array
      // or wrapped in an object like { value: [...], Count: N }
      const normalizeList = (v: any) => {
        if (!v) return [];
        if (Array.isArray(v)) return v;
        if (Array.isArray(v.value)) return v.value;
        // Some responses may embed lists under other keys
        for (const key of Object.keys(v)) {
          if (Array.isArray(v[key])) return v[key];
        }
        return [];
      };

      setRunning(normalizeList(r));
      setQueue(normalizeList(q));
    } catch (err) {
      console.error('Failed to load tasks:', err);
    } finally {
      if (mounted.current) setLoading(false);
    }
  };

  const formatDate = (val: any) => {
    if (!val) return '-';

    // If number: detect seconds vs milliseconds
    if (typeof val === 'number') {
      const asMs = val > 1e12 ? val : val * 1000;
      try {
        return new Date(asMs).toLocaleString();
      } catch {
        return '-';
      }
    }

    // If string, try to parse ISO
    if (typeof val === 'string') {
      const parsed = Date.parse(val);
      if (!isNaN(parsed)) return new Date(parsed).toLocaleString();
      // fallback: display raw string
      return val;
    }

    return '-';
  };

  return (
    <div className="tasks-page">
      <h2>Tasks</h2>
      <div className="tasks-columns">
        <div className="tasks-column">
          <h3>Running</h3>
          {loading ? (
            <div className="loading">Loading...</div>
          ) : running.length === 0 ? (
            <div className="no-data">No running tasks</div>
          ) : (
            <table className="tasks-table">
              <thead>
                <tr>
                  <th>ID</th>
                  <th>Worker</th>
                  <th>Task</th>
                  <th>Started</th>
                  <th>Progress</th>
                </tr>
              </thead>
              <tbody>
                {running.map((t: any) => (
                  <tr key={t.id || t.task_id || Math.random()}>
                    <td>{t.id ?? t.task_id ?? '-'}</td>
                    <td>{t.worker || t.host || '-'}</td>
                    <td>{t.name || t.task || t.action || '-'}</td>
                    <td>{formatDate(t.started_at ?? t.started ?? t.time_start)}</td>
                    <td>{t.progress ?? t.percent ?? t.state ?? '-'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>

        <div className="tasks-column">
          <h3>Queue</h3>
          {loading ? (
            <div className="loading">Loading...</div>
          ) : queue.length === 0 ? (
            <div className="no-data">Queue is empty</div>
          ) : (
            <table className="tasks-table">
              <thead>
                <tr>
                  <th>Position</th>
                  <th>Task</th>
                  <th>Enqueued</th>
                </tr>
              </thead>
              <tbody>
                {queue.map((qtask: any, idx: number) => (
                  <tr key={qtask.id ?? qtask.task_id ?? idx}>
                    <td>{idx + 1}</td>
                    <td>{qtask.name || qtask.task || qtask.action || '-'}</td>
                    <td>{formatDate(qtask.enqueued_at ?? qtask.eta ?? qtask.time_start)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>
    </div>
  );
};

export default Tasks;
