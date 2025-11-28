import React, { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { FaBiohazard, FaUpload, FaDatabase, FaClock } from 'react-icons/fa';
import { Chart as ChartJS, ArcElement, CategoryScale, LinearScale, BarElement, Title, Tooltip, Legend } from 'chart.js';
import { Pie, Bar } from 'react-chartjs-2';
import { malwarrApi, SystemInfo, FileTypeStats, FamilyStats, MalwareSample } from '../services/api';
import './Dashboard.css';

ChartJS.register(ArcElement, CategoryScale, LinearScale, BarElement, Title, Tooltip, Legend);

const Dashboard: React.FC = () => {
  const [systemInfo, setSystemInfo] = useState<SystemInfo | null>(null);
  const [fileTypeStats, setFileTypeStats] = useState<FileTypeStats | null>(null);
  const [familyStats, setFamilyStats] = useState<FamilyStats | null>(null);
  const [recentSamples, setRecentSamples] = useState<MalwareSample[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadDashboardData();
  }, []);

  const loadDashboardData = async () => {
    try {
      const [system, fileTypes, families, recent] = await Promise.all([
        malwarrApi.getSystemInfo(),
        malwarrApi.getFileTypeStats(),
        malwarrApi.getFamilyStats(),
        malwarrApi.getSamples({ limit: 5 }),
      ]);

      setSystemInfo(system);
      setFileTypeStats(fileTypes);
      setFamilyStats(families);
      setRecentSamples(recent);
    } catch (error) {
      console.error('Failed to load dashboard data:', error);
    } finally {
      setLoading(false);
    }
  };

  const formatBytes = (bytes: number): string => {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i];
  };

  const getFileTypeChartData = () => {
    if (!fileTypeStats) return null;

    const colors = ['#f4511e', '#ff6f00', '#ffab00', '#ffd600', '#aeea00', '#00c853'];

    return {
      labels: fileTypeStats.file_types.map(ft => ft.type.toUpperCase()),
      datasets: [{
        data: fileTypeStats.file_types.map(ft => ft.count),
        backgroundColor: colors,
        borderColor: '#1a1a1a',
        borderWidth: 2,
      }],
    };
  };

  const getFamilyChartData = () => {
    if (!familyStats) return null;

    return {
      labels: familyStats.top_families.map(f => f.family),
      datasets: [{
        label: 'Samples',
        data: familyStats.top_families.map(f => f.count),
        backgroundColor: '#f4511e',
        borderColor: '#f4511e',
        borderWidth: 1,
      }],
    };
  };

  if (loading) {
    return <div className="loading">Loading dashboard...</div>;
  }

  return (
    <div className="dashboard">
      <div className="stats-grid">
        <div className="stat-card">
          <div className="stat-icon">
            <FaBiohazard />
          </div>
          <div className="stat-content">
            <div className="stat-label">Total Samples</div>
            <div className="stat-value">{systemInfo?.total_samples || 0}</div>
          </div>
        </div>

        <div className="stat-card">
          <div className="stat-icon">
            <FaDatabase />
          </div>
          <div className="stat-content">
            <div className="stat-label">Storage Used</div>
            <div className="stat-value">{formatBytes(systemInfo?.storage_used || 0)}</div>
          </div>
        </div>

        <div className="stat-card">
          <div className="stat-icon">
            <FaUpload />
          </div>
          <div className="stat-content">
            <div className="stat-label">Recent Uploads</div>
            <div className="stat-value">{recentSamples.length}</div>
          </div>
        </div>

        <div className="stat-card">
          <div className="stat-icon">
            <FaClock />
          </div>
          <div className="stat-content">
            <div className="stat-label">Status</div>
            <div className="stat-value status-online">Online</div>
          </div>
        </div>
      </div>

      <div className="charts-grid">
        <div className="chart-card">
          <h3>File Type Distribution</h3>
          <div className="chart-container">
            {getFileTypeChartData() && (
              <Pie data={getFileTypeChartData()!} options={{
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                  legend: {
                    position: 'right',
                    labels: {
                      color: '#e0e0e0',
                    },
                  },
                },
              }} />
            )}
          </div>
        </div>

        <div className="chart-card">
          <h3>Top Malware Families</h3>
          <div className="chart-container">
            {getFamilyChartData() && (
              <Bar data={getFamilyChartData()!} options={{
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                  legend: {
                    display: false,
                  },
                },
                scales: {
                  y: {
                    beginAtZero: true,
                    ticks: {
                      color: '#e0e0e0',
                    },
                    grid: {
                      color: '#333',
                    },
                  },
                  x: {
                    ticks: {
                      color: '#e0e0e0',
                    },
                    grid: {
                      color: '#333',
                    },
                  },
                },
              }} />
            )}
          </div>
        </div>
      </div>

      <div className="recent-samples-card">
        <div className="card-header">
          <h3>Recent Samples</h3>
          <Link to="/samples" className="view-all-link">View All</Link>
        </div>
        <div className="samples-table">
          <table>
            <thead>
              <tr>
                <th>Filename</th>
                <th>Type</th>
                <th>Family</th>
                <th>SHA256</th>
                <th>Upload Date</th>
              </tr>
            </thead>
            <tbody>
              {recentSamples.map(sample => (
                <tr key={sample.sha512}>
                  <td>
                    <Link to={`/samples/${sample.sha512}`} className="sample-link">
                      {sample.filename}
                    </Link>
                  </td>
                  <td><span className={`type-badge type-${sample.file_type}`}>{sample.file_type.toUpperCase()}</span></td>
                  <td>{sample.family || '-'}</td>
                  <td><code className="hash">{sample.sha256.substring(0, 16)}...</code></td>
                  <td>{new Date(sample.upload_date).toLocaleDateString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {recentSamples.length === 0 && (
            <div className="no-data">No samples yet. <Link to="/upload">Upload your first sample</Link></div>
          )}
        </div>
      </div>
    </div>
  );
};

export default Dashboard;
