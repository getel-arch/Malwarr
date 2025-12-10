import React from 'react';
import { Link } from 'react-router-dom';
import { FaBiohazard, FaUpload, FaDatabase, FaClock } from 'react-icons/fa';
import { Chart as ChartJS, ArcElement, CategoryScale, LinearScale, BarElement, Title, Tooltip, Legend } from 'chart.js';
import { Pie, Bar } from 'react-chartjs-2';
import { useSystemInfo, useFileTypeStats, useFamilyStats, useSamples } from '../hooks';
import { LoadingSpinner, StatCard } from '../components/common';
import { formatBytes, formatHash } from '../utils';
import { CHART_COLORS } from '../constants';
import './Dashboard.css';

ChartJS.register(ArcElement, CategoryScale, LinearScale, BarElement, Title, Tooltip, Legend);

const Dashboard: React.FC = () => {
  const { systemInfo, loading: systemLoading } = useSystemInfo();
  const { stats: fileTypeStats, loading: fileTypeLoading } = useFileTypeStats();
  const { stats: familyStats, loading: familyLoading } = useFamilyStats();
  const { samples: recentSamples, loading: samplesLoading } = useSamples({ limit: 5 });

  const loading = systemLoading || fileTypeLoading || familyLoading || samplesLoading;

  const getFileTypeChartData = () => {
    if (!fileTypeStats) return null;

    const colors = [
      CHART_COLORS.primary,
      CHART_COLORS.secondary,
      CHART_COLORS.tertiary,
      CHART_COLORS.quaternary,
      CHART_COLORS.quinary,
      CHART_COLORS.senary,
    ];

    return {
      labels: fileTypeStats.file_types.map(ft => ft.type.toUpperCase()),
      datasets: [{
        data: fileTypeStats.file_types.map(ft => ft.count),
        backgroundColor: colors,
        borderColor: CHART_COLORS.background,
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
        backgroundColor: CHART_COLORS.primary,
        borderColor: CHART_COLORS.primary,
        borderWidth: 1,
      }],
    };
  };

  if (loading) {
    return <LoadingSpinner message="Loading dashboard..." />;
  }

  return (
    <div className="dashboard">
      <div className="stats-grid">
        <StatCard
          icon={<FaBiohazard />}
          label="Total Samples"
          value={systemInfo?.total_samples || 0}
        />
        <StatCard
          icon={<FaDatabase />}
          label="Storage Used"
          value={formatBytes(systemInfo?.storage_used || 0)}
        />
        <StatCard
          icon={<FaUpload />}
          label="Recent Uploads"
          value={recentSamples.length}
        />
        <StatCard
          icon={<FaClock />}
          label="Status"
          value="Online"
          className="status-online"
        />
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
                  <td><code className="hash">{formatHash(sample.sha256)}</code></td>
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
