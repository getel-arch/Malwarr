import React from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import { AppProvider } from './contexts/AppContext';
import Layout from './components/Layout/Layout';
import Dashboard from './pages/Dashboard';
import Samples from './pages/Samples';
import SampleDetail from './pages/SampleDetail';
import Upload from './pages/Upload';
import Settings from './pages/Settings';
import CapaExplorer from './pages/CapaExplorer';
import './App.css';

function App() {
  return (
    <AppProvider>
      <Router>
        <Layout>
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/samples" element={<Samples />} />
            <Route path="/samples/:sha512" element={<SampleDetail />} />
            <Route path="/samples/:sha512/capa" element={<CapaExplorer />} />
            <Route path="/upload" element={<Upload />} />
            <Route path="/settings" element={<Settings />} />
          </Routes>
        </Layout>
      </Router>
    </AppProvider>
  );
}

export default App;
