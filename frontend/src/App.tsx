import React from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import { AppProvider } from './contexts/AppContext';
import Layout from './components/Layout/Layout';
import Dashboard from './pages/Dashboard';
import Samples from './pages/Samples';
import SampleDetail from './pages/SampleDetail';
import Search from './pages/Search';
import Upload from './pages/Upload';
import Settings from './pages/Settings';
import CapaExplorer from './pages/CapaExplorer';
import Tasks from './pages/Tasks';
import { ROUTES } from './constants';
import './App.css';

function App() {
  return (
    <AppProvider>
      <Router>
        <Layout>
          <Routes>
            <Route path={ROUTES.HOME} element={<Dashboard />} />
            <Route path={ROUTES.SAMPLES} element={<Samples />} />
            <Route path={ROUTES.SAMPLE_DETAIL} element={<SampleDetail />} />
            <Route path={ROUTES.CAPA_EXPLORER} element={<CapaExplorer />} />
            <Route path={ROUTES.SEARCH} element={<Search />} />
            <Route path={ROUTES.TASKS} element={<Tasks />} />
            <Route path={ROUTES.UPLOAD} element={<Upload />} />
            <Route path={ROUTES.SETTINGS} element={<Settings />} />
          </Routes>
        </Layout>
      </Router>
    </AppProvider>
  );
}

export default App;
