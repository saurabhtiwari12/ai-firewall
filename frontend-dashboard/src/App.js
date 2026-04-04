import React, { useState, useEffect } from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import './App.css';
import Sidebar from './components/Sidebar';
import Dashboard from './pages/Dashboard';
import EventsPage from './pages/EventsPage';
import AnalyticsPage from './pages/AnalyticsPage';
import AlertsPage from './pages/AlertsPage';
import MapPage from './pages/MapPage';
import { getSocket, getConnectionStatus } from './services/socket';

function AppLayout({ children, wsStatus }) {
  return (
    <div className="app-layout">
      <Sidebar wsStatus={wsStatus} />
      <main className="main-content">
        {children}
      </main>
    </div>
  );
}

export default function App() {
  const [wsStatus, setWsStatus] = useState('connecting');

  useEffect(() => {
    const socket = getSocket();

    const onConnect    = () => setWsStatus('connected');
    const onDisconnect = () => setWsStatus('disconnected');
    const onError      = () => setWsStatus('disconnected');

    socket.on('connect',    onConnect);
    socket.on('disconnect', onDisconnect);
    socket.on('connect_error', onError);

    // Set initial status
    setWsStatus(getConnectionStatus());

    return () => {
      socket.off('connect',       onConnect);
      socket.off('disconnect',    onDisconnect);
      socket.off('connect_error', onError);
    };
  }, []);

  return (
    <BrowserRouter>
      <AppLayout wsStatus={wsStatus}>
        <Routes>
          <Route path="/"          element={<Dashboard />} />
          <Route path="/events"    element={<EventsPage />} />
          <Route path="/analytics" element={<AnalyticsPage />} />
          <Route path="/alerts"    element={<AlertsPage />} />
          <Route path="/map"       element={<MapPage />} />
          <Route path="*"          element={<Navigate to="/" replace />} />
        </Routes>
      </AppLayout>
    </BrowserRouter>
  );
}
