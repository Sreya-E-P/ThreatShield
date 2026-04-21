import React, { useState, useEffect } from 'react';
import {
  Box, Grid, Card, CardContent, Typography, Chip, IconButton,
  LinearProgress, Alert, Button, TextField, MenuItem, Select,
  FormControl, InputLabel, Tooltip
} from '@mui/material';
import {
  Refresh, Warning, CheckCircle, Error, Search, FilterList,
  Download, NotificationsActive, Security, Lock, AccountBalanceWallet, AutoFixHigh
} from '@mui/icons-material';
import { LineChart, Line, AreaChart, Area, BarChart, Bar, PieChart, Pie, Cell, XAxis, YAxis, CartesianGrid, Tooltip as RechartsTooltip, Legend, ResponsiveContainer } from 'recharts';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { format } from 'date-fns';
import toast from 'react-hot-toast';
import apiService from '../services/api';
import { webSocketService } from '../services/websocket';
import RiskGauge from '../components/RiskGauge';

const Dashboard = () => {
  const [timeRange, setTimeRange] = useState('24h');
  const [searchQuery, setSearchQuery] = useState('');
  const [wsConnected, setWsConnected] = useState(false);
  const [liveThreats, setLiveThreats] = useState([]);
  const [liveMetrics, setLiveMetrics] = useState({});
  const queryClient = useQueryClient();

  const { data: threats, isLoading, error, refetch } = useQuery({
    queryKey: ['threats', timeRange],
    queryFn: () => apiService.getThreats(timeRange),
    refetchInterval: 30000,
  });

  const { data: metrics } = useQuery({
    queryKey: ['metrics'],
    queryFn: () => apiService.getSystemMetrics(),
    refetchInterval: 60000,
  });

  const { data: enclaveStatus } = useQuery({
    queryKey: ['enclaveStatus'],
    queryFn: () => apiService.getEnclaveStatus(),
    refetchInterval: 45000,
  });

  // WebSocket Integration
  useEffect(() => {
    webSocketService.connect();

    const handleConnect = () => setWsConnected(true);
    const handleDisconnect = () => setWsConnected(false);

    webSocketService.subscribe('connect', handleConnect);
    webSocketService.subscribe('disconnect', handleDisconnect);
    webSocketService.subscribeToThreats((threat) => {
      setLiveThreats(prev => [threat, ...prev].slice(0, 20));
      if (threat.severity === 'critical') {
        toast.error(`⚠️ Critical Threat: ${threat.title}`, { duration: 5000 });
      } else if (threat.severity === 'high') {
        toast.warning(`⚠️ High Risk Threat: ${threat.title}`);
      }
    });

    webSocketService.subscribeToMetrics((metrics) => setLiveMetrics(metrics));
    webSocketService.subscribeToAlerts((alert) => {
      toast(alert.message, { icon: alert.type === 'defense' ? '🛡️' : '⚠️', duration: 4000 });
    });

    return () => {
      webSocketService.unsubscribe('connect', handleConnect);
      webSocketService.unsubscribe('disconnect', handleDisconnect);
      webSocketService.disconnect();
    };
  }, []);

  const threatTimeline = threats?.threats?.slice(0, 20).map((t, i) => ({
    time: format(new Date(t.timestamp), 'HH:mm'),
    count: 1,
    severity: t.severity === 'critical' ? 4 : t.severity === 'high' ? 3 : t.severity === 'medium' ? 2 : 1
  })) || [];

  const threatTypes = threats?.threats?.reduce((acc, t) => {
    acc[t.type] = (acc[t.type] || 0) + 1;
    return acc;
  }, {}) || {};

  const threatTypesChart = Object.entries(threatTypes).map(([name, value]) => ({ name, value }));
  const COLORS = ['#0088FE', '#00C49F', '#FFBB28', '#FF8042', '#8884d8'];

  if (isLoading) {
    return (
      <Box sx={{ p: 3 }}>
        <LinearProgress />
        <Typography sx={{ mt: 2 }}>Loading Dashboard...</Typography>
      </Box>
    );
  }

  if (error) {
    return (
      <Alert severity="error" sx={{ m: 3 }}>
        Failed to load: {error.message}
        <Button startIcon={<Refresh />} onClick={() => refetch()} sx={{ ml: 2 }}>Retry</Button>
      </Alert>
    );
  }

  return (
    <Box sx={{ p: 3, bgcolor: 'background.default', minHeight: '100vh' }}>
      {/* Header with WebSocket Status */}
      <Box sx={{ mb: 4 }}>
        <Grid container alignItems="center" justifyContent="space-between">
          <Grid item>
            <Typography variant="h4" sx={{ fontWeight: 'bold' }}>🛡️ ThreatShield Dashboard</Typography>
            <Typography variant="body2" color="text.secondary">Real-time threat intelligence & autonomous defense</Typography>
          </Grid>
          <Grid item>
            <Box sx={{ display: 'flex', gap: 1, alignItems: 'center' }}>
              <Tooltip title={wsConnected ? 'Live Updates Active' : 'Connecting...'}>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
                  <Box sx={{ width: 10, height: 10, borderRadius: '50%', bgcolor: wsConnected ? '#4caf50' : '#ff9800', animation: wsConnected ? 'pulse 1.5s infinite' : 'none', '@keyframes pulse': { '0%': { opacity: 1, transform: 'scale(1)' }, '50%': { opacity: 0.6, transform: 'scale(1.2)' }, '100%': { opacity: 1, transform: 'scale(1)' } } }} />
                  <Typography variant="caption" color="text.secondary">{wsConnected ? 'Live' : 'Connecting...'}</Typography>
                </Box>
              </Tooltip>
              <IconButton onClick={() => refetch()}><Refresh /></IconButton>
              <Button variant="outlined" startIcon={<Download />}>Export</Button>
              <Button variant="contained" startIcon={<NotificationsActive />}>Alerts</Button>
            </Box>
          </Grid>
        </Grid>
      </Box>

      {/* Search & Filter */}
      <Box sx={{ mb: 3, display: 'flex', gap: 2, flexWrap: 'wrap' }}>
        <TextField placeholder="Search threats..." size="small" value={searchQuery} onChange={(e) => setSearchQuery(e.target.value)} InputProps={{ startAdornment: <Search sx={{ mr: 1 }} /> }} sx={{ flexGrow: 1 }} />
        <FormControl size="small" sx={{ minWidth: 120 }}><InputLabel>Time Range</InputLabel><Select value={timeRange} onChange={(e) => setTimeRange(e.target.value)}><MenuItem value="1h">Last Hour</MenuItem><MenuItem value="24h">Last 24 Hours</MenuItem><MenuItem value="7d">Last 7 Days</MenuItem></Select></FormControl>
        <Button startIcon={<FilterList />} variant="outlined">Filters</Button>
      </Box>

      {/* Research Contributions */}
      <Card sx={{ mb: 3, bgcolor: 'primary.main', color: 'white' }}>
        <CardContent>
          <Typography variant="h6">🔬 </Typography>
          <Grid container spacing={2} sx={{ mt: 1 }}>
            <Grid item xs={2.4}><Box textAlign="center"><AutoFixHigh sx={{ fontSize: 40 }} /><Typography>Hybrid PQC</Typography><Chip label="Active" size="small" sx={{ bgcolor: 'success.main' }} /></Box></Grid>
            <Grid item xs={2.4}><Box textAlign="center"><Security sx={{ fontSize: 40 }} /><Typography>Zero-Day AI</Typography><Chip label="Active" size="small" sx={{ bgcolor: 'success.main' }} /></Box></Grid>
            <Grid item xs={2.4}><Box textAlign="center"><Lock sx={{ fontSize: 40 }} /><Typography>Autonomous Defense</Typography><Chip label="Active" size="small" sx={{ bgcolor: 'success.main' }} /></Box></Grid>
            <Grid item xs={2.4}><Box textAlign="center"><AccountBalanceWallet sx={{ fontSize: 40 }} /><Typography>Blockchain Forensics</Typography><Chip label="Active" size="small" sx={{ bgcolor: 'success.main' }} /></Box></Grid>
            <Grid item xs={2.4}><Box textAlign="center"><Security sx={{ fontSize: 40 }} /><Typography>Confidential Compute</Typography><Chip label="Active" size="small" sx={{ bgcolor: 'success.main' }} /></Box></Grid>
          </Grid>
        </CardContent>
      </Card>

      {/* Key Metrics */}
      <Grid container spacing={3} sx={{ mb: 4 }}>
        <Grid item xs={12} sm={6} md={3}><Card><CardContent><Typography color="text.secondary">Active Threats</Typography><Typography variant="h4" color="error.main">{threats?.count || 0}</Typography><Box sx={{ display: 'flex', alignItems: 'center', mt: 1 }}><Warning fontSize="small" color="error" /><Typography variant="body2" sx={{ ml: 0.5 }}>{threats?.threats?.filter(t => t.severity === 'high' || t.severity === 'critical').length || 0} high risk</Typography></Box></CardContent></Card></Grid>
        <Grid item xs={12} sm={6} md={3}><Card><CardContent><Typography color="text.secondary">Zero-Day Predictions</Typography><Typography variant="h4" color="warning.main">35%</Typography><Chip size="small" label="82% confidence" color="warning" variant="outlined" sx={{ mt: 1 }} /></CardContent></Card></Grid>
        <Grid item xs={12} sm={6} md={3}><Card><CardContent><Typography color="text.secondary">SGX Enclaves</Typography><Typography variant="h4">{enclaveStatus?.active_enclaves || 3}</Typography><Box sx={{ display: 'flex', alignItems: 'center', mt: 1 }}>{enclaveStatus?.attestation_valid ? <CheckCircle fontSize="small" color="success" /> : <Error fontSize="small" color="error" />}<Typography variant="body2" sx={{ ml: 0.5 }}>{enclaveStatus?.attestation_valid ? 'All attested' : 'Issues'}</Typography></Box></CardContent></Card></Grid>
        <Grid item xs={12} sm={6} md={3}><Card><CardContent><Typography color="text.secondary">System Health</Typography><Typography variant="h4">98%</Typography><Chip label="Operational" size="small" color="success" sx={{ mt: 1 }} /></CardContent></Card></Grid>
      </Grid>

      {/* Charts */}
      <Grid container spacing={3}>
        <Grid item xs={12} md={8}><Card><CardContent><Typography variant="h6">Threat Activity Timeline</Typography><Box sx={{ height: 300 }}><ResponsiveContainer><AreaChart data={threatTimeline}><CartesianGrid strokeDasharray="3 3" /><XAxis dataKey="time" /><YAxis /><RechartsTooltip /><Area type="monotone" dataKey="count" stroke="#8884d8" fill="#8884d8" fillOpacity={0.3} /></AreaChart></ResponsiveContainer></Box></CardContent></Card></Grid>
        <Grid item xs={12} md={4}><Card><CardContent><Typography variant="h6">Overall Risk</Typography><Box sx={{ height: 300, display: 'flex', justifyContent: 'center' }}><RiskGauge value={metrics?.risk_score || 45} /></Box></CardContent></Card></Grid>
        <Grid item xs={12} md={6}><Card><CardContent><Typography variant="h6">Threat Distribution</Typography><Box sx={{ height: 300 }}><ResponsiveContainer><PieChart><Pie data={threatTypesChart} cx="50%" cy="50%" labelLine={false} label={(e) => `${e.name}: ${e.value}`} outerRadius={100} dataKey="value">{threatTypesChart.map((_, i) => <Cell key={i} fill={COLORS[i % COLORS.length]} />)}</Pie><RechartsTooltip /><Legend /></PieChart></ResponsiveContainer></Box></CardContent></Card></Grid>
        <Grid item xs={12} md={6}><Card><CardContent><Typography variant="h6">Threat Severity</Typography><Box sx={{ height: 300 }}><ResponsiveContainer><BarChart data={threats?.threats?.slice(0, 10).map(t => ({ name: t.title?.substring(0, 20) || 'Unknown', severity: t.severity === 'critical' ? 4 : t.severity === 'high' ? 3 : t.severity === 'medium' ? 2 : 1 })) || []}><CartesianGrid /><XAxis dataKey="name" angle={-45} textAnchor="end" height={60} /><YAxis /><RechartsTooltip /><Bar dataKey="severity" fill="#8884d8" /></BarChart></ResponsiveContainer></Box></CardContent></Card></Grid>
      </Grid>
    </Box>
  );
};

export default Dashboard;