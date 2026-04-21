// frontend/src/pages/Settings.jsx
import React, { useState } from 'react';
import {
  Box,
  Card,
  CardContent,
  Typography,
  Grid,
  Switch,
  FormControlLabel,
  TextField,
  Button,
  Alert,
  Divider,
  Slider,
  Select,
  MenuItem,
  FormControl,
  InputLabel,
  Chip,
  IconButton,
  Tooltip,
} from '@mui/material';
import {
  Security,
  Speed,
  Storage,
  Notifications,
  Palette,
  Key,
  Save,
  Refresh,
  Info,
} from '@mui/icons-material';
import { useTheme as useCustomTheme } from '../context/ThemeContext';
import { useQuery, useMutation } from '@tanstack/react-query';
import apiService from '../services/api';

const Settings = () => {
  const { mode, toggleTheme } = useCustomTheme();
  const [settings, setSettings] = useState({
    autoRefresh: true,
    refreshInterval: 30,
    notifications: true,
    threatAlerts: true,
    defenseAlerts: true,
    darkMode: mode === 'dark',
    highContrast: false,
    dataRetentionDays: 30,
    defaultTimeRange: '24h',
    threatSensitivity: 0.7,
  });

  const { data: cryptoBenchmark, refetch: refetchBenchmark } = useQuery({
    queryKey: ['cryptoBenchmark'],
    queryFn: () => apiService.cryptoBenchmark(),
    enabled: false,
  });

  const saveSettings = useMutation({
    mutationFn: async (newSettings) => {
      localStorage.setItem('userSettings', JSON.stringify(newSettings));
      return { success: true };
    },
    onSuccess: () => {
      alert('Settings saved successfully!');
    },
  });

  const handleChange = (field, value) => {
    setSettings(prev => ({ ...prev, [field]: value }));
  };

  const handleSave = () => {
    saveSettings.mutate(settings);
    if (settings.darkMode !== (mode === 'dark')) {
      toggleTheme();
    }
  };

  const handleRunBenchmark = async () => {
    await refetchBenchmark();
  };

  return (
    <Box sx={{ p: 3, maxWidth: 1200, mx: 'auto' }}>
      <Typography variant="h4" gutterBottom sx={{ fontWeight: 'bold', mb: 3 }}>
        ⚙️ Settings
      </Typography>

      <Grid container spacing={3}>
        {/* Appearance */}
        <Grid item xs={12} md={6}>
          <Card>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
                <Palette sx={{ mr: 1, color: 'primary.main' }} />
                <Typography variant="h6">Appearance</Typography>
              </Box>
              <Divider sx={{ mb: 2 }} />
              
              <FormControlLabel
                control={
                  <Switch
                    checked={settings.darkMode}
                    onChange={(e) => handleChange('darkMode', e.target.checked)}
                  />
                }
                label="Dark Mode"
              />
              
              <FormControlLabel
                control={
                  <Switch
                    checked={settings.highContrast}
                    onChange={(e) => handleChange('highContrast', e.target.checked)}
                  />
                }
                label="High Contrast Mode"
              />
            </CardContent>
          </Card>
        </Grid>

        {/* Notifications */}
        <Grid item xs={12} md={6}>
          <Card>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
                <Notifications sx={{ mr: 1, color: 'primary.main' }} />
                <Typography variant="h6">Notifications</Typography>
              </Box>
              <Divider sx={{ mb: 2 }} />
              
              <FormControlLabel
                control={
                  <Switch
                    checked={settings.notifications}
                    onChange={(e) => handleChange('notifications', e.target.checked)}
                  />
                }
                label="Enable Notifications"
              />
              
              <FormControlLabel
                control={
                  <Switch
                    checked={settings.threatAlerts}
                    onChange={(e) => handleChange('threatAlerts', e.target.checked)}
                  />
                }
                label="Threat Alerts"
              />
              
              <FormControlLabel
                control={
                  <Switch
                    checked={settings.defenseAlerts}
                    onChange={(e) => handleChange('defenseAlerts', e.target.checked)}
                  />
                }
                label="Defense Action Alerts"
              />
            </CardContent>
          </Card>
        </Grid>

        {/* Data & Refresh */}
        <Grid item xs={12} md={6}>
          <Card>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
                <Refresh sx={{ mr: 1, color: 'primary.main' }} />
                <Typography variant="h6">Data & Refresh</Typography>
              </Box>
              <Divider sx={{ mb: 2 }} />
              
              <FormControlLabel
                control={
                  <Switch
                    checked={settings.autoRefresh}
                    onChange={(e) => handleChange('autoRefresh', e.target.checked)}
                  />
                }
                label="Auto-refresh Dashboard"
              />
              
              <Box sx={{ mt: 2 }}>
                <Typography gutterBottom>Refresh Interval (seconds)</Typography>
                <Slider
                  value={settings.refreshInterval}
                  onChange={(_, val) => handleChange('refreshInterval', val)}
                  min={10}
                  max={120}
                  step={5}
                  marks
                  valueLabelDisplay="auto"
                  disabled={!settings.autoRefresh}
                />
              </Box>
              
              <FormControl fullWidth sx={{ mt: 2 }}>
                <InputLabel>Default Time Range</InputLabel>
                <Select
                  value={settings.defaultTimeRange}
                  label="Default Time Range"
                  onChange={(e) => handleChange('defaultTimeRange', e.target.value)}
                >
                  <MenuItem value="1h">Last Hour</MenuItem>
                  <MenuItem value="24h">Last 24 Hours</MenuItem>
                  <MenuItem value="7d">Last 7 Days</MenuItem>
                  <MenuItem value="30d">Last 30 Days</MenuItem>
                </Select>
              </FormControl>
              
              <TextField
                fullWidth
                type="number"
                label="Data Retention (days)"
                value={settings.dataRetentionDays}
                onChange={(e) => handleChange('dataRetentionDays', parseInt(e.target.value))}
                sx={{ mt: 2 }}
              />
            </CardContent>
          </Card>
        </Grid>

        {/* Security & AI */}
        <Grid item xs={12} md={6}>
          <Card>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
                <Security sx={{ mr: 1, color: 'primary.main' }} />
                <Typography variant="h6">Security & AI</Typography>
              </Box>
              <Divider sx={{ mb: 2 }} />
              
              <Typography gutterBottom>Threat Detection Sensitivity</Typography>
              <Slider
                value={settings.threatSensitivity}
                onChange={(_, val) => handleChange('threatSensitivity', val)}
                min={0}
                max={1}
                step={0.1}
                marks={[
                  { value: 0, label: 'Low' },
                  { value: 0.5, label: 'Medium' },
                  { value: 1, label: 'High' },
                ]}
                valueLabelDisplay="auto"
              />
              
              <Box sx={{ mt: 3 }}>
                <Typography variant="subtitle2" gutterBottom>
                  Post-Quantum Cryptography
                </Typography>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
                  <Chip 
                    label="Kyber1024" 
                    color="primary" 
                    size="small" 
                    icon={<Key />}
                  />
                  <Chip 
                    label="Dilithium5" 
                    color="secondary" 
                    size="small" 
                    icon={<Security />}
                  />
                  <Chip 
                    label="AES-256-GCM" 
                    color="success" 
                    size="small" 
                  />
                </Box>
                
                <Button
                  variant="outlined"
                  size="small"
                  onClick={handleRunBenchmark}
                  sx={{ mt: 2 }}
                  startIcon={<Speed />}
                >
                  Run Crypto Benchmark
                </Button>
                
                {cryptoBenchmark && (
                  <Alert severity="info" sx={{ mt: 2 }}>
                    Key Generation: {cryptoBenchmark.benchmark?.key_generation?.mean?.toFixed(2)}ms
                    <br />
                    Encryption: {cryptoBenchmark.benchmark?.encryption?.mean?.toFixed(2)}ms
                  </Alert>
                )}
              </Box>
            </CardContent>
          </Card>
        </Grid>

        {/* Save Button */}
        <Grid item xs={12}>
          <Box sx={{ display: 'flex', justifyContent: 'flex-end', gap: 2 }}>
            <Button variant="outlined" onClick={() => window.location.reload()}>
              Cancel
            </Button>
            <Button 
              variant="contained" 
              onClick={handleSave}
              startIcon={<Save />}
              disabled={saveSettings.isLoading}
            >
              {saveSettings.isLoading ? 'Saving...' : 'Save Settings'}
            </Button>
          </Box>
        </Grid>
      </Grid>
    </Box>
  );
};

export default Settings;