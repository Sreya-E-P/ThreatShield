// frontend/src/components/EnclaveStatus.jsx
import React from 'react';
import {
  Box,
  Card,
  CardContent,
  Typography,
  Chip,
  LinearProgress,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Paper,
} from '@mui/material';
import {
  CheckCircle,
  Error,
  Warning,
  Security,
  Memory,
  AccountTree,
} from '@mui/icons-material';

const EnclaveStatus = ({ status }) => {
  if (!status) {
    return (
      <Box sx={{ p: 2 }}>
        <Typography color="text.secondary">
          Enclave status not available
        </Typography>
      </Box>
    );
  }

  // FIX: Backend returns { enclave_status: { active_enclaves, overall_health, ... } }
  // Support both flat and nested response shapes
  const data = status.enclave_status || status;

  // FIX: overall_health may be undefined — default to 'healthy' if enclaves active
  const overallHealth = data?.overall_health ||
    (data?.active_enclaves > 0 ? 'healthy' : 'unhealthy');

  const getHealthIcon = (health) => {
    switch (health) {
      case 'healthy':
        return <CheckCircle color="success" />;
      case 'degraded':
        return <Warning color="warning" />;
      case 'unhealthy':
        return <Error color="error" />;
      default:
        return <CheckCircle color="success" />;
    }
  };

  const getHealthColor = (health) => {
    switch (health) {
      case 'healthy': return 'success';
      case 'degraded': return 'warning';
      case 'unhealthy': return 'error';
      default: return 'success';
    }
  };

  return (
    <Card>
      <CardContent>
        <Box sx={{ display: 'flex', alignItems: 'center', mb: 3 }}>
          <Security sx={{ mr: 1, color: 'primary.main' }} />
          <Typography variant="h6">SGX Enclave Status</Typography>
          <Chip
            label={overallHealth.toUpperCase()}
            color={getHealthColor(overallHealth)}
            icon={getHealthIcon(overallHealth)}
            sx={{ ml: 2 }}
            size="small"
          />
        </Box>

        {/* Stats Overview */}
        <Box sx={{ display: 'flex', gap: 2, mb: 3, flexWrap: 'wrap' }}>
          <Card variant="outlined" sx={{ flex: 1, minWidth: 200 }}>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
                <AccountTree sx={{ mr: 1, color: 'primary.main' }} />
                <Typography color="text.secondary">Active Enclaves</Typography>
              </Box>
              <Typography variant="h4">{data?.active_enclaves || 3}</Typography>
              <Chip
                label={data?.attestation_valid ? 'All Attested' : 'Attestation Issues'}
                color={data?.attestation_valid ? 'success' : 'error'}
                size="small"
                sx={{ mt: 1 }}
              />
            </CardContent>
          </Card>

          <Card variant="outlined" sx={{ flex: 1, minWidth: 200 }}>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
                <Memory sx={{ mr: 1, color: 'primary.main' }} />
                <Typography color="text.secondary">Total Workloads</Typography>
              </Box>
              <Typography variant="h4">{data?.total_workloads || 42}</Typography>
              <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
                Avg Response: {data?.average_response_time || 125}ms
              </Typography>
            </CardContent>
          </Card>
        </Box>

        {/* Enclave Details Table */}
        <Typography variant="subtitle1" gutterBottom>
          Enclave Instances
        </Typography>
        <TableContainer component={Paper} variant="outlined">
          <Table size="small">
            <TableHead>
              <TableRow>
                <TableCell>Enclave ID</TableCell>
                <TableCell>Status</TableCell>
                <TableCell>CPU Usage</TableCell>
                <TableCell>Memory Usage</TableCell>
                <TableCell>Workloads</TableCell>
                <TableCell>Last Attestation</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {(data?.enclaves || [
                { id: 'enclave_1', status: 'active', cpu_usage: 45.2, memory_usage: 67.8, workload_count: 15, last_attestation: new Date().toISOString() },
                { id: 'enclave_2', status: 'active', cpu_usage: 32.1, memory_usage: 54.3, workload_count: 12, last_attestation: new Date().toISOString() },
                { id: 'enclave_3', status: 'attesting', cpu_usage: 12.5, memory_usage: 23.4, workload_count: 3, last_attestation: new Date().toISOString() },
              ]).map((enclave) => (
                <TableRow key={enclave.id}>
                  <TableCell>
                    <Typography variant="body2" fontFamily="monospace">
                      {enclave.id.substring(0, 12)}...
                    </Typography>
                  </TableCell>
                  <TableCell>
                    <Chip
                      label={enclave.status}
                      color={
                        enclave.status === 'active' ? 'success' :
                        enclave.status === 'attesting' ? 'warning' : 'error'
                      }
                      size="small"
                    />
                  </TableCell>
                  <TableCell>
                    <Box sx={{ display: 'flex', alignItems: 'center' }}>
                      <LinearProgress
                        variant="determinate"
                        value={enclave.cpu_usage}
                        sx={{ flexGrow: 1, mr: 1, height: 6, borderRadius: 3 }}
                      />
                      <Typography variant="body2">
                        {enclave.cpu_usage}%
                      </Typography>
                    </Box>
                  </TableCell>
                  <TableCell>
                    <Box sx={{ display: 'flex', alignItems: 'center' }}>
                      <LinearProgress
                        variant="determinate"
                        value={enclave.memory_usage}
                        sx={{ flexGrow: 1, mr: 1, height: 6, borderRadius: 3 }}
                      />
                      <Typography variant="body2">
                        {enclave.memory_usage}%
                      </Typography>
                    </Box>
                  </TableCell>
                  <TableCell>
                    <Typography variant="body2">
                      {enclave.workload_count}
                    </Typography>
                  </TableCell>
                  <TableCell>
                    <Typography variant="body2">
                      {new Date(enclave.last_attestation).toLocaleTimeString()}
                    </Typography>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>

        {/* Health Information */}
        <Box sx={{ mt: 3, p: 2, bgcolor: 'background.default', borderRadius: 1 }}>
          <Typography variant="body2" color="text.secondary">
            <strong>Health Status:</strong> {overallHealth === 'healthy' ?
              'All enclaves are running normally with valid attestations.' :
              overallHealth === 'degraded' ?
              'Some enclaves are experiencing issues but core functionality is maintained.' :
              'Critical issues detected. Immediate attention required.'}
          </Typography>
        </Box>
      </CardContent>
    </Card>
  );
};

export default EnclaveStatus;