// frontend/src/pages/ConfidentialCompute.jsx
import React, { useState } from 'react';
import {
  Box,
  Card,
  CardContent,
  Typography,
  Grid,
  Chip,
  Button,
  TextField,
  LinearProgress,
  Alert,
  Paper,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  IconButton,
  Switch,
  FormControlLabel,
} from '@mui/material';
import {
  Security,
  Memory,
  AccountTree,
  CheckCircle,
  Error,
  Warning,
  PlayArrow,
  Stop,
  Refresh,
  CloudUpload,
} from '@mui/icons-material';
import { useQuery, useMutation } from '@tanstack/react-query';

import apiService from '../services/api';
import EnclaveStatus from '../components/EnclaveStatus';

const ConfidentialCompute = () => {
  const [inputData, setInputData] = useState('[0.1, 0.2, 0.3, 0.4, 0.5]');
  const [modelId, setModelId] = useState('zero_day_predictor');
  const [useEnclave, setUseEnclave] = useState(true);

  const { data: enclaveStatus, isLoading: statusLoading, refetch: refetchStatus } = useQuery({
    queryKey: ['enclaveStatus'],
    queryFn: () => apiService.getEnclaveStatus(),
  });

  const inferenceMutation = useMutation({
    mutationFn: (data) => apiService.secureInference(data.inputData, data.modelId),
    onSuccess: () => {
      refetchStatus();
    },
  });

  const handleRunInference = () => {
    try {
      const parsedData = JSON.parse(inputData);
      inferenceMutation.mutate({ inputData: parsedData, modelId });
    } catch (error) {
      alert('Invalid input data. Please enter a valid JSON array.');
    }
  };

  return (
    <Box sx={{ p: 3, bgcolor: 'background.default', minHeight: '100vh' }}>
      <Typography variant="h4" gutterBottom sx={{ fontWeight: 'bold', mb: 3 }}>
        🔒 Confidential Compute
      </Typography>

      {/* SGX Enclave Status */}
      <Card sx={{ mb: 3 }}>
        <CardContent>
          <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
            <Security sx={{ mr: 1, color: 'primary.main' }} />
            <Typography variant="h6">Intel SGX Enclave Status</Typography>
            <IconButton onClick={() => refetchStatus()} sx={{ ml: 'auto' }}>
              <Refresh />
            </IconButton>
          </Box>
          <EnclaveStatus status={enclaveStatus} />
        </CardContent>
      </Card>

      {/* Secure Inference */}
      <Grid container spacing={3}>
        <Grid item xs={12} md={6}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Secure Inference
              </Typography>
              
              <FormControlLabel
                control={
                  <Switch
                    checked={useEnclave}
                    onChange={(e) => setUseEnclave(e.target.checked)}
                    color="primary"
                  />
                }
                label="Use SGX Enclave"
                sx={{ mb: 2 }}
              />

              <TextField
                fullWidth
                label="Input Data (JSON array)"
                value={inputData}
                onChange={(e) => setInputData(e.target.value)}
                multiline
                rows={4}
                variant="outlined"
                sx={{ mb: 2 }}
                helperText="Enter numerical data as JSON array, e.g., [0.1, 0.2, 0.3]"
              />

              <TextField
                fullWidth
                label="Model ID"
                value={modelId}
                onChange={(e) => setModelId(e.target.value)}
                variant="outlined"
                sx={{ mb: 2 }}
                select
                SelectProps={{
                  native: true,
                }}
              >
                <option value="zero_day_predictor">Zero-Day Predictor</option>
                <option value="threat_classifier">Threat Classifier</option>
                <option value="anomaly_detector">Anomaly Detector</option>
              </TextField>

              <Button
                fullWidth
                variant="contained"
                startIcon={<PlayArrow />}
                onClick={handleRunInference}
                disabled={inferenceMutation.isLoading || !enclaveStatus?.attestation_valid}
                size="large"
              >
                {inferenceMutation.isLoading ? 'Running Inference...' : 'Run Secure Inference'}
              </Button>

              {!enclaveStatus?.attestation_valid && (
                <Alert severity="warning" sx={{ mt: 2 }}>
                  Enclave attestation invalid. Cannot run secure inference.
                </Alert>
              )}
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} md={6}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Inference Results
              </Typography>
              
              {inferenceMutation.isLoading && (
                <Box sx={{ textAlign: 'center', py: 4 }}>
                  <LinearProgress sx={{ mb: 2 }} />
                  <Typography color="text.secondary">
                    Running secure inference in enclave...
                  </Typography>
                </Box>
              )}

              {inferenceMutation.error && (
                <Alert severity="error" sx={{ mb: 2 }}>
                  Inference failed: {inferenceMutation.error.message}
                </Alert>
              )}

              {inferenceMutation.data && (
                <>
                  <Alert 
                    severity={inferenceMutation.data.success ? 'success' : 'error'} 
                    sx={{ mb: 2 }}
                    icon={inferenceMutation.data.success ? <CheckCircle /> : <Error />}
                  >
                    {inferenceMutation.data.success ? 'Inference successful' : 'Inference failed'}
                  </Alert>

                  <Card variant="outlined" sx={{ mb: 2 }}>
                    <CardContent>
                      <Typography color="text.secondary" gutterBottom>
                        Results
                      </Typography>
                      <Box sx={{ fontFamily: 'monospace', fontSize: '0.875rem' }}>
                        {JSON.stringify(inferenceMutation.data.result, null, 2)}
                      </Box>
                    </CardContent>
                  </Card>

                  <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
                    <Chip
                      label={`Enclave: ${inferenceMutation.data.instance_id?.substring(0, 8)}...`}
                      color="primary"
                      variant="outlined"
                      size="small"
                    />
                    <Chip
                      label={`Attestation: ${inferenceMutation.data.attestation_valid ? 'Valid' : 'Invalid'}`}
                      color={inferenceMutation.data.attestation_valid ? 'success' : 'error'}
                      size="small"
                    />
                  </Box>
                </>
              )}
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Enclave Workloads */}
      <Card sx={{ mt: 3 }}>
        <CardContent>
          <Typography variant="h6" gutterBottom>
            Active Workloads
          </Typography>
          
          <TableContainer component={Paper} variant="outlined">
            <Table size="small">
              <TableHead>
                <TableRow>
                  <TableCell>Workload ID</TableCell>
                  <TableCell>Type</TableCell>
                  <TableCell>Enclave</TableCell>
                  <TableCell>Status</TableCell>
                  <TableCell>Started</TableCell>
                  <TableCell>Duration</TableCell>
                  <TableCell>Actions</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                <TableRow>
                  <TableCell sx={{ fontFamily: 'monospace' }}>
                    wl_7a3b9c
                  </TableCell>
                  <TableCell>
                    <Chip label="Inference" color="primary" size="small" />
                  </TableCell>
                  <TableCell sx={{ fontFamily: 'monospace' }}>
                    encl_abc123
                  </TableCell>
                  <TableCell>
                    <Chip label="Running" color="success" size="small" icon={<CheckCircle />} />
                  </TableCell>
                  <TableCell>
                    10:30 AM
                  </TableCell>
                  <TableCell>
                    2m 15s
                  </TableCell>
                  <TableCell>
                    <Button size="small" startIcon={<Stop />}>
                      Stop
                    </Button>
                  </TableCell>
                </TableRow>
                <TableRow>
                  <TableCell sx={{ fontFamily: 'monospace' }}>
                    wl_4d5e6f
                  </TableCell>
                  <TableCell>
                    <Chip label="Training" color="secondary" size="small" />
                  </TableCell>
                  <TableCell sx={{ fontFamily: 'monospace' }}>
                    encl_def456
                  </TableCell>
                  <TableCell>
                    <Chip label="Completed" color="info" size="small" />
                  </TableCell>
                  <TableCell>
                    9:15 AM
                  </TableCell>
                  <TableCell>
                    15m 30s
                  </TableCell>
                  <TableCell>
                    <Button size="small">View Logs</Button>
                  </TableCell>
                </TableRow>
              </TableBody>
            </Table>
          </TableContainer>
        </CardContent>
      </Card>
    </Box>
  );
};

export default ConfidentialCompute;