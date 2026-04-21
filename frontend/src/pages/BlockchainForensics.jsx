// frontend/src/pages/BlockchainForensics.jsx
import React, { useState } from 'react';
import {
  Box,
  Card,
  CardContent,
  Typography,
  TextField,
  Button,
  Grid,
  Chip,
  Alert,
  LinearProgress,
  Paper,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  IconButton,
} from '@mui/material';
import {
  Search,
  AccountBalanceWallet,
  Warning,
  CheckCircle,
  ContentCopy,
  OpenInNew,
} from '@mui/icons-material';
import { useQuery, useMutation } from '@tanstack/react-query';

import apiService from '../services/api';

const BlockchainForensics = () => {
  const [address, setAddress] = useState('');
  const [txHash, setTxHash] = useState('');
  const [searchType, setSearchType] = useState('address');

  const { data: walletData, isLoading: walletLoading, error: walletError, refetch: fetchWallet } = useQuery({
    queryKey: ['wallet', address],
    queryFn: () => apiService.investigateWallet(address, 2),
    enabled: false,
  });

  const { data: txData, isLoading: txLoading, error: txError, refetch: fetchTx } = useQuery({
    queryKey: ['transaction', txHash],
    queryFn: () => apiService.analyzeTransaction(txHash, 'ethereum'),
    enabled: false,
  });

  const handleSearch = () => {
    if (searchType === 'address' && address) {
      fetchWallet();
    } else if (searchType === 'transaction' && txHash) {
      fetchTx();
    }
  };

  const copyToClipboard = (text) => {
    navigator.clipboard.writeText(text);
  };

  const openInExplorer = (hash, type = 'tx') => {
    window.open(`https://etherscan.io/${type}/${hash}`, '_blank');
  };

  const isLoading = walletLoading || txLoading;
  const error = walletError || txError;
  const data = walletData || txData;

  return (
    <Box sx={{ p: 3, bgcolor: 'background.default', minHeight: '100vh' }}>
      <Typography variant="h4" gutterBottom sx={{ fontWeight: 'bold', mb: 3 }}>
        🔗 Blockchain Forensics
      </Typography>

      {/* Search Section */}
      <Card sx={{ mb: 3 }}>
        <CardContent>
          <Typography variant="h6" gutterBottom>
            Blockchain Investigation
          </Typography>
          
          <Box sx={{ display: 'flex', gap: 2, mb: 3 }}>
            <Button
              variant={searchType === 'address' ? 'contained' : 'outlined'}
              onClick={() => setSearchType('address')}
              startIcon={<AccountBalanceWallet />}
            >
              Wallet Address
            </Button>
            <Button
              variant={searchType === 'transaction' ? 'contained' : 'outlined'}
              onClick={() => setSearchType('transaction')}
              startIcon={<Search />}
            >
              Transaction Hash
            </Button>
          </Box>

          <Box sx={{ display: 'flex', gap: 2 }}>
            <TextField
              fullWidth
              placeholder={
                searchType === 'address' 
                  ? 'Enter wallet address (0x...)' 
                  : 'Enter transaction hash (0x...)'
              }
              value={searchType === 'address' ? address : txHash}
              onChange={(e) => {
                if (searchType === 'address') setAddress(e.target.value);
                else setTxHash(e.target.value);
              }}
              variant="outlined"
              InputProps={{
                startAdornment: <Search sx={{ mr: 1, color: 'action.active' }} />,
              }}
            />
            <Button
              variant="contained"
              onClick={handleSearch}
              disabled={isLoading || (!address && !txHash)}
              size="large"
            >
              {isLoading ? 'Analyzing...' : 'Analyze'}
            </Button>
          </Box>
        </CardContent>
      </Card>

      {isLoading && (
        <Box sx={{ mb: 3 }}>
          <LinearProgress />
          <Typography sx={{ mt: 1, textAlign: 'center' }}>
            Analyzing blockchain data...
          </Typography>
        </Box>
      )}

      {error && (
        <Alert severity="error" sx={{ mb: 3 }}>
          {error.message}
        </Alert>
      )}

      {/* Results */}
      {data && !isLoading && (
        <>
          {/* Wallet Analysis */}
          {walletData && (
            <Card sx={{ mb: 3 }}>
              <CardContent>
                <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
                  <Typography variant="h6">
                    Wallet Analysis
                  </Typography>
                  <Box sx={{ display: 'flex', gap: 1 }}>
                    <IconButton onClick={() => copyToClipboard(address)} size="small">
                      <ContentCopy fontSize="small" />
                    </IconButton>
                    <IconButton onClick={() => openInExplorer(address, 'address')} size="small">
                      <OpenInNew fontSize="small" />
                    </IconButton>
                  </Box>
                </Box>

                <Typography variant="body2" fontFamily="monospace" sx={{ mb: 2, wordBreak: 'break-all' }}>
                  {address}
                </Typography>

                <Grid container spacing={2}>
                  <Grid item xs={12} md={4}>
                    <Card variant="outlined">
                      <CardContent>
                        <Typography color="text.secondary" gutterBottom>
                          Risk Score
                        </Typography>
                        <Typography variant="h3" color={walletData.risk_score > 70 ? 'error' : walletData.risk_score > 40 ? 'warning' : 'success'}>
                          {Math.round(walletData.risk_score || 0)}%
                        </Typography>
                        <Chip
                          label={walletData.risk_level || 'MEDIUM'}
                          color={walletData.risk_level === 'HIGH' ? 'error' : walletData.risk_level === 'MEDIUM' ? 'warning' : 'success'}
                          sx={{ mt: 1 }}
                        />
                      </CardContent>
                    </Card>
                  </Grid>

                  <Grid item xs={12} md={8}>
                    <Card variant="outlined">
                      <CardContent>
                        <Typography color="text.secondary" gutterBottom>
                          Findings
                        </Typography>
                        {walletData.findings?.map((finding, index) => (
                          <Alert
                            key={index}
                            severity={finding.severity === 'high' ? 'error' : finding.severity === 'medium' ? 'warning' : 'info'}
                            sx={{ mb: 1 }}
                            icon={finding.severity === 'high' ? <Warning /> : <CheckCircle />}
                          >
                            {finding.description}
                          </Alert>
                        ))}
                      </CardContent>
                    </Card>
                  </Grid>
                </Grid>
              </CardContent>
            </Card>
          )}

          {/* Transaction Analysis */}
          {txData && (
            <Card sx={{ mb: 3 }}>
              <CardContent>
                <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
                  <Typography variant="h6">
                    Transaction Analysis
                  </Typography>
                  <Box sx={{ display: 'flex', gap: 1 }}>
                    <IconButton onClick={() => copyToClipboard(txHash)} size="small">
                      <ContentCopy fontSize="small" />
                    </IconButton>
                    <IconButton onClick={() => openInExplorer(txHash)} size="small">
                      <OpenInNew fontSize="small" />
                    </IconButton>
                  </Box>
                </Box>

                <Grid container spacing={2}>
                  <Grid item xs={12} md={6}>
                    <Card variant="outlined">
                      <CardContent>
                        <Typography color="text.secondary" gutterBottom>
                          Transaction Details
                        </Typography>
                        <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1 }}>
                          <Typography variant="body2">
                            <strong>From:</strong> {txData.transaction.from.substring(0, 8)}...{txData.transaction.from.substring(txData.transaction.from.length - 6)}
                          </Typography>
                          <Typography variant="body2">
                            <strong>To:</strong> {txData.transaction.to?.substring(0, 8)}...{txData.transaction.to?.substring(txData.transaction.to.length - 6) || 'Contract Creation'}
                          </Typography>
                          <Typography variant="body2">
                            <strong>Value:</strong> {txData.transaction.value} ETH
                          </Typography>
                          <Typography variant="body2">
                            <strong>Chain:</strong> {txData.transaction.chain}
                          </Typography>
                        </Box>
                      </CardContent>
                    </Card>
                  </Grid>

                  <Grid item xs={12} md={6}>
                    <Card variant="outlined">
                      <CardContent>
                        <Typography color="text.secondary" gutterBottom>
                          Risk Assessment
                        </Typography>
                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, mb: 2 }}>
                          <Typography variant="h3" color={txData.analysis.risk_assessment.score > 70 ? 'error' : txData.analysis.risk_assessment.score > 40 ? 'warning' : 'success'}>
                            {Math.round(txData.analysis.risk_assessment.score)}%
                          </Typography>
                          <Chip
                            label={txData.analysis.risk_assessment.level}
                            color={txData.analysis.risk_assessment.level === 'HIGH' ? 'error' : txData.analysis.risk_assessment.level === 'MEDIUM' ? 'warning' : 'success'}
                            size="large"
                          />
                        </Box>
                        <Typography variant="body2">
                          Anomaly Score: {Math.round(txData.analysis.anomaly_score * 100)}%
                        </Typography>
                      </CardContent>
                    </Card>
                  </Grid>
                </Grid>

                {/* Suspicious Patterns */}
                {txData.analysis.suspicious_patterns?.length > 0 && (
                  <Box sx={{ mt: 3 }}>
                    <Typography variant="h6" gutterBottom>
                      Suspicious Patterns Detected
                    </Typography>
                    <TableContainer component={Paper} variant="outlined">
                      <Table size="small">
                        <TableHead>
                          <TableRow>
                            <TableCell>Pattern</TableCell>
                            <TableCell>Confidence</TableCell>
                            <TableCell>Description</TableCell>
                          </TableRow>
                        </TableHead>
                        <TableBody>
                          {txData.analysis.suspicious_patterns.map((pattern, index) => (
                            <TableRow key={index}>
                              <TableCell>
                                <Chip label={pattern.pattern} color="warning" size="small" />
                              </TableCell>
                              <TableCell>
                                {Math.round(pattern.confidence * 100)}%
                              </TableCell>
                              <TableCell>
                                {pattern.description}
                              </TableCell>
                            </TableRow>
                          ))}
                        </TableBody>
                      </Table>
                    </TableContainer>
                  </Box>
                )}
              </CardContent>
            </Card>
          )}
        </>
      )}

      {/* Recent Investigations */}
      <Card>
        <CardContent>
          <Typography variant="h6" gutterBottom>
            Recent Investigations
          </Typography>
          <TableContainer component={Paper} variant="outlined">
            <Table size="small">
              <TableHead>
                <TableRow>
                  <TableCell>Type</TableCell>
                  <TableCell>Address/Hash</TableCell>
                  <TableCell>Risk Level</TableCell>
                  <TableCell>Time</TableCell>
                  <TableCell>Actions</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                <TableRow>
                  <TableCell>
                    <Chip label="Wallet" color="primary" size="small" />
                  </TableCell>
                  <TableCell sx={{ fontFamily: 'monospace' }}>
                    0x742d35Cc6634C053...
                  </TableCell>
                  <TableCell>
                    <Chip label="MEDIUM" color="warning" size="small" />
                  </TableCell>
                  <TableCell>
                    2 hours ago
                  </TableCell>
                  <TableCell>
                    <Button size="small">View</Button>
                  </TableCell>
                </TableRow>
                <TableRow>
                  <TableCell>
                    <Chip label="Transaction" color="secondary" size="small" />
                  </TableCell>
                  <TableCell sx={{ fontFamily: 'monospace' }}>
                    0x89ea5cd5a5e5a5e5...
                  </TableCell>
                  <TableCell>
                    <Chip label="HIGH" color="error" size="small" />
                  </TableCell>
                  <TableCell>
                    5 hours ago
                  </TableCell>
                  <TableCell>
                    <Button size="small">View</Button>
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

export default BlockchainForensics;