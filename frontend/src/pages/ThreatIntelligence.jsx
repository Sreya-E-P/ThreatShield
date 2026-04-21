// frontend/src/pages/ThreatIntelligence.jsx
import React, { useState } from 'react';
import {
  Box,
  Card,
  CardContent,
  Typography,
  Chip,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Paper,
  IconButton,
  Button,
  TextField,
  MenuItem,
  Select,
  FormControl,
  InputLabel,
  Alert,
  LinearProgress,
} from '@mui/material';
import {
  Search,
  FilterList,
  Download,
  Warning,
  Error,
  CheckCircle,
  Info,
  ArrowUpward,
  ArrowDownward,
} from '@mui/icons-material';
import { useQuery } from '@tanstack/react-query';
import { format } from 'date-fns';

import apiService from '../services/api';

const ThreatIntelligence = () => {
  const [search, setSearch] = useState('');
  const [severityFilter, setSeverityFilter] = useState('all');
  const [sourceFilter, setSourceFilter] = useState('all');
  const [sortField, setSortField] = useState('timestamp');
  const [sortDirection, setSortDirection] = useState('desc');

  const { data: threatsData, isLoading, error } = useQuery({
    queryKey: ['threats', 'all'],
    queryFn: () => apiService.getThreats('24h', undefined, 1000),
  });

  const handleSort = (field) => {
    if (sortField === field) {
      setSortDirection(sortDirection === 'asc' ? 'desc' : 'asc');
    } else {
      setSortField(field);
      setSortDirection('desc');
    }
  };

  const getSeverityColor = (severity) => {
    switch (severity) {
      case 'critical': return 'error';
      case 'high': return 'warning';
      case 'medium': return 'info';
      case 'low': return 'success';
      default: return 'default';
    }
  };

  const getSourceColor = (source) => {
    switch (source) {
      case 'misp': return 'primary';
      case 'virustotal': return 'secondary';
      case 'alienvault': return 'info';
      case 'internal': return 'success';
      default: return 'default';
    }
  };

  const filteredThreats = threatsData?.threats
    .filter(threat => 
      (severityFilter === 'all' || threat.severity === severityFilter) &&
      (sourceFilter === 'all' || threat.source === sourceFilter) &&
      (search === '' || 
        threat.title.toLowerCase().includes(search.toLowerCase()) ||
        threat.description.toLowerCase().includes(search.toLowerCase()) ||
        threat.type.toLowerCase().includes(search.toLowerCase()))
    )
    .sort((a, b) => {
      const aValue = a[sortField];
      const bValue = b[sortField];
      
      if (sortDirection === 'asc') {
        return aValue > bValue ? 1 : -1;
      } else {
        return aValue < bValue ? 1 : -1;
      }
    });

  if (isLoading) {
    return (
      <Box sx={{ p: 3 }}>
        <LinearProgress />
        <Typography sx={{ mt: 2 }}>Loading threat intelligence...</Typography>
      </Box>
    );
  }

  if (error) {
    return (
      <Box sx={{ p: 3 }}>
        <Alert severity="error">
          Failed to load threats: {error.message}
        </Alert>
      </Box>
    );
  }

  return (
    <Box sx={{ p: 3, bgcolor: 'background.default', minHeight: '100vh' }}>
      <Typography variant="h4" gutterBottom sx={{ fontWeight: 'bold', mb: 3 }}>
        🎯 Threat Intelligence
      </Typography>

      {/* Stats Overview */}
      <Box sx={{ display: 'flex', gap: 2, mb: 3, flexWrap: 'wrap' }}>
        <Card sx={{ flex: 1, minWidth: 200 }}>
          <CardContent>
            <Typography color="text.secondary" gutterBottom>
              Total Threats
            </Typography>
            <Typography variant="h4">
              {threatsData?.count || 0}
            </Typography>
            <Box sx={{ display: 'flex', gap: 1, mt: 1 }}>
              <Chip label="Last 24h" size="small" variant="outlined" />
            </Box>
          </CardContent>
        </Card>

        <Card sx={{ flex: 1, minWidth: 200 }}>
          <CardContent>
            <Typography color="text.secondary" gutterBottom>
              Critical Threats
            </Typography>
            <Typography variant="h4" color="error.main">
              {threatsData?.threats.filter(t => t.severity === 'critical').length || 0}
            </Typography>
            <Box sx={{ display: 'flex', gap: 1, mt: 1 }}>
              <Chip label="Immediate Action" size="small" color="error" />
            </Box>
          </CardContent>
        </Card>

        <Card sx={{ flex: 1, minWidth: 200 }}>
          <CardContent>
            <Typography color="text.secondary" gutterBottom>
              Sources
            </Typography>
            <Typography variant="h4">
              {new Set(threatsData?.threats.map(t => t.source)).size || 0}
            </Typography>
            <Box sx={{ display: 'flex', gap: 1, mt: 1 }}>
              <Chip label="Active Feeds" size="small" color="success" />
            </Box>
          </CardContent>
        </Card>
      </Box>

      {/* Filters */}
      <Card sx={{ mb: 3 }}>
        <CardContent>
          <Box sx={{ display: 'flex', gap: 2, flexWrap: 'wrap' }}>
            <TextField
              placeholder="Search threats..."
              variant="outlined"
              size="small"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              InputProps={{
                startAdornment: <Search sx={{ mr: 1, color: 'action.active' }} />,
              }}
              sx={{ flexGrow: 1, minWidth: 200 }}
            />
            
            <FormControl size="small" sx={{ minWidth: 120 }}>
              <InputLabel>Severity</InputLabel>
              <Select
                value={severityFilter}
                label="Severity"
                onChange={(e) => setSeverityFilter(e.target.value)}
              >
                <MenuItem value="all">All Severities</MenuItem>
                <MenuItem value="critical">Critical</MenuItem>
                <MenuItem value="high">High</MenuItem>
                <MenuItem value="medium">Medium</MenuItem>
                <MenuItem value="low">Low</MenuItem>
              </Select>
            </FormControl>

            <FormControl size="small" sx={{ minWidth: 120 }}>
              <InputLabel>Source</InputLabel>
              <Select
                value={sourceFilter}
                label="Source"
                onChange={(e) => setSourceFilter(e.target.value)}
              >
                <MenuItem value="all">All Sources</MenuItem>
                <MenuItem value="misp">MISP</MenuItem>
                <MenuItem value="virustotal">VirusTotal</MenuItem>
                <MenuItem value="alienvault">AlienVault</MenuItem>
                <MenuItem value="internal">Internal</MenuItem>
              </Select>
            </FormControl>

            <Button
              startIcon={<Download />}
              variant="outlined"
              size="large"
            >
              Export
            </Button>
          </Box>
        </CardContent>
      </Card>

      {/* Threats Table */}
      <Card>
        <CardContent>
          <Typography variant="h6" gutterBottom>
            Threat Feed
          </Typography>
          
          <TableContainer component={Paper} variant="outlined">
            <Table size="small">
              <TableHead>
                <TableRow sx={{ bgcolor: 'action.hover' }}>
                  <TableCell>
                    <Button
                      size="small"
                      onClick={() => handleSort('title')}
                      endIcon={sortField === 'title' && (
                        sortDirection === 'asc' ? <ArrowUpward fontSize="small" /> : <ArrowDownward fontSize="small" />
                      )}
                    >
                      Title
                    </Button>
                  </TableCell>
                  <TableCell>
                    <Button
                      size="small"
                      onClick={() => handleSort('type')}
                      endIcon={sortField === 'type' && (
                        sortDirection === 'asc' ? <ArrowUpward fontSize="small" /> : <ArrowDownward fontSize="small" />
                      )}
                    >
                      Type
                    </Button>
                  </TableCell>
                  <TableCell>
                    <Button
                      size="small"
                      onClick={() => handleSort('severity')}
                      endIcon={sortField === 'severity' && (
                        sortDirection === 'asc' ? <ArrowUpward fontSize="small" /> : <ArrowDownward fontSize="small" />
                      )}
                    >
                      Severity
                    </Button>
                  </TableCell>
                  <TableCell>
                    <Button
                      size="small"
                      onClick={() => handleSort('source')}
                      endIcon={sortField === 'source' && (
                        sortDirection === 'asc' ? <ArrowUpward fontSize="small" /> : <ArrowDownward fontSize="small" />
                      )}
                    >
                      Source
                    </Button>
                  </TableCell>
                  <TableCell>
                    <Button
                      size="small"
                      onClick={() => handleSort('timestamp')}
                      endIcon={sortField === 'timestamp' && (
                        sortDirection === 'asc' ? <ArrowUpward fontSize="small" /> : <ArrowDownward fontSize="small" />
                      )}
                    >
                      Time
                    </Button>
                  </TableCell>
                  <TableCell>Risk Score</TableCell>
                  <TableCell>Actions</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {filteredThreats?.map((threat) => (
                  <TableRow key={threat.id} hover>
                    <TableCell>
                      <Typography variant="body2" fontWeight="medium">
                        {threat.title}
                      </Typography>
                      <Typography variant="caption" color="text.secondary">
                        {threat.description.substring(0, 50)}...
                      </Typography>
                    </TableCell>
                    <TableCell>
                      <Chip
                        label={threat.type}
                        size="small"
                        variant="outlined"
                      />
                    </TableCell>
                    <TableCell>
                      <Chip
                        label={threat.severity.toUpperCase()}
                        color={getSeverityColor(threat.severity)}
                        size="small"
                        icon={
                          threat.severity === 'critical' ? <Error /> :
                          threat.severity === 'high' ? <Warning /> :
                          threat.severity === 'medium' ? <Info /> :
                          <CheckCircle />
                        }
                      />
                    </TableCell>
                    <TableCell>
                      <Chip
                        label={threat.source}
                        color={getSourceColor(threat.source)}
                        size="small"
                        variant="outlined"
                      />
                    </TableCell>
                    <TableCell>
                      <Typography variant="body2">
                        {format(new Date(threat.timestamp), 'MM/dd HH:mm')}
                      </Typography>
                    </TableCell>
                    <TableCell>
                      <Box sx={{ display: 'flex', alignItems: 'center' }}>
                        <LinearProgress
                          variant="determinate"
                          value={threat.risk_score * 100}
                          sx={{
                            width: 60,
                            mr: 1,
                            height: 6,
                            borderRadius: 3,
                          }}
                        />
                        <Typography variant="body2">
                          {Math.round(threat.risk_score * 100)}%
                        </Typography>
                      </Box>
                    </TableCell>
                    <TableCell>
                      <Box sx={{ display: 'flex', gap: 0.5 }}>
                        <Button size="small" variant="outlined">
                          Analyze
                        </Button>
                        <Button size="small">
                          Details
                        </Button>
                      </Box>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>

          {(!filteredThreats || filteredThreats.length === 0) && (
            <Box sx={{ textAlign: 'center', py: 4 }}>
              <Typography color="text.secondary">
                No threats found matching your criteria
              </Typography>
            </Box>
          )}
        </CardContent>
      </Card>
    </Box>
  );
};

export default ThreatIntelligence;