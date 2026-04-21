import React from 'react';
import {
  Box,
  Paper,
  Typography,
  Grid,
  Chip,
  Tooltip,
} from '@mui/material';

const MITREMatrix = ({ threats = [] }) => {
  // MITRE ATT&CK Tactics
  const tactics = [
    'Reconnaissance',
    'Resource Development',
    'Initial Access',
    'Execution',
    'Persistence',
    'Privilege Escalation',
    'Defense Evasion',
    'Credential Access',
    'Discovery',
    'Lateral Movement',
    'Collection',
    'Command and Control',
    'Exfiltration',
    'Impact'
  ];

  // Techniques for each tactic (simplified)
  const techniques = {
    'Reconnaissance': ['Active Scanning', 'Gather Victim Info'],
    'Resource Development': ['Acquire Infrastructure', 'Develop Capabilities'],
    'Initial Access': ['Phishing', 'Exploit Public Apps'],
    'Execution': ['Command and Scripting', 'User Execution'],
    'Persistence': ['Account Manipulation', 'Boot/Logon Autostart'],
    'Privilege Escalation': ['Process Injection', 'Exploitation for Privilege'],
    'Defense Evasion': ['Impair Defenses', 'Obfuscation'],
    'Credential Access': ['Brute Force', 'Credentials in Files'],
    'Discovery': ['Network Service Discovery', 'System Info Discovery'],
    'Lateral Movement': ['Remote Services', 'Internal Spearphishing'],
    'Collection': ['Archive Collected Data', 'Screen Capture'],
    'Command and Control': ['Application Layer Protocol', 'Encrypted Channel'],
    'Exfiltration': ['Exfiltration Over C2', 'Transfer Data to Cloud'],
    'Impact': ['Data Encrypted for Impact', 'Service Stop']
  };

  // Count threats by tactic
  const threatCounts = tactics.reduce((acc, tactic) => {
    // Count threats mentioning this tactic
    const count = threats.filter(t => 
      t.description?.toLowerCase().includes(tactic.toLowerCase()) ||
      t.title?.toLowerCase().includes(tactic.toLowerCase()) ||
      t.type?.toLowerCase().includes(tactic.toLowerCase())
    ).length;
    
    acc[tactic] = count;
    return acc;
  }, {});

  // Calculate severity for each tactic
  const getTacticSeverity = (tactic) => {
    const count = threatCounts[tactic];
    if (count === 0) return 'low';
    if (count <= 2) return 'medium';
    if (count <= 5) return 'high';
    return 'critical';
  };

  const getSeverityColor = (severity) => {
    switch (severity) {
      case 'critical': return '#f44336';
      case 'high': return '#ff9800';
      case 'medium': return '#ffeb3b';
      case 'low': return '#4caf50';
      default: return '#9e9e9e';
    }
  };

  return (
    <Paper elevation={2} sx={{ p: 2, height: '100%' }}>
      <Typography variant="h6" gutterBottom>
        MITRE ATT&CK Matrix
      </Typography>
      
      <Grid container spacing={1}>
        {tactics.map((tactic, index) => {
          const severity = getTacticSeverity(tactic);
          const color = getSeverityColor(severity);
          const count = threatCounts[tactic];
          
          return (
            <Grid item xs={12} sm={6} md={3} key={tactic}>
              <Tooltip 
                title={
                  <Box>
                    <Typography variant="subtitle2">{tactic}</Typography>
                    <Typography variant="body2">Threats: {count}</Typography>
                    <Typography variant="body2">
                      Techniques: {techniques[tactic].join(', ')}
                    </Typography>
                  </Box>
                }
              >
                <Paper
                  elevation={1}
                  sx={{
                    p: 1.5,
                    height: '100%',
                    cursor: 'pointer',
                    transition: 'transform 0.2s',
                    '&:hover': {
                      transform: 'translateY(-2px)',
                      boxShadow: 3,
                    },
                    borderLeft: `4px solid ${color}`,
                  }}
                >
                  <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <Typography variant="body2" sx={{ fontWeight: 'medium' }}>
                      {tactic.split(' ')[0]}
                    </Typography>
                    <Chip
                      label={count}
                      size="small"
                      sx={{
                        bgcolor: color,
                        color: 'white',
                        fontWeight: 'bold',
                      }}
                    />
                  </Box>
                  
                  {count > 0 && (
                    <Box sx={{ mt: 1 }}>
                      <Typography variant="caption" color="text.secondary">
                        Techniques detected:
                      </Typography>
                      <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5, mt: 0.5 }}>
                        {techniques[tactic].slice(0, 2).map((tech, idx) => (
                          <Chip
                            key={idx}
                            label={tech.split(' ')[0]}
                            size="small"
                            variant="outlined"
                            sx={{ fontSize: '0.6rem' }}
                          />
                        ))}
                      </Box>
                    </Box>
                  )}
                </Paper>
              </Tooltip>
            </Grid>
          );
        })}
      </Grid>
      
      {threats.length === 0 && (
        <Box sx={{ textAlign: 'center', py: 4 }}>
          <Typography color="text.secondary">
            No threat data available for MITRE analysis
          </Typography>
        </Box>
      )}
    </Paper>
  );
};

export default MITREMatrix;