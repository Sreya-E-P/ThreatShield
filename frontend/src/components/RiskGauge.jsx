// frontend/src/components/RiskGauge.jsx
import React from 'react';
import { Box, Typography, LinearProgress } from '@mui/material';

const RiskGauge = ({ value, thresholds = [30, 70, 90], size = 200, showLabel = true }) => {
  const getRiskLevel = (val) => {
    if (val < thresholds[0]) return 'LOW';
    if (val < thresholds[1]) return 'MEDIUM';
    if (val < thresholds[2]) return 'HIGH';
    return 'CRITICAL';
  };

  const getColor = (level) => {
    switch (level) {
      case 'LOW': return '#4caf50';
      case 'MEDIUM': return '#ff9800';
      case 'HIGH': return '#f44336';
      case 'CRITICAL': return '#d32f2f';
      default: return '#757575';
    }
  };

  const riskLevel = getRiskLevel(value);
  const color = getColor(riskLevel);

  // Calculate the angle for the gauge (0-180 degrees)
  const angle = (value / 100) * 180;
  const radians = (angle * Math.PI) / 180;
  
  // Calculate the end point of the needle
  const needleLength = size * 0.35;
  const centerX = size / 2;
  const centerY = size / 2;
  const needleX = centerX + needleLength * Math.sin(radians);
  const needleY = centerY - needleLength * Math.cos(radians);

  return (
    <Box sx={{ textAlign: 'center', position: 'relative' }}>
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`}>
        {/* Background arc (gray) */}
        <path
          d={`M ${size * 0.1} ${size * 0.9} A ${size * 0.4} ${size * 0.4} 0 0 1 ${size * 0.9} ${size * 0.9}`}
          fill="none"
          stroke="#e0e0e0"
          strokeWidth={20}
          strokeLinecap="round"
        />
        
        {/* Colored arc based on risk level */}
        <path
          d={`M ${size * 0.1} ${size * 0.9} A ${size * 0.4} ${size * 0.4} 0 0 1 ${size * 0.1 + (size * 0.8 * value/100)} ${size * 0.9 - (size * 0.4 * Math.sin(Math.acos(1 - 2 * value/100)))}`}
          fill="none"
          stroke={color}
          strokeWidth={20}
          strokeLinecap="round"
        />
        
        {/* Needle */}
        <line
          x1={centerX}
          y1={centerY}
          x2={needleX}
          y2={needleY}
          stroke="#333"
          strokeWidth={3}
          strokeLinecap="round"
        />
        
        {/* Center circle */}
        <circle
          cx={centerX}
          cy={centerY}
          r={8}
          fill="#333"
        />
        
        {/* Value text */}
        <text
          x={centerX}
          y={centerY + 30}
          textAnchor="middle"
          dominantBaseline="middle"
          fontSize={size/8}
          fontWeight="bold"
          fill={color}
        >
          {value}%
        </text>
      </svg>
      
      {showLabel && (
        <Box sx={{ mt: 2 }}>
          <Typography
            variant="h6"
            sx={{
              color,
              fontWeight: 'bold',
            }}
          >
            {riskLevel} RISK
          </Typography>
          <Typography variant="body2" color="text.secondary">
            Threat Level Assessment
          </Typography>
          
          <Box sx={{ mt: 2, px: 2 }}>
            <LinearProgress
              variant="determinate"
              value={value}
              sx={{
                height: 8,
                borderRadius: 4,
                backgroundColor: 'rgba(0,0,0,0.1)',
                '& .MuiLinearProgress-bar': {
                  backgroundColor: color,
                },
              }}
            />
            <Box sx={{ display: 'flex', justifyContent: 'space-between', mt: 0.5 }}>
              <Typography variant="caption">Low</Typography>
              <Typography variant="caption">Critical</Typography>
            </Box>
          </Box>
        </Box>
      )}
    </Box>
  );
};

export default RiskGauge;