import React from 'react';
import { Box, Skeleton, Grid, Card, CardContent } from '@mui/material';

export const DashboardSkeleton = () => (
  <Box sx={{ p: 3 }}>
    <Box sx={{ mb: 4 }}><Skeleton variant="text" width={300} height={40} /><Skeleton variant="text" width={500} height={24} /></Box>
    <Grid container spacing={3} sx={{ mb: 4 }}>
      {[1, 2, 3, 4].map((i) => (<Grid item xs={12} sm={6} md={3} key={i}><Card><CardContent><Skeleton variant="text" width={120} height={20} /><Skeleton variant="text" width={80} height={40} /><Skeleton variant="text" width={100} height={20} /></CardContent></Card></Grid>))}
    </Grid>
    <Grid container spacing={3}>
      <Grid item xs={12} md={8}><Card><CardContent><Skeleton variant="text" width={200} height={24} /><Skeleton variant="rectangular" height={300} sx={{ mt: 2 }} /></CardContent></Card></Grid>
      <Grid item xs={12} md={4}><Card><CardContent><Skeleton variant="text" width={200} height={24} /><Skeleton variant="circular" width={200} height={200} sx={{ mx: 'auto', mt: 2 }} /></CardContent></Card></Grid>
    </Grid>
  </Box>
);

export const TableSkeleton = ({ rows = 5, columns = 4 }) => (
  <Box sx={{ width: '100%' }}>
    <Skeleton variant="text" width={200} height={32} sx={{ mb: 2 }} />
    {[...Array(rows)].map((_, i) => (<Box key={i} sx={{ display: 'flex', gap: 2, mb: 1 }}>{[...Array(columns)].map((_, j) => (<Skeleton key={j} variant="rectangular" height={40} sx={{ flex: 1 }} />))}</Box>))}
  </Box>
);

export const CardSkeleton = () => (
  <Card><CardContent><Skeleton variant="text" width="60%" height={24} /><Skeleton variant="text" width="40%" height={20} sx={{ mt: 1 }} /><Skeleton variant="rectangular" height={100} sx={{ mt: 2 }} /></CardContent></Card>
);