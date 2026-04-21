// frontend/src/components/Layout.jsx
import React, { useState } from 'react';
import { 
  Box, Drawer, AppBar, Toolbar, Typography, List, ListItem, 
  ListItemIcon, ListItemText, IconButton, useTheme, Avatar, 
  Menu, MenuItem, Divider, Badge, Tooltip 
} from '@mui/material';
import {
  Menu as MenuIcon,
  Dashboard,
  Security,
  AccountBalanceWallet,
  Lock,
  Psychology,
  ChevronLeft,
  Settings,
  Notifications,
  Person,
  Logout,
  DarkMode,
  LightMode,
  Storage,
  Speed,
} from '@mui/icons-material';
import { useNavigate, useLocation } from 'react-router-dom';
import { useTheme as useCustomTheme } from '../context/ThemeContext';
import { authService } from '../services/auth';

const drawerWidth = 260;

const Layout = ({ children }) => {
  const [open, setOpen] = useState(true);
  const [anchorEl, setAnchorEl] = useState(null);
  const [notificationAnchor, setNotificationAnchor] = useState(null);
  const theme = useTheme();
  const { mode, toggleTheme } = useCustomTheme();
  const navigate = useNavigate();
  const location = useLocation();
  const user = authService.getCurrentUser();

  const menuItems = [
    { text: 'Dashboard', icon: <Dashboard />, path: '/dashboard', color: '#2196f3' },
    { text: 'Threat Intelligence', icon: <Security />, path: '/threat-intelligence', color: '#f44336' },
    { text: 'Blockchain Forensics', icon: <AccountBalanceWallet />, path: '/blockchain-forensics', color: '#4caf50' },
    { text: 'Confidential Compute', icon: <Lock />, path: '/confidential-compute', color: '#ff9800' },
    { text: 'AI Workloads', icon: <Psychology />, path: '/ai-workloads', color: '#9c27b0' },
  ];

  const handleDrawerToggle = () => {
    setOpen(!open);
  };

  const handleMenuOpen = (event) => {
    setAnchorEl(event.currentTarget);
  };

  const handleMenuClose = () => {
    setAnchorEl(null);
  };

  const handleNotificationOpen = (event) => {
    setNotificationAnchor(event.currentTarget);
  };

  const handleNotificationClose = () => {
    setNotificationAnchor(null);
  };

  const handleLogout = () => {
    authService.logout();
    navigate('/login');
  };

  const handleSettings = () => {
    navigate('/settings');
    handleMenuClose();
  };

  return (
    <Box sx={{ display: 'flex', width: '100%', minHeight: '100vh' }}>
      <AppBar 
        position="fixed" 
        sx={{ 
          zIndex: theme.zIndex.drawer + 1,
          backgroundColor: theme.palette.background.paper,
          borderBottom: `1px solid ${theme.palette.divider}`,
          boxShadow: 'none',
        }}
      >
        <Toolbar>
          <IconButton
            color="inherit"
            aria-label="open drawer"
            onClick={handleDrawerToggle}
            edge="start"
            sx={{ mr: 2 }}
          >
            <MenuIcon />
          </IconButton>
          
          <Typography variant="h6" noWrap component="div" sx={{ flexGrow: 1, fontWeight: 'bold' }}>
            <span style={{ color: '#2196f3' }}>Threat</span>Shield
          </Typography>
          
          <Box sx={{ display: 'flex', gap: 1 }}>
            <Tooltip title={mode === 'dark' ? 'Light Mode' : 'Dark Mode'}>
              <IconButton onClick={toggleTheme} color="inherit">
                {mode === 'dark' ? <LightMode /> : <DarkMode />}
              </IconButton>
            </Tooltip>
            
            <Tooltip title="Notifications">
              <IconButton onClick={handleNotificationOpen} color="inherit">
                <Badge badgeContent={3} color="error">
                  <Notifications />
                </Badge>
              </IconButton>
            </Tooltip>
            
            <Tooltip title={user?.name || 'Account'}>
              <IconButton onClick={handleMenuOpen} color="inherit">
                <Avatar sx={{ width: 32, height: 32, bgcolor: 'primary.main' }}>
                  {user?.name?.charAt(0) || 'U'}
                </Avatar>
              </IconButton>
            </Tooltip>
          </Box>
        </Toolbar>
      </AppBar>
      
      {/* User Menu */}
      <Menu
        anchorEl={anchorEl}
        open={Boolean(anchorEl)}
        onClose={handleMenuClose}
        transformOrigin={{ horizontal: 'right', vertical: 'top' }}
        anchorOrigin={{ horizontal: 'right', vertical: 'bottom' }}
      >
        <MenuItem onClick={handleMenuClose}>
          <ListItemIcon><Person fontSize="small" /></ListItemIcon>
          <ListItemText primary={user?.name || 'User'} secondary={user?.email} />
        </MenuItem>
        <Divider />
        <MenuItem onClick={handleSettings}>
          <ListItemIcon><Settings fontSize="small" /></ListItemIcon>
          <ListItemText primary="Settings" />
        </MenuItem>
        <MenuItem onClick={handleLogout}>
          <ListItemIcon><Logout fontSize="small" /></ListItemIcon>
          <ListItemText primary="Logout" />
        </MenuItem>
      </Menu>
      
      {/* Notification Menu */}
      <Menu
        anchorEl={notificationAnchor}
        open={Boolean(notificationAnchor)}
        onClose={handleNotificationClose}
        transformOrigin={{ horizontal: 'right', vertical: 'top' }}
        anchorOrigin={{ horizontal: 'right', vertical: 'bottom' }}
        PaperProps={{ sx: { width: 320, maxHeight: 400 } }}
      >
        <MenuItem>
          <Box sx={{ p: 1 }}>
            <Typography variant="subtitle2" color="error">⚠️ Critical Threat Detected</Typography>
            <Typography variant="caption" color="text.secondary">2 minutes ago</Typography>
          </Box>
        </MenuItem>
        <MenuItem>
          <Box sx={{ p: 1 }}>
            <Typography variant="subtitle2" color="warning">🔄 Model Training Complete</Typography>
            <Typography variant="caption" color="text.secondary">1 hour ago</Typography>
          </Box>
        </MenuItem>
        <MenuItem>
          <Box sx={{ p: 1 }}>
            <Typography variant="subtitle2">🔐 New Enclave Attested</Typography>
            <Typography variant="caption" color="text.secondary">3 hours ago</Typography>
          </Box>
        </MenuItem>
        <Divider />
        <MenuItem onClick={handleNotificationClose}>
          <Typography variant="body2" color="primary" textAlign="center" width="100%">
            View All Notifications
          </Typography>
        </MenuItem>
      </Menu>
      
      {/* Sidebar Drawer */}
      <Drawer
        variant="permanent"
        open={open}
        sx={{
          width: open ? drawerWidth : theme.spacing(7),
          transition: theme.transitions.create('width', {
            easing: theme.transitions.easing.sharp,
            duration: theme.transitions.duration.enteringScreen,
          }),
          '& .MuiDrawer-paper': {
            width: open ? drawerWidth : theme.spacing(7),
            transition: theme.transitions.create('width', {
              easing: theme.transitions.easing.sharp,
              duration: theme.transitions.duration.enteringScreen,
            }),
            overflowX: 'hidden',
            marginTop: '64px',
            height: 'calc(100% - 64px)',
            backgroundColor: theme.palette.background.paper,
            borderRight: `1px solid ${theme.palette.divider}`,
          },
        }}
      >
        <List sx={{ pt: 2 }}>
          {menuItems.map((item) => (
            <Tooltip key={item.text} title={!open ? item.text : ''} placement="right">
              <ListItem
                button
                onClick={() => navigate(item.path)}
                selected={location.pathname === item.path}
                sx={{
                  minHeight: 48,
                  justifyContent: open ? 'initial' : 'center',
                  px: 2.5,
                  mx: 1,
                  mb: 0.5,
                  borderRadius: 2,
                  '&.Mui-selected': {
                    backgroundColor: `${item.color}20`,
                    '&:hover': {
                      backgroundColor: `${item.color}30`,
                    },
                    '& .MuiListItemIcon-root': {
                      color: item.color,
                    },
                    '& .MuiListItemText-primary': {
                      color: item.color,
                      fontWeight: 600,
                    },
                  },
                }}
              >
                <ListItemIcon
                  sx={{
                    minWidth: 0,
                    mr: open ? 2 : 'auto',
                    justifyContent: 'center',
                    color: location.pathname === item.path ? item.color : 'inherit',
                  }}
                >
                  {item.icon}
                </ListItemIcon>
                <ListItemText 
                  primary={item.text} 
                  sx={{ 
                    opacity: open ? 1 : 0,
                    '& .MuiListItemText-primary': {
                      fontSize: '0.9rem',
                    },
                  }} 
                />
              </ListItem>
            </Tooltip>
          ))}
        </List>
        
        <Divider sx={{ my: 2 }} />
        
        {/* System Status */}
        <Box sx={{ px: open ? 2 : 1, mt: 'auto', mb: 2 }}>
          <Tooltip title={!open ? "System Status" : ""} placement="right">
            <Box sx={{ 
              p: 1.5, 
              borderRadius: 2, 
              bgcolor: theme.palette.action.hover,
              textAlign: open ? 'left' : 'center',
            }}>
              {open ? (
                <>
                  <Typography variant="caption" color="text.secondary" display="block">
                    System Status
                  </Typography>
                  <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mt: 1 }}>
                    <Speed sx={{ fontSize: 16, color: 'success.main' }} />
                    <Typography variant="body2">All Systems Operational</Typography>
                  </Box>
                  <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mt: 0.5 }}>
                    <Storage sx={{ fontSize: 16, color: 'info.main' }} />
                    <Typography variant="body2">3 Active Enclaves</Typography>
                  </Box>
                </>
              ) : (
                <Speed sx={{ fontSize: 20, color: 'success.main' }} />
              )}
            </Box>
          </Tooltip>
        </Box>
      </Drawer>
      
      {/* Main Content */}
      <Box
        component="main"
        sx={{
          flexGrow: 1,
          p: 3,
          marginTop: '64px',
          marginLeft: open ? `${drawerWidth}px` : theme.spacing(7),
          transition: theme.transitions.create('margin', {
            easing: theme.transitions.easing.sharp,
            duration: theme.transitions.duration.enteringScreen,
          }),
          width: `calc(100% - ${open ? drawerWidth : theme.spacing(7)}px)`,
          backgroundColor: theme.palette.background.default,
          minHeight: 'calc(100vh - 64px)',
        }}
      >
        {children}
      </Box>
    </Box>
  );
};

export default Layout;