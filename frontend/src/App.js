import React, { useState, useEffect } from 'react';
import { Routes, Route, Navigate, useNavigate, useLocation, Outlet } from 'react-router-dom';
import {
  AppBar,
  Toolbar,
  Typography,
  Box,
  Container,
  IconButton,
  Drawer,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  ListItemButton,
  Divider,
  useTheme,
  Alert,
  Snackbar,
  Chip,
  Avatar,
  Tooltip
} from '@mui/material';
import {
  Menu as MenuIcon,
  Security as SecurityIcon,
  Dashboard as DashboardIcon,
  BugReport as BugReportIcon,
  Assessment as AssessmentIcon,
  SmartToy as AIIcon,
  Settings as SettingsIcon,
  Help as HelpIcon,
  Favorite as DonateIcon,
  Logout as LogoutIcon
} from '@mui/icons-material';

// Import components
import Dashboard from './components/Dashboard';
import Scanner from './components/Scanner';
import Results from './components/Results';
import Reports from './components/Reports';
import AIAssistant from './components/AIAssistant';
import Settings from './components/Settings';
import Help from './components/Help';
import Donate from './components/Donate';
import Signin from './components/Signin';
import Signup from './components/Signup';
import ProtectedRoute from './components/ProtectedRoute';

// Import context
import { ScanProvider } from './context/ScanContext';
import { AuthProvider, useAuth } from './context/AuthContext';

const drawerWidth = 240;

const menuItems = [
  { text: 'Dashboard', icon: <DashboardIcon />, path: '/dashboard' },
  { text: 'Scanner', icon: <SecurityIcon />, path: '/scanner' },
  { text: 'Results', icon: <BugReportIcon />, path: '/results' },
  { text: 'Reports', icon: <AssessmentIcon />, path: '/reports' },
  { text: 'AI Assistant', icon: <AIIcon />, path: '/ai-assistant' },
  { text: 'Settings', icon: <SettingsIcon />, path: '/settings' },
  { text: 'Help', icon: <HelpIcon />, path: '/help' },
  { text: 'About', icon: <DonateIcon />, path: '/about' },
];

function AuthenticatedLayout({ showAlert }) {
  const navigate = useNavigate();
  const location = useLocation();
  const { user, logout } = useAuth();
  const [drawerOpen, setDrawerOpen] = useState(false);

  const handleDrawerToggle = () => {
    setDrawerOpen(!drawerOpen);
  };

  const handleMenuClick = (path) => {
    navigate(path);
    setDrawerOpen(false);
  };

  const handleLogout = () => {
    logout();
    showAlert('Logged out successfully', 'info');
    navigate('/signin');
  };

  const userRole = (user?.role || 'analyst').toUpperCase();

  const drawer = (
    <Box sx={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
      <Toolbar>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5 }}>
          <Box
            sx={{
              width: 38,
              height: 38,
              borderRadius: '8px',
              bgcolor: 'rgba(56, 189, 248, 0.12)',
              border: '1px solid rgba(56, 189, 248, 0.3)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
            }}
          >
            <SecurityIcon sx={{ color: '#38bdf8', fontSize: 24 }} />
          </Box>
          <Box>
            <Typography variant="subtitle1" sx={{ fontWeight: 800, color: '#f8fafc', lineHeight: 1.1 }}>
              CyberSentry
            </Typography>
            <Typography variant="caption" sx={{ color: '#94a3b8', fontSize: '0.65rem', fontWeight: 600, letterSpacing: '0.04em' }}>
              ENTERPRISE DEFENSE
            </Typography>
          </Box>
        </Box>
      </Toolbar>
      <Divider sx={{ borderColor: 'rgba(255, 255, 255, 0.08)' }} />
      <List sx={{ flexGrow: 1, pt: 1.5 }}>
        {menuItems.map((item) => (
          <ListItem key={item.text} disablePadding sx={{ mb: 0.5, px: 1 }}>
            <ListItemButton
              onClick={() => handleMenuClick(item.path)}
              selected={location.pathname === item.path}
              sx={{
                borderRadius: '8px',
                py: 1,
                '&.Mui-selected': {
                  backgroundColor: 'rgba(56, 189, 248, 0.12)',
                  color: '#38bdf8',
                  '& .MuiListItemIcon-root': { color: '#38bdf8' },
                  '&:hover': { backgroundColor: 'rgba(56, 189, 248, 0.18)' },
                },
                '&:hover': {
                  backgroundColor: 'rgba(255, 255, 255, 0.04)',
                },
              }}
            >
              <ListItemIcon sx={{ color: location.pathname === item.path ? '#38bdf8' : 'rgba(255, 255, 255, 0.6)', minWidth: 38 }}>
                {item.icon}
              </ListItemIcon>
              <ListItemText
                primary={item.text}
                primaryTypographyProps={{
                  fontSize: '0.875rem',
                  fontWeight: location.pathname === item.path ? 700 : 500,
                }}
              />
            </ListItemButton>
          </ListItem>
        ))}
      </List>

      {/* User Profile Footer in Drawer */}
      <Divider sx={{ borderColor: 'rgba(255, 255, 255, 0.08)' }} />
      <Box sx={{ p: 2, bgcolor: '#131822' }}>
        <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 1 }}>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, overflow: 'hidden' }}>
            <Avatar sx={{ width: 32, height: 32, bgcolor: '#0284c7', fontSize: '0.85rem', fontWeight: 700 }}>
              {user?.username ? user.username[0].toUpperCase() : 'U'}
            </Avatar>
            <Box sx={{ overflow: 'hidden' }}>
              <Typography variant="body2" sx={{ fontWeight: 700, color: '#f8fafc', whiteSpace: 'nowrap', textOverflow: 'ellipsis', overflow: 'hidden' }}>
                {user?.username || 'Analyst'}
              </Typography>
              <Typography variant="caption" sx={{ color: '#94a3b8', fontSize: '0.7rem' }}>
                {user?.email || 'operator'}
              </Typography>
            </Box>
          </Box>
          <Tooltip title="Sign Out">
            <IconButton size="small" onClick={handleLogout} sx={{ color: '#94a3b8', '&:hover': { color: '#ef4444' } }}>
              <LogoutIcon fontSize="small" />
            </IconButton>
          </Tooltip>
        </Box>
        <Chip
          label={userRole}
          size="small"
          sx={{
            width: '100%',
            height: 22,
            fontSize: '0.65rem',
            fontWeight: 800,
            letterSpacing: '0.05em',
            bgcolor: user?.role === 'admin' ? 'rgba(239, 68, 68, 0.15)' : 'rgba(56, 189, 248, 0.12)',
            color: user?.role === 'admin' ? '#f87171' : '#38bdf8',
            border: `1px solid ${user?.role === 'admin' ? 'rgba(239, 68, 68, 0.3)' : 'rgba(56, 189, 248, 0.25)'}`,
          }}
        />
      </Box>
    </Box>
  );

  return (
    <Box sx={{ display: 'flex', minHeight: '100vh', bgcolor: '#0f141c' }}>
      {/* App Bar */}
      <AppBar
        position="fixed"
        sx={{
          width: { sm: `calc(100% - ${drawerWidth}px)` },
          ml: { sm: `${drawerWidth}px` },
          backgroundColor: '#141a24',
          borderBottom: '1px solid rgba(255, 255, 255, 0.08)',
        }}
      >
        <Toolbar sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
            <IconButton
              color="inherit"
              aria-label="open drawer"
              edge="start"
              onClick={handleDrawerToggle}
              sx={{ mr: 1, display: { sm: 'none' } }}
            >
              <MenuIcon />
            </IconButton>
            <Typography variant="h6" noWrap component="div" sx={{ fontWeight: 700, color: '#f8fafc' }}>
              {menuItems.find((item) => item.path === location.pathname)?.text || 'CyberSentry'}
            </Typography>
          </Box>

          <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
            <Chip
              label="Vulnerability & Asset Intelligence Engine"
              size="small"
              variant="outlined"
              sx={{
                color: '#38bdf8',
                borderColor: 'rgba(56, 189, 248, 0.3)',
                backgroundColor: 'rgba(56, 189, 248, 0.08)',
                fontWeight: 600,
                fontSize: '0.75rem',
                display: { xs: 'none', md: 'inline-flex' },
              }}
            />

            {/* Top Toolbar User Badge */}
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5 }}>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                <Avatar sx={{ width: 30, height: 30, bgcolor: '#0284c7', fontSize: '0.8rem', fontWeight: 700 }}>
                  {user?.username ? user.username[0].toUpperCase() : 'U'}
                </Avatar>
                <Typography variant="body2" sx={{ fontWeight: 600, color: '#f8fafc', display: { xs: 'none', sm: 'block' } }}>
                  {user?.username}
                </Typography>
              </Box>

              <Tooltip title="Sign Out">
                <IconButton onClick={handleLogout} size="small" sx={{ color: '#94a3b8', '&:hover': { color: '#ef4444' } }}>
                  <LogoutIcon fontSize="small" />
                </IconButton>
              </Tooltip>
            </Box>
          </Box>
        </Toolbar>
      </AppBar>

      {/* Navigation Drawer */}
      <Box
        component="nav"
        sx={{ width: { sm: drawerWidth }, flexShrink: { sm: 0 } }}
      >
        <Drawer
          variant="temporary"
          open={drawerOpen}
          onClose={handleDrawerToggle}
          ModalProps={{
            keepMounted: true,
          }}
          sx={{
            display: { xs: 'block', sm: 'none' },
            '& .MuiDrawer-paper': {
              boxSizing: 'border-box',
              width: drawerWidth,
              backgroundColor: '#141a24',
              borderRight: '1px solid rgba(255, 255, 255, 0.08)',
            },
          }}
        >
          {drawer}
        </Drawer>
        <Drawer
          variant="permanent"
          sx={{
            display: { xs: 'none', sm: 'block' },
            '& .MuiDrawer-paper': {
              boxSizing: 'border-box',
              width: drawerWidth,
              backgroundColor: '#141a24',
              borderRight: '1px solid rgba(255, 255, 255, 0.08)',
            },
          }}
          open
        >
          {drawer}
        </Drawer>
      </Box>

      {/* Main Content */}
      <Box
        component="main"
        sx={{
          flexGrow: 1,
          p: 3,
          width: { sm: `calc(100% - ${drawerWidth}px)` },
          minHeight: '100vh',
          display: 'flex',
          flexDirection: 'column',
          bgcolor: '#0f141c',
        }}
      >
        <Toolbar />
        <Container maxWidth="xl" sx={{ mt: 2, flexGrow: 1 }}>
          <Outlet />
        </Container>

        {/* Persistent Footer Across All Views */}
        <Box
          component="footer"
          sx={{
            py: 2.5,
            px: 3,
            mt: 4,
            textAlign: 'center',
            borderTop: '1px solid rgba(255, 255, 255, 0.06)',
          }}
        >
          <Typography variant="body2" sx={{ color: 'text.secondary', fontSize: '0.85rem' }}>
            CyberSentry Security Suite | RT-MSSU Capstone 2026-27 | Academic Research Lab
          </Typography>
        </Box>
      </Box>
    </Box>
  );
}

function AppContent({ showAlert }) {
  return (
    <Routes>
      <Route path="/signin" element={<Signin showNotification={showAlert} />} />
      <Route path="/signup" element={<Signup showNotification={showAlert} />} />
      <Route
        path="/"
        element={
          <ProtectedRoute>
            <AuthenticatedLayout showAlert={showAlert} />
          </ProtectedRoute>
        }
      >
        <Route index element={<Navigate to="/dashboard" replace />} />
        <Route path="dashboard" element={<Dashboard showNotification={showAlert} />} />
        <Route path="scanner" element={<Scanner showNotification={showAlert} />} />
        <Route path="results" element={<Results showNotification={showAlert} />} />
        <Route path="reports" element={<Reports showNotification={showAlert} />} />
        <Route path="ai-assistant" element={<AIAssistant showNotification={showAlert} />} />
        <Route path="settings" element={<Settings showNotification={showAlert} />} />
        <Route path="help" element={<Help />} />
        <Route path="about" element={<Donate />} />
        <Route path="*" element={<Navigate to="/dashboard" replace />} />
      </Route>
      <Route path="*" element={<Navigate to="/dashboard" replace />} />
    </Routes>
  );
}

function App() {
  const [alertMessage, setAlertMessage] = useState(null);

  const showAlert = (message, severity = 'info') => {
    setAlertMessage({ message, severity });
  };

  const hideAlert = () => {
    setAlertMessage(null);
  };

  return (
    <AuthProvider>
      <ScanProvider>
        <AppContent showAlert={showAlert} />

        {/* Global Notifications */}
        <Snackbar
          open={!!alertMessage}
          autoHideDuration={6000}
          onClose={hideAlert}
          anchorOrigin={{ vertical: 'bottom', horizontal: 'right' }}
        >
          {alertMessage && (
            <Alert
              onClose={hideAlert}
              severity={alertMessage.severity}
              sx={{ width: '100%' }}
            >
              {alertMessage.message}
            </Alert>
          )}
        </Snackbar>
      </ScanProvider>
    </AuthProvider>
  );
}

export default App;
