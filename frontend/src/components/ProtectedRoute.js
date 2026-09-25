import React from 'react';
import { Navigate, useLocation } from 'react-router-dom';
import { Box, CircularProgress, Typography } from '@mui/material';
import { Shield as ShieldIcon } from '@mui/icons-material';
import { useAuth } from '../context/AuthContext';

const ProtectedRoute = ({ children }) => {
  const { isAuthenticated, isLoading } = useAuth();
  const location = useLocation();

  if (isLoading) {
    return (
      <Box
        sx={{
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          justifyContent: 'center',
          minHeight: '100vh',
          backgroundColor: '#12161f',
          gap: 2,
        }}
      >
        <ShieldIcon sx={{ fontSize: 48, color: 'primary.main', animation: 'pulse 1.5s infinite ease-in-out' }} />
        <CircularProgress size={32} color="primary" />
        <Typography variant="body2" sx={{ color: 'text.secondary', fontWeight: 500 }}>
          Authenticating CyberSentry Session...
        </Typography>
      </Box>
    );
  }

  if (!isAuthenticated) {
    return <Navigate to="/signin" state={{ from: location }} replace />;
  }

  return children;
};

export default ProtectedRoute;
