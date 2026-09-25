import React, { useState } from 'react';
import {
  Box,
  Card,
  CardContent,
  Typography,
  TextField,
  Button,
  InputAdornment,
  IconButton,
  FormControlLabel,
  Checkbox,
  Alert,
  Divider,
  Chip,
  Grid,
  CircularProgress
} from '@mui/material';
import {
  Security as SecurityIcon,
  Lock as LockIcon,
  Person as PersonIcon,
  Visibility as VisibilityIcon,
  VisibilityOff as VisibilityOffIcon,
  Login as LoginIcon,
  VpnKey as KeyIcon,
  ShieldOutlined as ShieldOutlineIcon,
  CheckCircleOutline as CheckIcon
} from '@mui/icons-material';
import { useNavigate, useLocation, Link as RouterLink } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';

const Signin = ({ showNotification }) => {
  const { signin } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();

  const [account, setAccount] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [rememberMe, setRememberMe] = useState(true);
  const [isLoading, setIsLoading] = useState(false);
  const [errorMessage, setErrorMessage] = useState('');

  const from = location.state?.from?.pathname || '/dashboard';

  const handleSignIn = async (e) => {
    if (e) e.preventDefault();
    setErrorMessage('');

    if (!account.trim()) {
      setErrorMessage('Please enter your username or email address');
      return;
    }
    if (!password) {
      setErrorMessage('Please enter your password');
      return;
    }

    try {
      setIsLoading(true);
      await signin({ account: account.trim(), password, rememberMe });
      if (showNotification) {
        showNotification('Authentication successful! Welcome to CyberSentry.', 'success');
      }
      navigate(from, { replace: true });
    } catch (error) {
      const msg = typeof error === 'string' ? error : error?.error || error?.message || 'Invalid username or password';
      setErrorMessage(msg);
      if (showNotification) {
        showNotification(msg, 'error');
      }
    } finally {
      setIsLoading(false);
    }
  };

  const handleDemoFill = () => {
    setAccount('admin');
    setPassword('Admin@123');
    setErrorMessage('');
  };

  return (
    <Box
      sx={{
        minHeight: '100vh',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        bgcolor: '#0f141c',
        backgroundImage: 'radial-gradient(circle at 50% 20%, rgba(56, 189, 248, 0.07) 0%, rgba(15, 20, 28, 0) 70%)',
        p: { xs: 2, sm: 4 },
      }}
    >
      <Box sx={{ maxWidth: 960, width: '100%' }}>
        <Grid container spacing={4} alignItems="center" justifyContent="center">
          {/* Left Hero Panel (Desktop) */}
          <Grid item xs={12} md={6} sx={{ display: { xs: 'none', md: 'block' } }}>
            <Box sx={{ p: 2 }}>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, mb: 3 }}>
                <Box
                  sx={{
                    width: 52,
                    height: 52,
                    borderRadius: '12px',
                    bgcolor: 'rgba(56, 189, 248, 0.12)',
                    border: '1.5px solid rgba(56, 189, 248, 0.3)',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    boxShadow: '0 0 20px rgba(56, 189, 248, 0.25)',
                  }}
                >
                  <SecurityIcon sx={{ fontSize: 32, color: '#38bdf8' }} />
                </Box>
                <Box>
                  <Typography variant="h5" sx={{ fontWeight: 800, color: '#f8fafc', letterSpacing: '-0.02em' }}>
                    CyberSentry
                  </Typography>
                  <Typography variant="caption" sx={{ color: '#94a3b8', fontWeight: 600, letterSpacing: '0.05em' }}>
                    ENTERPRISE CYBER DEFENSE
                  </Typography>
                </Box>
              </Box>

              <Typography variant="h4" sx={{ fontWeight: 800, color: '#ffffff', mb: 2, lineHeight: 1.3 }}>
                All-in-One Security Assessment & Threat Intelligence Platform
              </Typography>

              <Typography variant="body1" sx={{ color: '#94a3b8', mb: 4, lineHeight: 1.6 }}>
                Authenticate to access real-time multi-vector scanning, exploit-aware vulnerability correlation, automated PDF reports, and AI assistant intelligence.
              </Typography>

              <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
                {[
                  'Unified 5-Stage Automated Assessment Pipeline',
                  'High-Speed Native Port & Service Banner Probing',
                  'Exploit-Aware CVSS v3.1, CISA KEV & EPSS Scoring',
                  'Actionable Configuration & Shell Remediation Playbooks',
                ].map((feature, idx) => (
                  <Box key={idx} sx={{ display: 'flex', alignItems: 'center', gap: 1.5 }}>
                    <CheckIcon sx={{ color: '#38bdf8', fontSize: 20 }} />
                    <Typography variant="body2" sx={{ color: '#cbd5e1', fontWeight: 500 }}>
                      {feature}
                    </Typography>
                  </Box>
                ))}
              </Box>
            </Box>
          </Grid>

          {/* Right Form Card */}
          <Grid item xs={12} md={6}>
            <Card
              sx={{
                bgcolor: '#181f2a',
                border: '1px solid rgba(255, 255, 255, 0.1)',
                borderRadius: '16px',
                boxShadow: '0 12px 32px rgba(0, 0, 0, 0.4)',
                p: { xs: 1, sm: 2 },
              }}
            >
              <CardContent>
                {/* Header */}
                <Box sx={{ textAlign: 'center', mb: 3 }}>
                  <Box
                    sx={{
                      width: 44,
                      height: 44,
                      borderRadius: '50%',
                      bgcolor: 'rgba(56, 189, 248, 0.1)',
                      display: 'inline-flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                      mb: 1.5,
                      border: '1px solid rgba(56, 189, 248, 0.25)',
                    }}
                  >
                    <KeyIcon sx={{ color: '#38bdf8', fontSize: 24 }} />
                  </Box>
                  <Typography variant="h5" sx={{ fontWeight: 700, color: '#f8fafc' }}>
                    Sign In to CyberSentry
                  </Typography>
                  <Typography variant="body2" sx={{ color: '#94a3b8', mt: 0.5 }}>
                    Enter your operator credentials to access the security terminal
                  </Typography>
                </Box>

                {errorMessage && (
                  <Alert severity="error" sx={{ mb: 2.5, bgcolor: 'rgba(239, 68, 68, 0.1)', color: '#fca5a5' }}>
                    {errorMessage}
                  </Alert>
                )}

                <Box component="form" onSubmit={handleSignIn} noValidate>
                  <Box sx={{ mb: 2.5 }}>
                    <TextField
                      fullWidth
                      label="Username or Email Address"
                      variant="outlined"
                      value={account}
                      onChange={(e) => setAccount(e.target.value)}
                      disabled={isLoading}
                      autoFocus
                      placeholder="e.g. admin or analyst@cybersentry.io"
                      InputProps={{
                        startAdornment: (
                          <InputAdornment position="start">
                            <PersonIcon sx={{ color: '#64748b' }} />
                          </InputAdornment>
                        ),
                      }}
                      sx={{
                        '& .MuiOutlinedInput-root': {
                          bgcolor: '#111620',
                          '&:hover fieldset': { borderColor: '#38bdf8' },
                        },
                      }}
                    />
                  </Box>

                  <Box sx={{ mb: 2 }}>
                    <TextField
                      fullWidth
                      label="Password"
                      type={showPassword ? 'text' : 'password'}
                      variant="outlined"
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      disabled={isLoading}
                      placeholder="Enter your account password"
                      InputProps={{
                        startAdornment: (
                          <InputAdornment position="start">
                            <LockIcon sx={{ color: '#64748b' }} />
                          </InputAdornment>
                        ),
                        endAdornment: (
                          <InputAdornment position="end">
                            <IconButton
                              onClick={() => setShowPassword(!showPassword)}
                              edge="end"
                              size="small"
                              sx={{ color: '#94a3b8' }}
                            >
                              {showPassword ? <VisibilityOffIcon fontSize="small" /> : <VisibilityIcon fontSize="small" />}
                            </IconButton>
                          </InputAdornment>
                        ),
                      }}
                      sx={{
                        '& .MuiOutlinedInput-root': {
                          bgcolor: '#111620',
                          '&:hover fieldset': { borderColor: '#38bdf8' },
                        },
                      }}
                    />
                  </Box>

                  <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2.5 }}>
                    <FormControlLabel
                      control={
                        <Checkbox
                          checked={rememberMe}
                          onChange={(e) => setRememberMe(e.target.checked)}
                          color="primary"
                          size="small"
                        />
                      }
                      label={
                        <Typography variant="body2" sx={{ color: '#94a3b8' }}>
                          Remember this device
                        </Typography>
                      }
                    />

                    <Button
                      size="small"
                      variant="text"
                      onClick={handleDemoFill}
                      sx={{ color: '#38bdf8', textTransform: 'none', fontSize: '0.8rem', fontWeight: 600 }}
                    >
                      Fill Demo Admin
                    </Button>
                  </Box>

                  <Button
                    type="submit"
                    fullWidth
                    variant="contained"
                    size="large"
                    disabled={isLoading}
                    startIcon={isLoading ? <CircularProgress size={20} color="inherit" /> : <LoginIcon />}
                    sx={{
                      py: 1.4,
                      fontWeight: 700,
                      fontSize: '1rem',
                      bgcolor: '#0284c7',
                      '&:hover': { bgcolor: '#0369a1' },
                    }}
                  >
                    {isLoading ? 'Authenticating...' : 'Sign In'}
                  </Button>
                </Box>

                <Divider sx={{ my: 3, borderColor: 'rgba(255, 255, 255, 0.08)' }} />

                <Box sx={{ textAlign: 'center' }}>
                  <Typography variant="body2" sx={{ color: '#94a3b8' }}>
                    New security analyst on this team?{' '}
                    <Button
                      component={RouterLink}
                      to="/signup"
                      sx={{ color: '#38bdf8', fontWeight: 700, textTransform: 'none', p: 0, ml: 0.5 }}
                    >
                      Create an account
                    </Button>
                  </Typography>
                </Box>
              </CardContent>
            </Card>
          </Grid>
        </Grid>
      </Box>
    </Box>
  );
};

export default Signin;
