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
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  Alert,
  Divider,
  Grid,
  CircularProgress
} from '@mui/material';
import {
  Security as SecurityIcon,
  Lock as LockIcon,
  Person as PersonIcon,
  Email as EmailIcon,
  Badge as BadgeIcon,
  Visibility as VisibilityIcon,
  VisibilityOff as VisibilityOffIcon,
  PersonAdd as PersonAddIcon,
  CheckCircleOutline as CheckIcon
} from '@mui/icons-material';
import { useNavigate, Link as RouterLink } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';

const Signup = ({ showNotification }) => {
  const { signup } = useAuth();
  const navigate = useNavigate();

  const [username, setUsername] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [role, setRole] = useState('analyst');
  const [showPassword, setShowPassword] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [errorMessage, setErrorMessage] = useState('');

  const handleSignUp = async (e) => {
    if (e) e.preventDefault();
    setErrorMessage('');

    const cleanUsername = username.trim();
    const cleanEmail = email.trim().toLowerCase();

    if (!cleanUsername || cleanUsername.length < 3) {
      setErrorMessage('Username must be at least 3 characters long');
      return;
    }
    if (!/^[a-zA-Z0-9_.-]+$/.test(cleanUsername)) {
      setErrorMessage('Username may only contain letters, numbers, dots, and underscores');
      return;
    }
    if (!cleanEmail || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(cleanEmail)) {
      setErrorMessage('Please enter a valid email address');
      return;
    }
    if (!password || password.length < 6) {
      setErrorMessage('Password must be at least 6 characters long');
      return;
    }
    if (password !== confirmPassword) {
      setErrorMessage('Passwords do not match');
      return;
    }

    try {
      setIsLoading(true);
      await signup({
        username: cleanUsername,
        email: cleanEmail,
        password,
        role,
        rememberMe: true,
      });
      if (showNotification) {
        showNotification('Account created successfully! Welcome to CyberSentry.', 'success');
      }
      navigate('/dashboard', { replace: true });
    } catch (error) {
      const msg = typeof error === 'string' ? error : error?.error || error?.message || 'Failed to create account';
      setErrorMessage(msg);
      if (showNotification) {
        showNotification(msg, 'error');
      }
    } finally {
      setIsLoading(false);
    }
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
          <Grid item xs={12} md={5} sx={{ display: { xs: 'none', md: 'block' } }}>
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
                Create Your Analyst Account
              </Typography>

              <Typography variant="body1" sx={{ color: '#94a3b8', mb: 4, lineHeight: 1.6 }}>
                Join the security operations team to conduct comprehensive reconnaissance, vulnerability prioritization, and defensive playbooks.
              </Typography>

              <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
                {[
                  'Role-Based Assessment Capabilities',
                  'Persistent Audit History & Vulnerability Metrics',
                  'AI-Powered Security Explanation Engine',
                  'Instant Executive PDF & Technical HTML Exports',
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
          <Grid item xs={12} md={7}>
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
                    <PersonAddIcon sx={{ color: '#38bdf8', fontSize: 24 }} />
                  </Box>
                  <Typography variant="h5" sx={{ fontWeight: 700, color: '#f8fafc' }}>
                    Operator Registration
                  </Typography>
                  <Typography variant="body2" sx={{ color: '#94a3b8', mt: 0.5 }}>
                    Configure your credentials to initialize your CyberSentry account
                  </Typography>
                </Box>

                {errorMessage && (
                  <Alert severity="error" sx={{ mb: 2.5, bgcolor: 'rgba(239, 68, 68, 0.1)', color: '#fca5a5' }}>
                    {errorMessage}
                  </Alert>
                )}

                <Box component="form" onSubmit={handleSignUp} noValidate>
                  <Grid container spacing={2}>
                    <Grid item xs={12} sm={6}>
                      <TextField
                        fullWidth
                        label="Username"
                        variant="outlined"
                        value={username}
                        onChange={(e) => setUsername(e.target.value)}
                        disabled={isLoading}
                        autoFocus
                        placeholder="e.g. j_doe"
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
                    </Grid>

                    <Grid item xs={12} sm={6}>
                      <FormControl fullWidth sx={{ '& .MuiOutlinedInput-root': { bgcolor: '#111620' } }}>
                        <InputLabel id="role-label">Assigned Role</InputLabel>
                        <Select
                          labelId="role-label"
                          value={role}
                          label="Assigned Role"
                          onChange={(e) => setRole(e.target.value)}
                          disabled={isLoading}
                          startAdornment={
                            <InputAdornment position="start">
                              <BadgeIcon sx={{ color: '#64748b' }} />
                            </InputAdornment>
                          }
                        >
                          <MenuItem value="analyst">Security Analyst</MenuItem>
                          <MenuItem value="admin">Administrator</MenuItem>
                          <MenuItem value="engineer">Security Engineer</MenuItem>
                          <MenuItem value="viewer">Auditor / Viewer</MenuItem>
                        </Select>
                      </FormControl>
                    </Grid>

                    <Grid item xs={12}>
                      <TextField
                        fullWidth
                        label="Email Address"
                        type="email"
                        variant="outlined"
                        value={email}
                        onChange={(e) => setEmail(e.target.value)}
                        disabled={isLoading}
                        placeholder="analyst@domain.com"
                        InputProps={{
                          startAdornment: (
                            <InputAdornment position="start">
                              <EmailIcon sx={{ color: '#64748b' }} />
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
                    </Grid>

                    <Grid item xs={12} sm={6}>
                      <TextField
                        fullWidth
                        label="Password"
                        type={showPassword ? 'text' : 'password'}
                        variant="outlined"
                        value={password}
                        onChange={(e) => setPassword(e.target.value)}
                        disabled={isLoading}
                        placeholder="Minimum 6 characters"
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
                    </Grid>

                    <Grid item xs={12} sm={6}>
                      <TextField
                        fullWidth
                        label="Confirm Password"
                        type={showPassword ? 'text' : 'password'}
                        variant="outlined"
                        value={confirmPassword}
                        onChange={(e) => setConfirmPassword(e.target.value)}
                        disabled={isLoading}
                        placeholder="Re-enter password"
                        InputProps={{
                          startAdornment: (
                            <InputAdornment position="start">
                              <LockIcon sx={{ color: '#64748b' }} />
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
                    </Grid>
                  </Grid>

                  <Button
                    type="submit"
                    fullWidth
                    variant="contained"
                    size="large"
                    disabled={isLoading}
                    startIcon={isLoading ? <CircularProgress size={20} color="inherit" /> : <PersonAddIcon />}
                    sx={{
                      mt: 3,
                      py: 1.4,
                      fontWeight: 700,
                      fontSize: '1rem',
                      bgcolor: '#0284c7',
                      '&:hover': { bgcolor: '#0369a1' },
                    }}
                  >
                    {isLoading ? 'Creating Account...' : 'Complete Registration'}
                  </Button>
                </Box>

                <Divider sx={{ my: 3, borderColor: 'rgba(255, 255, 255, 0.08)' }} />

                <Box sx={{ textAlign: 'center' }}>
                  <Typography variant="body2" sx={{ color: '#94a3b8' }}>
                    Already an authorized operator?{' '}
                    <Button
                      component={RouterLink}
                      to="/signin"
                      sx={{ color: '#38bdf8', fontWeight: 700, textTransform: 'none', p: 0, ml: 0.5 }}
                    >
                      Sign in to your terminal
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

export default Signup;
