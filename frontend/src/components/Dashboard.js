import React, { useCallback, useEffect, useState, useMemo } from 'react';
import {
  Grid,
  Card,
  CardContent,
  Typography,
  Box,
  Button,
  LinearProgress,
  List,
  ListItem,
  ListItemText,
  ListItemIcon,
  Chip,
  IconButton,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  TextField,
  Alert,
  Tooltip as MuiTooltip
} from '@mui/material';
import {
  Security as SecurityIcon,
  BugReport as BugIcon,
  Dns as HostIcon,
  Hub as PortIcon,
  Shield as ShieldIcon,
  TrendingUp as TrendingIcon,
  PlayArrow as PlayIcon,
  Visibility as ViewIcon,
  Add as AddIcon,
  Refresh as RefreshIcon,
  Warning as WarningIcon,
  Computer as ComputerIcon,
  CheckCircle as CheckIcon
} from '@mui/icons-material';
import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer } from 'recharts';
import { useNavigate } from 'react-router-dom';
import { useScan } from '../context/ScanContext';
import apiService from '../services/apiService';

const SEVERITY_COLORS = {
  Critical: '#d32f2f',
  High: '#f57c00',
  Medium: '#fbc02d',
  Low: '#388e3c',
};

const Dashboard = ({ showNotification }) => {
  const { scanHistory, startScan, scanProgress } = useScan();
  const navigate = useNavigate();
  const [statistics, setStatistics] = useState(null);
  const [projects, setProjects] = useState([]);
  const [newProjectDialog, setNewProjectDialog] = useState(false);
  const [newProject, setNewProject] = useState({ name: '', description: '', target: '' });
  const [loading, setLoading] = useState(false);

  const loadDashboardData = useCallback(async () => {
    try {
      setLoading(true);
      const [stats, projectsData] = await Promise.all([
        apiService.getStatistics(),
        apiService.getProjects()
      ]);
      setStatistics(stats);
      setProjects(projectsData);
    } catch (error) {
      showNotification('Failed to load dashboard data', 'error');
    } finally {
      setLoading(false);
    }
  }, [showNotification]);

  useEffect(() => {
    loadDashboardData();
  }, [loadDashboardData]);

  const handleCreateProject = async () => {
    try {
      if (!newProject.name || !newProject.target) {
        showNotification('Please fill in required fields', 'error');
        return;
      }

      const project = await apiService.createProject(newProject);
      setProjects(prev => [project, ...prev]);
      setNewProjectDialog(false);
      setNewProject({ name: '', description: '', target: '' });
      showNotification('Project created successfully', 'success');
    } catch (error) {
      showNotification('Failed to create project', 'error');
    }
  };

  const handleQuickScan = async (target, scanType) => {
    try {
      await startScan(scanType, target);
      showNotification(`${scanType} scan started for ${target}`, 'info');
    } catch (error) {
      showNotification(`Failed to start scan: ${error.message}`, 'error');
    }
  };

  // Executive Visual Analytics dynamically computed from scanHistory in state
  const metrics = useMemo(() => {
    const hostMap = new Map();
    let totalPortsCount = 0;
    const portFrequencyMap = new Map();
    let criticalCount = 0;
    let highCount = 0;
    let mediumCount = 0;
    let lowCount = 0;

    scanHistory.forEach((scan) => {
      // 1. Process Monitored Hosts and Open Ports
      if (Array.isArray(scan.scan_results) && scan.scan_results.length > 0) {
        scan.scan_results.forEach((h) => {
          const ip = h.ip_address || h.host || 'Unknown';
          if (!hostMap.has(ip)) {
            hostMap.set(ip, {
              ip,
              hostname: h.hostname || ip,
              state: h.state || (h.alive ? 'up' : 'down'),
              inferred_os: h.inferred_os || 'Unknown',
              open_ports: [],
              vulnerabilities: [],
              maxCvss: 0,
              highestSeverity: 'None',
            });
          }
          const hostEntry = hostMap.get(ip);
          if (Array.isArray(h.open_ports)) {
            h.open_ports.forEach((p) => {
              const portKey = `${p.port}/${p.protocol || 'tcp'}`;
              const serviceKey = (p.service && p.service !== 'unknown' && p.service !== 'active-probe')
                ? p.service
                : `Port ${p.port}`;
              hostEntry.open_ports.push({ ...p, portKey, serviceKey });
              
              const currentPortFreq = portFrequencyMap.get(portKey) || {
                portKey,
                port: p.port,
                protocol: p.protocol || 'tcp',
                service: serviceKey,
                product: p.product || '',
                count: 0,
              };
              currentPortFreq.count += 1;
              portFrequencyMap.set(portKey, currentPortFreq);
            });
          }
        });
      } else if (scan.target || scan.domain) {
        const ip = scan.target || scan.domain;
        if (!hostMap.has(ip)) {
          hostMap.set(ip, {
            ip,
            hostname: scan.domain || ip,
            state: 'up',
            inferred_os: 'Web Application / Host',
            open_ports: [],
            vulnerabilities: [],
            maxCvss: 0,
            highestSeverity: 'None',
          });
        }
      }

      // 2. Process Detected Vulnerabilities
      const vulns = Array.isArray(scan.vulnerabilities) ? scan.vulnerabilities : [];
      vulns.forEach((v) => {
        const rawSev = (v.severity || 'Low').trim();
        const sevKey = rawSev.charAt(0).toUpperCase() + rawSev.slice(1).toLowerCase();
        let cvss = 2.5;

        if (sevKey === 'Critical') {
          criticalCount++;
          cvss = 9.8;
        } else if (sevKey === 'High') {
          highCount++;
          cvss = 7.8;
        } else if (sevKey === 'Medium') {
          mediumCount++;
          cvss = 5.4;
        } else {
          lowCount++;
          cvss = 2.5;
        }

        // Assign to corresponding host
        const targetHost = scan.target || scan.domain;
        if (targetHost && hostMap.has(targetHost)) {
          const entry = hostMap.get(targetHost);
          entry.vulnerabilities.push(v);
          if (cvss > entry.maxCvss) {
            entry.maxCvss = cvss;
            entry.highestSeverity = sevKey;
          }
        } else if (hostMap.size > 0) {
          const firstHost = hostMap.values().next().value;
          if (firstHost) {
            firstHost.vulnerabilities.push(v);
            if (cvss > firstHost.maxCvss) {
              firstHost.maxCvss = cvss;
              firstHost.highestSeverity = sevKey;
            }
          }
        }
      });

      if (scan.total_open_ports) {
        totalPortsCount += scan.total_open_ports;
      }
    });

    const totalMonitoredHosts = hostMap.size;
    const allDiscoveredPorts = Array.from(portFrequencyMap.values()).reduce((acc, p) => acc + p.count, 0) || totalPortsCount;
    const totalVulnerabilities = criticalCount + highCount + mediumCount + lowCount;

    // Threat Score Calculation (0–100 scale)
    const rawScore = (criticalCount * 25) + (highCount * 12) + (mediumCount * 5) + (lowCount * 1);
    const threatScore = Math.min(100, Math.max(0, totalVulnerabilities === 0 ? 0 : Math.round(rawScore)));

    // Threat Score Grading
    let threatGrade = { label: 'Low / Guarded', color: '#4caf50', bgColor: 'rgba(76, 175, 80, 0.12)' };
    if (threatScore > 70) {
      threatGrade = { label: 'Critical / High Risk', color: '#f44336', bgColor: 'rgba(244, 67, 54, 0.12)' };
    } else if (threatScore >= 40) {
      threatGrade = { label: 'Elevated Risk', color: '#ff9800', bgColor: 'rgba(255, 152, 0, 0.12)' };
    }

    // Severity Donut Chart Data
    const severityData = [
      { name: 'Critical', value: criticalCount, color: SEVERITY_COLORS.Critical },
      { name: 'High', value: highCount, color: SEVERITY_COLORS.High },
      { name: 'Medium', value: mediumCount, color: SEVERITY_COLORS.Medium },
      { name: 'Low', value: lowCount, color: SEVERITY_COLORS.Low },
    ].filter(item => item.value > 0);

    // Top Vulnerable Hosts Ranking
    const topVulnerableHosts = Array.from(hostMap.values())
      .sort((a, b) => b.maxCvss - a.maxCvss || b.vulnerabilities.length - a.vulnerabilities.length)
      .slice(0, 5);

    // Service & Open Port Distribution
    const serviceDistribution = Array.from(portFrequencyMap.values())
      .sort((a, b) => b.count - a.count)
      .slice(0, 6);

    const maxServiceCount = Math.max(...serviceDistribution.map(s => s.count), 1);

    return {
      totalMonitoredHosts,
      totalDiscoveredPorts: allDiscoveredPorts,
      totalVulnerabilities,
      threatScore,
      threatGrade,
      criticalCount,
      highCount,
      mediumCount,
      lowCount,
      severityData,
      topVulnerableHosts,
      serviceDistribution,
      maxServiceCount
    };
  }, [scanHistory]);

  return (
    <Box>
      {/* Header */}
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3, flexWrap: 'wrap', gap: 2 }}>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, flexWrap: 'wrap' }}>
          <Typography variant="h4" component="h1" sx={{ fontWeight: 'bold' }}>
            Dashboard
          </Typography>
          <Chip
            label="Vulnerability & Asset Intelligence Engine"
            size="small"
            variant="outlined"
            sx={{
              color: '#8a9ba8',
              borderColor: 'rgba(138, 155, 168, 0.4)',
              backgroundColor: 'rgba(138, 155, 168, 0.1)',
              fontWeight: 600,
              fontSize: '0.8rem',
              py: 0.5,
            }}
          />
        </Box>
        <Box sx={{ display: 'flex', gap: 2 }}>
          <Button
            variant="contained"
            startIcon={<AddIcon />}
            onClick={() => setNewProjectDialog(true)}
          >
            New Project
          </Button>
          <IconButton onClick={loadDashboardData} disabled={loading}>
            <RefreshIcon />
          </IconButton>
        </Box>
      </Box>

      {loading && <LinearProgress sx={{ mb: 2 }} />}

      {/* 1. Top Metric Stat Cards */}
      <Grid container spacing={3} sx={{ mb: 4 }}>
        {/* Total Monitored Hosts */}
        <Grid item xs={12} sm={6} md={3}>
          <Card className="stat-card" sx={{ height: '100%', border: '1px solid rgba(255, 255, 255, 0.08)' }}>
            <CardContent sx={{ textAlign: 'center', p: 3 }}>
              <HostIcon sx={{ fontSize: 40, color: '#8a9ba8', mb: 1 }} />
              <Typography variant="h4" component="div" className="stat-number" sx={{ fontWeight: 700 }}>
                {metrics.totalMonitoredHosts}
              </Typography>
              <Typography className="stat-label" sx={{ fontWeight: 600, color: 'text.secondary' }}>
                Total Monitored Hosts
              </Typography>
              <Typography variant="caption" sx={{ color: 'text.secondary', display: 'block', mt: 0.5 }}>
                Active Network Assets
              </Typography>
            </CardContent>
          </Card>
        </Grid>

        {/* Total Discovered Ports */}
        <Grid item xs={12} sm={6} md={3}>
          <Card className="stat-card" sx={{ height: '100%', border: '1px solid rgba(255, 255, 255, 0.08)' }}>
            <CardContent sx={{ textAlign: 'center', p: 3 }}>
              <PortIcon sx={{ fontSize: 40, color: '#6a7b88', mb: 1 }} />
              <Typography variant="h4" component="div" className="stat-number" sx={{ fontWeight: 700 }}>
                {metrics.totalDiscoveredPorts}
              </Typography>
              <Typography className="stat-label" sx={{ fontWeight: 600, color: 'text.secondary' }}>
                Total Discovered Ports
              </Typography>
              <Typography variant="caption" sx={{ color: 'text.secondary', display: 'block', mt: 0.5 }}>
                Exposed Services & Endpoints
              </Typography>
            </CardContent>
          </Card>
        </Grid>

        {/* Total Vulnerabilities */}
        <Grid item xs={12} sm={6} md={3}>
          <Card className="stat-card" sx={{ height: '100%', border: '1px solid rgba(255, 255, 255, 0.08)' }}>
            <CardContent sx={{ textAlign: 'center', p: 3 }}>
              <BugIcon sx={{ fontSize: 40, color: '#a85850', mb: 1 }} />
              <Typography variant="h4" component="div" className="stat-number" sx={{ fontWeight: 700 }}>
                {metrics.totalVulnerabilities}
              </Typography>
              <Typography className="stat-label" sx={{ fontWeight: 600, color: 'text.secondary' }}>
                Total Vulnerabilities
              </Typography>
              <Typography variant="caption" sx={{ color: metrics.criticalCount > 0 ? '#f44336' : 'text.secondary', display: 'block', mt: 0.5, fontWeight: 600 }}>
                {metrics.criticalCount} Critical • {metrics.highCount} High
              </Typography>
            </CardContent>
          </Card>
        </Grid>

        {/* Overall Enterprise Threat Score */}
        <Grid item xs={12} sm={6} md={3}>
          <Card className="stat-card" sx={{ height: '100%', border: `1px solid ${metrics.threatGrade.color}40`, bgcolor: metrics.threatGrade.bgColor }}>
            <CardContent sx={{ textAlign: 'center', p: 3 }}>
              <ShieldIcon sx={{ fontSize: 40, color: metrics.threatGrade.color, mb: 1 }} />
              <Box sx={{ display: 'flex', alignItems: 'baseline', justifyContent: 'center', gap: 0.5 }}>
                <Typography variant="h4" component="div" className="stat-number" sx={{ fontWeight: 700, color: metrics.threatGrade.color }}>
                  {metrics.threatScore}
                </Typography>
                <Typography variant="body2" sx={{ color: 'text.secondary', fontWeight: 600 }}>
                  / 100
                </Typography>
              </Box>
              <Typography className="stat-label" sx={{ fontWeight: 700, color: metrics.threatGrade.color }}>
                Threat Score: {metrics.threatGrade.label}
              </Typography>
              <LinearProgress
                variant="determinate"
                value={metrics.threatScore}
                sx={{
                  mt: 1,
                  height: 6,
                  borderRadius: 3,
                  bgcolor: 'rgba(255, 255, 255, 0.1)',
                  '& .MuiLinearProgress-bar': { backgroundColor: metrics.threatGrade.color }
                }}
              />
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Current Scan Progress */}
      {scanProgress && (
        <Card sx={{ mb: 3 }} className="fade-in">
          <CardContent>
            <Typography variant="h6" gutterBottom>
              Scan in Progress
            </Typography>
            <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
              {scanProgress.message}
            </Typography>
            <LinearProgress className="pulsing" />
          </CardContent>
        </Card>
      )}

      {/* 2. Visual Breakdown Cards: Severity Donut, Top Vulnerable Hosts, Service Distribution */}
      <Grid container spacing={3} sx={{ mb: 4 }}>
        {/* Severity Donut Chart */}
        <Grid item xs={12} md={4}>
          <Card sx={{ height: '100%', border: '1px solid rgba(255, 255, 255, 0.08)' }}>
            <CardContent>
              <Typography variant="h6" gutterBottom sx={{ fontWeight: 600 }}>
                Finding Severity Breakdown
              </Typography>
              <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                Distribution of risk levels across findings
              </Typography>

              {metrics.severityData.length === 0 ? (
                <Box sx={{ py: 6, textAlign: 'center' }}>
                  <CheckIcon sx={{ fontSize: 48, color: '#4caf50', mb: 1 }} />
                  <Typography variant="body1" sx={{ fontWeight: 600, color: 'text.primary' }}>
                    Zero Vulnerabilities Detected
                  </Typography>
                  <Typography variant="body2" color="text.secondary">
                    All scanned network assets are currently in good standing.
                  </Typography>
                </Box>
              ) : (
                <Box>
                  <Box sx={{ height: 200, position: 'relative' }}>
                    <ResponsiveContainer width="100%" height="100%">
                      <PieChart>
                        <Pie
                          data={metrics.severityData}
                          cx="50%"
                          cy="50%"
                          innerRadius={55}
                          outerRadius={80}
                          paddingAngle={3}
                          dataKey="value"
                        >
                          {metrics.severityData.map((entry, index) => (
                            <Cell key={`cell-${index}`} fill={entry.color} />
                          ))}
                        </Pie>
                        <Tooltip
                          contentStyle={{ backgroundColor: '#1a1a1a', borderColor: '#333', borderRadius: 8 }}
                          formatter={(val, name) => [`${val} Findings`, name]}
                        />
                      </PieChart>
                    </ResponsiveContainer>
                    <Box
                      sx={{
                        position: 'absolute',
                        top: '50%',
                        left: '50%',
                        transform: 'translate(-50%, -50%)',
                        textAlign: 'center',
                        pointerEvents: 'none',
                      }}
                    >
                      <Typography variant="h6" sx={{ fontWeight: 700, lineHeight: 1 }}>
                        {metrics.totalVulnerabilities}
                      </Typography>
                      <Typography variant="caption" sx={{ color: 'text.secondary', fontSize: '0.7rem' }}>
                        Findings
                      </Typography>
                    </Box>
                  </Box>

                  {/* Legend Chips */}
                  <Box sx={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 1, mt: 2 }}>
                    <Box sx={{ p: 1, bgcolor: 'rgba(211, 47, 47, 0.1)', borderRadius: 1.5, border: '1px solid rgba(211, 47, 47, 0.2)' }}>
                      <Typography variant="caption" sx={{ color: '#d32f2f', fontWeight: 700, display: 'block' }}>
                        CRITICAL ({metrics.criticalCount})
                      </Typography>
                      <Typography variant="caption" color="text.secondary">
                        {metrics.totalVulnerabilities > 0 ? Math.round((metrics.criticalCount / metrics.totalVulnerabilities) * 100) : 0}% of total
                      </Typography>
                    </Box>
                    <Box sx={{ p: 1, bgcolor: 'rgba(245, 124, 0, 0.1)', borderRadius: 1.5, border: '1px solid rgba(245, 124, 0, 0.2)' }}>
                      <Typography variant="caption" sx={{ color: '#f57c00', fontWeight: 700, display: 'block' }}>
                        HIGH ({metrics.highCount})
                      </Typography>
                      <Typography variant="caption" color="text.secondary">
                        {metrics.totalVulnerabilities > 0 ? Math.round((metrics.highCount / metrics.totalVulnerabilities) * 100) : 0}% of total
                      </Typography>
                    </Box>
                    <Box sx={{ p: 1, bgcolor: 'rgba(251, 192, 45, 0.1)', borderRadius: 1.5, border: '1px solid rgba(251, 192, 45, 0.2)' }}>
                      <Typography variant="caption" sx={{ color: '#fbc02d', fontWeight: 700, display: 'block' }}>
                        MEDIUM ({metrics.mediumCount})
                      </Typography>
                      <Typography variant="caption" color="text.secondary">
                        {metrics.totalVulnerabilities > 0 ? Math.round((metrics.mediumCount / metrics.totalVulnerabilities) * 100) : 0}% of total
                      </Typography>
                    </Box>
                    <Box sx={{ p: 1, bgcolor: 'rgba(56, 142, 60, 0.1)', borderRadius: 1.5, border: '1px solid rgba(56, 142, 60, 0.2)' }}>
                      <Typography variant="caption" sx={{ color: '#388e3c', fontWeight: 700, display: 'block' }}>
                        LOW ({metrics.lowCount})
                      </Typography>
                      <Typography variant="caption" color="text.secondary">
                        {metrics.totalVulnerabilities > 0 ? Math.round((metrics.lowCount / metrics.totalVulnerabilities) * 100) : 0}% of total
                      </Typography>
                    </Box>
                  </Box>
                </Box>
              )}
            </CardContent>
          </Card>
        </Grid>

        {/* Top Vulnerable Hosts Widget */}
        <Grid item xs={12} md={4}>
          <Card sx={{ height: '100%', border: '1px solid rgba(255, 255, 255, 0.08)' }}>
            <CardContent>
              <Typography variant="h6" gutterBottom sx={{ fontWeight: 600 }}>
                Top Vulnerable Hosts
              </Typography>
              <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                Monitored assets ranked by risk exposure
              </Typography>

              {metrics.topVulnerableHosts.length === 0 ? (
                <Box sx={{ py: 6, textAlign: 'center' }}>
                  <ComputerIcon sx={{ fontSize: 48, color: '#8a9ba8', mb: 1 }} />
                  <Typography variant="body2" color="text.secondary">
                    No hosts scanned yet. Run a scan to populate asset rankings.
                  </Typography>
                </Box>
              ) : (
                <List disablePadding>
                  {metrics.topVulnerableHosts.map((host, idx) => {
                    const cvssColor = host.maxCvss >= 9.0 ? '#d32f2f' : host.maxCvss >= 7.0 ? '#f57c00' : host.maxCvss >= 4.0 ? '#fbc02d' : '#4caf50';
                    return (
                      <ListItem
                        key={idx}
                        sx={{
                          mb: 1.5,
                          p: 1.5,
                          bgcolor: '#1e1e1e',
                          borderRadius: 1.5,
                          border: '1px solid rgba(255, 255, 255, 0.05)',
                          display: 'flex',
                          justifyContent: 'space-between',
                          alignItems: 'center',
                        }}
                      >
                        <Box sx={{ flex: 1, minWidth: 0, mr: 1 }}>
                          <Typography variant="subtitle2" noWrap sx={{ fontWeight: 700, color: 'text.primary' }}>
                            {host.ip}
                          </Typography>
                          <Typography variant="caption" noWrap sx={{ color: 'text.secondary', display: 'block' }}>
                            {host.hostname !== host.ip ? host.hostname : host.inferred_os}
                          </Typography>
                          <Typography variant="caption" sx={{ color: 'text.secondary' }}>
                            {host.open_ports.length} Open Ports • {host.vulnerabilities.length} Issues
                          </Typography>
                        </Box>

                        <Box sx={{ textAlign: 'right' }}>
                          <Chip
                            label={host.maxCvss > 0 ? `CVSS ${host.maxCvss.toFixed(1)}` : 'Clean'}
                            size="small"
                            sx={{
                              fontWeight: 700,
                              fontSize: '0.75rem',
                              color: cvssColor,
                              borderColor: `${cvssColor}40`,
                              backgroundColor: `${cvssColor}15`,
                              borderWidth: 1,
                              borderStyle: 'solid',
                            }}
                          />
                        </Box>
                      </ListItem>
                    );
                  })}
                </List>
              )}
            </CardContent>
          </Card>
        </Grid>

        {/* Service & Port Distribution Widget */}
        <Grid item xs={12} md={4}>
          <Card sx={{ height: '100%', border: '1px solid rgba(255, 255, 255, 0.08)' }}>
            <CardContent>
              <Typography variant="h6" gutterBottom sx={{ fontWeight: 600 }}>
                Service & Port Distribution
              </Typography>
              <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                Most frequently exposed network services
              </Typography>

              {metrics.serviceDistribution.length === 0 ? (
                <Box sx={{ py: 6, textAlign: 'center' }}>
                  <PortIcon sx={{ fontSize: 48, color: '#8a9ba8', mb: 1 }} />
                  <Typography variant="body2" color="text.secondary">
                    No open service ports discovered yet.
                  </Typography>
                </Box>
              ) : (
                <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
                  {metrics.serviceDistribution.map((service, idx) => {
                    const percentage = Math.round((service.count / metrics.maxServiceCount) * 100);
                    return (
                      <Box key={idx}>
                        <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 0.5 }}>
                          <Typography variant="body2" sx={{ fontWeight: 600, color: 'text.primary' }}>
                            {service.service.toUpperCase()} <span style={{ color: '#8a9ba8', fontWeight: 400 }}>({service.portKey})</span>
                          </Typography>
                          <Typography variant="caption" sx={{ fontWeight: 700, color: 'primary.light' }}>
                            {service.count} {service.count === 1 ? 'Host' : 'Hosts'}
                          </Typography>
                        </Box>
                        <LinearProgress
                          variant="determinate"
                          value={percentage}
                          sx={{
                            height: 6,
                            borderRadius: 3,
                            bgcolor: 'rgba(255, 255, 255, 0.08)',
                            '& .MuiLinearProgress-bar': {
                              backgroundColor: '#8a9ba8',
                            }
                          }}
                        />
                      </Box>
                    );
                  })}
                </Box>
              )}
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* 3. Secondary Section: Recent Scans, Projects, and Quick Actions */}
      <Grid container spacing={3}>
        {/* Recent Scans */}
        <Grid item xs={12} md={6}>
          <Card sx={{ height: '100%', border: '1px solid rgba(255, 255, 255, 0.08)' }}>
            <CardContent>
              <Typography variant="h6" gutterBottom sx={{ fontWeight: 600 }}>
                Recent Scans Activity
              </Typography>
              {scanHistory.length === 0 ? (
                <Alert severity="info">
                  No scans yet. Start your first scan to see results here!
                </Alert>
              ) : (
                <List disablePadding>
                  {scanHistory.slice(0, 5).map((scan, index) => (
                    <ListItem key={index} divider sx={{ py: 1.5, px: 0 }}>
                      <ListItemIcon>
                        <SecurityIcon color="primary" />
                      </ListItemIcon>
                      <ListItemText
                        primary={scan.domain || scan.target || 'Unknown Target'}
                        secondary={`${scan.scan_type || 'Unknown'} scan • ${new Date(scan.timestamp).toLocaleString()}`}
                      />
                      <Box sx={{ display: 'flex', gap: 1, alignItems: 'center' }}>
                        {scan.vulnerabilities && (
                          <Chip
                            label={`${scan.vulnerabilities.length} issues`}
                            size="small"
                            color={scan.vulnerabilities.length > 5 ? 'error' : scan.vulnerabilities.length > 0 ? 'warning' : 'success'}
                          />
                        )}
                        <IconButton size="small" onClick={() => navigate('/results')} aria-label="View scan results">
                          <ViewIcon />
                        </IconButton>
                      </Box>
                    </ListItem>
                  ))}
                </List>
              )}
            </CardContent>
          </Card>
        </Grid>

        {/* Projects */}
        <Grid item xs={12} md={6}>
          <Card sx={{ height: '100%', border: '1px solid rgba(255, 255, 255, 0.08)' }}>
            <CardContent>
              <Typography variant="h6" gutterBottom sx={{ fontWeight: 600 }}>
                Active Security Projects
              </Typography>
              {projects.length === 0 ? (
                <Alert severity="info">
                  No projects yet. Create your first project to organize your scans!
                </Alert>
              ) : (
                <List disablePadding>
                  {projects.slice(0, 5).map((project) => (
                    <ListItem key={project.id} divider sx={{ py: 1.5, px: 0 }}>
                      <ListItemText
                        primary={project.name}
                        secondary={`Target: ${project.target} • ${project.scan_count} scans`}
                      />
                      <Chip
                        label={project.status}
                        size="small"
                        color={project.status === 'active' ? 'success' : 'default'}
                      />
                    </ListItem>
                  ))}
                </List>
              )}
            </CardContent>
          </Card>
        </Grid>

        {/* Quick Launch Actions */}
        <Grid item xs={12}>
          <Card sx={{ border: '1px solid rgba(255, 255, 255, 0.08)' }}>
            <CardContent>
              <Typography variant="h6" gutterBottom sx={{ fontWeight: 600 }}>
                Quick Scan Launchers
              </Typography>
              <Grid container spacing={2} sx={{ mt: 0.5 }}>
                <Grid item xs={12} sm={6} md={3}>
                  <Button
                    fullWidth
                    variant="outlined"
                    startIcon={<PlayIcon />}
                    onClick={() => {
                      const target = prompt('Enter target domain:');
                      if (target) handleQuickScan(target, 'subdomain');
                    }}
                  >
                    Subdomain Recon
                  </Button>
                </Grid>
                <Grid item xs={12} sm={6} md={3}>
                  <Button
                    fullWidth
                    variant="outlined"
                    startIcon={<PlayIcon />}
                    onClick={() => {
                      const target = prompt('Enter target IP/CIDR/domain:');
                      if (target) handleQuickScan(target, 'port');
                    }}
                  >
                    Port & CIDR Sweep
                  </Button>
                </Grid>
                <Grid item xs={12} sm={6} md={3}>
                  <Button
                    fullWidth
                    variant="outlined"
                    startIcon={<PlayIcon />}
                    onClick={() => {
                      const target = prompt('Enter target URL/Host:');
                      if (target) handleQuickScan(target, 'vulnerability');
                    }}
                  >
                    Vulnerability Scan
                  </Button>
                </Grid>
                <Grid item xs={12} sm={6} md={3}>
                  <Button
                    fullWidth
                    variant="outlined"
                    startIcon={<PlayIcon />}
                    onClick={() => {
                      const target = prompt('Enter target domain:');
                      if (target) handleQuickScan(target, 'automated');
                    }}
                  >
                    Full Enterprise Scan
                  </Button>
                </Grid>
              </Grid>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* CyberSentry Platform Card */}
      <Card sx={{ mt: 4, backgroundColor: '#2a2a2a', border: '1px solid rgba(255, 255, 255, 0.06)' }}>
        <CardContent sx={{ textAlign: 'center' }}>
          <Typography variant="h5" gutterBottom sx={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 1 }}>
            🛡️ CyberSentry
          </Typography>
          <Typography variant="body1" paragraph>
            CyberSentry - Enterprise Network Vulnerability Platform
          </Typography>
          <Box sx={{ display: 'flex', gap: 2, justifyContent: 'center', flexWrap: 'wrap' }}>
            <Button
              variant="outlined"
              color="inherit"
              size="large"
              onClick={() => window.open('https://github.com/maabma28818-lang', '_blank', 'noopener,noreferrer')}
              sx={{ 
                borderColor: 'rgba(255, 255, 255, 0.5)',
                '&:hover': { borderColor: 'white', backgroundColor: 'rgba(255, 255, 255, 0.1)' }
              }}
            >
              ⭐ Star on GitHub
            </Button>
          </Box>
          <Typography variant="body2" sx={{ mt: 2, opacity: 0.9 }}>
            CyberSentry Security Suite | RT-MSSU Capstone 2026-27 | Academic Research Lab
          </Typography>
        </CardContent>
      </Card>

      {/* New Project Dialog */}
      <Dialog open={newProjectDialog} onClose={() => setNewProjectDialog(false)} maxWidth="sm" fullWidth>
        <DialogTitle>Create New Project</DialogTitle>
        <DialogContent>
          <TextField
            autoFocus
            margin="dense"
            label="Project Name *"
            fullWidth
            variant="outlined"
            value={newProject.name}
            onChange={(e) => setNewProject(prev => ({ ...prev, name: e.target.value }))}
            sx={{ mb: 2 }}
          />
          <TextField
            margin="dense"
            label="Description"
            fullWidth
            multiline
            rows={3}
            variant="outlined"
            value={newProject.description}
            onChange={(e) => setNewProject(prev => ({ ...prev, description: e.target.value }))}
            sx={{ mb: 2 }}
          />
          <TextField
            margin="dense"
            label="Target Domain/IP/CIDR *"
            fullWidth
            variant="outlined"
            value={newProject.target}
            onChange={(e) => setNewProject(prev => ({ ...prev, target: e.target.value }))}
            helperText="e.g., example.com, 192.168.1.1, or 192.168.1.0/24"
          />
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setNewProjectDialog(false)}>Cancel</Button>
          <Button onClick={handleCreateProject} variant="contained">Create</Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
};

export default Dashboard;

