import React, { useState } from 'react';
import {
  Box,
  Card,
  CardContent,
  Typography,
  TextField,
  Button,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  Chip,
  Grid,
  Alert,
  LinearProgress,
  Tabs,
  Tab,
  Switch,
  FormControlLabel,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  List,
  ListItem,
  ListItemIcon,
  ListItemText
} from '@mui/material';
import {
  PlayArrow as PlayIcon,
  Stop as StopIcon,
  Settings as SettingsIcon,
  ExpandMore as ExpandMoreIcon,
  Security as SecurityIcon,
  BugReport as BugIcon,
  Language as DnsIcon,
  Info as InfoIcon,
  CheckCircle as CheckIcon,
  Speed as SpeedIcon,
  Shield as ShieldIcon,
  Http as HttpIcon,
  FolderOpen as FolderIcon,
  Assessment as AssessmentIcon
} from '@mui/icons-material';
import { useNavigate } from 'react-router-dom';
import { useScan } from '../context/ScanContext';

const Scanner = ({ showNotification }) => {
  const { startScan, scanProgress, learningMode, toggleLearningMode } = useScan();
  const navigate = useNavigate();
  const [activeTab, setActiveTab] = useState(0);
  const [target, setTarget] = useState('');
  const [scanType, setScanType] = useState('comprehensive');
  const [portRange, setPortRange] = useState('1-1000');
  const [selectedScanTypes, setSelectedScanTypes] = useState(['subdomain', 'port', 'vuln']);
  const [isScanning, setIsScanning] = useState(false);

  const handleStartScan = async () => {
    if (!target.trim()) {
      showNotification('Please enter a target domain, IP, or CIDR block', 'error');
      return;
    }

    try {
      setIsScanning(true);
      
      let scanTypeToUse = 'unified';
      let options = {};
      
      switch (activeTab) {
        case 0: // Unified All-in-One Assessment
          scanTypeToUse = 'unified';
          options.portRange = portRange;
          break;
        case 1: // Subdomain
          scanTypeToUse = 'subdomain';
          break;
        case 2: // Port Scan
          scanTypeToUse = 'port';
          options.portRange = portRange;
          break;
        case 3: // Vulnerability
          scanTypeToUse = 'vulnerability';
          options.scanType = scanType;
          break;
        case 4: // DNS
          scanTypeToUse = 'dns';
          break;
        case 5: // WHOIS
          scanTypeToUse = 'whois';
          break;
        case 6: // Automated Socket
          scanTypeToUse = 'automated';
          options.scanTypes = selectedScanTypes;
          break;
        default:
          scanTypeToUse = 'unified';
      }

      const result = await startScan(scanTypeToUse, target, options);
      showNotification(`${scanTypeToUse.toUpperCase()} scan completed successfully!`, 'success');
      if (result && (activeTab === 0 || activeTab === 3)) {
        setTimeout(() => {
          navigate('/results');
        }, 1200);
      }
    } catch (error) {
      const message = error?.error || error?.message || 'Unexpected scan error';
      showNotification(`Scan failed: ${message}`, 'error');
    } finally {
      setIsScanning(false);
    }
  };

  const handleScanTypeToggle = (type) => {
    setSelectedScanTypes(prev => 
      prev.includes(type) 
        ? prev.filter(t => t !== type)
        : [...prev, type]
    );
  };

  const tabLabels = [
    'Unified All-in-One Assessment',
    'Subdomain Discovery',
    'Port & Banner Scan',
    'Vulnerability Assessment',
    'DNS Enumeration',
    'WHOIS Lookup'
  ];

  const learningTips = {
    0: {
      title: "Unified End-to-End Security Assessment",
      content: "Executes a complete, automated sequential pipeline across Subdomains, High-Speed Banner Scanning, Web Security Posture, Sensitive Endpoint Probing, and Exploit-Aware Scoring. Generates comprehensive audit findings with CVSS vectors and practical remediation guides."
    },
    1: {
      title: "Subdomain Enumeration",
      content: "Discovers subdomains of your target domain using Certificate Transparency (crt.sh) and DNS resolution. Identifies hidden hosts, staging domains, and exposed API gateways."
    },
    2: {
      title: "High-Speed Port & Banner Scanning",
      content: "Identifies open TCP ports and service banners (Server headers, OpenSSH versions, FTP/SMTP greetings, MySQL versions) using Python standard sockets without requiring local Nmap binaries."
    },
    3: {
      title: "Web Security & Vulnerability Assessment",
      content: "Audits HTTP/HTTPS headers for missing modern defenses (CSP, HSTS, X-Frame-Options, X-Content-Type-Options), checks cookie flags, probes sensitive paths, and assigns CVSS vectors with CISA KEV tags."
    },
    4: {
      title: "DNS Enumeration",
      content: "Gathers DNS records (A, AAAA, MX, NS, TXT, SOA) which can reveal infrastructure details, mail providers, and SPF/DMARC configurations."
    },
    5: {
      title: "WHOIS Lookup",
      content: "Retrieves domain registration information including registrar, creation date, nameservers, and organization details."
    }
  };

  return (
    <Box>
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
        <Typography variant="h4" component="h1" sx={{ fontWeight: 'bold' }}>
          Security Assessment Engine
        </Typography>
        <FormControlLabel
          control={<Switch checked={learningMode} onChange={toggleLearningMode} />}
          label="Learning Mode"
        />
      </Box>

      {/* Learning Mode Tip */}
      {learningMode && (
        <Card className="learning-tip fade-in" sx={{ mb: 3 }}>
          <CardContent>
            <Box sx={{ display: 'flex', alignItems: 'flex-start', gap: 2 }}>
              <InfoIcon className="tip-icon" />
              <Box>
                <Typography variant="h6" gutterBottom>
                  {learningTips[activeTab]?.title}
                </Typography>
                <Typography variant="body2">
                  {learningTips[activeTab]?.content}
                </Typography>
              </Box>
            </Box>
          </CardContent>
        </Card>
      )}

      {/* Target Input */}
      <Card sx={{ mb: 3 }}>
        <CardContent>
          <Grid container spacing={3} alignItems="center">
            <Grid item xs={12} md={6}>
              <TextField
                fullWidth
                label="Target Domain or IP Address"
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                placeholder="e.g. mssu.ac.in, example.com, 192.168.1.1, or 192.168.1.0/24"
                variant="outlined"
                disabled={isScanning}
                helperText="Accepts domain names, single IP addresses, or CIDR subnet blocks (/24 - /32)"
              />
              <Box sx={{ display: 'flex', gap: 1, mt: 1.5, alignItems: 'center', flexWrap: 'wrap' }}>
                <Typography variant="caption" sx={{ color: 'text.secondary', fontWeight: 600 }}>
                  Quick Target Presets:
                </Typography>
                <Chip
                  label="Localhost (127.0.0.1)"
                  size="small"
                  clickable
                  variant={target === '127.0.0.1' ? 'filled' : 'outlined'}
                  color={target === '127.0.0.1' ? 'primary' : 'default'}
                  onClick={() => setTarget('127.0.0.1')}
                  disabled={isScanning}
                  sx={{ fontSize: '0.75rem', fontWeight: 500 }}
                />
                <Chip
                  label="Academic Target (mssu.ac.in)"
                  size="small"
                  clickable
                  variant={target === 'mssu.ac.in' ? 'filled' : 'outlined'}
                  color={target === 'mssu.ac.in' ? 'primary' : 'default'}
                  onClick={() => setTarget('mssu.ac.in')}
                  disabled={isScanning}
                  sx={{ fontSize: '0.75rem', fontWeight: 500 }}
                />
                <Chip
                  label="Local Subnet (/24)"
                  size="small"
                  clickable
                  variant={target.includes('/24') ? 'filled' : 'outlined'}
                  color={target.includes('/24') ? 'primary' : 'default'}
                  onClick={() => {
                    const trimmed = target.trim();
                    if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(\/\d{1,2})?$/.test(trimmed)) {
                      const base = trimmed.split('/')[0].split('.').slice(0, 3).join('.');
                      setTarget(`${base}.0/24`);
                    } else {
                      setTarget('192.168.1.0/24');
                    }
                  }}
                  disabled={isScanning}
                  sx={{ fontSize: '0.75rem', fontWeight: 500 }}
                />
              </Box>
            </Grid>
            <Grid item xs={12} md={3}>
              <Button
                fullWidth
                variant="contained"
                size="large"
                color="primary"
                startIcon={isScanning ? <StopIcon /> : <PlayIcon />}
                onClick={handleStartScan}
                disabled={isScanning || !target.trim()}
                sx={{ height: 56, fontWeight: 700 }}
              >
                {isScanning ? 'Executing Pipeline...' : 'Start Assessment'}
              </Button>
            </Grid>
            <Grid item xs={12} md={3}>
              <Button
                fullWidth
                variant="outlined"
                startIcon={<AssessmentIcon />}
                onClick={() => navigate('/results')}
                sx={{ height: 56 }}
              >
                View Scan Results
              </Button>
            </Grid>
          </Grid>
        </CardContent>
      </Card>

      {/* Scan Progress */}
      {scanProgress && (
        <Card sx={{ mb: 3 }} className="fade-in">
          <CardContent>
            <Typography variant="h6" gutterBottom>
              {scanProgress.status === 'running' ? 'Unified Pipeline in Progress' : 'Scan Status'}
            </Typography>
            <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
              {scanProgress.message}
            </Typography>
            <LinearProgress 
              className={scanProgress.status === 'running' ? 'pulsing' : ''} 
              variant={scanProgress.status === 'running' ? 'indeterminate' : 'determinate'}
              value={scanProgress.status === 'completed' ? 100 : undefined}
            />
          </CardContent>
        </Card>
      )}

      {/* Scan Types */}
      <Card>
        <CardContent>
          <Tabs 
            value={activeTab} 
            onChange={(e, val) => setActiveTab(val)}
            variant="scrollable"
            scrollButtons="auto"
            sx={{ mb: 3 }}
          >
            {tabLabels.map((label, index) => (
              <Tab 
                key={index} 
                label={label} 
                sx={{ fontWeight: index === 0 ? 800 : 500 }}
              />
            ))}
          </Tabs>

          {/* Unified All-in-One Assessment */}
          {activeTab === 0 && (
            <Box>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5, mb: 1 }}>
                <ShieldIcon color="primary" />
                <Typography variant="h6" sx={{ fontWeight: 700 }}>
                  Unified End-to-End Security Assessment Pipeline
                </Typography>
              </Box>
              <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
                Executes all security modules in a unified sequential pipeline. Automatically runs subdomain discovery, high-speed socket banner grabber, web security posture & header audit, sensitive endpoint probing, and exploit-aware CVE scoring with remediation playbooks.
              </Typography>

              <Grid container spacing={2} sx={{ mb: 3 }}>
                {[
                  {
                    step: '1. Subdomain Discovery',
                    desc: 'Certificate Transparency (crt.sh) and DNS brute-forcing',
                    icon: <DnsIcon color="primary" />
                  },
                  {
                    step: '2. Port & Banner Scan',
                    desc: 'High-speed socket banner grabber (HTTP, SSH, MySQL, FTP, SMTP, RDP)',
                    icon: <SpeedIcon color="secondary" />
                  },
                  {
                    step: '3. Web Posture & Headers',
                    desc: 'CSP, HSTS, X-Frame-Options, X-Content-Type-Options & cookie flags',
                    icon: <HttpIcon color="warning" />
                  },
                  {
                    step: '4. Sensitive Endpoints',
                    desc: 'Probes /robots.txt, /.well-known/security.txt, /.git/HEAD, /swagger.json',
                    icon: <FolderIcon color="info" />
                  },
                  {
                    step: '5. Threat Scoring & Remediation',
                    desc: 'CVSS v3.1 vectors, CISA KEV tags, EPSS percentiles & Nginx/Apache playbooks',
                    icon: <BugIcon color="error" />
                  }
                ].map((item, idx) => (
                  <Grid item xs={12} sm={6} md={4} key={idx}>
                    <Box sx={{ p: 2, bgcolor: '#1e293b', borderRadius: 2, border: '1px solid rgba(255,255,255,0.08)', height: '100%' }}>
                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 0.5 }}>
                        {item.icon}
                        <Typography variant="subtitle2" sx={{ fontWeight: 700, color: '#f8fafc' }}>
                          {item.step}
                        </Typography>
                      </Box>
                      <Typography variant="caption" sx={{ color: '#94a3b8' }}>
                        {item.desc}
                      </Typography>
                    </Box>
                  </Grid>
                ))}
              </Grid>

              <Alert severity="success" icon={<CheckIcon fontSize="inherit" />}>
                Unified mode provides complete executive intelligence in a single run. Results automatically populate the findings table, risk charts, and downloadable PDF reports.
              </Alert>
            </Box>
          )}

          {/* Subdomain Enumeration */}
          {activeTab === 1 && (
            <Box>
              <Typography variant="h6" gutterBottom>
                Subdomain Enumeration
              </Typography>
              <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                Discover subdomains using multiple techniques including brute force, certificate transparency (crt.sh), and DNS enumeration.
              </Typography>
              <Alert severity="info" sx={{ mb: 2 }}>
                This scan will attempt to find subdomains of your target domain. Results include verified resolving subdomains.
              </Alert>
            </Box>
          )}

          {/* Port Scanning */}
          {activeTab === 2 && (
            <Box>
              <Typography variant="h6" gutterBottom>
                High-Speed Port & Banner Scanning
              </Typography>
              <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                Identify open ports and running service banners across standard network protocols.
              </Typography>
              <FormControl fullWidth sx={{ mb: 2 }}>
                <InputLabel>Port Range</InputLabel>
                <Select
                  value={portRange}
                  onChange={(e) => setPortRange(e.target.value)}
                  label="Port Range"
                >
                  <MenuItem value="21,22,23,25,53,80,110,143,443,445,993,995,1433,3306,3389,5432,5900,8080,8443">Standard Security Probe Ports</MenuItem>
                  <MenuItem value="1-1000">Top 1000 ports</MenuItem>
                  <MenuItem value="80,443,8080,8443">Web ports only</MenuItem>
                  <MenuItem value="1-65535">All ports (comprehensive)</MenuItem>
                </Select>
              </FormControl>
              <Alert severity="warning">
                Native socket probes execute rapidly and gather software banners without requiring local Nmap binaries.
              </Alert>
            </Box>
          )}

          {/* Vulnerability Scanning */}
          {activeTab === 3 && (
            <Box>
              <Typography variant="h6" gutterBottom>
                Web & Network Vulnerability Assessment
              </Typography>
              <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                Analyze the target for missing headers (CSP, HSTS, X-Frame-Options), cookie flags, sensitive exposed paths, and CVEs.
              </Typography>
              <FormControl fullWidth sx={{ mb: 2 }}>
                <InputLabel>Scan Type</InputLabel>
                <Select
                  value={scanType}
                  onChange={(e) => setScanType(e.target.value)}
                  label="Scan Type"
                >
                  <MenuItem value="comprehensive">Comprehensive (All Checks)</MenuItem>
                  <MenuItem value="web">Web Application & Headers</MenuItem>
                  <MenuItem value="network">Network Services</MenuItem>
                  <MenuItem value="basic">Basic (Quick)</MenuItem>
                </Select>
              </FormControl>
              <Alert severity="info">
                Findings are enriched with CVSS v3.1 vectors, CISA KEV tags, EPSS probabilities, and copyable remediation playbooks.
              </Alert>
            </Box>
          )}

          {/* DNS Enumeration */}
          {activeTab === 4 && (
            <Box>
              <Typography variant="h6" gutterBottom>
                DNS Enumeration
              </Typography>
              <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                Gather DNS records to understand the domain infrastructure.
              </Typography>
              <List dense>
                <ListItem>
                  <ListItemIcon><DnsIcon /></ListItemIcon>
                  <ListItemText primary="A Records" secondary="IPv4 addresses" />
                </ListItem>
                <ListItem>
                  <ListItemIcon><DnsIcon /></ListItemIcon>
                  <ListItemText primary="MX Records" secondary="Mail servers" />
                </ListItem>
                <ListItem>
                  <ListItemIcon><DnsIcon /></ListItemIcon>
                  <ListItemText primary="NS Records" secondary="Name servers" />
                </ListItem>
                <ListItem>
                  <ListItemIcon><DnsIcon /></ListItemIcon>
                  <ListItemText primary="TXT Records" secondary="Text records (SPF, DMARC, verification)" />
                </ListItem>
              </List>
            </Box>
          )}

          {/* WHOIS Lookup */}
          {activeTab === 5 && (
            <Box>
              <Typography variant="h6" gutterBottom>
                WHOIS Lookup
              </Typography>
              <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                Retrieve domain registration information, expiration date, and registrar details.
              </Typography>
              <Alert severity="info">
                WHOIS data includes registrar information, creation date, expiration date, and nameservers.
              </Alert>
            </Box>
          )}

          {/* Advanced Options Accordion */}
          <Accordion sx={{ mt: 3 }}>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Typography sx={{ fontWeight: 600 }}>Advanced Assessment Options</Typography>
            </AccordionSummary>
            <AccordionDetails>
              <Grid container spacing={2}>
                <Grid item xs={12} sm={6}>
                  <TextField
                    fullWidth
                    label="Socket Probe Timeout (seconds)"
                    type="number"
                    defaultValue={10}
                    variant="outlined"
                    size="small"
                  />
                </Grid>
                <Grid item xs={12} sm={6}>
                  <TextField
                    fullWidth
                    label="Parallel Worker Threads"
                    type="number"
                    defaultValue={40}
                    variant="outlined"
                    size="small"
                  />
                </Grid>
                <Grid item xs={12}>
                  <FormControlLabel
                    control={<Switch defaultChecked />}
                    label="Enable AI Threat Analysis & Remediation Recommendations"
                  />
                </Grid>
              </Grid>
            </AccordionDetails>
          </Accordion>
        </CardContent>
      </Card>
    </Box>
  );
};

export default Scanner;
