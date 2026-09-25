import React, { useState } from 'react';
import {
  Box,
  Card,
  CardContent,
  Typography,
  List,
  Chip,
  Button,
  Grid,
  Alert,
  IconButton,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  TextField,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  Accordion,
  AccordionSummary,
  AccordionDetails
} from '@mui/material';
import {
  Visibility as ViewIcon,
  Download as DownloadIcon,
  Delete as DeleteIcon,
  ExpandMore as ExpandMoreIcon,
  BugReport as BugIcon,
  Security as SecurityIcon,
  Warning as WarningIcon,
  LockOpen as LockOpenIcon,
  ContentCopy as ContentCopyIcon,
  Check as CheckIcon,
  Terminal as TerminalIcon,
  PlaylistAddCheck as PlaybookIcon
} from '@mui/icons-material';
import { useScan } from '../context/ScanContext';
import ReactJson from 'react-json-view';

const Results = ({ showNotification }) => {
  const { scanHistory, removeScanFromHistory, generateReport } = useScan();
  const [selectedResult, setSelectedResult] = useState(null);
  const [dialogOpen, setDialogOpen] = useState(false);
  const [filter, setFilter] = useState('all');
  const [searchTerm, setSearchTerm] = useState('');
  const [copiedSnippetId, setCopiedSnippetId] = useState(null);

  const handleCopySnippet = (snippet, id) => {
    if (!snippet) return;
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(snippet);
    } else {
      const textarea = document.createElement('textarea');
      textarea.value = snippet;
      document.body.appendChild(textarea);
      textarea.select();
      document.execCommand('copy');
      document.body.removeChild(textarea);
    }
    setCopiedSnippetId(id);
    if (showNotification) {
      showNotification('Remediation command copied to clipboard!', 'success');
    }
    setTimeout(() => {
      setCopiedSnippetId((prev) => (prev === id ? null : prev));
    }, 2500);
  };

  const handleViewResult = (result, index) => {
    setSelectedResult({ ...result, index });
    setDialogOpen(true);
  };

  const handleDeleteResult = (index) => {
    removeScanFromHistory(index);
    showNotification('Scan result deleted', 'info');
  };

  const handleGenerateReport = async (result) => {
    try {
      const report = await generateReport(result, 'html');
      showNotification(`Report generated: ${report.report_path}`, 'success');
    } catch (error) {
      showNotification(`Report generation failed: ${error?.error || error?.message || error}`, 'error');
    }
  };

  const filteredResults = scanHistory.filter((result) => {
    const scanType = result.scan_type?.toLowerCase() || '';
    const isVulnerabilityScan = ['vulnerability', 'basic', 'web', 'network', 'comprehensive'].includes(scanType)
      || Array.isArray(result.vulnerabilities) || Array.isArray(result.misconfigurations);
    const matchesFilter = filter === 'all'
      || (filter === 'vulnerability' ? isVulnerabilityScan : scanType.includes(filter));

    const normalizedSearch = searchTerm.trim().toLowerCase();
    const matchesSearch = !normalizedSearch
      || [result.domain, result.target].filter(Boolean).some((value) => value.toLowerCase().includes(normalizedSearch));

    return matchesFilter && matchesSearch;
  });

  const getSeverityColor = (severity) => {
    const colors = {
      'Critical': 'error',
      'High': 'error',
      'Medium': 'warning',
      'Low': 'success'
    };
    return colors[severity] || 'default';
  };

  const getCvssScore = (vuln) => {
    if (vuln.cvss_score != null) return Number(vuln.cvss_score).toFixed(1);
    if (vuln.cvss != null) return Number(vuln.cvss).toFixed(1);
    const sev = (vuln.severity || 'Low').toLowerCase();
    if (sev === 'critical') return '9.8';
    if (sev === 'high') return '7.8';
    if (sev === 'medium') return '5.4';
    return '2.5';
  };

  const getCvssColor = (score) => {
    const num = Number(score);
    if (num >= 9.0) return { color: '#ffffff', bg: '#d32f2f', border: '#b71c1c' };
    if (num >= 7.0) return { color: '#ffffff', bg: '#f57c00', border: '#e65100' };
    if (num >= 4.0) return { color: '#1a1a1a', bg: '#fbc02d', border: '#f57f17' };
    return { color: '#ffffff', bg: '#388e3c', border: '#1b5e20' };
  };

  const renderMisconfigurations = (misconfigurations, targetHost = '127.0.0.1') => {
    if (!misconfigurations || misconfigurations.length === 0) {
      return null;
    }

    return (
      <Box sx={{ mt: 2, mb: 3 }}>
        <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 1.5, flexWrap: 'wrap', gap: 1 }}>
          <Typography variant="h6" sx={{ display: 'flex', alignItems: 'center', gap: 1, color: '#ff9800', fontWeight: 700 }}>
            <WarningIcon color="warning" fontSize="small" />
            Critical Misconfigurations & Insecure Services ({misconfigurations.length})
          </Typography>
          <Chip
            label="Service & Credential Auditor"
            size="small"
            variant="outlined"
            sx={{ borderColor: 'rgba(255, 152, 0, 0.4)', color: '#ffb74d', fontWeight: 600, fontSize: '0.75rem' }}
          />
        </Box>

        <Alert severity="warning" sx={{ mb: 2, bgcolor: 'rgba(255, 152, 0, 0.08)', color: '#ffe0b2', border: '1px solid rgba(255, 152, 0, 0.2)' }}>
          The following insecure network services, administrative exposures, or default credential vectors were actively verified.
        </Alert>

        {misconfigurations.map((item, index) => {
          const cvssScore = getCvssScore(item);
          const cvssTheme = getCvssColor(cvssScore);
          const isCritical = (item.severity || '').toLowerCase() === 'critical';
          const snippetId = `misc-${index}`;

          return (
            <Accordion
              key={index}
              defaultExpanded={index === 0}
              sx={{
                mb: 1.5,
                bgcolor: '#221e1a',
                border: isCritical ? '1.5px solid #ff5722' : '1px solid rgba(255, 152, 0, 0.25)',
                boxShadow: isCritical ? '0 0 14px rgba(255, 87, 34, 0.25)' : 'none',
                borderRadius: '8px !important',
                '&:before': { display: 'none' },
              }}
            >
              <AccordionSummary
                expandIcon={<ExpandMoreIcon sx={{ color: '#ffb74d' }} />}
                sx={{
                  px: 2,
                  py: 1,
                  '& .MuiAccordionSummary-content': {
                    display: 'flex',
                    justifyContent: 'space-between',
                    alignItems: 'center',
                    flexWrap: 'wrap',
                    gap: 1.5,
                    my: 0.5,
                  },
                }}
              >
                {/* Collapsed State: Category / Title & Target Host IP */}
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5, flexWrap: 'wrap', flex: 1, minWidth: 280 }}>
                  <LockOpenIcon sx={{ color: isCritical ? '#ff5722' : '#ffa726', fontSize: 20 }} />
                  <Typography variant="subtitle1" sx={{ fontWeight: 700, color: '#ffffff' }}>
                    {item.title}
                  </Typography>
                  <Chip
                    label={`Host: ${targetHost}`}
                    size="small"
                    sx={{
                      bgcolor: 'rgba(255, 152, 0, 0.12)',
                      color: '#ffb74d',
                      fontFamily: 'monospace',
                      fontSize: '0.7rem',
                      height: 22,
                    }}
                  />
                  {item.category && (
                    <Chip
                      label={item.category}
                      size="small"
                      sx={{
                        bgcolor: 'rgba(255, 152, 0, 0.15)',
                        color: '#ffb74d',
                        fontWeight: 600,
                        fontSize: '0.7rem',
                        border: '1px solid rgba(255, 152, 0, 0.3)',
                        height: 22,
                      }}
                    />
                  )}
                </Box>

                {/* Collapsed State: Severity Badge & CVSS Score */}
                <Box sx={{ display: 'flex', gap: 1, alignItems: 'center', flexWrap: 'wrap' }}>
                  <Box
                    sx={{
                      px: 1.2,
                      py: 0.3,
                      borderRadius: '16px',
                      bgcolor: cvssTheme.bg,
                      color: cvssTheme.color,
                      border: `1px solid ${cvssTheme.border}`,
                      fontWeight: 800,
                      fontSize: '0.75rem',
                      letterSpacing: '0.02em',
                      display: 'inline-flex',
                      alignItems: 'center',
                      boxShadow: '0 2px 4px rgba(0,0,0,0.3)',
                    }}
                  >
                    CVSS {cvssScore}
                  </Box>

                  <Chip
                    label={(item.severity || 'Medium').toUpperCase()}
                    color={getSeverityColor(item.severity)}
                    size="small"
                    sx={{ fontWeight: 700, fontSize: '0.75rem' }}
                  />
                </Box>
              </AccordionSummary>

              <AccordionDetails sx={{ px: 2.5, pb: 2.5, pt: 1, borderTop: '1px solid rgba(255, 152, 0, 0.12)' }}>
                {/* Description & Impact */}
                <Box sx={{ mb: 2 }}>
                  <Typography variant="body2" sx={{ color: '#eceff1', mb: 1, lineHeight: 1.6 }}>
                    {item.description}
                  </Typography>
                  {item.impact && (
                    <Box sx={{ p: 1.2, bgcolor: 'rgba(255, 87, 34, 0.08)', borderRadius: 1.5, borderLeft: '3px solid #ff5722', mb: 1.5 }}>
                      <Typography variant="body2" sx={{ color: '#ffab91', fontSize: '0.85rem' }}>
                        <strong>Security & Operational Impact:</strong> {item.impact}
                      </Typography>
                    </Box>
                  )}
                </Box>

                {/* Affected Component / Port */}
                <Box
                  sx={{
                    p: 1.2,
                    mb: 2,
                    bgcolor: '#191512',
                    borderRadius: 1.5,
                    border: '1px solid rgba(255, 152, 0, 0.12)',
                    display: 'flex',
                    flexWrap: 'wrap',
                    gap: 2.5,
                    fontSize: '0.8rem',
                  }}
                >
                  <Typography variant="caption" sx={{ color: 'text.secondary' }}>
                    <strong>Target Host:</strong> {targetHost}
                  </Typography>
                  <Typography variant="caption" sx={{ color: 'text.secondary' }}>
                    <strong>Protocol / Port:</strong> {item.protocol ? `${item.protocol.toUpperCase()} / ` : ''}Port {item.port || 'N/A'}
                  </Typography>
                  {item.url && (
                    <Typography variant="caption" sx={{ color: '#ffb74d', fontFamily: 'monospace' }}>
                      <strong>Target URI:</strong> {item.url}
                    </Typography>
                  )}
                </Box>

                {/* Remediation Playbook (Step-by-Step) */}
                {((item.remediation_steps && item.remediation_steps.length > 0) || item.remediation) && (
                  <Box sx={{ mb: 2, p: 2, bgcolor: '#2a221b', borderRadius: 2, border: '1px solid rgba(255, 152, 0, 0.25)' }}>
                    <Typography variant="subtitle2" sx={{ color: '#ffb74d', fontWeight: 700, display: 'flex', alignItems: 'center', gap: 1, mb: 1 }}>
                      <PlaybookIcon fontSize="small" />
                      Remediation Playbook (Administrator Action Plan)
                    </Typography>

                    {item.remediation_steps && item.remediation_steps.length > 0 ? (
                      <Box component="ol" sx={{ pl: 2.5, m: 0 }}>
                        {item.remediation_steps.map((step, sIdx) => (
                          <Typography component="li" key={sIdx} variant="body2" sx={{ color: '#ffe0b2', mb: 0.8, fontSize: '0.85rem' }}>
                            {step.replace(/^\d+\.\s*/, '')}
                          </Typography>
                        ))}
                      </Box>
                    ) : (
                      <Typography variant="body2" sx={{ color: '#ffe0b2' }}>
                        {item.remediation}
                      </Typography>
                    )}
                  </Box>
                )}

                {/* Copyable Fix Snippet */}
                {item.fix_snippet && (
                  <Box sx={{ bgcolor: '#121212', borderRadius: 2, border: '1px solid rgba(255, 152, 0, 0.2)', overflow: 'hidden' }}>
                    <Box sx={{ px: 2, py: 1, bgcolor: '#1b1714', display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px solid rgba(255, 152, 0, 0.1)' }}>
                      <Typography variant="caption" sx={{ color: '#ffb74d', fontFamily: 'monospace', fontWeight: 600, display: 'flex', alignItems: 'center', gap: 0.8 }}>
                        <TerminalIcon fontSize="inherit" sx={{ color: '#ffa726' }} />
                        CONFIGURATION / SHELL REMEDIATION SNIPPET
                      </Typography>
                      <Button
                        size="small"
                        variant="outlined"
                        onClick={() => handleCopySnippet(item.fix_snippet, snippetId)}
                        startIcon={copiedSnippetId === snippetId ? <CheckIcon sx={{ color: '#4caf50' }} /> : <ContentCopyIcon fontSize="small" />}
                        sx={{
                          py: 0.2,
                          px: 1,
                          fontSize: '0.7rem',
                          color: copiedSnippetId === snippetId ? '#81c784' : '#ffb74d',
                          borderColor: copiedSnippetId === snippetId ? '#4caf50' : 'rgba(255, 152, 0, 0.3)',
                          textTransform: 'none',
                        }}
                      >
                        {copiedSnippetId === snippetId ? 'Copied!' : 'Copy Fix Snippet'}
                      </Button>
                    </Box>
                    <Box sx={{ p: 2, overflowX: 'auto' }}>
                      <Typography
                        component="pre"
                        sx={{
                          m: 0,
                          fontFamily: 'Consolas, Monaco, "Courier New", monospace',
                          fontSize: '0.8rem',
                          color: '#80cbc4',
                          lineHeight: 1.5,
                          whiteSpace: 'pre-wrap',
                        }}
                      >
                        {item.fix_snippet}
                      </Typography>
                    </Box>
                  </Box>
                )}
              </AccordionDetails>
            </Accordion>
          );
        })}
      </Box>
    );
  };

  const renderVulnerabilities = (vulnerabilities, targetHost = '127.0.0.1') => {
    if (!vulnerabilities || vulnerabilities.length === 0) {
      return <Typography variant="body2">No vulnerabilities found</Typography>;
    }

    return (
      <Box sx={{ mt: 2 }}>
        <Typography variant="h6" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
          <BugIcon color="error" fontSize="small" />
          Vulnerabilities & Exploit Threat Intelligence ({vulnerabilities.length})
        </Typography>
        {vulnerabilities.map((vuln, index) => {
          const cvssScore = getCvssScore(vuln);
          const cvssTheme = getCvssColor(cvssScore);
          const isKev = vuln.cisa_kev_listed || vuln.active_exploit_in_wild;
          const isEpssHigh = vuln.epss_high_risk || (vuln.epss_score != null && vuln.epss_score >= 0.50) || (isKev && vuln.epss_score == null);
          const epssText = vuln.epss_percentile || (vuln.epss_score != null ? `${Math.round(vuln.epss_score * 100)}th percentile` : '85th percentile');
          const snippetId = `vuln-${index}`;

          return (
            <Accordion
              key={index}
              defaultExpanded={index === 0}
              sx={{
                mb: 1.5,
                bgcolor: '#242424',
                border: isKev ? '1.5px solid #d32f2f' : '1px solid rgba(255, 255, 255, 0.08)',
                boxShadow: isKev ? '0 0 12px rgba(211, 47, 47, 0.25)' : 'none',
                borderRadius: '8px !important',
                '&:before': { display: 'none' },
              }}
            >
              <AccordionSummary
                expandIcon={<ExpandMoreIcon sx={{ color: 'text.secondary' }} />}
                sx={{
                  px: 2,
                  py: 1,
                  '& .MuiAccordionSummary-content': {
                    display: 'flex',
                    justifyContent: 'space-between',
                    alignItems: 'center',
                    flexWrap: 'wrap',
                    gap: 1.5,
                    my: 0.5,
                  },
                }}
              >
                {/* Collapsed State: CVE ID, Vulnerability Name, Target Host IP */}
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5, flexWrap: 'wrap', flex: 1, minWidth: 280 }}>
                  {vuln.cve_id && (
                    <Chip
                      label={vuln.cve_id}
                      size="small"
                      variant="outlined"
                      sx={{
                        fontFamily: 'monospace',
                        fontWeight: 700,
                        fontSize: '0.75rem',
                        color: 'primary.light',
                        borderColor: 'primary.main',
                      }}
                    />
                  )}
                  <Typography variant="subtitle1" sx={{ fontWeight: 700, color: 'text.primary' }}>
                    {vuln.title || 'Unknown Vulnerability'}
                  </Typography>
                  <Chip
                    label={`Host: ${targetHost}`}
                    size="small"
                    sx={{
                      bgcolor: 'rgba(255, 255, 255, 0.05)',
                      color: 'text.secondary',
                      fontFamily: 'monospace',
                      fontSize: '0.7rem',
                      height: 22,
                    }}
                  />
                </Box>

                {/* Collapsed State: Severity Badge & CVSS Score */}
                <Box sx={{ display: 'flex', gap: 1, alignItems: 'center', flexWrap: 'wrap' }}>
                  {/* CVSS Score Pill */}
                  <Box
                    sx={{
                      px: 1.2,
                      py: 0.3,
                      borderRadius: '16px',
                      bgcolor: cvssTheme.bg,
                      color: cvssTheme.color,
                      border: `1px solid ${cvssTheme.border}`,
                      fontWeight: 800,
                      fontSize: '0.75rem',
                      letterSpacing: '0.02em',
                      display: 'inline-flex',
                      alignItems: 'center',
                      boxShadow: '0 2px 4px rgba(0,0,0,0.3)',
                    }}
                  >
                    CVSS {cvssScore}
                  </Box>

                  {/* CISA KEV Listed Badge */}
                  {isKev && (
                    <Chip
                      label="CISA KEV Listed"
                      size="small"
                      sx={{
                        bgcolor: '#d32f2f',
                        color: '#ffffff',
                        fontWeight: 800,
                        fontSize: '0.75rem',
                        boxShadow: '0 2px 6px rgba(211, 47, 47, 0.4)',
                      }}
                    />
                  )}

                  {/* EPSS High Exploit Risk Badge */}
                  {isEpssHigh && (
                    <Chip
                      label={`EPSS ${epssText}`}
                      size="small"
                      sx={{
                        bgcolor: '#f57c00',
                        color: '#ffffff',
                        fontWeight: 700,
                        fontSize: '0.75rem',
                      }}
                    />
                  )}

                  {/* Unified Severity Badge */}
                  <Chip
                    label={(vuln.severity || 'Low').toUpperCase()}
                    color={getSeverityColor(vuln.severity)}
                    size="small"
                    sx={{ fontWeight: 700, fontSize: '0.75rem' }}
                  />
                </Box>
              </AccordionSummary>

              <AccordionDetails sx={{ px: 2.5, pb: 2.5, pt: 1, borderTop: '1px solid rgba(255, 255, 255, 0.05)' }}>
                {/* Description & Impact */}
                <Box sx={{ mb: 2 }}>
                  <Typography variant="body2" sx={{ color: 'text.primary', mb: 1, lineHeight: 1.6 }}>
                    {vuln.description || 'No description available'}
                  </Typography>
                  {vuln.impact && (
                    <Box sx={{ p: 1.2, bgcolor: 'rgba(244, 67, 54, 0.08)', borderRadius: 1.5, borderLeft: '3px solid #f44336', mb: 1.5 }}>
                      <Typography variant="body2" sx={{ color: '#ef9a9a', fontSize: '0.85rem' }}>
                        <strong>Security & Operational Impact:</strong> {vuln.impact}
                      </Typography>
                    </Box>
                  )}
                </Box>

                {/* Affected Component / Port */}
                <Box
                  sx={{
                    p: 1.2,
                    mb: 2,
                    bgcolor: '#1a1a1a',
                    borderRadius: 1.5,
                    border: '1px solid rgba(255, 255, 255, 0.05)',
                    display: 'flex',
                    flexWrap: 'wrap',
                    gap: 2.5,
                    fontSize: '0.8rem',
                  }}
                >
                  <Typography variant="caption" sx={{ color: 'text.secondary' }}>
                    <strong>Target Host:</strong> {targetHost}
                  </Typography>
                  <Typography variant="caption" sx={{ color: 'text.secondary' }}>
                    <strong>Affected Component / Port:</strong> {vuln.port || 'N/A'} {vuln.service ? `(${vuln.service.toUpperCase()})` : ''}
                  </Typography>
                  <Typography variant="caption" sx={{ color: 'text.secondary' }}>
                    <strong>Category / Type:</strong> {vuln.type || vuln.category || 'General Security'}
                  </Typography>
                  {isKev && (
                    <Typography variant="caption" sx={{ color: '#f44336', fontWeight: 700 }}>
                      ⚡ Active Weaponized Exploit in the Wild: Verified
                    </Typography>
                  )}
                </Box>

                {/* Remediation Playbook (Step-by-Step for network administrators) */}
                {((vuln.remediation_steps && vuln.remediation_steps.length > 0) || vuln.recommendation) && (
                  <Box sx={{ mb: 2, p: 2, bgcolor: '#1e2429', borderRadius: 2, border: '1px solid rgba(138, 155, 168, 0.2)' }}>
                    <Typography variant="subtitle2" sx={{ color: 'primary.light', fontWeight: 700, display: 'flex', alignItems: 'center', gap: 1, mb: 1 }}>
                      <PlaybookIcon fontSize="small" />
                      Remediation Playbook (Administrator Action Plan)
                    </Typography>

                    {vuln.remediation_steps && vuln.remediation_steps.length > 0 ? (
                      <Box component="ol" sx={{ pl: 2.5, m: 0 }}>
                        {vuln.remediation_steps.map((step, sIdx) => (
                          <Typography component="li" key={sIdx} variant="body2" sx={{ color: '#cfd8dc', mb: 0.8, fontSize: '0.85rem' }}>
                            {step.replace(/^\d+\.\s*/, '')}
                          </Typography>
                        ))}
                      </Box>
                    ) : (
                      <Typography variant="body2" sx={{ color: '#cfd8dc' }}>
                        {vuln.recommendation}
                      </Typography>
                    )}
                  </Box>
                )}

                {/* Copyable Configuration / Shell Fix Snippet */}
                {vuln.fix_snippet && (
                  <Box sx={{ bgcolor: '#121212', borderRadius: 2, border: '1px solid rgba(255, 255, 255, 0.1)', overflow: 'hidden' }}>
                    <Box sx={{ px: 2, py: 1, bgcolor: '#1a1a1a', display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px solid rgba(255, 255, 255, 0.05)' }}>
                      <Typography variant="caption" sx={{ color: 'text.secondary', fontFamily: 'monospace', fontWeight: 600, display: 'flex', alignItems: 'center', gap: 0.8 }}>
                        <TerminalIcon fontSize="inherit" sx={{ color: 'primary.light' }} />
                        CONFIGURATION / SHELL REMEDIATION SNIPPET
                      </Typography>
                      <Button
                        size="small"
                        variant="outlined"
                        onClick={() => handleCopySnippet(vuln.fix_snippet, snippetId)}
                        startIcon={copiedSnippetId === snippetId ? <CheckIcon sx={{ color: '#4caf50' }} /> : <ContentCopyIcon fontSize="small" />}
                        sx={{
                          py: 0.2,
                          px: 1,
                          fontSize: '0.7rem',
                          color: copiedSnippetId === snippetId ? '#81c784' : 'text.primary',
                          borderColor: copiedSnippetId === snippetId ? '#4caf50' : 'rgba(255, 255, 255, 0.2)',
                          textTransform: 'none',
                        }}
                      >
                        {copiedSnippetId === snippetId ? 'Copied!' : 'Copy Fix Snippet'}
                      </Button>
                    </Box>
                    <Box sx={{ p: 2, overflowX: 'auto' }}>
                      <Typography
                        component="pre"
                        sx={{
                          m: 0,
                          fontFamily: 'Consolas, Monaco, "Courier New", monospace',
                          fontSize: '0.8rem',
                          color: '#80cbc4',
                          lineHeight: 1.5,
                          whiteSpace: 'pre-wrap',
                        }}
                      >
                        {vuln.fix_snippet}
                      </Typography>
                    </Box>
                  </Box>
                )}
              </AccordionDetails>
            </Accordion>
          );
        })}
      </Box>
    );
  };

  const renderSubdomains = (subdomains) => {
    if (!subdomains || subdomains.length === 0) {
      return <Typography variant="body2">No subdomains found</Typography>;
    }

    return (
      <Box sx={{ mt: 2 }}>
        <Typography variant="h6" gutterBottom>
          Subdomains ({subdomains.length})
        </Typography>
        <div className="subdomain-grid">
          {subdomains.slice(0, 20).map((subdomain, index) => (
            <div key={index} className="subdomain-item">
              {subdomain}
            </div>
          ))}
          {subdomains.length > 20 && (
            <div className="subdomain-item" style={{ fontStyle: 'italic' }}>
              ... and {subdomains.length - 20} more
            </div>
          )}
        </div>
      </Box>
    );
  };

  const renderPortScan = (scanResults) => {
    if (!scanResults || scanResults.length === 0) {
      return <Typography variant="body2">No port scan results</Typography>;
    }

    return (
      <Box sx={{ mt: 2 }}>
        <Typography variant="h6" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
          <SecurityIcon color="primary" fontSize="small" />
          Host Discovery & Port Scan Results ({scanResults.length} {scanResults.length === 1 ? 'Host' : 'Hosts'})
        </Typography>
        {scanResults.map((host, hostIndex) => (
          <Box
            key={hostIndex}
            sx={{
              mb: 2.5,
              p: 2,
              bgcolor: '#242424',
              borderRadius: 2,
              border: '1px solid rgba(255, 255, 255, 0.08)',
            }}
          >
            {/* Host Header: IP, Canonical Hostname, Alive Chip, Inferred OS */}
            <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: 1, mb: 1.5 }}>
              <Box>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5, flexWrap: 'wrap' }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 700, color: 'text.primary' }}>
                    {host.ip_address || host.host}
                  </Typography>
                  {host.hostname && host.hostname !== (host.ip_address || host.host) && (
                    <Typography variant="body2" sx={{ color: 'text.secondary', fontStyle: 'italic' }}>
                      ({host.hostname})
                    </Typography>
                  )}
                </Box>
                <Typography variant="caption" sx={{ color: 'text.secondary', display: 'block', mt: 0.2 }}>
                  Canonical Name: <strong>{host.hostname || host.ip_address || host.host}</strong>
                </Typography>
              </Box>

              <Box sx={{ display: 'flex', gap: 1, alignItems: 'center', flexWrap: 'wrap' }}>
                <Chip
                  label={host.alive || host.state === 'up' ? 'Alive / Active' : 'Offline'}
                  color={host.alive || host.state === 'up' ? 'success' : 'default'}
                  size="small"
                  sx={{ fontWeight: 600, fontSize: '0.75rem' }}
                />
                {host.inferred_os && (
                  <Chip
                    label={`OS: ${host.inferred_os}`}
                    variant="outlined"
                    size="small"
                    sx={{
                      color: '#a8b8c4',
                      borderColor: 'rgba(168, 184, 196, 0.3)',
                      backgroundColor: 'rgba(168, 184, 196, 0.06)',
                      fontSize: '0.75rem',
                      fontWeight: 500,
                    }}
                  />
                )}
              </Box>
            </Box>

            {/* Open Ports List */}
            {host.open_ports && host.open_ports.length > 0 ? (
              <Box sx={{ mt: 1 }}>
                <Typography variant="caption" sx={{ fontWeight: 600, color: 'text.secondary', letterSpacing: '0.05em', textTransform: 'uppercase', display: 'block', mb: 1 }}>
                  Discovered Ports ({host.open_ports.length})
                </Typography>
                <Grid container spacing={1}>
                  {host.open_ports.map((port, portIndex) => (
                    <Grid item xs={12} sm={6} md={4} key={portIndex}>
                      <Box
                        sx={{
                          p: 1.2,
                          bgcolor: '#1a1a1a',
                          borderRadius: 1.5,
                          border: '1px solid rgba(255, 255, 255, 0.05)',
                        }}
                      >
                        <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                          <Typography variant="body2" sx={{ fontWeight: 700, color: 'primary.light' }}>
                            Port {port.port}/{port.protocol || 'tcp'}
                          </Typography>
                          <Chip
                            label={port.state || 'open'}
                            size="small"
                            variant="outlined"
                            color={port.state === 'open' ? 'success' : 'default'}
                            sx={{ height: 20, fontSize: '0.65rem' }}
                          />
                        </Box>
                        <Typography variant="caption" sx={{ color: 'text.secondary', display: 'block', mt: 0.5 }}>
                          <strong>Service:</strong> {port.service || 'unknown'}
                        </Typography>
                        {(port.product || port.version) && (
                          <Typography variant="caption" sx={{ color: 'text.secondary', display: 'block' }}>
                            <strong>Version:</strong> {[port.product, port.version].filter(Boolean).join(' ')}
                          </Typography>
                        )}
                      </Box>
                    </Grid>
                  ))}
                </Grid>
              </Box>
            ) : (
              <Typography variant="body2" sx={{ color: 'text.secondary', fontStyle: 'italic', mt: 1 }}>
                No open ports identified in the requested port range.
              </Typography>
            )}
          </Box>
        ))}
      </Box>
    );
  };

  const renderAIAnalysis = (aiAnalysis) => {
    if (!aiAnalysis) return null;

    // Analyses degrade to built-in heuristics when no AI key is configured
    // or the model request fails; that origin must stay visible instead of
    // masquerading as a model assessment.
    const fellBack = aiAnalysis.source === 'fallback'
      || Object.values(aiAnalysis.sources || {}).includes('fallback');

    return (
      <Box className="ai-analysis" sx={{ mt: 2 }}>
        <Typography variant="h6" gutterBottom>
          🤖 AI Security Analysis
        </Typography>

        {fellBack && (
          <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
            Produced with built-in fallback heuristics (no AI key configured or the AI request failed).
          </Typography>
        )}
        
        {aiAnalysis.assessment && (
          <Typography variant="body1" sx={{ mb: 2 }}>
            <strong>Assessment:</strong> {aiAnalysis.assessment}
          </Typography>
        )}
        
        {aiAnalysis.risk_level && (
          <Typography variant="body1" sx={{ mb: 2 }}>
            <strong>Risk Level:</strong> {aiAnalysis.risk_level}
          </Typography>
        )}
        
        {aiAnalysis.recommendations && Array.isArray(aiAnalysis.recommendations) && (
          <Box>
            <Typography variant="body1" sx={{ fontWeight: 'bold', mb: 1 }}>
              Recommendations:
            </Typography>
            <ul style={{ margin: 0, paddingLeft: 20 }}>
              {aiAnalysis.recommendations.map((rec, index) => (
                <li key={index}>
                  <Typography variant="body2">{rec}</Typography>
                </li>
              ))}
            </ul>
          </Box>
        )}
      </Box>
    );
  };

  return (
    <Box>
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
        <Typography variant="h4" component="h1" sx={{ fontWeight: 'bold' }}>
          Scan Results
        </Typography>
      </Box>

      {/* Filters */}
      <Card sx={{ mb: 3 }}>
        <CardContent>
          <Grid container spacing={2} alignItems="center">
            <Grid item xs={12} sm={6} md={4}>
              <TextField
                fullWidth
                label="Search"
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                placeholder="Search by target or domain..."
                variant="outlined"
                size="small"
              />
            </Grid>
            <Grid item xs={12} sm={6} md={4}>
              <FormControl fullWidth size="small">
                <InputLabel>Filter by Type</InputLabel>
                <Select
                  value={filter}
                  onChange={(e) => setFilter(e.target.value)}
                  label="Filter by Type"
                >
                  <MenuItem value="all">All Scans</MenuItem>
                  <MenuItem value="subdomain">Subdomain</MenuItem>
                  <MenuItem value="port">Port Scan</MenuItem>
                  <MenuItem value="vulnerability">Vulnerability</MenuItem>
                  <MenuItem value="dns">DNS</MenuItem>
                  <MenuItem value="whois">WHOIS</MenuItem>
                </Select>
              </FormControl>
            </Grid>
            <Grid item xs={12} sm={12} md={4}>
              <Typography variant="body2" color="text.secondary">
                {filteredResults.length} of {scanHistory.length} results
              </Typography>
            </Grid>
          </Grid>
        </CardContent>
      </Card>

      {/* Results List */}
      {filteredResults.length === 0 ? (
        <Alert severity="info">
          {scanHistory.length === 0 
            ? "No scan results yet. Run your first scan to see results here!"
            : "No results match your current filters."}
        </Alert>
      ) : (
        <List>
          {filteredResults.map((result, index) => {
            const actualIndex = scanHistory.indexOf(result);
            const vulnerabilityCount = result.vulnerabilities?.length || 0;
            const misconfigurationCount = result.misconfigurations?.length || 0;
            const subdomainCount = result.subdomains?.length || 0;
            const target = result.domain || result.target || 'Unknown';
            
            return (
              <Card key={actualIndex} sx={{ mb: 2 }} className="fade-in">
                <CardContent>
                  <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                    <Box sx={{ flex: 1 }}>
                      <Typography variant="h6" gutterBottom>
                        {target}
                      </Typography>
                      <Box sx={{ display: 'flex', gap: 1, mb: 2, flexWrap: 'wrap' }}>
                        <Chip 
                          label={result.scan_type || 'Unknown'} 
                          color="primary" 
                          size="small" 
                        />
                        {misconfigurationCount > 0 && (
                          <Chip 
                            label={`${misconfigurationCount} misconfigurations`}
                            color="warning"
                            size="small"
                            icon={<WarningIcon />}
                          />
                        )}
                        {vulnerabilityCount > 0 && (
                          <Chip 
                            label={`${vulnerabilityCount} vulnerabilities`}
                            color={vulnerabilityCount > 5 ? 'error' : 'warning'}
                            size="small"
                            icon={<BugIcon />}
                          />
                        )}
                        {subdomainCount > 0 && (
                          <Chip 
                            label={`${subdomainCount} subdomains`}
                            color="info"
                            size="small"
                            icon={<SecurityIcon />}
                          />
                        )}
                      </Box>
                      <Typography variant="body2" color="text.secondary">
                        Scanned: {new Date(result.timestamp).toLocaleString()}
                      </Typography>
                    </Box>
                    <Box sx={{ display: 'flex', gap: 1 }}>
                      <IconButton 
                        color="primary" 
                        onClick={() => handleViewResult(result, actualIndex)}
                        title="View details"
                      >
                        <ViewIcon />
                      </IconButton>
                      <IconButton 
                        color="secondary" 
                        onClick={() => handleGenerateReport(result)}
                        title="Generate report"
                      >
                        <DownloadIcon />
                      </IconButton>
                      <IconButton 
                        color="error" 
                        onClick={() => handleDeleteResult(actualIndex)}
                        title="Delete result"
                      >
                        <DeleteIcon />
                      </IconButton>
                    </Box>
                  </Box>
                </CardContent>
              </Card>
            );
          })}
        </List>
      )}

      {/* Result Detail Dialog */}
      <Dialog 
        open={dialogOpen} 
        onClose={() => setDialogOpen(false)}
        maxWidth="lg"
        fullWidth
        PaperProps={{
          sx: { minHeight: '80vh' }
        }}
      >
        <DialogTitle>
          <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <Typography variant="h6">
              Scan Results: {selectedResult?.domain || selectedResult?.target || 'Unknown'}
            </Typography>
            <Chip 
              label={selectedResult?.scan_type || 'Unknown'} 
              color="primary" 
              size="small" 
            />
          </Box>
        </DialogTitle>
        <DialogContent dividers>
          {selectedResult && (
            <Box>
              {/* Scan Info */}
              <Typography variant="h6" gutterBottom>
                Scan Information
              </Typography>
              <Typography variant="body2" sx={{ mb: 2 }}>
                <strong>Target:</strong> {selectedResult.domain || selectedResult.target}<br/>
                <strong>Type:</strong> {selectedResult.scan_type}<br/>
                <strong>Date:</strong> {new Date(selectedResult.timestamp).toLocaleString()}
              </Typography>

              {/* Critical Misconfigurations Section */}
              {selectedResult.misconfigurations && renderMisconfigurations(selectedResult.misconfigurations, selectedResult.target || selectedResult.domain || '127.0.0.1')}

              {/* Results based on scan type */}
              {selectedResult.vulnerabilities && renderVulnerabilities(selectedResult.vulnerabilities, selectedResult.target || selectedResult.domain || '127.0.0.1')}
              {selectedResult.subdomains && renderSubdomains(selectedResult.subdomains)}
              {selectedResult.scan_results && renderPortScan(selectedResult.scan_results)}
              
              {/* AI Analysis */}
              {selectedResult.ai_analysis && renderAIAnalysis(selectedResult.ai_analysis)}

              {/* Raw Data */}
              <Accordion sx={{ mt: 3 }}>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography>Raw Scan Data (JSON)</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <ReactJson 
                    src={selectedResult} 
                    theme="monokai"
                    collapsed={2}
                    enableClipboard={true}
                    displayObjectSize={true}
                    displayDataTypes={false}
                  />
                </AccordionDetails>
              </Accordion>
            </Box>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => handleGenerateReport(selectedResult)} color="secondary">
            Generate Report
          </Button>
          <Button onClick={() => setDialogOpen(false)}>
            Close
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
};

export default Results;
