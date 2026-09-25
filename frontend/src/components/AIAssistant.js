import React, { useState } from 'react';
import {
  Box,
  Card,
  CardContent,
  Typography,
  TextField,
  Button,
  List,
  ListItem,
  ListItemText,
  Divider,
  Paper,
  Chip,
  Alert,
  CircularProgress
} from '@mui/material';
import {
  Send as SendIcon,
  SmartToy as AIIcon,
  Person as PersonIcon,
  Clear as ClearIcon,
  Help as HelpIcon
} from '@mui/icons-material';
import { useScan } from '../context/ScanContext';

const AIAssistant = ({ showNotification }) => {
  const { chatWithAI, currentScan, learningMode } = useScan();
  const [messages, setMessages] = useState([
    {
      type: 'ai',
      content: 'Hello! I\'m your AI security assistant. I can help analyze scan results, explain vulnerabilities, suggest next steps, and answer cybersecurity questions. How can I assist you today?',
      timestamp: new Date()
    }
  ]);
  const [inputMessage, setInputMessage] = useState('');
  const [isLoading, setIsLoading] = useState(false);

  const quickQuestions = [
    "Explain subdomain enumeration",
    "What are common web vulnerabilities?",
    "How to prioritize vulnerability fixes?",
    "Analyze my latest scan results",
    "Best practices for port scanning",
    "How does SQL injection work?",
    "Explain OWASP Top 10",
    "What is reconnaissance in pentesting?"
  ];

  const handleSendMessage = async () => {
    if (!inputMessage.trim()) return;

    const userMessage = {
      type: 'user',
      content: inputMessage,
      timestamp: new Date()
    };

    setMessages(prev => [...prev, userMessage]);
    setInputMessage('');
    setIsLoading(true);

    try {
      // Prepare context from current scan if available
      const context = currentScan ? {
        scan_results: currentScan,
        learning_mode: learningMode
      } : { learning_mode: learningMode };

      const response = await chatWithAI(inputMessage, context);

      // The API returns { message, response: { response, note }, timestamp };
      // older payloads replied with a bare string. Handle both shapes so the
      // message list always receives plain text (objects crash React render).
      const candidate = typeof response === 'string'
        ? response
        : (response?.response?.response ?? response?.response);
      const content = typeof candidate === 'string' ? candidate : '';
      // The backend tags fallback replies with a note; keep it attached so
      // the origin of the answer stays visible in the conversation.
      const note = response && typeof response === 'object'
        ? (response?.response?.note ?? null)
        : null;

      const aiMessage = {
        type: 'ai',
        content,
        note,
        timestamp: new Date()
      };

      setMessages(prev => [...prev, aiMessage]);
      
    } catch (error) {
      const errorMessage = {
        type: 'ai',
        content: 'I apologize, but I encountered an error. Please try again or check if the AI service is configured properly.',
        timestamp: new Date(),
        isError: true
      };
      setMessages(prev => [...prev, errorMessage]);
      showNotification('AI chat failed. Please try again.', 'error');
    } finally {
      setIsLoading(false);
    }
  };

  const handleQuickQuestion = (question) => {
    setInputMessage(question);
  };

  const clearChat = () => {
    setMessages([
      {
        type: 'ai',
        content: 'Chat cleared. How can I help you with your security assessment?',
        timestamp: new Date()
      }
    ]);
  };

  const handleKeyPress = (event) => {
    if (event.key === 'Enter' && !event.shiftKey) {
      event.preventDefault();
      handleSendMessage();
    }
  };

  return (
    <Box>
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
        <Typography variant="h4" component="h1" sx={{ fontWeight: 'bold' }}>
          🤖 AI Security Assistant
        </Typography>
        <Button
          variant="outlined"
          startIcon={<ClearIcon />}
          onClick={clearChat}
        >
          Clear Chat
        </Button>
      </Box>

      {/* Learning Mode Alert */}
      {learningMode && (
        <Alert severity="info" sx={{ mb: 3 }}>
          Learning Mode is enabled. The AI will provide educational explanations and beginner-friendly guidance.
        </Alert>
      )}

      <Box sx={{ display: 'flex', gap: 3, height: 'calc(100vh - 200px)' }}>
        {/* Chat Area */}
        <Card sx={{ flex: 1, display: 'flex', flexDirection: 'column' }}>
          {/* Messages */}
          <Box sx={{ flex: 1, overflow: 'auto', p: 2 }}>
            <List>
              {messages.map((message, index) => {
                const isUser = message.type === 'user';
                return (
                  <ListItem key={index} sx={{ flexDirection: 'column', alignItems: 'stretch', p: 0, mb: 2 }}>
                    <Paper
                      elevation={2}
                      sx={{
                        p: 2,
                        maxWidth: '80%',
                        borderRadius: 2,
                        alignSelf: isUser ? 'flex-end' : 'flex-start',
                        backgroundColor: isUser 
                          ? '#1976d2' 
                          : message.isError 
                            ? '#ffebee' 
                            : '#ffffff',
                        color: isUser ? '#ffffff' : '#0f172a',
                        border: isUser ? 'none' : '1px solid #e2e8f0',
                        boxShadow: isUser ? '0 2px 8px rgba(25, 118, 210, 0.3)' : '0 2px 8px rgba(0, 0, 0, 0.12)',
                      }}
                    >
                      <Box sx={{ display: 'flex', alignItems: 'flex-start', gap: 1.5 }}>
                        {isUser ? (
                          <PersonIcon sx={{ color: '#ffffff', mt: 0.3 }} />
                        ) : (
                          <AIIcon sx={{ color: message.isError ? '#d32f2f' : '#1976d2', mt: 0.3 }} />
                        )}
                        <Box sx={{ flex: 1 }}>
                          <Typography
                            variant="body1"
                            sx={{
                              whiteSpace: 'pre-wrap',
                              color: isUser ? '#ffffff' : '#0f172a',
                              fontWeight: 500,
                              lineHeight: 1.6,
                            }}
                          >
                            {message.content}
                          </Typography>
                          {message.note && (
                            <Typography
                              variant="caption"
                              sx={{
                                color: isUser ? 'rgba(255, 255, 255, 0.85)' : '#475569',
                                display: 'block',
                                mt: 1,
                                fontStyle: 'italic',
                              }}
                            >
                              {message.note}
                            </Typography>
                          )}
                          <Typography
                            variant="caption"
                            sx={{
                              color: isUser ? 'rgba(255, 255, 255, 0.75)' : '#64748b',
                              display: 'block',
                              mt: 0.5,
                              fontWeight: 500,
                            }}
                          >
                            {message.timestamp.toLocaleTimeString()}
                          </Typography>
                        </Box>
                      </Box>
                    </Paper>
                  </ListItem>
                );
              })}
              
              {/* Loading indicator */}
              {isLoading && (
                <ListItem sx={{ justifyContent: 'flex-start', p: 0, mb: 2 }}>
                  <Paper
                    elevation={2}
                    sx={{
                      p: 2,
                      borderRadius: 2,
                      backgroundColor: '#ffffff',
                      color: '#0f172a',
                      border: '1px solid #e2e8f0',
                    }}
                  >
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5 }}>
                      <AIIcon sx={{ color: '#1976d2' }} />
                      <CircularProgress size={16} sx={{ color: '#1976d2' }} />
                      <Typography variant="body2" sx={{ color: '#0f172a', fontWeight: 600 }}>
                        AI is thinking...
                      </Typography>
                    </Box>
                  </Paper>
                </ListItem>
              )}
            </List>
          </Box>

          <Divider />

          {/* Input Area */}
          <Box sx={{ p: 2 }}>
            <Box sx={{ display: 'flex', gap: 1 }}>
              <TextField
                fullWidth
                multiline
                maxRows={4}
                value={inputMessage}
                onChange={(e) => setInputMessage(e.target.value)}
                onKeyPress={handleKeyPress}
                placeholder="Ask me about security assessments, vulnerabilities, or scan results..."
                variant="outlined"
                disabled={isLoading}
              />
              <Button
                variant="contained"
                onClick={handleSendMessage}
                disabled={!inputMessage.trim() || isLoading}
                sx={{ alignSelf: 'flex-end' }}
              >
                <SendIcon />
              </Button>
            </Box>
          </Box>
        </Card>

        {/* Sidebar with Quick Questions and Context */}
        <Box sx={{ width: 300, display: 'flex', flexDirection: 'column', gap: 2 }}>
          {/* Quick Questions */}
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                <HelpIcon sx={{ mr: 1, verticalAlign: 'middle' }} />
                Quick Questions
              </Typography>
              <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1 }}>
                {quickQuestions.map((question, index) => (
                  <Chip
                    key={index}
                    label={question}
                    onClick={() => handleQuickQuestion(question)}
                    clickable
                    variant="outlined"
                    size="small"
                  />
                ))}
              </Box>
            </CardContent>
          </Card>

          {/* Current Scan Context */}
          {currentScan && (
            <Card>
              <CardContent>
                <Typography variant="h6" gutterBottom>
                  Current Scan Context
                </Typography>
                <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
                  The AI can analyze your latest scan results:
                </Typography>
                <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1 }}>
                  <Chip 
                    label={`Target: ${currentScan.domain || currentScan.target}`}
                    size="small"
                    color="primary"
                  />
                  <Chip 
                    label={`Type: ${currentScan.scan_type || 'Unknown'}`}
                    size="small"
                    color="secondary"
                  />
                  {currentScan.vulnerabilities && (
                    <Chip 
                      label={`${currentScan.vulnerabilities.length} findings`}
                      size="small"
                      color={currentScan.vulnerabilities.length > 0 ? 'error' : 'success'}
                    />
                  )}
                </Box>
                <Button
                  fullWidth
                  variant="outlined"
                  size="small"
                  sx={{ mt: 2 }}
                  onClick={() => handleQuickQuestion("Analyze my latest scan results in detail")}
                >
                  Analyze Latest Scan
                </Button>
              </CardContent>
            </Card>
          )}

          {/* AI Capabilities */}
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                AI Capabilities
              </Typography>
              <List dense>
                <ListItem disablePadding>
                  <ListItemText 
                    primary="Vulnerability Analysis"
                    secondary="Explain security findings and their impact"
                  />
                </ListItem>
                <ListItem disablePadding>
                  <ListItemText 
                    primary="Remediation Guidance"
                    secondary="Provide specific fix recommendations"
                  />
                </ListItem>
                <ListItem disablePadding>
                  <ListItemText 
                    primary="Educational Content"
                    secondary="Explain security concepts and techniques"
                  />
                </ListItem>
                <ListItem disablePadding>
                  <ListItemText 
                    primary="Risk Assessment"
                    secondary="Prioritize security issues by severity"
                  />
                </ListItem>
                <ListItem disablePadding>
                  <ListItemText 
                    primary="Next Steps"
                    secondary="Suggest follow-up actions and tests"
                  />
                </ListItem>
              </List>
            </CardContent>
          </Card>
        </Box>
      </Box>
    </Box>
  );
};

export default AIAssistant;
