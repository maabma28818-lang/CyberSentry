import React from 'react';
import { render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { ThemeProvider, createTheme } from '@mui/material/styles';
import App from './App';

let scannerProps;

jest.mock('./components/Scanner', () => (props) => {
  scannerProps = props;
  return <div data-testid="scanner-route">Mocked Scanner</div>;
});

jest.mock('socket.io-client', () => () => ({
  on: jest.fn(),
  disconnect: jest.fn(),
  emit: jest.fn(),
}));

jest.mock('./services/apiService', () => {
  const actual = jest.requireActual('./services/apiService');
  const mockUser = { id: 1, username: 'admin', role: 'admin' };
  return {
    ...actual,
    __esModule: true,
    authGetMe: jest.fn(() => {
      const token = actual.getApiAccessToken();
      return token ? Promise.resolve({ success: true, user: mockUser }) : Promise.reject(new Error('Unauthorized'));
    }),
    authSignin: jest.fn().mockResolvedValue({
      success: true,
      token: 'mock-token',
      user: mockUser,
    }),
    authSignup: jest.fn().mockResolvedValue({
      success: true,
      token: 'mock-token',
      user: mockUser,
    }),
    authLogout: jest.fn().mockResolvedValue({ success: true, message: 'Logged out' }),
    default: {
      ...actual.default,
      getScanHistory: jest.fn().mockResolvedValue([]),
      authGetMe: jest.fn(() => {
        const token = actual.getApiAccessToken();
        return token ? Promise.resolve({ success: true, user: mockUser }) : Promise.reject(new Error('Unauthorized'));
      }),
      authSignin: jest.fn().mockResolvedValue({
        success: true,
        token: 'mock-token',
        user: mockUser,
      }),
      authSignup: jest.fn().mockResolvedValue({
        success: true,
        token: 'mock-token',
        user: mockUser,
      }),
      authLogout: jest.fn().mockResolvedValue({ success: true, message: 'Logged out' }),
    },
  };
});

describe('CyberSentry App Routing & Auth', () => {
  beforeEach(() => {
    localStorage.clear();
    sessionStorage.clear();
  });

  test('routes to Signin page on unauthenticated access', async () => {
    render(
      <MemoryRouter initialEntries={['/scanner']}>
        <ThemeProvider theme={createTheme()}>
          <App />
        </ThemeProvider>
      </MemoryRouter>
    );

    await waitFor(() => {
      expect(screen.getByText(/Sign In to CyberSentry/i)).not.toBeNull();
    });
  });

  test('routes Scanner with its showNotification contract when authenticated', async () => {
    localStorage.setItem('cybersentry-user-data', JSON.stringify({ id: 1, username: 'admin', role: 'admin' }));
    localStorage.setItem('cybersentry-auth-token', 'mock-token');

    render(
      <MemoryRouter initialEntries={['/scanner']}>
        <ThemeProvider theme={createTheme()}>
          <App />
        </ThemeProvider>
      </MemoryRouter>
    );

    await waitFor(() => {
      expect(screen.getByTestId('scanner-route')).not.toBeNull();
    });
    expect(typeof scannerProps.showNotification).toBe('function');
    expect(scannerProps.showAlert).toBeUndefined();
  });

  test('renders Signin page on /signin route', async () => {
    render(
      <MemoryRouter initialEntries={['/signin']}>
        <ThemeProvider theme={createTheme()}>
          <App />
        </ThemeProvider>
      </MemoryRouter>
    );

    await waitFor(() => {
      expect(screen.getByText(/Sign In to CyberSentry/i)).not.toBeNull();
    });
  });

  test('renders Signup page on /signup route', async () => {
    render(
      <MemoryRouter initialEntries={['/signup']}>
        <ThemeProvider theme={createTheme()}>
          <App />
        </ThemeProvider>
      </MemoryRouter>
    );

    await waitFor(() => {
      expect(screen.getByText(/Operator Registration/i)).not.toBeNull();
    });
  });
});


