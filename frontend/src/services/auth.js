// frontend/src/services/auth.js
class AuthService {
  constructor() {
    this.storageKey = 'threatshield_auth';
    this.tokenKey = 'access_token';
    this.refreshKey = 'refresh_token';
    this.userKey = 'user';
  }

  async login(email, password) {
    try {
      // In production, this would call your backend API
      // For demo, simulate successful login
      const mockResponse = {
        access_token: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiIsImV4cCI6MTczNTY5NTk5OX0.mock',
        refresh_token: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.refresh.mock',
        user: {
          id: '1',
          email: email,
          name: 'Admin User',
          role: 'admin',
          permissions: ['read', 'write', 'delete', 'admin', 'view_metrics', 'train_models']
        },
        expires_in: 3600
      };

      this.setAuth(mockResponse);
      return mockResponse;
    } catch (error) {
      console.error('Login failed:', error);
      throw error;
    }
  }

  async logout() {
    localStorage.removeItem(this.storageKey);
    localStorage.removeItem(this.tokenKey);
    localStorage.removeItem(this.refreshKey);
    localStorage.removeItem(this.userKey);
    window.location.href = '/login';
  }

  async refreshToken(refreshToken) {
    try {
      const response = await fetch('/api/v1/auth/refresh', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ refresh_token: refreshToken })
      });

      if (!response.ok) {
        throw new Error('Token refresh failed');
      }

      const data = await response.json();
      this.setAuth(data);
      return data;
    } catch (error) {
      console.error('Token refresh failed:', error);
      this.logout();
      throw error;
    }
  }

  isAuthenticated() {
    const token = localStorage.getItem(this.tokenKey);
    if (!token) return false;

    try {
      const payload = JSON.parse(atob(token.split('.')[1]));
      return payload.exp * 1000 > Date.now();
    } catch {
      return false;
    }
  }

  getCurrentUser() {
    const userStr = localStorage.getItem(this.userKey);
    if (!userStr) return null;
    
    try {
      return JSON.parse(userStr);
    } catch {
      return null;
    }
  }

  getAccessToken() {
    return localStorage.getItem(this.tokenKey);
  }

  hasPermission(permission) {
    const user = this.getCurrentUser();
    if (!user) return false;
    
    return user.permissions?.includes(permission) || user.role === 'admin';
  }

  setAuth(authResponse) {
    localStorage.setItem(this.tokenKey, authResponse.access_token);
    localStorage.setItem(this.refreshKey, authResponse.refresh_token);
    localStorage.setItem(this.userKey, JSON.stringify(authResponse.user));
    
    // Store full auth object
    localStorage.setItem(this.storageKey, JSON.stringify({
      ...authResponse,
      timestamp: Date.now()
    }));
  }
}

export const authService = new AuthService();
export const logout = () => authService.logout();