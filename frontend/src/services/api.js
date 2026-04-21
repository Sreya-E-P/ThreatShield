// frontend/src/services/api.js
import axios from 'axios';

class APIService {
  constructor() {
    this.baseURL = process.env.REACT_APP_API_URL || 'http://localhost:8000';
    
    this.api = axios.create({
      baseURL: this.baseURL,
      timeout: 60000,
      headers: {
        'Content-Type': 'application/json',
      },
    });

    // Request interceptor
    this.api.interceptors.request.use(
      (config) => {
        const token = localStorage.getItem('access_token');
        if (token && config.headers) {
          config.headers.Authorization = `Bearer ${token}`;
        }
        return config;
      },
      (error) => Promise.reject(error)
    );

    // Response interceptor
    this.api.interceptors.response.use(
      (response) => response,
      async (error) => {
        const originalRequest = error.config;
        
        if (error.response?.status === 401 && !originalRequest._retry) {
          originalRequest._retry = true;
          
          try {
            const refreshToken = localStorage.getItem('refresh_token');
            if (refreshToken) {
              const response = await this.refreshToken(refreshToken);
              const { access_token } = response.data;
              
              localStorage.setItem('access_token', access_token);
              originalRequest.headers.Authorization = `Bearer ${access_token}`;
              
              return this.api(originalRequest);
            }
          } catch (refreshError) {
            console.error('Token refresh failed:', refreshError);
            localStorage.removeItem('access_token');
            localStorage.removeItem('refresh_token');
            window.location.href = '/login';
          }
        }
        
        return Promise.reject(error);
      }
    );
  }

  // ============================================
  // AUTHENTICATION
  // ============================================
  
  async login(email, password) {
    const response = await this.api.post('/api/v1/auth/login', { email, password });
    return response.data;
  }

  async refreshToken(refreshToken) {
    const response = await this.api.post('/api/v1/auth/refresh', { refresh_token: refreshToken });
    return response.data;
  }

  // ============================================
  // THREAT INTELLIGENCE
  // ============================================
  
  async getThreats(timeRange = '24h', severity = null, limit = 100) {
    const params = { time_range: timeRange, limit };
    if (severity) params.severity = severity;
    
    const response = await this.api.get('/api/v1/threats', { params });
    return response.data;
  }

  async analyzeThreats(threats) {
    const response = await this.api.post('/api/v1/ai/analyze-threats', { 
      threat_data: threats,
      include_explanation: true,
      deep_analysis: true
    });
    return response.data;
  }

  async enrichThreats(threats) {
    const response = await this.api.post('/api/v1/threats/enrich', threats);
    return response.data;
  }

  // ============================================
  // ZERO-DAY PREDICTOR (AI)
  // ============================================
  
  async predictZeroDay(threats) {
    const response = await this.api.post('/api/v1/ai/analyze-threats', {
      threat_data: threats,
      include_explanation: true,
      deep_analysis: true
    });
    return response.data;
  }

  async trainZeroDayModel(epochs = 100, batchSize = 32) {
    const response = await this.api.post('/api/v1/ai/train-model', {
      model_type: 'zero_day_predictor',
      epochs: epochs,
      config: { batch_size: batchSize }
    });
    return response.data;
  }

  // FIX: Added trainModels method called by AIWorkloads.jsx
  // Original code was calling apiService.trainModels() but method didn't exist
  async trainModels({ model_id, epochs }) {
    const response = await this.api.post('/api/v1/ai/train-model', {
      model_type: model_id,
      epochs: epochs,
    });
    return response.data;
  }

  // ============================================
  // AUTONOMOUS DEFENSE
  // ============================================
  
  async executeAutonomousDefense(threatData) {
    const response = await this.api.post('/api/v1/ai/autonomous-defense', {
      threat_data: threatData,
      action_preference: null
    });
    return response.data;
  }

  async trainDefenseAgent(episodes = 1000) {
    const response = await this.api.post('/api/v1/ai/train-model', {
      model_type: 'defense_agent',
      epochs: episodes
    });
    return response.data;
  }

  // ============================================
  // POST-QUANTUM CRYPTOGRAPHY
  // ============================================
  
  async generateHybridKey() {
    const response = await this.api.post('/api/v1/crypto/generate-key');
    return response.data;
  }

  async encryptWithPQC(plaintext, keyId = null) {
    const response = await this.api.post('/api/v1/crypto/encrypt', {
      plaintext: plaintext,
      key_id: keyId
    });
    return response.data;
  }

  async decryptWithPQC(encryptedPackage) {
    const response = await this.api.post('/api/v1/crypto/decrypt', encryptedPackage);
    return response.data;
  }

  async signWithPQC(message, keyId) {
    const response = await this.api.post('/api/v1/crypto/sign', {
      message: message,
      key_id: keyId
    });
    return response.data;
  }

  async verifySignature(message, signature, keyId) {
    const response = await this.api.post('/api/v1/crypto/verify', {
      message: message,
      signature: signature,
      key_id: keyId
    });
    return response.data;
  }

  async cryptoBenchmark() {
    const response = await this.api.get('/api/v1/crypto/benchmark');
    return response.data;
  }

  // ============================================
  // BLOCKCHAIN FORENSICS
  // ============================================
  
  async analyzeTransaction(txHash, chain = 'ethereum') {
    const response = await this.api.get(`/api/v1/blockchain/analyze/${txHash}`, {
      params: { chain }
    });
    return response.data;
  }

  async investigateWallet(address, depth = 2) {
    const response = await this.api.post('/api/v1/blockchain/investigate', {
      address,
      depth,
      chains: ['ethereum', 'polygon', 'bsc']
    });
    return response.data;
  }

  async generateComplianceReport(address, timeframeDays = 30) {
    const response = await this.api.post('/api/v1/blockchain/compliance-report', {
      address,
      timeframe_days: timeframeDays
    });
    return response.data;
  }

  async batchAnalyzeTransactions(txHashes, chain = 'ethereum') {
    const response = await this.api.post('/api/v1/blockchain/batch-analyze', {
      tx_hashes: txHashes,
      chain
    });
    return response.data;
  }

  // ============================================
  // CONFIDENTIAL COMPUTE (SGX)
  // ============================================
  
  async getEnclaveStatus() {
    const response = await this.api.get('/api/v1/confidential/status');
    return response.data;
  }

  async secureInference(inputData, modelId) {
    const response = await this.api.post('/api/v1/confidential/inference', {
      input_data: inputData,
      model_id: modelId
    });
    return response.data;
  }

  async confidentialThreatVerification(threatData, peerEnclaves = []) {
    const response = await this.api.post('/api/v1/confidential/verify-threat', {
      threat_data: threatData,
      peer_enclaves: peerEnclaves
    });
    return response.data;
  }

  // ============================================
  // SYSTEM METRICS
  // ============================================
  
  async getSystemMetrics(timeRange = '1h') {
    const response = await this.api.get('/api/v1/metrics/system', {
      params: { time_range: timeRange }
    });
    return response.data;
  }

  async getResearchBenchmarks() {
    const response = await this.api.get('/api/v1/research/benchmarks');
    return response.data;
  }

  // ============================================
  // HEALTH & STATUS
  // ============================================
  
  async healthCheck() {
    const response = await this.api.get('/health');
    return response.data;
  }

  async readinessCheck() {
    const response = await this.api.get('/ready');
    return response.data;
  }

  // ============================================
  // WEB SOCKET CONNECTION
  // ============================================
  
  getWebSocketUrl() {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const host = window.location.host;
    return `${protocol}//${host}/ws`;
  }

  // ============================================
  // DATA EXPORT
  // ============================================
  
  async exportThreatData(format = 'json', timeRange = '24h') {
    const response = await this.api.get('/api/v1/threats/export', {
      params: { format, time_range: timeRange },
      responseType: 'blob'
    });
    return response.data;
  }
}

export const apiService = new APIService();
export default apiService;