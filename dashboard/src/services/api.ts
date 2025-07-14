import axios, { AxiosInstance, AxiosResponse } from 'axios';

// API Configuration
const API_BASE_URL = process.env.REACT_APP_API_BASE_URL || 'http://localhost:8000';

// Create axios instance
const apiClient: AxiosInstance = axios.create({
  baseURL: API_BASE_URL,
  timeout: 30000,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Request interceptor for auth token
apiClient.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('authToken');
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);

// Response interceptor for error handling
apiClient.interceptors.response.use(
  (response: AxiosResponse) => {
    return response;
  },
  (error) => {
    if (error.response?.status === 401) {
      // Handle unauthorized access
      localStorage.removeItem('authToken');
      window.location.href = '/login';
    }
    return Promise.reject(error);
  }
);

// Types
export interface ThreatAlert {
  id: string;
  timestamp: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  type: string;
  source_ip: string;
  destination_ip: string;
  description: string;
  status: 'open' | 'investigating' | 'resolved';
  risk_score: number;
  mitre_tactics?: string[];
}

export interface SecurityIncident {
  id: string;
  title: string;
  description: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  status: 'open' | 'investigating' | 'contained' | 'resolved';
  created_at: string;
  updated_at: string;
  assigned_to?: string;
  source_ip: string;
  target_ip: string;
  threat_type: string;
  risk_score: number;
  timeline: Array<{
    timestamp: string;
    action: string;
    description: string;
    actor: string;
  }>;
  artifacts: Array<{
    type: string;
    value: string;
    description: string;
  }>;
}

export interface NetworkNode {
  id: string;
  label: string;
  type: 'server' | 'workstation' | 'router' | 'switch' | 'firewall';
  ip_address: string;
  status: 'online' | 'offline' | 'warning' | 'critical';
  connections: string[];
  metrics: {
    cpu_usage: number;
    memory_usage: number;
    network_usage: number;
  };
}

export interface ComplianceReport {
  framework: 'SOC2' | 'ISO27001' | 'PCI-DSS' | 'GDPR';
  overall_score: number;
  last_assessment: string;
  controls: Array<{
    id: string;
    name: string;
    status: 'compliant' | 'non-compliant' | 'partial';
    score: number;
    evidence: string[];
    recommendations: string[];
  }>;
}

// Dashboard Service
export const dashboardService = {
  getMetrics: async () => {
    const response = await apiClient.get('/api/v1/dashboard/metrics');
    return response.data;
  },

  getSystemHealth: async () => {
    const response = await apiClient.get('/api/v1/dashboard/health');
    return response.data;
  },

  getThreatTrends: async (timeRange: string = '24h') => {
    const response = await apiClient.get(`/api/v1/dashboard/threats/trends?range=${timeRange}`);
    return response.data;
  },

  getNetworkTraffic: async (timeRange: string = '24h') => {
    const response = await apiClient.get(`/api/v1/dashboard/network/traffic?range=${timeRange}`);
    return response.data;
  },
};

// Threat Detection Service
export const threatService = {
  getAlerts: async (page: number = 1, limit: number = 50, filters?: any) => {
    const params = new URLSearchParams({
      page: page.toString(),
      limit: limit.toString(),
      ...filters,
    });
    const response = await apiClient.get(`/api/v1/threats/alerts?${params}`);
    return response.data;
  },

  getAlertById: async (id: string): Promise<ThreatAlert> => {
    const response = await apiClient.get(`/api/v1/threats/alerts/${id}`);
    return response.data;
  },

  updateAlertStatus: async (id: string, status: string) => {
    const response = await apiClient.patch(`/api/v1/threats/alerts/${id}`, { status });
    return response.data;
  },

  blockIP: async (ip: string, reason: string) => {
    const response = await apiClient.post('/api/v1/threats/block-ip', { ip, reason });
    return response.data;
  },

  unblockIP: async (ip: string) => {
    const response = await apiClient.post('/api/v1/threats/unblock-ip', { ip });
    return response.data;
  },

  getThreatIntelligence: async (indicator: string) => {
    const response = await apiClient.get(`/api/v1/threats/intel/${indicator}`);
    return response.data;
  },
};

// Incident Response Service
export const incidentService = {
  getIncidents: async (page: number = 1, limit: number = 50, filters?: any) => {
    const params = new URLSearchParams({
      page: page.toString(),
      limit: limit.toString(),
      ...filters,
    });
    const response = await apiClient.get(`/api/v1/incidents?${params}`);
    return response.data;
  },

  getIncidentById: async (id: string): Promise<SecurityIncident> => {
    const response = await apiClient.get(`/api/v1/incidents/${id}`);
    return response.data;
  },

  createIncident: async (incident: Partial<SecurityIncident>) => {
    const response = await apiClient.post('/api/v1/incidents', incident);
    return response.data;
  },

  updateIncident: async (id: string, updates: Partial<SecurityIncident>) => {
    const response = await apiClient.patch(`/api/v1/incidents/${id}`, updates);
    return response.data;
  },

  addTimelineEntry: async (id: string, entry: any) => {
    const response = await apiClient.post(`/api/v1/incidents/${id}/timeline`, entry);
    return response.data;
  },

  escalateIncident: async (id: string, escalation_data: any) => {
    const response = await apiClient.post(`/api/v1/incidents/${id}/escalate`, escalation_data);
    return response.data;
  },
};

// Network Service
export const networkService = {
  getTopology: async (): Promise<NetworkNode[]> => {
    const response = await apiClient.get('/api/v1/network/topology');
    return response.data;
  },

  getNodeDetails: async (nodeId: string) => {
    const response = await apiClient.get(`/api/v1/network/nodes/${nodeId}`);
    return response.data;
  },

  getNetworkMetrics: async (timeRange: string = '1h') => {
    const response = await apiClient.get(`/api/v1/network/metrics?range=${timeRange}`);
    return response.data;
  },

  isolateNode: async (nodeId: string, reason: string) => {
    const response = await apiClient.post(`/api/v1/network/nodes/${nodeId}/isolate`, { reason });
    return response.data;
  },

  restoreNode: async (nodeId: string) => {
    const response = await apiClient.post(`/api/v1/network/nodes/${nodeId}/restore`);
    return response.data;
  },
};

// Compliance Service
export const complianceService = {
  getReports: async (): Promise<ComplianceReport[]> => {
    const response = await apiClient.get('/api/v1/compliance/reports');
    return response.data;
  },

  getReportByFramework: async (framework: string): Promise<ComplianceReport> => {
    const response = await apiClient.get(`/api/v1/compliance/reports/${framework}`);
    return response.data;
  },

  generateReport: async (framework: string, options?: any) => {
    const response = await apiClient.post(`/api/v1/compliance/reports/${framework}/generate`, options);
    return response.data;
  },

  getAuditLogs: async (page: number = 1, limit: number = 50, filters?: any) => {
    const params = new URLSearchParams({
      page: page.toString(),
      limit: limit.toString(),
      ...filters,
    });
    const response = await apiClient.get(`/api/v1/compliance/audit-logs?${params}`);
    return response.data;
  },
};

// Reports Service
export const reportsService = {
  getAvailableReports: async () => {
    const response = await apiClient.get('/api/v1/reports');
    return response.data;
  },

  generateReport: async (reportType: string, parameters: any) => {
    const response = await apiClient.post(`/api/v1/reports/${reportType}/generate`, parameters);
    return response.data;
  },

  downloadReport: async (reportId: string) => {
    const response = await apiClient.get(`/api/v1/reports/${reportId}/download`, {
      responseType: 'blob',
    });
    return response.data;
  },

  getReportHistory: async (page: number = 1, limit: number = 20) => {
    const params = new URLSearchParams({
      page: page.toString(),
      limit: limit.toString(),
    });
    const response = await apiClient.get(`/api/v1/reports/history?${params}`);
    return response.data;
  },
};

// Settings Service
export const settingsService = {
  getSettings: async () => {
    const response = await apiClient.get('/api/v1/settings');
    return response.data;
  },

  updateSettings: async (settings: any) => {
    const response = await apiClient.patch('/api/v1/settings', settings);
    return response.data;
  },

  getUsers: async () => {
    const response = await apiClient.get('/api/v1/settings/users');
    return response.data;
  },

  createUser: async (user: any) => {
    const response = await apiClient.post('/api/v1/settings/users', user);
    return response.data;
  },

  updateUser: async (userId: string, updates: any) => {
    const response = await apiClient.patch(`/api/v1/settings/users/${userId}`, updates);
    return response.data;
  },

  deleteUser: async (userId: string) => {
    const response = await apiClient.delete(`/api/v1/settings/users/${userId}`);
    return response.data;
  },

  getIntegrations: async () => {
    const response = await apiClient.get('/api/v1/settings/integrations');
    return response.data;
  },

  updateIntegration: async (integrationId: string, config: any) => {
    const response = await apiClient.patch(`/api/v1/settings/integrations/${integrationId}`, config);
    return response.data;
  },

  testIntegration: async (integrationId: string) => {
    const response = await apiClient.post(`/api/v1/settings/integrations/${integrationId}/test`);
    return response.data;
  },
};

// Authentication Service
export const authService = {
  login: async (username: string, password: string) => {
    const response = await apiClient.post('/api/v1/auth/login', { username, password });
    return response.data;
  },

  logout: async () => {
    const response = await apiClient.post('/api/v1/auth/logout');
    localStorage.removeItem('authToken');
    return response.data;
  },

  refreshToken: async () => {
    const response = await apiClient.post('/api/v1/auth/refresh');
    return response.data;
  },

  getCurrentUser: async () => {
    const response = await apiClient.get('/api/v1/auth/me');
    return response.data;
  },

  changePassword: async (currentPassword: string, newPassword: string) => {
    const response = await apiClient.post('/api/v1/auth/change-password', {
      current_password: currentPassword,
      new_password: newPassword,
    });
    return response.data;
  },
};

export default apiClient;
