import React from 'react';
import {
  Grid,
  Card,
  CardContent,
  Typography,
  Box,
  Alert,
  Chip,
  LinearProgress,
  IconButton,
  Tooltip,
} from '@mui/material';
import {
  Security,
  Warning,
  CheckCircle,
  Error,
  TrendingUp,
  NetworkCheck,
  Shield,
  Speed,
  Refresh,
} from '@mui/icons-material';
import { useQuery } from 'react-query';
import { Helmet } from 'react-helmet-async';

// Components
import ThreatOverviewChart from '../components/charts/ThreatOverviewChart';
import NetworkTrafficChart from '../components/charts/NetworkTrafficChart';
import IncidentTimelineChart from '../components/charts/IncidentTimelineChart';
import ThreatMapComponent from '../components/ThreatMapComponent';
import RecentAlertsTable from '../components/tables/RecentAlertsTable';
import SystemHealthIndicators from '../components/SystemHealthIndicators';

// Services
import { dashboardService } from '../services/api';
import { useWebSocket } from '../services/WebSocketContext';

// Types
interface DashboardMetrics {
  totalThreats: number;
  activeIncidents: number;
  blockedIPs: number;
  systemHealth: number;
  threatTrends: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
  networkStats: {
    totalTraffic: string;
    blockedTraffic: string;
    latency: number;
    throughput: string;
  };
  complianceScore: number;
  lastUpdated: string;
}

// Metric Card Component
const MetricCard: React.FC<{
  title: string;
  value: string | number;
  icon: React.ReactNode;
  color: 'primary' | 'secondary' | 'error' | 'warning' | 'success';
  trend?: number;
  subtitle?: string;
}> = ({ title, value, icon, color, trend, subtitle }) => {
  return (
    <Card sx={{ height: '100%' }}>
      <CardContent>
        <Box display="flex" alignItems="center" justifyContent="space-between">
          <Box>
            <Typography color="textSecondary" gutterBottom variant="body2">
              {title}
            </Typography>
            <Typography variant="h4" component="div" color={`${color}.main`}>
              {value}
            </Typography>
            {subtitle && (
              <Typography variant="body2" color="textSecondary">
                {subtitle}
              </Typography>
            )}
            {trend !== undefined && (
              <Box display="flex" alignItems="center" mt={1}>
                <TrendingUp
                  fontSize="small"
                  color={trend > 0 ? 'error' : 'success'}
                />
                <Typography
                  variant="body2"
                  color={trend > 0 ? 'error.main' : 'success.main'}
                  ml={0.5}
                >
                  {trend > 0 ? '+' : ''}{trend}%
                </Typography>
              </Box>
            )}
          </Box>
          <Box color={`${color}.main`}>
            {icon}
          </Box>
        </Box>
      </CardContent>
    </Card>
  );
};

// Threat Level Indicator Component
const ThreatLevelIndicator: React.FC<{ level: string; count: number }> = ({
  level,
  count,
}) => {
  const getColor = (level: string) => {
    switch (level.toLowerCase()) {
      case 'critical':
        return 'error';
      case 'high':
        return 'warning';
      case 'medium':
        return 'info';
      case 'low':
        return 'success';
      default:
        return 'default';
    }
  };

  return (
    <Box display="flex" alignItems="center" justifyContent="space-between" mb={1}>
      <Chip
        label={level}
        color={getColor(level) as any}
        size="small"
        variant="outlined"
      />
      <Typography variant="h6" color={`${getColor(level)}.main`}>
        {count}
      </Typography>
    </Box>
  );
};

// Main Dashboard Component
const Dashboard: React.FC = () => {
  const { lastMessage } = useWebSocket();

  // Fetch dashboard data
  const {
    data: metrics,
    isLoading,
    error,
    refetch,
  } = useQuery<DashboardMetrics>(
    'dashboardMetrics',
    dashboardService.getMetrics,
    {
      refetchInterval: 30000, // Refetch every 30 seconds
    }
  );

  // Handle real-time updates
  React.useEffect(() => {
    if (lastMessage) {
      // Handle real-time metric updates
      refetch();
    }
  }, [lastMessage, refetch]);

  if (isLoading) {
    return (
      <Box display="flex" justifyContent="center" alignItems="center" height="400px">
        <LinearProgress sx={{ width: '50%' }} />
      </Box>
    );
  }

  if (error) {
    return (
      <Alert severity="error" sx={{ mb: 2 }}>
        Failed to load dashboard data. Please try again.
      </Alert>
    );
  }

  return (
    <>
      <Helmet>
        <title>Security Dashboard - Enterprise Security Platform</title>
      </Helmet>

      <Box mb={3} display="flex" justifyContent="space-between" alignItems="center">
        <Typography variant="h4" component="h1" gutterBottom>
          Security Operations Dashboard
        </Typography>
        <Tooltip title="Refresh Data">
          <IconButton onClick={() => refetch()} color="primary">
            <Refresh />
          </IconButton>
        </Tooltip>
      </Box>

      {/* Key Metrics Row */}
      <Grid container spacing={3} mb={3}>
        <Grid item xs={12} sm={6} md={3}>
          <MetricCard
            title="Active Threats"
            value={metrics?.totalThreats || 0}
            icon={<Security fontSize="large" />}
            color="error"
            trend={5}
          />
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <MetricCard
            title="Open Incidents"
            value={metrics?.activeIncidents || 0}
            icon={<Warning fontSize="large" />}
            color="warning"
            trend={-2}
          />
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <MetricCard
            title="Blocked IPs"
            value={metrics?.blockedIPs || 0}
            icon={<Shield fontSize="large" />}
            color="success"
            trend={12}
          />
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <MetricCard
            title="System Health"
            value={`${metrics?.systemHealth || 0}%`}
            icon={<CheckCircle fontSize="large" />}
            color="success"
            subtitle="All systems operational"
          />
        </Grid>
      </Grid>

      {/* Network Performance Row */}
      <Grid container spacing={3} mb={3}>
        <Grid item xs={12} sm={6} md={3}>
          <MetricCard
            title="Network Latency"
            value={`${metrics?.networkStats?.latency || 0}ms`}
            icon={<Speed fontSize="large" />}
            color="primary"
            subtitle="Average response time"
          />
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <MetricCard
            title="Throughput"
            value={metrics?.networkStats?.throughput || '0 Gbps'}
            icon={<NetworkCheck fontSize="large" />}
            color="primary"
            subtitle="Current network speed"
          />
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <MetricCard
            title="Total Traffic"
            value={metrics?.networkStats?.totalTraffic || '0 GB'}
            icon={<TrendingUp fontSize="large" />}
            color="info"
            subtitle="Last 24 hours"
          />
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <MetricCard
            title="Compliance Score"
            value={`${metrics?.complianceScore || 0}%`}
            icon={<CheckCircle fontSize="large" />}
            color="success"
            subtitle="SOC 2 & ISO 27001"
          />
        </Grid>
      </Grid>

      {/* Threat Breakdown and System Health */}
      <Grid container spacing={3} mb={3}>
        <Grid item xs={12} md={4}>
          <Card sx={{ height: '300px' }}>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Threat Breakdown
              </Typography>
              {metrics?.threatTrends && (
                <Box>
                  <ThreatLevelIndicator
                    level="Critical"
                    count={metrics.threatTrends.critical}
                  />
                  <ThreatLevelIndicator
                    level="High"
                    count={metrics.threatTrends.high}
                  />
                  <ThreatLevelIndicator
                    level="Medium"
                    count={metrics.threatTrends.medium}
                  />
                  <ThreatLevelIndicator
                    level="Low"
                    count={metrics.threatTrends.low}
                  />
                </Box>
              )}
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={12} md={8}>
          <Card sx={{ height: '300px' }}>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                System Health Indicators
              </Typography>
              <SystemHealthIndicators />
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Charts Row */}
      <Grid container spacing={3} mb={3}>
        <Grid item xs={12} md={6}>
          <Card sx={{ height: '400px' }}>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Threat Detection Trends
              </Typography>
              <ThreatOverviewChart />
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={12} md={6}>
          <Card sx={{ height: '400px' }}>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Network Traffic Analysis
              </Typography>
              <NetworkTrafficChart />
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Incident Timeline and Threat Map */}
      <Grid container spacing={3} mb={3}>
        <Grid item xs={12} md={8}>
          <Card sx={{ height: '400px' }}>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Incident Timeline
              </Typography>
              <IncidentTimelineChart />
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={12} md={4}>
          <Card sx={{ height: '400px' }}>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Global Threat Map
              </Typography>
              <ThreatMapComponent />
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Recent Alerts Table */}
      <Grid container spacing={3}>
        <Grid item xs={12}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Recent Security Alerts
              </Typography>
              <RecentAlertsTable />
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Last Updated Info */}
      <Box mt={2} display="flex" justifyContent="flex-end">
        <Typography variant="caption" color="textSecondary">
          Last updated: {metrics?.lastUpdated || 'Never'}
        </Typography>
      </Box>
    </>
  );
};

export default Dashboard;
