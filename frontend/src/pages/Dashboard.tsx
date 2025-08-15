import React, { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import {
  ShieldExclamationIcon,
  ExclamationTriangleIcon,
  ServerIcon,
  ChartBarIcon,
  ClockIcon,
  CheckCircleIcon
} from '@heroicons/react/24/outline';

import { api } from '../services/api';
import MetricCard from '../components/Dashboard/MetricCard';
import ThreatChart from '../components/Dashboard/ThreatChart';
import VulnerabilityChart from '../components/Dashboard/VulnerabilityChart';
import RecentThreats from '../components/Dashboard/RecentThreats';
import SecurityScore from '../components/Dashboard/SecurityScore';
import ThreatFeed from '../components/Dashboard/ThreatFeed';
import SearchBar from '../components/Dashboard/SearchBar';
import IncidentMatches from '../components/Dashboard/IncidentMatches';
import RemediationSteps from '../components/Dashboard/RemediationSteps';
import PDFExport from '../components/Dashboard/PDFExport';

interface DashboardStats {
  totalThreats: number;
  activeThreats: number;
  totalVulnerabilities: number;
  criticalVulnerabilities: number;
  totalAssets: number;
  atRiskAssets: number;
  totalIncidents: number;
  openIncidents: number;
  securityScore: number;
  threatsThisWeek: number;
  vulnerabilitiesThisWeek: number;
}

const Dashboard: React.FC = () => {
  const [activeTab, setActiveTab] = useState('overview');

  const { data: stats, isLoading } = useQuery<DashboardStats>({
    queryKey: ['dashboard-stats'],
    queryFn: () => api.get('/analytics/dashboard-stats').then(res => res.data),
    refetchInterval: 30000, // Refresh every 30 seconds
  });

  const tabs = [
    { id: 'overview', name: 'Overview', icon: ChartBarIcon },
    { id: 'threats', name: 'Threat Feed', icon: ShieldExclamationIcon },
    { id: 'search', name: 'AI Assistant', icon: CheckCircleIcon },
    { id: 'incidents', name: 'Incident Matches', icon: ExclamationTriangleIcon },
    { id: 'remediation', name: 'Remediation', icon: ServerIcon },
    { id: 'reports', name: 'PDF Export', icon: ClockIcon },
  ];

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600"></div>
      </div>
    );
  }

  const renderTabContent = () => {
    switch (activeTab) {
      case 'overview':
        return (
          <div className="space-y-6">
            {/* Security Score */}
            <SecurityScore score={stats?.securityScore || 0} />

            {/* Key Metrics */}
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
              <MetricCard
                title="Active Threats"
                value={stats?.activeThreats || 0}
                total={stats?.totalThreats || 0}
                icon={ShieldExclamationIcon}
                color="red"
                trend={stats?.threatsThisWeek || 0}
                trendLabel="this week"
              />
              <MetricCard
                title="Critical Vulnerabilities"
                value={stats?.criticalVulnerabilities || 0}
                total={stats?.totalVulnerabilities || 0}
                icon={ExclamationTriangleIcon}
                color="orange"
                trend={stats?.vulnerabilitiesThisWeek || 0}
                trendLabel="this week"
              />
              <MetricCard
                title="At-Risk Assets"
                value={stats?.atRiskAssets || 0}
                total={stats?.totalAssets || 0}
                icon={ServerIcon}
                color="yellow"
              />
              <MetricCard
                title="Open Incidents"
                value={stats?.openIncidents || 0}
                total={stats?.totalIncidents || 0}
                icon={ChartBarIcon}
                color="blue"
              />
            </div>

            {/* Charts Row */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              <div className="bg-white rounded-lg shadow p-6">
                <h3 className="text-lg font-semibold text-gray-900 mb-4">
                  Threat Trends (Last 30 Days)
                </h3>
                <ThreatChart />
              </div>
              <div className="bg-white rounded-lg shadow p-6">
                <h3 className="text-lg font-semibold text-gray-900 mb-4">
                  Vulnerability Distribution
                </h3>
                <VulnerabilityChart />
              </div>
            </div>

            {/* Recent Activity */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              <div className="bg-white rounded-lg shadow p-6">
                <h3 className="text-lg font-semibold text-gray-900 mb-4">
                  Recent Threats
                </h3>
                <RecentThreats />
              </div>
              <div className="bg-white rounded-lg shadow p-6">
                <h3 className="text-lg font-semibold text-gray-900 mb-4">
                  Quick Actions
                </h3>
                <div className="space-y-3">
                  <button className="w-full flex items-center justify-between p-3 text-left bg-blue-50 hover:bg-blue-100 rounded-lg transition-colors">
                    <div>
                      <div className="font-medium text-blue-900">Scan Assets</div>
                      <div className="text-sm text-blue-700">Run vulnerability scan on all assets</div>
                    </div>
                    <CheckCircleIcon className="h-5 w-5 text-blue-600" />
                  </button>
                  <button className="w-full flex items-center justify-between p-3 text-left bg-green-50 hover:bg-green-100 rounded-lg transition-colors">
                    <div>
                      <div className="font-medium text-green-900">Update Threat Feeds</div>
                      <div className="text-sm text-green-700">Refresh threat intelligence data</div>
                    </div>
                    <CheckCircleIcon className="h-5 w-5 text-green-600" />
                  </button>
                  <button className="w-full flex items-center justify-between p-3 text-left bg-purple-50 hover:bg-purple-100 rounded-lg transition-colors">
                    <div>
                      <div className="font-medium text-purple-900">Generate Report</div>
                      <div className="text-sm text-purple-700">Create security posture report</div>
                    </div>
                    <CheckCircleIcon className="h-5 w-5 text-purple-600" />
                  </button>
                </div>
              </div>
            </div>
          </div>
        );
      case 'threats':
        return <ThreatFeed />;
      case 'search':
        return <SearchBar />;
      case 'incidents':
        return <IncidentMatches />;
      case 'remediation':
        return <RemediationSteps />;
      case 'reports':
        return <PDFExport />;
      default:
        return null;
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-gray-900">Security Dashboard</h1>
          <p className="text-gray-600 mt-1">
            Real-time threat intelligence and security posture overview
          </p>
        </div>
        <div className="flex items-center space-x-4">
          <div className="flex items-center text-sm text-gray-500">
            <ClockIcon className="h-4 w-4 mr-1" />
            Last updated: {new Date().toLocaleTimeString()}
          </div>
        </div>
      </div>

      {/* Tab Navigation */}
      <div className="border-b border-gray-200">
        <nav className="-mb-px flex space-x-8">
          {tabs.map((tab) => {
            const Icon = tab.icon;
            return (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`flex items-center space-x-2 py-2 px-1 border-b-2 font-medium text-sm transition-colors ${
                  activeTab === tab.id
                    ? 'border-blue-500 text-blue-600'
                    : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
                }`}
              >
                <Icon className="h-5 w-5" />
                <span>{tab.name}</span>
              </button>
            );
          })}
        </nav>
      </div>

      {/* Tab Content */}
      <div className="min-h-[600px]">
        {renderTabContent()}
      </div>
    </div>
  );
};

export default Dashboard; 