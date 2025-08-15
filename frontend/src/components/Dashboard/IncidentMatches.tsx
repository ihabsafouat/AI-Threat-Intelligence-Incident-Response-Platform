import React, { useState } from 'react';
import { ExclamationTriangleIcon, CheckCircleIcon, ClockIcon, UserIcon } from '@heroicons/react/24/outline';

interface Incident {
  id: string;
  title: string;
  description: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  status: 'open' | 'investigating' | 'resolved' | 'closed';
  threatMatches: string[];
  affectedAssets: string[];
  assignedTo: string;
  createdAt: string;
  updatedAt: string;
  matchScore: number;
}

const IncidentMatches: React.FC = () => {
  const [selectedStatus, setSelectedStatus] = useState('all');
  const [selectedSeverity, setSelectedSeverity] = useState('all');

  const incidents: Incident[] = [
    {
      id: '1',
      title: 'Suspicious Login Attempts Detected',
      description: 'Multiple failed login attempts detected from suspicious IP addresses matching known threat patterns.',
      severity: 'high',
      status: 'investigating',
      threatMatches: ['APT Group Activity', 'Credential Stuffing'],
      affectedAssets: ['web-server-01', 'auth-service'],
      assignedTo: 'John Smith',
      createdAt: '2024-01-15T10:30:00Z',
      updatedAt: '2024-01-15T14:20:00Z',
      matchScore: 0.92
    },
    {
      id: '2',
      title: 'Malware Detection on Endpoint',
      description: 'Antivirus software detected malware matching signatures from recent ransomware campaigns.',
      severity: 'critical',
      status: 'open',
      threatMatches: ['Ransomware Campaign', 'Malware Distribution'],
      affectedAssets: ['workstation-045', 'file-server-02'],
      assignedTo: 'Sarah Johnson',
      createdAt: '2024-01-15T09:15:00Z',
      updatedAt: '2024-01-15T09:15:00Z',
      matchScore: 0.88
    },
    {
      id: '3',
      title: 'Unusual Network Traffic Pattern',
      description: 'Detected unusual outbound traffic patterns consistent with data exfiltration attempts.',
      severity: 'medium',
      status: 'investigating',
      threatMatches: ['Data Exfiltration', 'C2 Communication'],
      affectedAssets: ['database-server', 'network-gateway'],
      assignedTo: 'Mike Chen',
      createdAt: '2024-01-14T16:45:00Z',
      updatedAt: '2024-01-15T11:30:00Z',
      matchScore: 0.75
    },
    {
      id: '4',
      title: 'Phishing Email Campaign',
      description: 'Multiple users reported suspicious emails matching known phishing campaign patterns.',
      severity: 'medium',
      status: 'resolved',
      threatMatches: ['Phishing Campaign', 'Social Engineering'],
      affectedAssets: ['email-server', 'user-workstations'],
      assignedTo: 'Lisa Wang',
      createdAt: '2024-01-14T08:20:00Z',
      updatedAt: '2024-01-15T10:00:00Z',
      matchScore: 0.82
    }
  ];

  const statuses = ['all', 'open', 'investigating', 'resolved', 'closed'];
  const severities = ['all', 'critical', 'high', 'medium', 'low'];

  const filteredIncidents = incidents.filter(incident => {
    const matchesStatus = selectedStatus === 'all' || incident.status === selectedStatus;
    const matchesSeverity = selectedSeverity === 'all' || incident.severity === selectedSeverity;
    return matchesStatus && matchesSeverity;
  });

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return 'bg-red-100 text-red-800 border-red-200';
      case 'high': return 'bg-orange-100 text-orange-800 border-orange-200';
      case 'medium': return 'bg-yellow-100 text-yellow-800 border-yellow-200';
      case 'low': return 'bg-blue-100 text-blue-800 border-blue-200';
      default: return 'bg-gray-100 text-gray-800 border-gray-200';
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'open': return 'bg-red-100 text-red-800';
      case 'investigating': return 'bg-yellow-100 text-yellow-800';
      case 'resolved': return 'bg-green-100 text-green-800';
      case 'closed': return 'bg-gray-100 text-gray-800';
      default: return 'bg-gray-100 text-gray-800';
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'open': return <ExclamationTriangleIcon className="h-4 w-4" />;
      case 'investigating': return <ClockIcon className="h-4 w-4" />;
      case 'resolved': return <CheckCircleIcon className="h-4 w-4" />;
      case 'closed': return <CheckCircleIcon className="h-4 w-4" />;
      default: return <ClockIcon className="h-4 w-4" />;
    }
  };

  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleString();
  };

  return (
    <div className="bg-white rounded-lg shadow">
      <div className="p-6 border-b border-gray-200">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-lg font-semibold text-gray-900">Incident Matches</h3>
          <div className="text-sm text-gray-500">
            {filteredIncidents.length} incidents found
          </div>
        </div>
        
        {/* Filters */}
        <div className="flex flex-wrap gap-2 mb-4">
          <select
            value={selectedStatus}
            onChange={(e) => setSelectedStatus(e.target.value)}
            className="px-3 py-1 border border-gray-300 rounded-md text-sm focus:ring-2 focus:ring-blue-500"
          >
            {statuses.map(status => (
              <option key={status} value={status}>
                {status === 'all' ? 'All Statuses' : status.charAt(0).toUpperCase() + status.slice(1)}
              </option>
            ))}
          </select>
          
          <select
            value={selectedSeverity}
            onChange={(e) => setSelectedSeverity(e.target.value)}
            className="px-3 py-1 border border-gray-300 rounded-md text-sm focus:ring-2 focus:ring-blue-500"
          >
            {severities.map(severity => (
              <option key={severity} value={severity}>
                {severity === 'all' ? 'All Severities' : severity.charAt(0).toUpperCase() + severity.slice(1)}
              </option>
            ))}
          </select>
        </div>
      </div>

      {/* Incidents List */}
      <div className="divide-y divide-gray-200">
        {filteredIncidents.map((incident) => (
          <div key={incident.id} className="p-6 hover:bg-gray-50 transition-colors">
            <div className="flex items-start justify-between mb-3">
              <div className="flex-1">
                <div className="flex items-center space-x-2 mb-2">
                  <h4 className="text-lg font-medium text-gray-900">{incident.title}</h4>
                  <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium border ${getSeverityColor(incident.severity)}`}>
                    {incident.severity}
                  </span>
                  <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${getStatusColor(incident.status)}`}>
                    {getStatusIcon(incident.status)}
                    <span className="ml-1">{incident.status}</span>
                  </span>
                </div>
                
                <p className="text-gray-600 mb-3">{incident.description}</p>
                
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-3">
                  <div>
                    <span className="text-sm font-medium text-gray-700">Threat Matches:</span>
                    <div className="flex flex-wrap gap-1 mt-1">
                      {incident.threatMatches.map((match, index) => (
                        <span
                          key={index}
                          className="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium bg-purple-100 text-purple-800"
                        >
                          {match}
                        </span>
                      ))}
                    </div>
                  </div>
                  
                  <div>
                    <span className="text-sm font-medium text-gray-700">Affected Assets:</span>
                    <div className="flex flex-wrap gap-1 mt-1">
                      {incident.affectedAssets.map((asset, index) => (
                        <span
                          key={index}
                          className="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium bg-gray-100 text-gray-800"
                        >
                          {asset}
                        </span>
                      ))}
                    </div>
                  </div>
                </div>
                
                <div className="flex items-center justify-between text-sm text-gray-500">
                  <div className="flex items-center space-x-4">
                    <span className="flex items-center">
                      <UserIcon className="h-4 w-4 mr-1" />
                      {incident.assignedTo}
                    </span>
                    <span>Match Score: {Math.round(incident.matchScore * 100)}%</span>
                  </div>
                  <div className="text-right">
                    <div>Created: {formatDate(incident.createdAt)}</div>
                    <div>Updated: {formatDate(incident.updatedAt)}</div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        ))}
      </div>
      
      {filteredIncidents.length === 0 && (
        <div className="p-6 text-center text-gray-500">
          No incidents found matching your criteria.
        </div>
      )}
    </div>
  );
};

export default IncidentMatches; 