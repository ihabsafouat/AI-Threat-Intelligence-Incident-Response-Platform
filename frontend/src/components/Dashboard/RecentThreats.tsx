import React from 'react';
import { ShieldExclamationIcon, ExclamationTriangleIcon, InformationCircleIcon } from '@heroicons/react/24/outline';

interface Threat {
  id: string;
  title: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  type: string;
  timestamp: string;
  source: string;
}

const RecentThreats: React.FC = () => {
  const threats: Threat[] = [
    {
      id: '1',
      title: 'Suspicious login attempt detected',
      severity: 'high',
      type: 'Authentication',
      timestamp: '2 minutes ago',
      source: '192.168.1.100'
    },
    {
      id: '2',
      title: 'Malware signature detected',
      severity: 'critical',
      type: 'Malware',
      timestamp: '5 minutes ago',
      source: 'web-server-01'
    },
    {
      id: '3',
      title: 'Unusual network traffic pattern',
      severity: 'medium',
      type: 'Network',
      timestamp: '10 minutes ago',
      source: 'firewall-01'
    },
    {
      id: '4',
      title: 'Failed authentication attempts',
      severity: 'low',
      type: 'Authentication',
      timestamp: '15 minutes ago',
      source: '192.168.1.105'
    }
  ];

  const getSeverityIcon = (severity: string) => {
    switch (severity) {
      case 'critical':
        return <ShieldExclamationIcon className="h-5 w-5 text-red-600" />;
      case 'high':
        return <ExclamationTriangleIcon className="h-5 w-5 text-orange-600" />;
      default:
        return <InformationCircleIcon className="h-5 w-5 text-blue-600" />;
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical':
        return 'bg-red-100 text-red-800';
      case 'high':
        return 'bg-orange-100 text-orange-800';
      case 'medium':
        return 'bg-yellow-100 text-yellow-800';
      case 'low':
        return 'bg-blue-100 text-blue-800';
      default:
        return 'bg-gray-100 text-gray-800';
    }
  };

  return (
    <div className="space-y-4">
      {threats.map((threat) => (
        <div key={threat.id} className="flex items-start space-x-3 p-3 bg-gray-50 rounded-lg">
          <div className="flex-shrink-0 mt-1">
            {getSeverityIcon(threat.severity)}
          </div>
          <div className="flex-1 min-w-0">
            <div className="flex items-center justify-between">
              <p className="text-sm font-medium text-gray-900 truncate">
                {threat.title}
              </p>
              <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${getSeverityColor(threat.severity)}`}>
                {threat.severity}
              </span>
            </div>
            <div className="flex items-center space-x-4 mt-1 text-xs text-gray-500">
              <span>{threat.type}</span>
              <span>•</span>
              <span>{threat.source}</span>
              <span>•</span>
              <span>{threat.timestamp}</span>
            </div>
          </div>
        </div>
      ))}
      <div className="text-center">
        <button className="text-sm text-blue-600 hover:text-blue-800 font-medium">
          View all threats →
        </button>
      </div>
    </div>
  );
};

export default RecentThreats; 