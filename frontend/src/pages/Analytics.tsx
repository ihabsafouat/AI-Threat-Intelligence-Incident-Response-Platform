import React from 'react';
import ThreatChart from '../components/Dashboard/ThreatChart';
import VulnerabilityChart from '../components/Dashboard/VulnerabilityChart';

const Analytics: React.FC = () => {
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold text-gray-900">Analytics</h1>
        <p className="text-gray-600 mt-1">
          Security analytics and reporting
        </p>
      </div>
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
    </div>
  );
};

export default Analytics; 