import React from 'react';
import VulnerabilityChart from '../components/Dashboard/VulnerabilityChart';

const Vulnerabilities: React.FC = () => {
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold text-gray-900">Vulnerabilities</h1>
        <p className="text-gray-600 mt-1">
          Track and manage security vulnerabilities across your infrastructure
        </p>
      </div>
      <div className="bg-white rounded-lg shadow p-6">
        <h3 className="text-lg font-semibold text-gray-900 mb-4">
          Vulnerability Distribution
        </h3>
        <VulnerabilityChart />
      </div>
    </div>
  );
};

export default Vulnerabilities; 