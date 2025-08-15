import React from 'react';
import ThreatFeed from '../components/Dashboard/ThreatFeed';

const Threats: React.FC = () => {
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold text-gray-900">Threat Intelligence</h1>
        <p className="text-gray-600 mt-1">
          Monitor and analyze security threats in real-time
        </p>
      </div>
      <ThreatFeed />
    </div>
  );
};

export default Threats; 