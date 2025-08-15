import React from 'react';
import IncidentMatches from '../components/Dashboard/IncidentMatches';

const Incidents: React.FC = () => {
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold text-gray-900">Incidents</h1>
        <p className="text-gray-600 mt-1">
          Track and manage security incidents
        </p>
      </div>
      <IncidentMatches />
    </div>
  );
};

export default Incidents; 