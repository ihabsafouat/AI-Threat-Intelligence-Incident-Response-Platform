import React, { useState } from 'react';
import { CheckCircleIcon, ClockIcon, ExclamationTriangleIcon, DocumentTextIcon, UserGroupIcon } from '@heroicons/react/24/outline';

interface RemediationStep {
  id: string;
  title: string;
  description: string;
  status: 'pending' | 'in-progress' | 'completed' | 'failed';
  priority: 'critical' | 'high' | 'medium' | 'low';
  estimatedTime: string;
  assignedTo: string;
  dependencies: string[];
  instructions: string[];
  tools: string[];
}

const RemediationSteps: React.FC = () => {
  const [selectedPriority, setSelectedPriority] = useState('all');
  const [selectedStatus, setSelectedStatus] = useState('all');

  const remediationSteps: RemediationStep[] = [
    {
      id: '1',
      title: 'Isolate Affected Systems',
      description: 'Immediately isolate compromised systems from the network to prevent further spread.',
      status: 'completed',
      priority: 'critical',
      estimatedTime: '15 minutes',
      assignedTo: 'Network Team',
      dependencies: [],
      instructions: [
        'Disconnect affected endpoints from network',
        'Block suspicious IP addresses at firewall',
        'Disable compromised user accounts',
        'Document isolation actions taken'
      ],
      tools: ['Firewall Management', 'Network Monitoring', 'Active Directory']
    },
    {
      id: '2',
      title: 'Collect Forensic Evidence',
      description: 'Gather digital evidence for analysis and potential legal proceedings.',
      status: 'in-progress',
      priority: 'high',
      estimatedTime: '2 hours',
      assignedTo: 'Forensics Team',
      dependencies: ['1'],
      instructions: [
        'Create memory dumps of affected systems',
        'Capture network traffic logs',
        'Preserve system logs and event data',
        'Document evidence collection process'
      ],
      tools: ['Volatility', 'Wireshark', 'Event Logs', 'Memory Imaging']
    },
    {
      id: '3',
      title: 'Analyze Malware Samples',
      description: 'Analyze collected malware samples to understand attack vectors and capabilities.',
      status: 'pending',
      priority: 'high',
      estimatedTime: '4 hours',
      assignedTo: 'Malware Analysis Team',
      dependencies: ['2'],
      instructions: [
        'Submit samples to sandbox environment',
        'Perform static and dynamic analysis',
        'Identify indicators of compromise (IOCs)',
        'Document malware characteristics'
      ],
      tools: ['Cuckoo Sandbox', 'IDA Pro', 'VirusTotal', 'Malware Analysis Tools']
    },
    {
      id: '4',
      title: 'Patch Vulnerabilities',
      description: 'Apply security patches to address identified vulnerabilities.',
      status: 'pending',
      priority: 'medium',
      estimatedTime: '1 hour',
      assignedTo: 'System Administration',
      dependencies: ['3'],
      instructions: [
        'Identify affected systems and applications',
        'Download and test patches in staging environment',
        'Deploy patches to production systems',
        'Verify patch installation and system stability'
      ],
      tools: ['Patch Management System', 'Configuration Management', 'System Monitoring']
    },
    {
      id: '5',
      title: 'Update Security Controls',
      description: 'Enhance security controls based on lessons learned from the incident.',
      status: 'pending',
      priority: 'medium',
      estimatedTime: '3 hours',
      assignedTo: 'Security Team',
      dependencies: ['4'],
      instructions: [
        'Review and update firewall rules',
        'Enhance endpoint detection and response',
        'Update threat intelligence feeds',
        'Improve monitoring and alerting'
      ],
      tools: ['SIEM', 'EDR Platform', 'Threat Intelligence Platform', 'Security Orchestration']
    }
  ];

  const priorities = ['all', 'critical', 'high', 'medium', 'low'];
  const statuses = ['all', 'pending', 'in-progress', 'completed', 'failed'];

  const filteredSteps = remediationSteps.filter(step => {
    const matchesPriority = selectedPriority === 'all' || step.priority === selectedPriority;
    const matchesStatus = selectedStatus === 'all' || step.status === selectedStatus;
    return matchesPriority && matchesStatus;
  });

  const getPriorityColor = (priority: string) => {
    switch (priority) {
      case 'critical': return 'bg-red-100 text-red-800 border-red-200';
      case 'high': return 'bg-orange-100 text-orange-800 border-orange-200';
      case 'medium': return 'bg-yellow-100 text-yellow-800 border-yellow-200';
      case 'low': return 'bg-blue-100 text-blue-800 border-blue-200';
      default: return 'bg-gray-100 text-gray-800 border-gray-200';
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'completed': return 'bg-green-100 text-green-800';
      case 'in-progress': return 'bg-blue-100 text-blue-800';
      case 'pending': return 'bg-gray-100 text-gray-800';
      case 'failed': return 'bg-red-100 text-red-800';
      default: return 'bg-gray-100 text-gray-800';
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'completed': return <CheckCircleIcon className="h-4 w-4" />;
      case 'in-progress': return <ClockIcon className="h-4 w-4" />;
      case 'pending': return <ClockIcon className="h-4 w-4" />;
      case 'failed': return <ExclamationTriangleIcon className="h-4 w-4" />;
      default: return <ClockIcon className="h-4 w-4" />;
    }
  };

  return (
    <div className="bg-white rounded-lg shadow">
      <div className="p-6 border-b border-gray-200">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center space-x-2">
            <DocumentTextIcon className="h-6 w-6 text-blue-600" />
            <h3 className="text-lg font-semibold text-gray-900">Remediation Steps</h3>
          </div>
          <div className="text-sm text-gray-500">
            {filteredSteps.length} steps remaining
          </div>
        </div>
        
        {/* Filters */}
        <div className="flex flex-wrap gap-2 mb-4">
          <select
            value={selectedPriority}
            onChange={(e) => setSelectedPriority(e.target.value)}
            className="px-3 py-1 border border-gray-300 rounded-md text-sm focus:ring-2 focus:ring-blue-500"
          >
            {priorities.map(priority => (
              <option key={priority} value={priority}>
                {priority === 'all' ? 'All Priorities' : priority.charAt(0).toUpperCase() + priority.slice(1)}
              </option>
            ))}
          </select>
          
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
        </div>
      </div>

      {/* Remediation Steps */}
      <div className="divide-y divide-gray-200">
        {filteredSteps.map((step) => (
          <div key={step.id} className="p-6 hover:bg-gray-50 transition-colors">
            <div className="flex items-start justify-between mb-3">
              <div className="flex-1">
                <div className="flex items-center space-x-2 mb-2">
                  <h4 className="text-lg font-medium text-gray-900">{step.title}</h4>
                  <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium border ${getPriorityColor(step.priority)}`}>
                    {step.priority}
                  </span>
                  <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${getStatusColor(step.status)}`}>
                    {getStatusIcon(step.status)}
                    <span className="ml-1">{step.status}</span>
                  </span>
                </div>
                
                <p className="text-gray-600 mb-3">{step.description}</p>
                
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-3">
                  <div>
                    <span className="text-sm font-medium text-gray-700">Instructions:</span>
                    <ol className="list-decimal list-inside mt-1 space-y-1">
                      {step.instructions.map((instruction, index) => (
                        <li key={index} className="text-sm text-gray-600">{instruction}</li>
                      ))}
                    </ol>
                  </div>
                  
                  <div>
                    <span className="text-sm font-medium text-gray-700">Required Tools:</span>
                    <div className="flex flex-wrap gap-1 mt-1">
                      {step.tools.map((tool, index) => (
                        <span
                          key={index}
                          className="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium bg-blue-100 text-blue-800"
                        >
                          {tool}
                        </span>
                      ))}
                    </div>
                  </div>
                </div>
                
                <div className="flex items-center justify-between text-sm text-gray-500">
                  <div className="flex items-center space-x-4">
                    <span className="flex items-center">
                      <UserGroupIcon className="h-4 w-4 mr-1" />
                      {step.assignedTo}
                    </span>
                    <span>Est. Time: {step.estimatedTime}</span>
                  </div>
                  {step.dependencies.length > 0 && (
                    <div className="text-right">
                      <span className="text-xs text-gray-500">Depends on: {step.dependencies.join(', ')}</span>
                    </div>
                  )}
                </div>
              </div>
            </div>
          </div>
        ))}
      </div>
      
      {filteredSteps.length === 0 && (
        <div className="p-6 text-center text-gray-500">
          No remediation steps found matching your criteria.
        </div>
      )}
    </div>
  );
};

export default RemediationSteps; 