import React, { useState } from 'react';
import { MagnifyingGlassIcon, FunnelIcon, BellIcon } from '@heroicons/react/24/outline';

interface ThreatFeedItem {
  id: string;
  title: string;
  description: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  category: string;
  timestamp: string;
  source: string;
  ioc?: string;
  tags: string[];
}

const ThreatFeed: React.FC = () => {
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedCategory, setSelectedCategory] = useState('all');
  const [selectedSeverity, setSelectedSeverity] = useState('all');

  const threatFeed: ThreatFeedItem[] = [
    {
      id: '1',
      title: 'New Ransomware Campaign Targeting Healthcare',
      description: 'A new ransomware campaign has been identified targeting healthcare organizations using sophisticated phishing techniques.',
      severity: 'critical',
      category: 'Ransomware',
      timestamp: '2 hours ago',
      source: 'CISA',
      ioc: '192.168.1.100',
      tags: ['healthcare', 'phishing', 'encryption']
    },
    {
      id: '2',
      title: 'Zero-day Vulnerability in Apache Log4j',
      description: 'Critical vulnerability discovered in Apache Log4j library allowing remote code execution.',
      severity: 'critical',
      category: 'Vulnerability',
      timestamp: '4 hours ago',
      source: 'Apache Security',
      ioc: 'CVE-2023-1234',
      tags: ['apache', 'log4j', 'rce']
    },
    {
      id: '3',
      title: 'APT Group Activity in Financial Sector',
      description: 'Advanced Persistent Threat group targeting financial institutions with new malware variant.',
      severity: 'high',
      category: 'APT',
      timestamp: '6 hours ago',
      source: 'FBI',
      tags: ['apt', 'financial', 'malware']
    },
    {
      id: '4',
      title: 'Supply Chain Attack via NPM Package',
      description: 'Malicious code discovered in popular NPM package affecting thousands of applications.',
      severity: 'high',
      category: 'Supply Chain',
      timestamp: '8 hours ago',
      source: 'GitHub Security',
      tags: ['npm', 'supply-chain', 'javascript']
    }
  ];

  const categories = ['all', 'Ransomware', 'Vulnerability', 'APT', 'Supply Chain', 'Malware', 'Phishing'];
  const severities = ['all', 'critical', 'high', 'medium', 'low'];

  const filteredFeed = threatFeed.filter(item => {
    const matchesSearch = item.title.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         item.description.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         item.tags.some(tag => tag.toLowerCase().includes(searchTerm.toLowerCase()));
    const matchesCategory = selectedCategory === 'all' || item.category === selectedCategory;
    const matchesSeverity = selectedSeverity === 'all' || item.severity === selectedSeverity;
    
    return matchesSearch && matchesCategory && matchesSeverity;
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

  return (
    <div className="bg-white rounded-lg shadow">
      <div className="p-6 border-b border-gray-200">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-lg font-semibold text-gray-900">Threat Intelligence Feed</h3>
          <div className="flex items-center space-x-2">
            <BellIcon className="h-5 w-5 text-gray-400" />
            <span className="text-sm text-gray-500">Real-time updates</span>
          </div>
        </div>
        
        {/* Search and Filters */}
        <div className="space-y-4">
          <div className="relative">
            <MagnifyingGlassIcon className="absolute left-3 top-1/2 transform -translate-y-1/2 h-5 w-5 text-gray-400" />
            <input
              type="text"
              placeholder="Search threats, IOCs, or tags..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="w-full pl-10 pr-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
            />
          </div>
          
          <div className="flex flex-wrap gap-2">
            <select
              value={selectedCategory}
              onChange={(e) => setSelectedCategory(e.target.value)}
              className="px-3 py-1 border border-gray-300 rounded-md text-sm focus:ring-2 focus:ring-blue-500"
            >
              {categories.map(category => (
                <option key={category} value={category}>
                  {category === 'all' ? 'All Categories' : category}
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
      </div>

      {/* Threat Feed Items */}
      <div className="divide-y divide-gray-200">
        {filteredFeed.map((item) => (
          <div key={item.id} className="p-6 hover:bg-gray-50 transition-colors">
            <div className="flex items-start justify-between">
              <div className="flex-1">
                <div className="flex items-center space-x-2 mb-2">
                  <h4 className="text-lg font-medium text-gray-900">{item.title}</h4>
                  <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium border ${getSeverityColor(item.severity)}`}>
                    {item.severity}
                  </span>
                </div>
                <p className="text-gray-600 mb-3">{item.description}</p>
                
                <div className="flex items-center space-x-4 text-sm text-gray-500 mb-3">
                  <span>Category: {item.category}</span>
                  <span>Source: {item.source}</span>
                  <span>{item.timestamp}</span>
                </div>
                
                {item.ioc && (
                  <div className="mb-3">
                    <span className="text-sm font-medium text-gray-700">IOC: </span>
                    <code className="text-sm bg-gray-100 px-2 py-1 rounded">{item.ioc}</code>
                  </div>
                )}
                
                <div className="flex flex-wrap gap-1">
                  {item.tags.map((tag, index) => (
                    <span
                      key={index}
                      className="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium bg-blue-100 text-blue-800"
                    >
                      {tag}
                    </span>
                  ))}
                </div>
              </div>
            </div>
          </div>
        ))}
      </div>
      
      {filteredFeed.length === 0 && (
        <div className="p-6 text-center text-gray-500">
          No threats found matching your criteria.
        </div>
      )}
    </div>
  );
};

export default ThreatFeed; 