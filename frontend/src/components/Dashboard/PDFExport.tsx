import React, { useState } from 'react';
import { DocumentArrowDownIcon, DocumentTextIcon, CalendarIcon, ChartBarIcon } from '@heroicons/react/24/outline';

interface ReportTemplate {
  id: string;
  name: string;
  description: string;
  sections: string[];
  estimatedTime: string;
}

const PDFExport: React.FC = () => {
  const [selectedTemplate, setSelectedTemplate] = useState('');
  const [dateRange, setDateRange] = useState('last-30-days');
  const [includeCharts, setIncludeCharts] = useState(true);
  const [includeThreats, setIncludeThreats] = useState(true);
  const [includeIncidents, setIncludeIncidents] = useState(true);
  const [includeRemediation, setIncludeRemediation] = useState(true);
  const [isGenerating, setIsGenerating] = useState(false);

  const reportTemplates: ReportTemplate[] = [
    {
      id: 'executive-summary',
      name: 'Executive Summary',
      description: 'High-level security overview for executive leadership',
      sections: ['Security Score', 'Key Metrics', 'Top Threats', 'Recommendations'],
      estimatedTime: '2-3 minutes'
    },
    {
      id: 'incident-report',
      name: 'Incident Report',
      description: 'Detailed incident analysis and response documentation',
      sections: ['Incident Timeline', 'Impact Assessment', 'Response Actions', 'Lessons Learned'],
      estimatedTime: '5-7 minutes'
    },
    {
      id: 'threat-intelligence',
      name: 'Threat Intelligence Report',
      description: 'Comprehensive threat landscape analysis',
      sections: ['Threat Trends', 'IOC Analysis', 'Attack Patterns', 'Mitigation Strategies'],
      estimatedTime: '3-5 minutes'
    },
    {
      id: 'compliance-report',
      name: 'Compliance Report',
      description: 'Security compliance and audit documentation',
      sections: ['Compliance Status', 'Gap Analysis', 'Remediation Plans', 'Evidence'],
      estimatedTime: '4-6 minutes'
    },
    {
      id: 'custom-report',
      name: 'Custom Report',
      description: 'Build your own report with selected sections',
      sections: ['Customizable Sections'],
      estimatedTime: 'Variable'
    }
  ];

  const dateRanges = [
    { value: 'last-7-days', label: 'Last 7 Days' },
    { value: 'last-30-days', label: 'Last 30 Days' },
    { value: 'last-90-days', label: 'Last 90 Days' },
    { value: 'last-6-months', label: 'Last 6 Months' },
    { value: 'last-year', label: 'Last Year' },
    { value: 'custom', label: 'Custom Range' }
  ];

  const handleGenerateReport = async () => {
    if (!selectedTemplate) return;
    
    setIsGenerating(true);
    
    // Simulate PDF generation
    setTimeout(() => {
      setIsGenerating(false);
      // In a real implementation, this would trigger the actual PDF generation
      alert('Report generated successfully! Download will begin shortly.');
    }, 3000);
  };

  const selectedTemplateData = reportTemplates.find(t => t.id === selectedTemplate);

  return (
    <div className="bg-white rounded-lg shadow">
      <div className="p-6 border-b border-gray-200">
        <div className="flex items-center space-x-2 mb-4">
          <DocumentArrowDownIcon className="h-6 w-6 text-blue-600" />
          <h3 className="text-lg font-semibold text-gray-900">Export PDF Reports</h3>
        </div>
        
        <p className="text-gray-600 mb-6">
          Generate comprehensive security reports in PDF format for stakeholders, compliance, and documentation.
        </p>
      </div>

      <div className="p-6 space-y-6">
        {/* Report Template Selection */}
        <div>
          <label className="block text-sm font-medium text-gray-700 mb-3">
            Report Template
          </label>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {reportTemplates.map((template) => (
              <div
                key={template.id}
                className={`p-4 border rounded-lg cursor-pointer transition-colors ${
                  selectedTemplate === template.id
                    ? 'border-blue-500 bg-blue-50'
                    : 'border-gray-300 hover:border-gray-400'
                }`}
                onClick={() => setSelectedTemplate(template.id)}
              >
                <div className="flex items-start justify-between mb-2">
                  <h4 className="font-medium text-gray-900">{template.name}</h4>
                  <DocumentTextIcon className="h-5 w-5 text-gray-400" />
                </div>
                <p className="text-sm text-gray-600 mb-2">{template.description}</p>
                <div className="text-xs text-gray-500">
                  Est. generation time: {template.estimatedTime}
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Date Range Selection */}
        <div>
          <label className="block text-sm font-medium text-gray-700 mb-3">
            Date Range
          </label>
          <div className="flex items-center space-x-2">
            <CalendarIcon className="h-5 w-5 text-gray-400" />
            <select
              value={dateRange}
              onChange={(e) => setDateRange(e.target.value)}
              className="flex-1 px-3 py-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-blue-500 focus:border-transparent"
            >
              {dateRanges.map((range) => (
                <option key={range.value} value={range.value}>
                  {range.label}
                </option>
              ))}
            </select>
          </div>
        </div>

        {/* Report Sections */}
        {selectedTemplate === 'custom-report' && (
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-3">
              Include Sections
            </label>
            <div className="space-y-3">
              <label className="flex items-center">
                <input
                  type="checkbox"
                  checked={includeCharts}
                  onChange={(e) => setIncludeCharts(e.target.checked)}
                  className="rounded border-gray-300 text-blue-600 focus:ring-blue-500"
                />
                <span className="ml-2 text-sm text-gray-700">Charts and Visualizations</span>
              </label>
              <label className="flex items-center">
                <input
                  type="checkbox"
                  checked={includeThreats}
                  onChange={(e) => setIncludeThreats(e.target.checked)}
                  className="rounded border-gray-300 text-blue-600 focus:ring-blue-500"
                />
                <span className="ml-2 text-sm text-gray-700">Threat Intelligence Data</span>
              </label>
              <label className="flex items-center">
                <input
                  type="checkbox"
                  checked={includeIncidents}
                  onChange={(e) => setIncludeIncidents(e.target.checked)}
                  className="rounded border-gray-300 text-blue-600 focus:ring-blue-500"
                />
                <span className="ml-2 text-sm text-gray-700">Incident Details</span>
              </label>
              <label className="flex items-center">
                <input
                  type="checkbox"
                  checked={includeRemediation}
                  onChange={(e) => setIncludeRemediation(e.target.checked)}
                  className="rounded border-gray-300 text-blue-600 focus:ring-blue-500"
                />
                <span className="ml-2 text-sm text-gray-700">Remediation Steps</span>
              </label>
            </div>
          </div>
        )}

        {/* Template Details */}
        {selectedTemplateData && selectedTemplate !== 'custom-report' && (
          <div className="bg-gray-50 rounded-lg p-4">
            <h4 className="font-medium text-gray-900 mb-2">Report Sections</h4>
            <div className="flex flex-wrap gap-2">
              {selectedTemplateData.sections.map((section, index) => (
                <span
                  key={index}
                  className="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium bg-blue-100 text-blue-800"
                >
                  {section}
                </span>
              ))}
            </div>
          </div>
        )}

        {/* Generate Button */}
        <div className="flex items-center justify-between pt-4 border-t border-gray-200">
          <div className="text-sm text-gray-500">
            {selectedTemplateData && `Estimated time: ${selectedTemplateData.estimatedTime}`}
          </div>
          <button
            onClick={handleGenerateReport}
            disabled={!selectedTemplate || isGenerating}
            className="flex items-center space-x-2 px-6 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:bg-gray-400 disabled:cursor-not-allowed transition-colors"
          >
            {isGenerating ? (
              <>
                <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white"></div>
                <span>Generating...</span>
              </>
            ) : (
              <>
                <DocumentArrowDownIcon className="h-4 w-4" />
                <span>Generate PDF Report</span>
              </>
            )}
          </button>
        </div>
      </div>
    </div>
  );
};

export default PDFExport; 