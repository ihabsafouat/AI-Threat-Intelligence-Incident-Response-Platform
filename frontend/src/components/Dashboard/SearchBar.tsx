import React, { useState } from 'react';
import { MagnifyingGlassIcon, PaperAirplaneIcon, SparklesIcon } from '@heroicons/react/24/outline';

interface SearchResult {
  id: string;
  question: string;
  answer: string;
  confidence: number;
  sources: string[];
  timestamp: string;
}

const SearchBar: React.FC = () => {
  const [query, setQuery] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [results, setResults] = useState<SearchResult[]>([]);
  const [showResults, setShowResults] = useState(false);

  const sampleQuestions = [
    "What are the latest ransomware threats?",
    "How to detect APT activity?",
    "What vulnerabilities affect our systems?",
    "How to respond to a data breach?",
    "What are the best practices for incident response?"
  ];

  const handleSearch = async () => {
    if (!query.trim()) return;
    
    setIsLoading(true);
    setShowResults(true);
    
    // Simulate API call
    setTimeout(() => {
      const mockResult: SearchResult = {
        id: Date.now().toString(),
        question: query,
        answer: `Based on our threat intelligence analysis, here's what we found regarding "${query}":\n\n` +
                `• Recent threat intelligence indicates increased activity in this area\n` +
                `• Our systems have detected similar patterns in the last 30 days\n` +
                `• Recommended actions include updating security policies and monitoring for suspicious activity\n` +
                `• Consider implementing additional detection mechanisms\n\n` +
                `This analysis is based on our comprehensive threat database and real-time monitoring systems.`,
        confidence: 0.87,
        sources: ['Threat Intelligence Database', 'Security Reports', 'Incident History'],
        timestamp: new Date().toLocaleString()
      };
      
      setResults([mockResult, ...results.slice(0, 4)]);
      setIsLoading(false);
    }, 2000);
  };

  const handleKeyPress = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter') {
      handleSearch();
    }
  };

  return (
    <div className="bg-white rounded-lg shadow">
      <div className="p-6 border-b border-gray-200">
        <div className="flex items-center space-x-2 mb-4">
          <SparklesIcon className="h-6 w-6 text-blue-600" />
          <h3 className="text-lg font-semibold text-gray-900">AI Security Assistant</h3>
        </div>
        
        <div className="space-y-4">
          <div className="relative">
            <input
              type="text"
              placeholder="Ask about threats, vulnerabilities, incidents, or security best practices..."
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              onKeyPress={handleKeyPress}
              className="w-full pl-4 pr-12 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
            />
            <button
              onClick={handleSearch}
              disabled={isLoading || !query.trim()}
              className="absolute right-2 top-1/2 transform -translate-y-1/2 p-2 text-blue-600 hover:text-blue-800 disabled:text-gray-400"
            >
              {isLoading ? (
                <div className="animate-spin rounded-full h-5 w-5 border-b-2 border-blue-600"></div>
              ) : (
                <PaperAirplaneIcon className="h-5 w-5" />
              )}
            </button>
          </div>
          
          <div className="text-sm text-gray-600">
            <p className="mb-2">Try asking:</p>
            <div className="flex flex-wrap gap-2">
              {sampleQuestions.map((question, index) => (
                <button
                  key={index}
                  onClick={() => setQuery(question)}
                  className="px-3 py-1 text-xs bg-gray-100 hover:bg-gray-200 rounded-full transition-colors"
                >
                  {question}
                </button>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* Search Results */}
      {showResults && (
        <div className="divide-y divide-gray-200">
          {isLoading && (
            <div className="p-6 text-center">
              <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600 mx-auto mb-2"></div>
              <p className="text-gray-600">Analyzing your question...</p>
            </div>
          )}
          
          {results.map((result) => (
            <div key={result.id} className="p-6">
              <div className="mb-4">
                <div className="flex items-center justify-between mb-2">
                  <h4 className="text-lg font-medium text-gray-900">Q: {result.question}</h4>
                  <span className="text-sm text-gray-500">{result.timestamp}</span>
                </div>
                <div className="flex items-center space-x-2">
                  <span className="text-sm text-gray-600">Confidence:</span>
                  <div className="flex items-center space-x-1">
                    <div className="w-16 bg-gray-200 rounded-full h-2">
                      <div
                        className="bg-blue-600 h-2 rounded-full"
                        style={{ width: `${result.confidence * 100}%` }}
                      ></div>
                    </div>
                    <span className="text-sm text-gray-600">{Math.round(result.confidence * 100)}%</span>
                  </div>
                </div>
              </div>
              
              <div className="bg-gray-50 rounded-lg p-4 mb-4">
                <p className="text-gray-800 whitespace-pre-line">{result.answer}</p>
              </div>
              
              <div className="text-sm text-gray-600">
                <span className="font-medium">Sources: </span>
                {result.sources.join(', ')}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

export default SearchBar; 