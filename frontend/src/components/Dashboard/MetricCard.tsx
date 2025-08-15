import React from 'react';
import { IconType } from '@heroicons/react/24/outline';

interface MetricCardProps {
  title: string;
  value: number;
  total?: number;
  icon: IconType;
  color: 'red' | 'orange' | 'yellow' | 'blue' | 'green' | 'purple';
  trend?: number;
  trendLabel?: string;
}

const MetricCard: React.FC<MetricCardProps> = ({
  title,
  value,
  total,
  icon: Icon,
  color,
  trend,
  trendLabel
}) => {
  const colorClasses = {
    red: 'text-red-600 bg-red-100',
    orange: 'text-orange-600 bg-orange-100',
    yellow: 'text-yellow-600 bg-yellow-100',
    blue: 'text-blue-600 bg-blue-100',
    green: 'text-green-600 bg-green-100',
    purple: 'text-purple-600 bg-purple-100'
  };

  return (
    <div className="bg-white rounded-lg shadow p-6">
      <div className="flex items-center justify-between">
        <div>
          <p className="text-sm font-medium text-gray-600">{title}</p>
          <div className="flex items-baseline">
            <p className="text-2xl font-semibold text-gray-900">{value}</p>
            {total && (
              <p className="ml-2 text-sm text-gray-500">/ {total}</p>
            )}
          </div>
          {trend !== undefined && (
            <p className="text-sm text-gray-500 mt-1">
              {trend > 0 ? '+' : ''}{trend} {trendLabel}
            </p>
          )}
        </div>
        <div className={`p-3 rounded-full ${colorClasses[color]}`}>
          <Icon className="h-6 w-6" />
        </div>
      </div>
    </div>
  );
};

export default MetricCard; 