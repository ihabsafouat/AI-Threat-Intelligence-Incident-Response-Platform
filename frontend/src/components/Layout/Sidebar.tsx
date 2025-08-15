import React from 'react';
import { Link, useLocation } from 'react-router-dom';
import {
  HomeIcon,
  ShieldExclamationIcon,
  ExclamationTriangleIcon,
  ServerIcon,
  ChartBarIcon,
  DocumentTextIcon,
  CogIcon,
  UserIcon
} from '@heroicons/react/24/outline';

const Sidebar: React.FC = () => {
  const location = useLocation();

  const navigation = [
    { name: 'Dashboard', href: '/dashboard', icon: HomeIcon },
    { name: 'Threats', href: '/threats', icon: ShieldExclamationIcon },
    { name: 'Vulnerabilities', href: '/vulnerabilities', icon: ExclamationTriangleIcon },
    { name: 'Assets', href: '/assets', icon: ServerIcon },
    { name: 'Incidents', href: '/incidents', icon: ChartBarIcon },
    { name: 'Analytics', href: '/analytics', icon: DocumentTextIcon },
  ];

  const isActive = (href: string) => {
    return location.pathname === href;
  };

  return (
    <div className="flex flex-col w-64 bg-white shadow-lg">
      <div className="flex items-center justify-center h-16 px-4 border-b border-gray-200">
        <h1 className="text-xl font-bold text-gray-900">Security Platform</h1>
      </div>
      
      <nav className="flex-1 px-4 py-6 space-y-2">
        {navigation.map((item) => {
          const Icon = item.icon;
          return (
            <Link
              key={item.name}
              to={item.href}
              className={`flex items-center px-3 py-2 text-sm font-medium rounded-md transition-colors ${
                isActive(item.href)
                  ? 'bg-blue-100 text-blue-700'
                  : 'text-gray-600 hover:bg-gray-100 hover:text-gray-900'
              }`}
            >
              <Icon className="mr-3 h-5 w-5" />
              {item.name}
            </Link>
          );
        })}
      </nav>
      
      <div className="p-4 border-t border-gray-200">
        <div className="space-y-2">
          <Link
            to="/settings"
            className="flex items-center px-3 py-2 text-sm font-medium text-gray-600 rounded-md hover:bg-gray-100 hover:text-gray-900"
          >
            <CogIcon className="mr-3 h-5 w-5" />
            Settings
          </Link>
          <Link
            to="/profile"
            className="flex items-center px-3 py-2 text-sm font-medium text-gray-600 rounded-md hover:bg-gray-100 hover:text-gray-900"
          >
            <UserIcon className="mr-3 h-5 w-5" />
            Profile
          </Link>
        </div>
      </div>
    </div>
  );
};

export default Sidebar; 