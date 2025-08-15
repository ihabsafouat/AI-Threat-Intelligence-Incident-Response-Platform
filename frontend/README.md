# Security Intelligence Platform - Frontend

A modern React-based dashboard for threat intelligence and security management.

## Features

- **Threat Feed**: Real-time threat intelligence with filtering and search
- **AI Assistant**: Ask questions about security threats and get AI-powered responses
- **Incident Matches**: View incidents that match current threats with correlation analysis
- **Remediation Steps**: Step-by-step remediation guidance for security incidents
- **PDF Export**: Generate comprehensive security reports in PDF format
- **Interactive Charts**: Visualize threat trends and vulnerability distributions
- **Real-time Updates**: Live data updates and notifications

## Tech Stack

- **React 18** with TypeScript
- **Tailwind CSS** for styling
- **Chart.js** with react-chartjs-2 for data visualization
- **React Query** for data fetching and caching
- **React Router** for navigation
- **Zustand** for state management
- **Axios** for HTTP requests
- **Heroicons** for icons

## Getting Started

### Prerequisites

- Node.js 16+ 
- npm or yarn

### Installation

1. Install dependencies:
```bash
npm install
```

2. Start the development server:
```bash
npm start
```

3. Open [http://localhost:3000](http://localhost:3000) to view it in the browser.

### Available Scripts

- `npm start` - Runs the app in development mode
- `npm run build` - Builds the app for production
- `npm test` - Launches the test runner
- `npm run lint` - Runs ESLint
- `npm run lint:fix` - Fixes ESLint errors automatically
- `npm run format` - Formats code with Prettier

## Project Structure

```
src/
├── components/
│   ├── Dashboard/          # Dashboard-specific components
│   │   ├── MetricCard.tsx
│   │   ├── ThreatChart.tsx
│   │   ├── VulnerabilityChart.tsx
│   │   ├── RecentThreats.tsx
│   │   ├── SecurityScore.tsx
│   │   ├── ThreatFeed.tsx
│   │   ├── SearchBar.tsx
│   │   ├── IncidentMatches.tsx
│   │   ├── RemediationSteps.tsx
│   │   └── PDFExport.tsx
│   └── Layout/             # Layout components
│       ├── Layout.tsx
│       ├── Sidebar.tsx
│       └── Header.tsx
├── pages/                  # Page components
│   ├── Dashboard.tsx
│   ├── Threats.tsx
│   ├── Vulnerabilities.tsx
│   ├── Assets.tsx
│   ├── Incidents.tsx
│   ├── Analytics.tsx
│   ├── Login.tsx
│   └── Register.tsx
├── services/               # API services
│   └── api.ts
├── stores/                 # State management
│   └── authStore.ts
├── App.tsx                 # Main app component
├── index.tsx              # App entry point
└── index.css              # Global styles
```

## Features Overview

### 1. Threat Feed
- Real-time threat intelligence updates
- Filter by category and severity
- Search through threats, IOCs, and tags
- Detailed threat information with sources

### 2. AI Security Assistant
- Natural language queries about security
- AI-powered responses with confidence scores
- Sample questions for quick access
- Source attribution for responses

### 3. Incident Matches
- Correlate incidents with threat intelligence
- Filter by status and severity
- Match scores and affected assets
- Assignment and timeline tracking

### 4. Remediation Steps
- Step-by-step remediation guidance
- Priority and dependency management
- Required tools and instructions
- Progress tracking

### 5. PDF Export
- Multiple report templates
- Customizable date ranges
- Configurable report sections
- Professional PDF generation

## API Integration

The frontend is configured to connect to a backend API. Update the `API_BASE_URL` in `src/services/api.ts` to point to your backend server.

## Development

### Adding New Components

1. Create the component in the appropriate directory
2. Export it as the default export
3. Import and use it in the relevant page or component

### Styling

This project uses Tailwind CSS for styling. All components use utility classes for consistent styling.

### State Management

- **Zustand** is used for global state management
- **React Query** handles server state and caching
- Local component state uses React hooks

## Deployment

### Production Build

```bash
npm run build
```

The build artifacts will be stored in the `build/` directory.

### Docker

Use the provided Dockerfile for containerized deployment:

```bash
docker build -t security-frontend .
docker run -p 3000:3000 security-frontend
```

## Contributing

1. Follow the existing code style
2. Add TypeScript types for all new components
3. Test your changes thoroughly
4. Update documentation as needed

## License

This project is part of the Security Intelligence Platform. 