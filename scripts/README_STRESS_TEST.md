# CVE Ingestion Stress Testing Suite

A comprehensive stress testing suite for evaluating the performance and scalability of CVE ingestion systems. This suite includes tools for generating realistic CVE data, monitoring system performance, and analyzing results.

## 🎯 Features

- **Realistic CVE Generation**: Creates authentic CVE data with proper CVSS scores, CWE types, and metadata
- **Concurrent Testing**: Supports configurable concurrent requests to test system scalability
- **Batch Processing**: Processes CVEs in configurable batch sizes for optimal performance
- **System Monitoring**: Real-time monitoring of CPU, memory, disk, and network usage
- **Comprehensive Reporting**: Detailed JSON results and markdown reports
- **Multiple Test Types**: Baseline, light, medium, heavy, and extreme load tests
- **Scalability Analysis**: Tests system performance across different load levels

## 📁 Files Overview

### Core Scripts
- `stress_test_cve_ingestion.py` - Main CVE ingestion stress tester
- `monitor_system_performance.py` - System performance monitoring
- `run_stress_test.sh` - Basic stress test runner
- `run_comprehensive_stress_test.sh` - Comprehensive test suite runner

### Configuration
- `requirements_stress_test.txt` - Python dependencies
- `README_STRESS_TEST.md` - This documentation

## 🚀 Quick Start

### 1. Install Dependencies

```bash
cd scripts
pip3 install -r requirements_stress_test.txt
```

### 2. Run Basic Stress Test

```bash
# Run 10,000 CVEs with default settings
./run_stress_test.sh heavy

# Run custom test
TOTAL_CVES=5000 BATCH_SIZE=50 CONCURRENT_REQUESTS=10 ./run_stress_test.sh custom
```

### 3. Run Comprehensive Test Suite

```bash
# Run all test types with system monitoring
./run_comprehensive_stress_test.sh comprehensive

# Run scalability tests
./run_comprehensive_stress_test.sh scalability
```

## 📊 Test Types

### Baseline Test
- **CVEs**: 100
- **Batch Size**: 10
- **Concurrent Requests**: 1
- **Purpose**: Establish baseline performance

### Light Load Test
- **CVEs**: 1,000
- **Batch Size**: 50
- **Concurrent Requests**: 5
- **Purpose**: Test system under light load

### Medium Load Test
- **CVEs**: 5,000
- **Batch Size**: 100
- **Concurrent Requests**: 10
- **Purpose**: Test system under moderate load

### Heavy Load Test
- **CVEs**: 10,000
- **Batch Size**: 200
- **Concurrent Requests**: 20
- **Purpose**: Test system under heavy load

### Extreme Load Test
- **CVEs**: 20,000
- **Batch Size**: 500
- **Concurrent Requests**: 50
- **Purpose**: Test system limits

## 🔧 Configuration Options

### Environment Variables

```bash
# API Configuration
export API_URL="http://localhost:8000"
export API_KEY="your-api-key"

# Test Configuration
export TOTAL_CVES=10000
export BATCH_SIZE=100
export CONCURRENT_REQUESTS=10

# Output Configuration
export TEST_NAME="my_stress_test"
export OUTPUT_DIR="test_results"
export MONITOR_INTERVAL=1.0
```

### Command Line Options

```bash
# Basic stress test
./run_stress_test.sh [OPTIONS] [TEST_TYPE]

Options:
  -u, --url URL           API base URL
  -k, --api-key KEY       API key for authentication
  -c, --cves COUNT        Total number of CVEs
  -b, --batch-size SIZE   Batch size
  -n, --concurrent NUM    Concurrent requests
  -o, --output FILE       Output file

# Comprehensive test
./run_comprehensive_stress_test.sh [OPTIONS] [TEST_TYPE]

Options:
  -u, --url URL           API base URL
  -k, --api-key KEY       API key for authentication
  -n, --name NAME         Test name
  -o, --output DIR        Output directory
  -i, --interval SEC      Monitor interval
```

## 📈 Understanding Results

### Performance Metrics

1. **Total CVEs Processed**: Number of CVEs successfully ingested
2. **Success Rate**: Percentage of successful ingestions
3. **Average Response Time**: Mean time per request
4. **Requests per Second**: Throughput measurement
5. **Error Analysis**: Types and frequency of failures

### System Metrics

1. **CPU Usage**: Processor utilization during tests
2. **Memory Usage**: RAM consumption patterns
3. **Disk I/O**: Storage read/write operations
4. **Network Usage**: Network traffic and connections

### Output Files

- `*_results.json`: Detailed test results with timing data
- `system_metrics.json`: System performance data
- `comprehensive_report.md`: Human-readable test summary
- `stress_test.log`: Execution logs

## 🔍 Example Usage Scenarios

### Scenario 1: Performance Baseline
```bash
# Establish baseline performance
./run_stress_test.sh baseline
```

### Scenario 2: Load Testing
```bash
# Test system under increasing load
./run_comprehensive_stress_test.sh comprehensive
```

### Scenario 3: Scalability Analysis
```bash
# Test system scaling capabilities
./run_comprehensive_stress_test.sh scalability
```

### Scenario 4: Custom Load Test
```bash
# Test specific configuration
TOTAL_CVES=5000 BATCH_SIZE=50 CONCURRENT_REQUESTS=10 \
./run_stress_test.sh custom --url http://api.example.com
```

### Scenario 5: Production Load Simulation
```bash
# Simulate production load
TOTAL_CVES=50000 BATCH_SIZE=500 CONCURRENT_REQUESTS=100 \
./run_comprehensive_stress_test.sh custom \
--url https://api.production.com \
--api-key $PROD_API_KEY
```

## 📊 Interpreting Results

### Performance Indicators

| Metric | Good | Warning | Critical |
|--------|------|---------|----------|
| Success Rate | > 95% | 90-95% | < 90% |
| Avg Response Time | < 1s | 1-5s | > 5s |
| Requests/Second | > 100 | 50-100 | < 50 |
| CPU Usage | < 70% | 70-90% | > 90% |
| Memory Usage | < 80% | 80-95% | > 95% |

### Common Issues

1. **High Error Rate**: Check API endpoints and authentication
2. **Slow Response Times**: Investigate database performance
3. **High CPU Usage**: Consider optimizing processing logic
4. **Memory Leaks**: Monitor memory usage patterns
5. **Network Timeouts**: Check network configuration

## 🛠️ Troubleshooting

### Common Problems

1. **Import Errors**
   ```bash
   pip3 install -r requirements_stress_test.txt
   ```

2. **Permission Denied**
   ```bash
   chmod +x *.sh
   ```

3. **API Connection Issues**
   - Verify API URL is accessible
   - Check API key authentication
   - Test with curl or Postman

4. **System Resource Issues**
   - Monitor system resources during tests
   - Adjust batch sizes and concurrency
   - Consider running tests during off-peak hours

### Debug Mode

```bash
# Enable verbose logging
export DEBUG=1
./run_stress_test.sh heavy
```

## 📋 Best Practices

### Before Running Tests

1. **System Preparation**
   - Ensure adequate disk space
   - Close unnecessary applications
   - Monitor system resources

2. **API Preparation**
   - Verify API endpoints are working
   - Test authentication
   - Check rate limiting policies

3. **Database Preparation**
   - Ensure sufficient storage
   - Check database performance
   - Monitor connection pools

### During Tests

1. **Monitoring**
   - Watch system resources
   - Monitor error rates
   - Track response times

2. **Adjustments**
   - Modify batch sizes if needed
   - Adjust concurrency levels
   - Monitor for bottlenecks

### After Tests

1. **Analysis**
   - Review performance metrics
   - Analyze error patterns
   - Identify optimization opportunities

2. **Documentation**
   - Save test results
   - Document findings
   - Plan follow-up tests

## 🔄 Continuous Testing

### Automated Testing

```bash
# Create automated test script
cat > run_automated_tests.sh << 'EOF'
#!/bin/bash
set -e

# Run tests daily at 2 AM
0 2 * * * /path/to/scripts/run_comprehensive_stress_test.sh comprehensive

# Run scalability tests weekly
0 3 * * 0 /path/to/scripts/run_comprehensive_stress_test.sh scalability
EOF

chmod +x run_automated_tests.sh
```

### CI/CD Integration

```yaml
# Example GitHub Actions workflow
name: Stress Test
on: [push, pull_request]

jobs:
  stress-test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Run Stress Test
        run: |
          cd scripts
          pip3 install -r requirements_stress_test.txt
          ./run_stress_test.sh baseline
```

## 📞 Support

For issues or questions:

1. Check the troubleshooting section
2. Review the logs in `stress_test.log`
3. Examine the generated JSON results
4. Consult the system monitoring data

## 📄 License

This stress testing suite is part of the Security Intelligence Platform. 