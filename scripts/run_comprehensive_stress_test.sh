#!/bin/bash

# Comprehensive CVE Ingestion Stress Test Runner
# Combines stress testing with system monitoring for complete performance analysis

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m' # No Color

# Default values
API_URL=${API_URL:-"http://localhost:8000"}
API_KEY=${API_KEY:-""}
TEST_NAME=${TEST_NAME:-"comprehensive_stress_test"}
OUTPUT_DIR=${OUTPUT_DIR:-"stress_test_results"}
MONITOR_INTERVAL=${MONITOR_INTERVAL:-1.0}

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_header() {
    echo -e "${PURPLE}[HEADER]${NC} $1"
}

# Function to check dependencies
check_dependencies() {
    print_status "Checking dependencies..."
    
    # Check Python
    if ! command -v python3 &> /dev/null; then
        print_error "Python 3 is not installed"
        exit 1
    fi
    
    # Check required Python packages
    local missing_packages=()
    
    if ! python3 -c "import aiohttp" &> /dev/null; then
        missing_packages+=("aiohttp")
    fi
    
    if ! python3 -c "import psutil" &> /dev/null; then
        missing_packages+=("psutil")
    fi
    
    if [ ${#missing_packages[@]} -ne 0 ]; then
        print_warning "Missing packages: ${missing_packages[*]}"
        print_status "Installing dependencies..."
        pip3 install -r requirements_stress_test.txt
    fi
    
    print_success "Dependencies check completed"
}

# Function to create output directory
setup_output_directory() {
    print_status "Setting up output directory..."
    
    mkdir -p "$OUTPUT_DIR"
    
    # Create timestamped subdirectory
    local timestamp=$(date +%Y%m%d_%H%M%S)
    local test_dir="$OUTPUT_DIR/${TEST_NAME}_${timestamp}"
    mkdir -p "$test_dir"
    
    echo "$test_dir"
}

# Function to start system monitoring
start_monitoring() {
    local output_dir=$1
    local monitor_output="$output_dir/system_metrics.json"
    
    print_status "Starting system monitoring..."
    
    python3 monitor_system_performance.py \
        --output "$monitor_output" \
        --interval "$MONITOR_INTERVAL" &
    
    local monitor_pid=$!
    echo $monitor_pid
}

# Function to stop system monitoring
stop_monitoring() {
    local monitor_pid=$1
    
    if [ -n "$monitor_pid" ] && kill -0 "$monitor_pid" 2>/dev/null; then
        print_status "Stopping system monitoring..."
        kill "$monitor_pid"
        wait "$monitor_pid" 2>/dev/null || true
        print_success "System monitoring stopped"
    fi
}

# Function to run a single stress test with monitoring
run_stress_test_with_monitoring() {
    local test_name=$1
    local total_cves=$2
    local batch_size=$3
    local concurrent=$4
    local output_dir=$5
    
    print_header "Running $test_name stress test"
    print_status "Configuration:"
    print_status "  - Total CVEs: $total_cves"
    print_status "  - Batch Size: $batch_size"
    print_status "  - Concurrent Requests: $concurrent"
    print_status "  - API URL: $API_URL"
    
    # Start system monitoring
    local monitor_pid=$(start_monitoring "$output_dir")
    
    # Wait a moment for monitoring to start
    sleep 2
    
    # Run stress test
    local test_start_time=$(date +%s)
    
    python3 stress_test_cve_ingestion.py \
        --url "$API_URL" \
        --api-key "$API_KEY" \
        --total-cves "$total_cves" \
        --batch-size "$batch_size" \
        --concurrent "$concurrent" \
        --output "$output_dir/${test_name}_results.json"
    
    local test_end_time=$(date +%s)
    local test_duration=$((test_end_time - test_start_time))
    
    # Stop monitoring
    stop_monitoring "$monitor_pid"
    
    print_success "$test_name test completed in ${test_duration}s"
}

# Function to run comprehensive test suite
run_comprehensive_suite() {
    local output_dir=$1
    
    print_header "Starting comprehensive stress test suite"
    
    # Test configurations
    local tests=(
        "baseline:100:10:1"
        "light_load:1000:50:5"
        "medium_load:5000:100:10"
        "heavy_load:10000:200:20"
        "extreme_load:20000:500:50"
    )
    
    for test_config in "${tests[@]}"; do
        IFS=':' read -r test_name total_cves batch_size concurrent <<< "$test_config"
        
        print_status "Running $test_name test..."
        run_stress_test_with_monitoring "$test_name" "$total_cves" "$batch_size" "$concurrent" "$output_dir"
        
        # Brief pause between tests
        sleep 5
    done
    
    print_success "Comprehensive test suite completed"
}

# Function to run scalability test
run_scalability_test() {
    local output_dir=$1
    
    print_header "Starting scalability test"
    
    # Scalability test configurations
    local cve_counts=(100 500 1000 5000 10000)
    local batch_sizes=(10 25 50 100 200)
    local concurrent_levels=(1 5 10 20 50)
    
    for i in "${!cve_counts[@]}"; do
        local cves=${cve_counts[$i]}
        local batch=${batch_sizes[$i]}
        local concurrent=${concurrent_levels[$i]}
        
        local test_name="scalability_${cves}"
        print_status "Running $test_name test..."
        run_stress_test_with_monitoring "$test_name" "$cves" "$batch" "$concurrent" "$output_dir"
        
        # Brief pause between tests
        sleep 3
    done
    
    print_success "Scalability test completed"
}

# Function to generate comprehensive report
generate_comprehensive_report() {
    local output_dir=$1
    
    print_status "Generating comprehensive test report..."
    
    local report_file="$output_dir/comprehensive_report.md"
    local timestamp=$(date)
    
    cat > "$report_file" << EOF
# Comprehensive CVE Ingestion Stress Test Report
Generated on: $timestamp

## Test Configuration
- API URL: $API_URL
- Test Name: $TEST_NAME
- Output Directory: $output_dir
- Monitor Interval: ${MONITOR_INTERVAL}s

## Test Summary

### Test Types Executed
1. **Baseline Test**: 100 CVEs, batch size 10, 1 concurrent request
2. **Light Load Test**: 1,000 CVEs, batch size 50, 5 concurrent requests
3. **Medium Load Test**: 5,000 CVEs, batch size 100, 10 concurrent requests
4. **Heavy Load Test**: 10,000 CVEs, batch size 200, 20 concurrent requests
5. **Extreme Load Test**: 20,000 CVEs, batch size 500, 50 concurrent requests
6. **Scalability Tests**: Various configurations to test system scaling

### Performance Metrics
- **Total CVEs Processed**: [See individual test results]
- **Average Response Time**: [See individual test results]
- **Requests per Second**: [See individual test results]
- **Success Rate**: [See individual test results]

### System Performance
- **CPU Usage**: [See system_metrics.json]
- **Memory Usage**: [See system_metrics.json]
- **Disk I/O**: [See system_metrics.json]
- **Network Usage**: [See system_metrics.json]

## Files Generated
- \`*_results.json\`: Individual test results
- \`system_metrics.json\`: System performance data
- \`stress_test.log\`: Test execution logs

## Analysis Recommendations
1. **Performance Bottlenecks**: Identify slowest operations
2. **Resource Utilization**: Monitor CPU, memory, and disk usage
3. **Scalability Limits**: Determine optimal batch sizes and concurrency
4. **Error Analysis**: Review failed requests and error patterns
5. **Optimization Opportunities**: Identify areas for improvement

## Next Steps
1. Analyze detailed results in JSON files
2. Generate performance graphs and charts
3. Identify and address performance bottlenecks
4. Optimize system configuration
5. Run follow-up tests with optimizations

## Test Environment
- **Operating System**: $(uname -s) $(uname -r)
- **CPU**: $(nproc) cores
- **Memory**: $(free -h | awk '/^Mem:/{print $2}')
- **Python Version**: $(python3 --version)
- **Test Duration**: [Calculated from timestamps]

EOF
    
    print_success "Comprehensive report generated: $report_file"
}

# Function to show usage
show_usage() {
    echo "Usage: $0 [OPTIONS] [TEST_TYPE]"
    echo ""
    echo "OPTIONS:"
    echo "  -h, --help              Show this help message"
    echo "  -u, --url URL           API base URL (default: http://localhost:8000)"
    echo "  -k, --api-key KEY       API key for authentication"
    echo "  -n, --name NAME         Test name (default: comprehensive_stress_test)"
    echo "  -o, --output DIR        Output directory (default: stress_test_results)"
    echo "  -i, --interval SEC      Monitor interval in seconds (default: 1.0)"
    echo ""
    echo "TEST_TYPE:"
    echo "  comprehensive           Run comprehensive test suite (default)"
    echo "  scalability             Run scalability test suite"
    echo "  custom                  Run custom test with environment variables"
    echo ""
    echo "ENVIRONMENT VARIABLES:"
    echo "  API_URL                 API base URL"
    echo "  API_KEY                 API key for authentication"
    echo "  TEST_NAME               Test name"
    echo "  OUTPUT_DIR              Output directory"
    echo "  MONITOR_INTERVAL        Monitor interval in seconds"
    echo "  TOTAL_CVES              Total number of CVEs (for custom test)"
    echo "  BATCH_SIZE              Batch size (for custom test)"
    echo "  CONCURRENT_REQUESTS     Number of concurrent requests (for custom test)"
    echo ""
    echo "EXAMPLES:"
    echo "  $0 comprehensive"
    echo "  $0 scalability --url http://api.example.com"
    echo "  TOTAL_CVES=5000 BATCH_SIZE=50 $0 custom"
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            show_usage
            exit 0
            ;;
        -u|--url)
            API_URL="$2"
            shift 2
            ;;
        -k|--api-key)
            API_KEY="$2"
            shift 2
            ;;
        -n|--name)
            TEST_NAME="$2"
            shift 2
            ;;
        -o|--output)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        -i|--interval)
            MONITOR_INTERVAL="$2"
            shift 2
            ;;
        comprehensive|scalability|custom)
            TEST_TYPE="$1"
            shift
            ;;
        *)
            print_error "Unknown option: $1"
            show_usage
            exit 1
            ;;
    esac
done

# Main execution
main() {
    print_header "Comprehensive CVE Ingestion Stress Test Runner"
    print_status "API URL: $API_URL"
    print_status "Test Name: $TEST_NAME"
    print_status "Output Directory: $OUTPUT_DIR"
    print_status "Monitor Interval: ${MONITOR_INTERVAL}s"
    
    # Check dependencies
    check_dependencies
    
    # Setup output directory
    local output_dir=$(setup_output_directory)
    print_status "Output directory: $output_dir"
    
    # Change to scripts directory
    cd "$(dirname "$0")"
    
    # Run selected test
    case ${TEST_TYPE:-comprehensive} in
        comprehensive)
            run_comprehensive_suite "$output_dir"
            ;;
        scalability)
            run_scalability_test "$output_dir"
            ;;
        custom)
            if [ -z "$TOTAL_CVES" ] || [ -z "$BATCH_SIZE" ] || [ -z "$CONCURRENT_REQUESTS" ]; then
                print_error "Custom test requires TOTAL_CVES, BATCH_SIZE, and CONCURRENT_REQUESTS environment variables"
                exit 1
            fi
            run_stress_test_with_monitoring "custom" "$TOTAL_CVES" "$BATCH_SIZE" "$CONCURRENT_REQUESTS" "$output_dir"
            ;;
        *)
            print_error "Unknown test type: $TEST_TYPE"
            show_usage
            exit 1
            ;;
    esac
    
    # Generate comprehensive report
    generate_comprehensive_report "$output_dir"
    
    print_success "Comprehensive stress test completed successfully!"
    print_status "Results saved to: $output_dir"
    print_status "Files generated:"
    ls -la "$output_dir"/*.json "$output_dir"/*.md 2>/dev/null || true
}

# Run main function
main "$@" 