#!/bin/bash

# CVE Ingestion Stress Test Runner
# This script runs the CVE stress test with different configurations

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default values
API_URL=${API_URL:-"http://localhost:8000"}
API_KEY=${API_KEY:-""}
TOTAL_CVES=${TOTAL_CVES:-10000}
BATCH_SIZE=${BATCH_SIZE:-100}
CONCURRENT_REQUESTS=${CONCURRENT_REQUESTS:-10}
OUTPUT_FILE=${OUTPUT_FILE:-"stress_test_results.json"}

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

# Function to check if Python and required packages are available
check_dependencies() {
    print_status "Checking dependencies..."
    
    if ! command -v python3 &> /dev/null; then
        print_error "Python 3 is not installed"
        exit 1
    fi
    
    if ! python3 -c "import aiohttp" &> /dev/null; then
        print_warning "aiohttp not found. Installing dependencies..."
        pip3 install -r requirements_stress_test.txt
    fi
    
    print_success "Dependencies check completed"
}

# Function to run a single stress test
run_stress_test() {
    local test_name=$1
    local total_cves=$2
    local batch_size=$3
    local concurrent=$4
    
    print_status "Running $test_name test..."
    print_status "Configuration: $total_cves CVEs, batch size: $batch_size, concurrent: $concurrent"
    
    python3 stress_test_cve_ingestion.py \
        --url "$API_URL" \
        --api-key "$API_KEY" \
        --total-cves "$total_cves" \
        --batch-size "$batch_size" \
        --concurrent "$concurrent" \
        --output "${test_name}_${OUTPUT_FILE}"
    
    print_success "$test_name test completed"
}

# Function to run comprehensive stress test suite
run_comprehensive_tests() {
    print_status "Starting comprehensive stress test suite..."
    
    # Test 1: Light load test
    run_stress_test "light_load" 1000 50 5
    
    # Test 2: Medium load test
    run_stress_test "medium_load" 5000 100 10
    
    # Test 3: Heavy load test
    run_stress_test "heavy_load" 10000 200 20
    
    # Test 4: Extreme load test
    run_stress_test "extreme_load" 20000 500 50
    
    print_success "Comprehensive stress test suite completed"
}

# Function to run performance baseline test
run_baseline_test() {
    print_status "Running baseline performance test..."
    
    run_stress_test "baseline" 100 10 1
    
    print_success "Baseline test completed"
}

# Function to run scalability test
run_scalability_test() {
    print_status "Running scalability test..."
    
    local cve_counts=(100 500 1000 5000 10000)
    local batch_sizes=(10 25 50 100 200)
    local concurrent_levels=(1 5 10 20 50)
    
    for i in "${!cve_counts[@]}"; do
        local cves=${cve_counts[$i]}
        local batch=${batch_sizes[$i]}
        local concurrent=${concurrent_levels[$i]}
        
        run_stress_test "scalability_${cves}" "$cves" "$batch" "$concurrent"
    done
    
    print_success "Scalability test completed"
}

# Function to generate test report
generate_report() {
    print_status "Generating test report..."
    
    local report_file="stress_test_report_$(date +%Y%m%d_%H%M%S).md"
    
    cat > "$report_file" << EOF
# CVE Ingestion Stress Test Report
Generated on: $(date)

## Test Configuration
- API URL: $API_URL
- Total CVEs: $TOTAL_CVES
- Batch Size: $BATCH_SIZE
- Concurrent Requests: $CONCURRENT_REQUESTS

## Test Results Summary

### Performance Metrics
- Total CVEs Processed: [See individual test results]
- Average Response Time: [See individual test results]
- Requests per Second: [See individual test results]
- Success Rate: [See individual test results]

### System Performance
- CPU Usage: [Monitor during tests]
- Memory Usage: [Monitor during tests]
- Database Performance: [Monitor during tests]
- Network Latency: [Monitor during tests]

## Recommendations
1. Monitor system resources during tests
2. Adjust batch sizes based on system capacity
3. Optimize database queries for bulk operations
4. Consider implementing rate limiting
5. Monitor error rates and types

## Next Steps
1. Analyze detailed results in JSON files
2. Identify performance bottlenecks
3. Optimize system configuration
4. Run follow-up tests with optimizations
EOF
    
    print_success "Test report generated: $report_file"
}

# Function to show usage
show_usage() {
    echo "Usage: $0 [OPTIONS] [TEST_TYPE]"
    echo ""
    echo "OPTIONS:"
    echo "  -h, --help              Show this help message"
    echo "  -u, --url URL           API base URL (default: http://localhost:8000)"
    echo "  -k, --api-key KEY       API key for authentication"
    echo "  -c, --cves COUNT        Total number of CVEs (default: 10000)"
    echo "  -b, --batch-size SIZE   Batch size (default: 100)"
    echo "  -n, --concurrent NUM    Concurrent requests (default: 10)"
    echo "  -o, --output FILE       Output file (default: stress_test_results.json)"
    echo ""
    echo "TEST_TYPE:"
    echo "  baseline                Run baseline performance test (100 CVEs)"
    echo "  light                   Run light load test (1,000 CVEs)"
    echo "  medium                  Run medium load test (5,000 CVEs)"
    echo "  heavy                   Run heavy load test (10,000 CVEs)"
    echo "  extreme                 Run extreme load test (20,000 CVEs)"
    echo "  scalability             Run scalability test suite"
    echo "  comprehensive           Run comprehensive test suite"
    echo "  custom                  Run custom test with provided parameters"
    echo ""
    echo "ENVIRONMENT VARIABLES:"
    echo "  API_URL                 API base URL"
    echo "  API_KEY                 API key for authentication"
    echo "  TOTAL_CVES              Total number of CVEs"
    echo "  BATCH_SIZE              Batch size"
    echo "  CONCURRENT_REQUESTS     Number of concurrent requests"
    echo "  OUTPUT_FILE             Output file name"
    echo ""
    echo "EXAMPLES:"
    echo "  $0 baseline"
    echo "  $0 heavy --url http://api.example.com --api-key mykey"
    echo "  $0 comprehensive"
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
        -c|--cves)
            TOTAL_CVES="$2"
            shift 2
            ;;
        -b|--batch-size)
            BATCH_SIZE="$2"
            shift 2
            ;;
        -n|--concurrent)
            CONCURRENT_REQUESTS="$2"
            shift 2
            ;;
        -o|--output)
            OUTPUT_FILE="$2"
            shift 2
            ;;
        baseline|light|medium|heavy|extreme|scalability|comprehensive|custom)
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
    print_status "CVE Ingestion Stress Test Runner"
    print_status "API URL: $API_URL"
    print_status "Total CVEs: $TOTAL_CVES"
    print_status "Batch Size: $BATCH_SIZE"
    print_status "Concurrent Requests: $CONCURRENT_REQUESTS"
    
    # Check dependencies
    check_dependencies
    
    # Run selected test
    case ${TEST_TYPE:-custom} in
        baseline)
            run_baseline_test
            ;;
        light)
            run_stress_test "light_load" 1000 50 5
            ;;
        medium)
            run_stress_test "medium_load" 5000 100 10
            ;;
        heavy)
            run_stress_test "heavy_load" 10000 200 20
            ;;
        extreme)
            run_stress_test "extreme_load" 20000 500 50
            ;;
        scalability)
            run_scalability_test
            ;;
        comprehensive)
            run_comprehensive_tests
            ;;
        custom)
            run_stress_test "custom" "$TOTAL_CVES" "$BATCH_SIZE" "$CONCURRENT_REQUESTS"
            ;;
        *)
            print_error "Unknown test type: $TEST_TYPE"
            show_usage
            exit 1
            ;;
    esac
    
    # Generate report
    generate_report
    
    print_success "Stress test completed successfully!"
    print_status "Check the generated files for detailed results:"
    ls -la *stress_test*.json *stress_test*.log 2>/dev/null || true
}

# Run main function
main "$@" 