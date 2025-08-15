@echo off
REM CVE Ingestion Stress Test Runner for Windows
REM This script runs the CVE stress test with different configurations

setlocal enabledelayedexpansion

REM Default values
if "%API_URL%"=="" set API_URL=http://localhost:8000
if "%API_KEY%"=="" set API_KEY=
if "%TOTAL_CVES%"=="" set TOTAL_CVES=10000
if "%BATCH_SIZE%"=="" set BATCH_SIZE=100
if "%CONCURRENT_REQUESTS%"=="" set CONCURRENT_REQUESTS=10
if "%OUTPUT_FILE%"=="" set OUTPUT_FILE=stress_test_results.json

REM Function to print colored output
:print_status
echo [INFO] %~1
goto :eof

:print_success
echo [SUCCESS] %~1
goto :eof

:print_warning
echo [WARNING] %~1
goto :eof

:print_error
echo [ERROR] %~1
goto :eof

REM Function to check if Python and required packages are available
:check_dependencies
call :print_status "Checking dependencies..."

python --version >nul 2>&1
if errorlevel 1 (
    call :print_error "Python is not installed or not in PATH"
    exit /b 1
)

python -c "import aiohttp" >nul 2>&1
if errorlevel 1 (
    call :print_warning "aiohttp not found. Installing dependencies..."
    pip install -r requirements_stress_test.txt
)

python -c "import psutil" >nul 2>&1
if errorlevel 1 (
    call :print_warning "psutil not found. Installing dependencies..."
    pip install -r requirements_stress_test.txt
)

call :print_success "Dependencies check completed"
goto :eof

REM Function to run a single stress test
:run_stress_test
set test_name=%~1
set total_cves=%~2
set batch_size=%~3
set concurrent=%~4

call :print_status "Running %test_name% test..."
call :print_status "Configuration: %total_cves% CVEs, batch size: %batch_size%, concurrent: %concurrent%"

python stress_test_cve_ingestion.py --url "%API_URL%" --api-key "%API_KEY%" --total-cves %total_cves% --batch-size %batch_size% --concurrent %concurrent% --output "%test_name%_%OUTPUT_FILE%"

if errorlevel 1 (
    call :print_error "%test_name% test failed"
    exit /b 1
)

call :print_success "%test_name% test completed"
goto :eof

REM Function to run comprehensive stress test suite
:run_comprehensive_tests
call :print_status "Starting comprehensive stress test suite..."

REM Test 1: Light load test
call :run_stress_test "light_load" 1000 50 5

REM Test 2: Medium load test
call :run_stress_test "medium_load" 5000 100 10

REM Test 3: Heavy load test
call :run_stress_test "heavy_load" 10000 200 20

REM Test 4: Extreme load test
call :run_stress_test "extreme_load" 20000 500 50

call :print_success "Comprehensive stress test suite completed"
goto :eof

REM Function to run performance baseline test
:run_baseline_test
call :print_status "Running baseline performance test..."
call :run_stress_test "baseline" 100 10 1
call :print_success "Baseline test completed"
goto :eof

REM Function to run scalability test
:run_scalability_test
call :print_status "Running scalability test..."

set cve_counts=100 500 1000 5000 10000
set batch_sizes=10 25 50 100 200
set concurrent_levels=1 5 10 20 50

set i=0
for %%c in (%cve_counts%) do (
    set /a i+=1
    set cves=%%c
    
    set j=0
    for %%b in (%batch_sizes%) do (
        set /a j+=1
        if !j!==!i! set batch=%%b
    )
    
    set k=0
    for %%n in (%concurrent_levels%) do (
        set /a k+=1
        if !k!==!i! set concurrent=%%n
    )
    
    call :run_stress_test "scalability_!cves!" !cves! !batch! !concurrent!
)

call :print_success "Scalability test completed"
goto :eof

REM Function to generate test report
:generate_report
call :print_status "Generating test report..."

set report_file=stress_test_report_%date:~-4,4%%date:~-10,2%%date:~-7,2%_%time:~0,2%%time:~3,2%%time:~6,2%.md
set report_file=%report_file: =0%

(
echo # CVE Ingestion Stress Test Report
echo Generated on: %date% %time%
echo.
echo ## Test Configuration
echo - API URL: %API_URL%
echo - Total CVEs: %TOTAL_CVES%
echo - Batch Size: %BATCH_SIZE%
echo - Concurrent Requests: %CONCURRENT_REQUESTS%
echo.
echo ## Test Results Summary
echo.
echo ### Performance Metrics
echo - Total CVEs Processed: [See individual test results]
echo - Average Response Time: [See individual test results]
echo - Requests per Second: [See individual test results]
echo - Success Rate: [See individual test results]
echo.
echo ### System Performance
echo - CPU Usage: [Monitor during tests]
echo - Memory Usage: [Monitor during tests]
echo - Database Performance: [Monitor during tests]
echo - Network Latency: [Monitor during tests]
echo.
echo ## Recommendations
echo 1. Monitor system resources during tests
echo 2. Adjust batch sizes based on system capacity
echo 3. Optimize database queries for bulk operations
echo 4. Consider implementing rate limiting
echo 5. Monitor error rates and types
echo.
echo ## Next Steps
echo 1. Analyze detailed results in JSON files
echo 2. Identify performance bottlenecks
echo 3. Optimize system configuration
echo 4. Run follow-up tests with optimizations
) > "%report_file%"

call :print_success "Test report generated: %report_file%"
goto :eof

REM Function to show usage
:show_usage
echo Usage: %~nx0 [OPTIONS] [TEST_TYPE]
echo.
echo OPTIONS:
echo   /?                    Show this help message
echo   /url URL              API base URL ^(default: http://localhost:8000^)
echo   /api-key KEY          API key for authentication
echo   /cves COUNT           Total number of CVEs ^(default: 10000^)
echo   /batch-size SIZE      Batch size ^(default: 100^)
echo   /concurrent NUM       Concurrent requests ^(default: 10^)
echo   /output FILE          Output file ^(default: stress_test_results.json^)
echo.
echo TEST_TYPE:
echo   baseline               Run baseline performance test ^(100 CVEs^)
echo   light                  Run light load test ^(1,000 CVEs^)
echo   medium                 Run medium load test ^(5,000 CVEs^)
echo   heavy                  Run heavy load test ^(10,000 CVEs^)
echo   extreme                Run extreme load test ^(20,000 CVEs^)
echo   scalability            Run scalability test suite
echo   comprehensive          Run comprehensive test suite
echo   custom                 Run custom test with provided parameters
echo.
echo ENVIRONMENT VARIABLES:
echo   API_URL                API base URL
echo   API_KEY                API key for authentication
echo   TOTAL_CVES             Total number of CVEs
echo   BATCH_SIZE             Batch size
echo   CONCURRENT_REQUESTS    Number of concurrent requests
echo   OUTPUT_FILE            Output file name
echo.
echo EXAMPLES:
echo   %~nx0 baseline
echo   %~nx0 heavy /url http://api.example.com /api-key mykey
echo   %~nx0 comprehensive
echo   set TOTAL_CVES=5000 ^& set BATCH_SIZE=50 ^& %~nx0 custom
goto :eof

REM Parse command line arguments
set TEST_TYPE=custom
:parse_args
if "%~1"=="" goto :main
if /i "%~1"=="/?" goto :show_usage
if /i "%~1"=="/url" (
    set API_URL=%~2
    shift
    shift
    goto :parse_args
)
if /i "%~1"=="/api-key" (
    set API_KEY=%~2
    shift
    shift
    goto :parse_args
)
if /i "%~1"=="/cves" (
    set TOTAL_CVES=%~2
    shift
    shift
    goto :parse_args
)
if /i "%~1"=="/batch-size" (
    set BATCH_SIZE=%~2
    shift
    shift
    goto :parse_args
)
if /i "%~1"=="/concurrent" (
    set CONCURRENT_REQUESTS=%~2
    shift
    shift
    goto :parse_args
)
if /i "%~1"=="/output" (
    set OUTPUT_FILE=%~2
    shift
    shift
    goto :parse_args
)
if /i "%~1"=="baseline" (
    set TEST_TYPE=baseline
    shift
    goto :parse_args
)
if /i "%~1"=="light" (
    set TEST_TYPE=light
    shift
    goto :parse_args
)
if /i "%~1"=="medium" (
    set TEST_TYPE=medium
    shift
    goto :parse_args
)
if /i "%~1"=="heavy" (
    set TEST_TYPE=heavy
    shift
    goto :parse_args
)
if /i "%~1"=="extreme" (
    set TEST_TYPE=extreme
    shift
    goto :parse_args
)
if /i "%~1"=="scalability" (
    set TEST_TYPE=scalability
    shift
    goto :parse_args
)
if /i "%~1"=="comprehensive" (
    set TEST_TYPE=comprehensive
    shift
    goto :parse_args
)
if /i "%~1"=="custom" (
    set TEST_TYPE=custom
    shift
    goto :parse_args
)
call :print_error "Unknown option: %~1"
call :show_usage
exit /b 1

REM Main execution
:main
call :print_status "CVE Ingestion Stress Test Runner"
call :print_status "API URL: %API_URL%"
call :print_status "Total CVEs: %TOTAL_CVES%"
call :print_status "Batch Size: %BATCH_SIZE%"
call :print_status "Concurrent Requests: %CONCURRENT_REQUESTS%"

REM Check dependencies
call :check_dependencies
if errorlevel 1 exit /b 1

REM Run selected test
if "%TEST_TYPE%"=="baseline" (
    call :run_baseline_test
) else if "%TEST_TYPE%"=="light" (
    call :run_stress_test "light_load" 1000 50 5
) else if "%TEST_TYPE%"=="medium" (
    call :run_stress_test "medium_load" 5000 100 10
) else if "%TEST_TYPE%"=="heavy" (
    call :run_stress_test "heavy_load" 10000 200 20
) else if "%TEST_TYPE%"=="extreme" (
    call :run_stress_test "extreme_load" 20000 500 50
) else if "%TEST_TYPE%"=="scalability" (
    call :run_scalability_test
) else if "%TEST_TYPE%"=="comprehensive" (
    call :run_comprehensive_tests
) else if "%TEST_TYPE%"=="custom" (
    call :run_stress_test "custom" %TOTAL_CVES% %BATCH_SIZE% %CONCURRENT_REQUESTS%
) else (
    call :print_error "Unknown test type: %TEST_TYPE%"
    call :show_usage
    exit /b 1
)

REM Generate report
call :generate_report

call :print_success "Stress test completed successfully!"
call :print_status "Check the generated files for detailed results:"
dir *stress_test*.json *stress_test*.log 2>nul

endlocal 