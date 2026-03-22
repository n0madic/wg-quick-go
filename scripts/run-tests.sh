#!/bin/bash

# WireGuard Integration Test Runner
# Comprehensive test runner for all platforms and scenarios

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
TEST_TIMEOUT=300  # 5 minutes
LOG_FILE="/tmp/wg-quick-test-$(date +%Y%m%d-%H%M%S).log"

# Default options
RUN_UNIT=true
RUN_INTEGRATION=true
RUN_VALIDATION=true
RUN_CLEANUP=true
VERBOSE=false
DRY_RUN=false
CLEANUP_ONLY=false

# Usage information
usage() {
    echo "Usage: $0 [options]"
    echo ""
    echo "Options:"
    echo "  -h, --help              Show this help message"
    echo "  -v, --verbose           Enable verbose output"
    echo "  -n, --dry-run           Show what would be done without executing"
    echo "  -c, --cleanup-only      Only run cleanup, no tests"
    echo "  --unit-only             Run only unit tests"
    echo "  --integration-only      Run only integration tests"
    echo "  --validation-only       Run only validation tests"
    echo "  --no-unit              Skip unit tests"
    echo "  --no-integration       Skip integration tests"
    echo "  --no-validation        Skip validation tests"
    echo "  --no-cleanup           Skip cleanup tests"
    echo "  --timeout SECONDS      Set test timeout (default: 300)"
    echo "  --log-file FILE        Set log file path"
    echo ""
    echo "Examples:"
    echo "  $0                     Run all tests"
    echo "  $0 --unit-only         Run only unit tests"
    echo "  $0 --integration-only  Run only integration tests"
    echo "  $0 --cleanup-only      Clean up test artifacts"
    echo "  $0 -v --timeout 600    Run with verbose output and 10min timeout"
}

# Logging functions
log() {
    echo -e "${BLUE}[$(date '+%H:%M:%S')]${NC} $*" | tee -a "$LOG_FILE"
}

log_success() {
    echo -e "${GREEN}[$(date '+%H:%M:%S')] ✓${NC} $*" | tee -a "$LOG_FILE"
}

log_warning() {
    echo -e "${YELLOW}[$(date '+%H:%M:%S')] ⚠${NC} $*" | tee -a "$LOG_FILE"
}

log_error() {
    echo -e "${RED}[$(date '+%H:%M:%S')] ✗${NC} $*" | tee -a "$LOG_FILE"
}

# Parse command line arguments
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                usage
                exit 0
                ;;
            -v|--verbose)
                VERBOSE=true
                shift
                ;;
            -n|--dry-run)
                DRY_RUN=true
                shift
                ;;
            -c|--cleanup-only)
                CLEANUP_ONLY=true
                RUN_UNIT=false
                RUN_INTEGRATION=false
                RUN_VALIDATION=false
                shift
                ;;
            --unit-only)
                RUN_UNIT=true
                RUN_INTEGRATION=false
                RUN_VALIDATION=false
                RUN_CLEANUP=false
                shift
                ;;
            --integration-only)
                RUN_UNIT=false
                RUN_INTEGRATION=true
                RUN_VALIDATION=false
                RUN_CLEANUP=false
                shift
                ;;
            --validation-only)
                RUN_UNIT=false
                RUN_INTEGRATION=false
                RUN_VALIDATION=true
                RUN_CLEANUP=false
                shift
                ;;
            --no-unit)
                RUN_UNIT=false
                shift
                ;;
            --no-integration)
                RUN_INTEGRATION=false
                shift
                ;;
            --no-validation)
                RUN_VALIDATION=false
                shift
                ;;
            --no-cleanup)
                RUN_CLEANUP=false
                shift
                ;;
            --timeout)
                TEST_TIMEOUT="$2"
                shift 2
                ;;
            --log-file)
                LOG_FILE="$2"
                shift 2
                ;;
            *)
                echo "Unknown option: $1"
                usage
                exit 1
                ;;
        esac
    done
}

# System detection
detect_platform() {
    case "$(uname -s)" in
        Linux*)     PLATFORM="linux" ;;
        Darwin*)    PLATFORM="macos" ;;
        FreeBSD*)   PLATFORM="freebsd" ;;
        OpenBSD*)   PLATFORM="openbsd" ;;
        *)          PLATFORM="unknown" ;;
    esac
    
    log "Detected platform: $PLATFORM"
}

# Check prerequisites
check_prerequisites() {
    log "Checking prerequisites..."
    
    # Check if running as root for integration tests
    if [[ $RUN_INTEGRATION == true || $RUN_CLEANUP == true || $CLEANUP_ONLY == true ]]; then
        if [[ $EUID -ne 0 ]]; then
            log_error "Integration tests and cleanup require root privileges"
            log_error "Please run with: sudo $0 $*"
            exit 1
        fi
    fi
    
    # Check Go installation
    if ! command -v go &> /dev/null; then
        log_error "Go is not installed or not in PATH"
        exit 1
    fi
    
    # Check WireGuard tools for integration tests
    if [[ $RUN_INTEGRATION == true ]]; then
        if ! command -v wg &> /dev/null; then
            log_error "WireGuard tools (wg) not found"
            log_error "Please install wireguard-tools package"
            exit 1
        fi
    fi
    
    # Platform-specific checks
    case $PLATFORM in
        linux)
            if [[ $RUN_INTEGRATION == true ]]; then
                command -v ip &> /dev/null || { log_error "ip command not found"; exit 1; }
            fi
            ;;
        macos)
            if [[ $RUN_INTEGRATION == true ]]; then
                command -v ifconfig &> /dev/null || { log_error "ifconfig not found"; exit 1; }
                command -v networksetup &> /dev/null || { log_error "networksetup not found"; exit 1; }
                command -v wireguard-go &> /dev/null || { log_error "wireguard-go not found"; exit 1; }
            fi
            ;;
        freebsd|openbsd)
            if [[ $RUN_INTEGRATION == true ]]; then
                command -v ifconfig &> /dev/null || { log_error "ifconfig not found"; exit 1; }
                command -v route &> /dev/null || { log_error "route not found"; exit 1; }
            fi
            ;;
    esac
    
    log_success "Prerequisites check passed"
}

# Cleanup function
cleanup_test_artifacts() {
    log "Cleaning up test artifacts..."
    
    if [[ $DRY_RUN == true ]]; then
        log "DRY RUN: Would clean up test artifacts"
        return 0
    fi
    
    # Remove test WireGuard interfaces
    for interface in wg-test1 wg-test2 wg-cleanup wg-force wg-partial wg-duplicate wg-conflict1 wg-conflict2; do
        if ip link show "$interface" &>/dev/null 2>&1; then
            log "Removing interface: $interface"
            ip link delete "$interface" 2>/dev/null || true
        fi
    done
    
    # Clean up temporary files
    rm -rf /tmp/wg-*test* 2>/dev/null || true
    rm -rf /tmp/wg-integration-test-* 2>/dev/null || true
    rm -rf /tmp/wg-validation-test-* 2>/dev/null || true
    rm -rf /tmp/wg-error-test-* 2>/dev/null || true
    rm -rf /tmp/wg-cleanup-test-* 2>/dev/null || true
    
    # Clean up any leftover WireGuard socket files
    rm -f /var/run/wireguard/wg-test*.sock 2>/dev/null || true
    rm -f /var/run/wireguard/wg-test*.name 2>/dev/null || true
    
    log_success "Cleanup completed"
}

# Run a test with timeout
run_test_with_timeout() {
    local test_name="$1"
    local test_command="$2"
    local timeout="$3"
    
    log "Running $test_name..."
    
    if [[ $DRY_RUN == true ]]; then
        log "DRY RUN: Would run: $test_command"
        return 0
    fi
    
    if [[ $VERBOSE == true ]]; then
        timeout "$timeout" bash -c "$test_command" 2>&1 | tee -a "$LOG_FILE"
        local exit_code=${PIPESTATUS[0]}
    else
        timeout "$timeout" bash -c "$test_command" >> "$LOG_FILE" 2>&1
        local exit_code=$?
    fi
    
    if [[ $exit_code -eq 0 ]]; then
        log_success "$test_name passed"
        return 0
    elif [[ $exit_code -eq 124 ]]; then
        log_error "$test_name timed out after $timeout seconds"
        return 1
    else
        log_error "$test_name failed with exit code $exit_code"
        return 1
    fi
}

# Main test execution
main() {
    log "Starting WireGuard test suite"
    log "Platform: $PLATFORM"
    log "Log file: $LOG_FILE"
    
    local failed_tests=0
    local total_tests=0
    
    # Cleanup first if requested
    if [[ $CLEANUP_ONLY == true ]]; then
        cleanup_test_artifacts
        exit 0
    fi
    
    # Build the project first
    if [[ $RUN_UNIT == true || $RUN_INTEGRATION == true ]]; then
        log "Building project..."
        if [[ $DRY_RUN == false ]]; then
            cd "$PROJECT_ROOT"
            if ! go build -o build/wg-quick-go wg-quick.go; then
                log_error "Build failed"
                exit 1
            fi
            log_success "Build completed"
        fi
    fi
    
    # Run unit tests
    if [[ $RUN_UNIT == true ]]; then
        ((++total_tests))
        if run_test_with_timeout "Unit Tests" "cd '$PROJECT_ROOT' && go test -v ./pkg/..." "$TEST_TIMEOUT"; then
            log_success "Unit tests completed successfully"
        else
            ((++failed_tests))
            log_error "Unit tests failed"
        fi
    fi
    
    # Run integration tests
    if [[ $RUN_INTEGRATION == true ]]; then
        ((++total_tests))
        if run_test_with_timeout "Integration Tests" "cd '$PROJECT_ROOT' && go test -v ./test/ -run TestIntegration_PeerToPeerConnectivity" "$TEST_TIMEOUT"; then
            log_success "Integration tests completed successfully"
        else
            ((++failed_tests))
            log_error "Integration tests failed"
        fi
    fi
    
    # Run validation tests
    if [[ $RUN_VALIDATION == true ]]; then
        ((++total_tests))
        if run_test_with_timeout "Validation Tests" "cd '$PROJECT_ROOT' && go test -v ./test/ -run TestIntegration_ConfigValidation" "$TEST_TIMEOUT"; then
            log_success "Validation tests completed successfully"
        else
            ((++failed_tests))
            log_error "Validation tests failed"
        fi
    fi
    
    # Run cleanup tests
    if [[ $RUN_CLEANUP == true ]]; then
        ((++total_tests))
        if run_test_with_timeout "Cleanup Tests" "cd '$PROJECT_ROOT' && go test -v ./test/ -run TestIntegration_CleanupScenarios" "$TEST_TIMEOUT"; then
            log_success "Cleanup tests completed successfully"
        else
            ((++failed_tests))
            log_error "Cleanup tests failed"
        fi
    fi
    
    # Final cleanup
    cleanup_test_artifacts
    
    # Summary
    echo ""
    log "Test Summary:"
    log "  Total tests: $total_tests"
    log "  Passed: $((total_tests - failed_tests))"
    log "  Failed: $failed_tests"
    log "  Log file: $LOG_FILE"
    
    if [[ $failed_tests -eq 0 ]]; then
        log_success "All tests passed!"
        exit 0
    else
        log_error "$failed_tests test(s) failed"
        exit 1
    fi
}

# Signal handlers for cleanup
trap cleanup_test_artifacts EXIT
trap 'log_error "Test interrupted"; cleanup_test_artifacts; exit 130' INT TERM

# Main execution
parse_args "$@"
detect_platform
check_prerequisites
main