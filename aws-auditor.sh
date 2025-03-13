#!/bin/bash
# AWS Resource Auditor Wrapper Script

# Set default values
PROFILE="default"
REGIONS=""
SERVICES="all"
ROLE=""
AUDIT_ALL_ACCOUNTS=false
MAX_WORKERS=5

# Display help message
function show_help {
    echo "AWS Resource Auditor - A tool to audit AWS resources across accounts"
    echo ""
    echo "Usage: $0 [options]"
    echo ""
    echo "Options:"
    echo "  --profile PROFILE       AWS profile to use (default: default)"
    echo "  --role ROLE             Role to assume when switching organizations"
    echo "  --regions REGIONS       Comma-separated list of AWS regions to scan (default: all regions)"
    echo "  --services SERVICES     Comma-separated list of services to audit (default: all services)"
    echo "  --audit-all-accounts    Audit all accounts in the organization (requires --role)"
    echo "  --max-workers N         Maximum number of worker threads for parallel processing (default: 5)"
    echo "  --help                  Display this help message and exit"
    echo ""
    echo "Example:"
    echo "  $0 --profile myprofile --regions us-east-1,us-west-2 --services ec2,s3"
    echo "  $0 --profile myprofile --role AuditRole --audit-all-accounts --max-workers 10"
    exit 0
}

# Parse command-line arguments
while [[ $# -gt 0 ]]; do
    key="$1"
    case $key in
        --profile)
            PROFILE="$2"
            shift 2
            ;;
        --role)
            ROLE="$2"
            shift 2
            ;;
        --regions)
            REGIONS="$2"
            shift 2
            ;;
        --services)
            SERVICES="$2"
            shift 2
            ;;
        --audit-all-accounts)
            AUDIT_ALL_ACCOUNTS=true
            shift
            ;;
        --max-workers)
            MAX_WORKERS="$2"
            shift 2
            ;;
        --help)
            show_help
            ;;
        *)
            echo "Unknown option: $1"
            show_help
            ;;
    esac
done

# Activate virtual environment
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -d "${SCRIPT_DIR}/venv" ]; then
    source "${SCRIPT_DIR}/venv/bin/activate"
    echo "Virtual environment activated."
else
    echo "Warning: Virtual environment not found. Please run setup.sh first."
    exit 1
fi

# Build command
CMD="${SCRIPT_DIR}/src/main.py --profile ${PROFILE}"

if [ -n "$ROLE" ]; then
    CMD="${CMD} --role ${ROLE}"
fi

if [ -n "$REGIONS" ]; then
    CMD="${CMD} --regions ${REGIONS}"
fi

if [ "$SERVICES" != "all" ]; then
    CMD="${CMD} --services ${SERVICES}"
fi

if [ "$AUDIT_ALL_ACCOUNTS" = true ]; then
    CMD="${CMD} --audit-all-accounts"
fi

CMD="${CMD} --max-workers ${MAX_WORKERS}"

# Run the command
echo "Running: python ${CMD}"
python ${CMD}

# Check exit status
EXIT_CODE=$?
if [ $EXIT_CODE -eq 0 ]; then
    echo "AWS Resource Auditor completed successfully."
    
    # Check if there are any reports
    REPORTS_DIR="${SCRIPT_DIR}/reports"
    if [ -d "$REPORTS_DIR" ]; then
        # Find latest report (macOS compatible)
        LATEST_REPORT=$(find "$REPORTS_DIR" -type f -name "*.csv" | grep -v "error_report" | xargs ls -t 2>/dev/null | head -1)
        if [ -n "$LATEST_REPORT" ]; then
            echo "Reports are available in the 'reports' directory."
            echo "Latest report: $(basename "$LATEST_REPORT")"
        fi
        
        # Check for error reports (macOS compatible)
        ERROR_REPORTS=$(find "$REPORTS_DIR" -type f -name "error_report_*.csv" | wc -l)
        if [ "$ERROR_REPORTS" -gt 0 ]; then
            LATEST_ERROR_REPORT=$(find "$REPORTS_DIR" -type f -name "error_report_*.csv" | xargs ls -t 2>/dev/null | head -1)
            echo ""
            echo "Warning: Errors occurred during execution."
            echo "Error report: $(basename "$LATEST_ERROR_REPORT")"
            echo "Please check the logs in the 'logs' directory for details."
        fi
    else
        echo "No reports were generated."
    fi
else
    echo "AWS Resource Auditor encountered an error (exit code: $EXIT_CODE)."
    echo "Please check the logs in the 'logs' directory for details."
    
    # Check for error reports
    REPORTS_DIR="${SCRIPT_DIR}/reports"
    if [ -d "$REPORTS_DIR" ]; then
        ERROR_REPORTS=$(find "$REPORTS_DIR" -type f -name "error_report_*.csv" | wc -l)
        if [ "$ERROR_REPORTS" -gt 0 ]; then
            LATEST_ERROR_REPORT=$(find "$REPORTS_DIR" -type f -name "error_report_*.csv" | xargs ls -t 2>/dev/null | head -1)
            echo "Error report: $(basename "$LATEST_ERROR_REPORT")"
        fi
    fi
fi

# Deactivate virtual environment
deactivate
echo "Virtual environment deactivated." 
