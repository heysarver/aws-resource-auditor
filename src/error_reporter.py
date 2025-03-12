#!/usr/bin/env python3
"""
Error Reporter Module

This module provides functionality to collect errors during execution
and generate a final error report.
"""

import logging
import os
import csv
from datetime import datetime

logger = logging.getLogger(__name__)

class ErrorCollector:
    """Class to collect errors during execution and generate a report."""
    
    def __init__(self):
        """Initialize the error collector."""
        self.errors = []
    
    def add_error(self, service, operation, region, account_id, error_message):
        """
        Add an error to the collection.
        
        Args:
            service (str): The AWS service where the error occurred.
            operation (str): The operation that was being performed.
            region (str): The AWS region where the error occurred.
            account_id (str): The AWS account ID where the error occurred.
            error_message (str): The error message.
        """
        error_entry = {
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'service': service,
            'operation': operation,
            'region': region,
            'account_id': account_id,
            'error_message': str(error_message)
        }
        self.errors.append(error_entry)
        logger.error(f"Error in {service}/{operation} for account {account_id} in region {region}: {error_message}")
    
    def has_errors(self):
        """Check if there are any errors collected."""
        return len(self.errors) > 0
    
    def get_error_count(self):
        """Get the number of errors collected."""
        return len(self.errors)
    
    def generate_error_report(self, timestamp):
        """
        Generate a CSV report of all collected errors.
        
        Args:
            timestamp (str): Timestamp to use in the report filename.
            
        Returns:
            str: Path to the generated report file, or None if no errors.
        """
        if not self.errors:
            logger.info("No errors to report.")
            return None
        
        # Create reports directory if it doesn't exist
        reports_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'reports')
        os.makedirs(reports_dir, exist_ok=True)
        
        # Create the report file
        report_file = os.path.join(reports_dir, f'error_report_{timestamp}.csv')
        
        try:
            with open(report_file, 'w', newline='') as csvfile:
                fieldnames = ['timestamp', 'service', 'operation', 'region', 'account_id', 'error_message']
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                
                writer.writeheader()
                for error in self.errors:
                    writer.writerow(error)
            
            logger.info(f"Error report generated: {report_file}")
            return report_file
        except Exception as e:
            logger.error(f"Failed to generate error report: {e}")
            return None
    
    def print_error_summary(self):
        """Print a summary of errors to the console."""
        if not self.errors:
            logger.info("No errors occurred during execution.")
            return
        
        logger.warning(f"Total errors: {len(self.errors)}")
        
        # Group errors by service
        service_counts = {}
        for error in self.errors:
            service = error['service']
            if service not in service_counts:
                service_counts[service] = 0
            service_counts[service] += 1
        
        # Print summary by service
        for service, count in service_counts.items():
            logger.warning(f"  {service}: {count} errors")

# Global error collector instance
error_collector = ErrorCollector() 
