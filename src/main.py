#!/usr/bin/env python3
"""
AWS Resource Auditor - Main Script

This script is the entry point for the AWS Resource Auditor tool.
It parses command-line arguments and orchestrates the auditing process.
"""

import argparse
import logging
import os
import sys
from datetime import datetime
import concurrent.futures

# Import collector modules
import aws_org_enumerator
import ec2_collector
import volumes_collector
import ami_collector
import high_cost_inventory
import csv_reporter
import error_reporter
import boto3

# Configure logging
log_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'logs')
os.makedirs(log_dir, exist_ok=True)
log_file = os.path.join(log_dir, f'audit_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log')

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(log_file),
        logging.StreamHandler(sys.stdout)
    ]
)

logger = logging.getLogger(__name__)

def parse_arguments():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(description='AWS Resource Auditor - A tool to audit AWS resources across accounts')
    
    parser.add_argument('--profile', type=str, default='default',
                        help='AWS profile to use (default: default)')
    
    parser.add_argument('--role', type=str,
                        help='Role to assume when switching organizations (required for cross-account auditing)')
    
    parser.add_argument('--regions', type=str, default='',
                        help='Comma-separated list of AWS regions to scan (default: all regions)')
    
    parser.add_argument('--services', type=str, default='all',
                        help='Comma-separated list of services to audit (default: all services)')
    
    parser.add_argument('--audit-all-accounts', action='store_true',
                        help='Audit all accounts in the organization (requires --role)')
    
    parser.add_argument('--max-workers', type=int, default=5,
                        help='Maximum number of worker threads for parallel account auditing (default: 5)')
    
    return parser.parse_args()

def audit_account(profile_name, role_name, account_id, account_name, regions, services_to_audit, timestamp, org_id):
    """
    Audit a specific AWS account.
    
    Args:
        profile_name (str): AWS profile name to use.
        role_name (str): Name of the role to assume.
        account_id (str): AWS account ID to audit.
        account_name (str): AWS account name.
        regions (list): List of regions to scan.
        services_to_audit (list): List of services to audit.
        timestamp (str): Timestamp for report filenames.
        org_id (str): Organization ID.
        
    Returns:
        dict: Dictionary containing audit results.
    """
    logger.info(f"Auditing account: {account_name} ({account_id})")
    
    # Check if this is the current account
    try:
        current_session = boto3.Session(profile_name=profile_name)
        sts_client = current_session.client('sts')
        current_account_id = sts_client.get_caller_identity()['Account']
        
        # If this is the current account, use the current session
        if account_id == current_account_id:
            logger.info(f"Using current session for account {account_id} (current account)")
            session = current_session
        else:
            # Assume role in the other account
            logger.info(f"Assuming role in account {account_id}")
            session = aws_org_enumerator.assume_role_for_account(profile_name, role_name, account_id)
            if not session:
                error_reporter.error_collector.add_error(
                    'STS', 'AssumeRole', 'global', account_id, 
                    f"Failed to assume role {role_name} in account {account_id}"
                )
                logger.error(f"Failed to assume role in account {account_id}. Skipping.")
                return {}
    except Exception as e:
        error_reporter.error_collector.add_error(
            'STS', 'AssumeRole', 'global', account_id, str(e)
        )
        logger.error(f"Exception assuming role in account {account_id}: {e}")
        return {}
    
    results = {
        'account_id': account_id,
        'account_name': account_name,
        'ec2_instances': [],
        'volumes': [],
        'unused_amis': [],
        'high_cost_services': {}
    }
    
    # Define worker functions for each service to be used with ThreadPoolExecutor
    def collect_ec2_worker():
        try:
            logger.info(f"Collecting EC2 instances for account {account_name}")
            ec2_instances = ec2_collector.collect_ec2_instances(
                session=session,
                regions=regions,
                org_id=org_id,
                account_id=account_id,
                account_name=account_name
            )
            logger.info(f"Found {len(ec2_instances)} EC2 instances in account {account_name}")
            return ec2_instances
        except Exception as e:
            error_reporter.error_collector.add_error(
                'EC2', 'CollectInstances', ','.join(regions), account_id, str(e)
            )
            logger.error(f"Error collecting EC2 instances for account {account_name}: {e}")
            return []
    
    def collect_volumes_worker():
        try:
            logger.info(f"Collecting EBS volumes for account {account_name}")
            volumes = volumes_collector.collect_volumes(
                session=session,
                regions=regions,
                account_id=account_id,
                account_name=account_name
            )
            logger.info(f"Found {len(volumes)} EBS volumes in account {account_name}")
            return volumes
        except Exception as e:
            error_reporter.error_collector.add_error(
                'EBS', 'CollectVolumes', ','.join(regions), account_id, str(e)
            )
            logger.error(f"Error collecting EBS volumes for account {account_name}: {e}")
            return []
    
    def collect_amis_worker():
        try:
            logger.info(f"Detecting unused AMIs for account {account_name}")
            unused_amis = ami_collector.collect_unused_amis(
                session=session,
                regions=regions,
                account_id=account_id,
                account_name=account_name
            )
            logger.info(f"Found {len(unused_amis)} unused AMIs in account {account_name}")
            return unused_amis
        except Exception as e:
            error_reporter.error_collector.add_error(
                'AMI', 'CollectUnusedAMIs', ','.join(regions), account_id, str(e)
            )
            logger.error(f"Error collecting unused AMIs for account {account_name}: {e}")
            return []
    
    def collect_high_cost_services_worker():
        try:
            logger.info(f"Collecting high-cost services for account {account_name}")
            high_cost_services = high_cost_inventory.collect_high_cost_services(
                session=session,
                regions=regions,
                account_id=account_id,
                account_name=account_name
            )
            logger.info(f"Found high-cost services in account {account_name}")
            return high_cost_services
        except Exception as e:
            error_reporter.error_collector.add_error(
                'HighCostServices', 'CollectServices', ','.join(regions), account_id, str(e)
            )
            logger.error(f"Error collecting high-cost services for account {account_name}: {e}")
            return {}
    
    # Create a list of tasks to run in parallel based on services_to_audit
    tasks = []
    task_names = []
    
    if not services_to_audit or 'ec2' in services_to_audit:
        tasks.append(collect_ec2_worker)
        task_names.append('ec2_instances')
    
    if not services_to_audit or 'volumes' in services_to_audit:
        tasks.append(collect_volumes_worker)
        task_names.append('volumes')
    
    if not services_to_audit or 'amis' in services_to_audit:
        tasks.append(collect_amis_worker)
        task_names.append('unused_amis')
    
    high_cost_services_to_audit = [s for s in ['elb', 'nat', 's3', 'rds'] if not services_to_audit or s in services_to_audit]
    if high_cost_services_to_audit:
        tasks.append(collect_high_cost_services_worker)
        task_names.append('high_cost_services')
    
    # Use ThreadPoolExecutor to run tasks in parallel
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(tasks)) as executor:
        # Map future objects to their task names to maintain the correct association
        future_to_task_name = {executor.submit(task): task_name for task, task_name in zip(tasks, task_names)}
        
        # Process each future as it completes
        for future in concurrent.futures.as_completed(future_to_task_name.keys()):
            task_name = future_to_task_name[future]
            try:
                result = future.result()
                results[task_name] = result
                logger.info(f"Completed task {task_name} for account {account_name}")
            except Exception as e:
                logger.error(f"Error in task {task_name}: {e}")
                results[task_name] = [] if task_name != 'high_cost_services' else {}
    
    return results

def main():
    """Main function to orchestrate the AWS resource auditing process."""
    logger.info("Starting AWS Resource Auditor")
    
    # Parse command-line arguments
    args = parse_arguments()
    
    # Log the configuration
    logger.info(f"Using AWS profile: {args.profile}")
    if args.role:
        logger.info(f"Role to assume: {args.role}")
    
    # Process regions
    regions = []
    if args.regions:
        regions = [region.strip() for region in args.regions.split(',')]
        logger.info(f"Scanning regions: {', '.join(regions)}")
    else:
        logger.info("Scanning all regions")
        # Get all available regions
        try:
            session = boto3.Session(profile_name=args.profile)
            ec2_client = session.client('ec2')
            available_regions = [region['RegionName'] for region in ec2_client.describe_regions()['Regions']]
            regions = available_regions
            logger.info(f"Found {len(regions)} available regions")
        except Exception as e:
            error_reporter.error_collector.add_error(
                'EC2', 'DescribeRegions', 'global', 'current', str(e)
            )
            logger.error(f"Error listing available regions: {e}")
            logger.info("Defaulting to us-east-1 region")
            regions = ['us-east-1']
    
    # Process services
    services_to_audit = []
    if args.services != 'all':
        services_to_audit = [service.strip().lower() for service in args.services.split(',')]
        logger.info(f"Auditing services: {', '.join(services_to_audit)}")
    else:
        logger.info("Auditing all services")
    
    # Generate a timestamp for report filenames
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    
    # Step 1: Enumerate AWS Organization accounts
    logger.info("Step 1: Enumerating AWS Organization accounts")
    try:
        accounts = aws_org_enumerator.get_organization_accounts(profile_name=args.profile, role_arn=args.role)
        org_id = aws_org_enumerator.get_organization_id(profile_name=args.profile, role_arn=args.role)
    except Exception as e:
        error_reporter.error_collector.add_error(
            'Organizations', 'EnumerateAccounts', 'global', 'current', str(e)
        )
        logger.error(f"Error enumerating AWS Organization accounts: {e}")
        accounts = []
        org_id = None
    
    if not accounts:
        # If we couldn't get accounts from Organizations, try to get the current account
        try:
            session = boto3.Session(profile_name=args.profile)
            sts_client = session.client('sts')
            identity = sts_client.get_caller_identity()
            account_id = identity['Account']
            accounts = [{
                'Id': account_id,
                'Name': 'Current Account',
                'Status': 'ACTIVE'
            }]
            logger.warning("No AWS Organization accounts found. Using current account only.")
        except Exception as e:
            error_reporter.error_collector.add_error(
                'STS', 'GetCallerIdentity', 'global', 'current', str(e)
            )
            logger.error(f"Error getting current account identity: {e}")
            logger.warning("No AWS accounts found. Check your credentials and permissions.")
            
            # Generate error report before exiting
            if error_reporter.error_collector.has_errors():
                error_report = error_reporter.error_collector.generate_error_report(timestamp)
                if error_report:
                    logger.info(f"Error report generated: {error_report}")
                error_reporter.error_collector.print_error_summary()
            return
    
    logger.info(f"Found {len(accounts)} AWS accounts")
    for account in accounts:
        logger.info(f"Account ID: {account['Id']}, Name: {account.get('Name', 'N/A')}, Status: {account.get('Status', 'N/A')}")
    
    # Check if we should audit all accounts
    if args.audit_all_accounts:
        if not args.role:
            error_reporter.error_collector.add_error(
                'Configuration', 'ValidateArgs', 'global', 'current', 
                "--role is required when --audit-all-accounts is specified"
            )
            logger.error("--role is required when --audit-all-accounts is specified")
            
            # Generate error report before exiting
            if error_reporter.error_collector.has_errors():
                error_report = error_reporter.error_collector.generate_error_report(timestamp)
                if error_report:
                    logger.info(f"Error report generated: {error_report}")
                error_reporter.error_collector.print_error_summary()
            return
        
        # Audit each account in parallel using ThreadPoolExecutor
        active_accounts = [account for account in accounts if account['Status'] == 'ACTIVE']
        logger.info(f"Auditing {len(active_accounts)} active accounts with {args.max_workers} worker threads")
        
        all_results = {}
        
        # Define a worker function for ThreadPoolExecutor
        def audit_account_worker(account):
            account_id = account['Id']
            account_name = account.get('Name', 'Unknown')
            
            try:
                return account_id, audit_account(
                    profile_name=args.profile,
                    role_name=args.role,
                    account_id=account_id,
                    account_name=account_name,
                    regions=regions,
                    services_to_audit=services_to_audit,
                    timestamp=timestamp,
                    org_id=org_id
                )
            except Exception as e:
                error_reporter.error_collector.add_error(
                    'Audit', 'AuditAccount', 'all', account_id, str(e)
                )
                logger.error(f"Error auditing account {account_name} ({account_id}): {e}")
                return account_id, {}
        
        # Use ThreadPoolExecutor to process accounts in parallel
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.max_workers) as executor:
            future_to_account = {executor.submit(audit_account_worker, account): account for account in active_accounts}
            
            for future in concurrent.futures.as_completed(future_to_account):
                account = future_to_account[future]
                try:
                    account_id, account_results = future.result()
                    if account_results:
                        all_results[account_id] = account_results
                        logger.info(f"Completed audit for account: {account.get('Name', 'Unknown')} ({account['Id']})")
                except Exception as e:
                    logger.error(f"Exception processing account {account.get('Name', 'Unknown')} ({account['Id']}): {e}")
        
        # Combine results from all accounts for consolidated reports
        all_ec2_instances = []
        all_volumes = []
        all_unused_amis = []
        all_high_cost_services = {
            'elbs': [],
            'nat_gateways': [],
            's3_buckets': [],
            'rds_instances': []
        }
        
        for account_id, results in all_results.items():
            all_ec2_instances.extend(results.get('ec2_instances', []))
            all_volumes.extend(results.get('volumes', []))
            all_unused_amis.extend(results.get('unused_amis', []))
            
            # Check if high_cost_services is a dictionary before trying to iterate through its items
            high_cost_services_result = results.get('high_cost_services', {})
            if isinstance(high_cost_services_result, dict):
                for service, items in high_cost_services_result.items():
                    if service in all_high_cost_services:
                        all_high_cost_services[service].extend(items)
            # If high_cost_services is not a dictionary (possibly a list or other type), log an error
            else:
                logger.error(f"high_cost_services for account {account_id} is not a dictionary: {type(high_cost_services_result)}")
                logger.error(f"Skipping high cost services processing for account {account_id}")
        
        # Generate consolidated reports
        try:
            if all_ec2_instances:
                ec2_report = csv_reporter.generate_ec2_report(all_ec2_instances, timestamp)
                if ec2_report:
                    logger.info(f"Consolidated EC2 report generated: {ec2_report}")
            
            if all_volumes:
                volumes_report = csv_reporter.generate_volumes_report(all_volumes, timestamp)
                if volumes_report:
                    logger.info(f"Consolidated EBS volumes report generated: {volumes_report}")
            
            if all_unused_amis:
                amis_report = csv_reporter.generate_unused_amis_report(all_unused_amis, timestamp)
                if amis_report:
                    logger.info(f"Consolidated unused AMIs report generated: {amis_report}")
            
            if any(all_high_cost_services.values()):
                service_reports = csv_reporter.generate_high_cost_services_reports(all_high_cost_services, timestamp)
                for service, report in service_reports.items():
                    if report:
                        logger.info(f"Consolidated {service.upper()} report generated: {report}")
        except Exception as e:
            error_reporter.error_collector.add_error(
                'Reporting', 'GenerateReports', 'all', 'all', str(e)
            )
            logger.error(f"Error generating consolidated reports: {e}")
    else:
        # Audit only the main account
        logger.info("Auditing only the main account (use --audit-all-accounts to audit all accounts)")
        
        # Step 2: Collect EC2 instances
        if not services_to_audit or 'ec2' in services_to_audit:
            logger.info("Step 2: Collecting EC2 instances")
            try:
                ec2_instances = ec2_collector.collect_ec2_instances(
                    profile_name=args.profile,
                    role_arn=args.role,
                    regions=regions,
                    org_id=org_id
                )
                
                if ec2_instances:
                    logger.info(f"Found {len(ec2_instances)} EC2 instances")
                    # Generate EC2 report
                    ec2_report = csv_reporter.generate_ec2_report(ec2_instances, timestamp)
                    if ec2_report:
                        logger.info(f"EC2 report generated: {ec2_report}")
                else:
                    logger.warning("No EC2 instances found")
            except Exception as e:
                error_reporter.error_collector.add_error(
                    'EC2', 'CollectInstances', ','.join(regions), 'current', str(e)
                )
                logger.error(f"Error collecting EC2 instances: {e}")
        
        # Step 3: Collect EBS volumes
        if not services_to_audit or 'volumes' in services_to_audit:
            logger.info("Step 3: Collecting EBS volumes")
            try:
                volumes = volumes_collector.collect_volumes(
                    profile_name=args.profile,
                    role_arn=args.role,
                    regions=regions
                )
                
                if volumes:
                    logger.info(f"Found {len(volumes)} EBS volumes")
                    # Generate volumes report
                    volumes_report = csv_reporter.generate_volumes_report(volumes, timestamp)
                    if volumes_report:
                        logger.info(f"EBS volumes report generated: {volumes_report}")
                else:
                    logger.warning("No EBS volumes found")
            except Exception as e:
                error_reporter.error_collector.add_error(
                    'EBS', 'CollectVolumes', ','.join(regions), 'current', str(e)
                )
                logger.error(f"Error collecting EBS volumes: {e}")
        
        # Step 4: Detect unused AMIs
        if not services_to_audit or 'amis' in services_to_audit:
            logger.info("Step 4: Detecting unused AMIs")
            try:
                unused_amis = ami_collector.collect_unused_amis(
                    profile_name=args.profile,
                    role_arn=args.role,
                    regions=regions
                )
                
                if unused_amis:
                    logger.info(f"Found {len(unused_amis)} unused AMIs")
                    # Generate unused AMIs report
                    amis_report = csv_reporter.generate_unused_amis_report(unused_amis, timestamp)
                    if amis_report:
                        logger.info(f"Unused AMIs report generated: {amis_report}")
                else:
                    logger.warning("No unused AMIs found")
            except Exception as e:
                error_reporter.error_collector.add_error(
                    'AMI', 'CollectUnusedAMIs', ','.join(regions), 'current', str(e)
                )
                logger.error(f"Error detecting unused AMIs: {e}")
        
        # Step 5: Collect high-cost services
        high_cost_services_to_audit = [s for s in ['elb', 'nat', 's3', 'rds'] if not services_to_audit or s in services_to_audit]
        
        if high_cost_services_to_audit:
            logger.info("Step 5: Collecting high-cost services")
            try:
                high_cost_services = high_cost_inventory.collect_high_cost_services(
                    profile_name=args.profile,
                    role_arn=args.role,
                    regions=regions
                )
                
                # Generate high-cost services reports
                service_reports = csv_reporter.generate_high_cost_services_reports(high_cost_services, timestamp)
                
                for service, report in service_reports.items():
                    if report:
                        logger.info(f"{service.upper()} report generated: {report}")
            except Exception as e:
                error_reporter.error_collector.add_error(
                    'HighCostServices', 'CollectServices', ','.join(regions), 'current', str(e)
                )
                logger.error(f"Error collecting high-cost services: {e}")
    
    # Generate error report if there are any errors
    if error_reporter.error_collector.has_errors():
        error_report = error_reporter.error_collector.generate_error_report(timestamp)
        if error_report:
            logger.info(f"Error report generated: {error_report}")
        error_reporter.error_collector.print_error_summary()
    else:
        logger.info("No errors occurred during execution")
    
    logger.info("AWS Resource Auditor completed successfully")

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        logger.critical(f"Unhandled exception in main: {e}", exc_info=True)
        error_reporter.error_collector.add_error(
            'Main', 'ExecuteMain', 'global', 'current', str(e)
        )
        # Generate error report for unhandled exceptions
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        error_report = error_reporter.error_collector.generate_error_report(timestamp)
        if error_report:
            logger.info(f"Error report generated: {error_report}")
        error_reporter.error_collector.print_error_summary()
        sys.exit(1) 
