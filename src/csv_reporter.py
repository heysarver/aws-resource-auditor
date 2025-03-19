#!/usr/bin/env python3
"""
CSV Reporter Module

This module generates CSV reports from the collected AWS resource data.
"""

import csv
import logging
import os
from datetime import datetime

logger = logging.getLogger(__name__)

# Define the reports directory
reports_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'reports')
os.makedirs(reports_dir, exist_ok=True)

def generate_ec2_report(ec2_instances, timestamp):
    """
    Generate a CSV report for EC2 instances.
    
    Args:
        ec2_instances (list): List of EC2 instance dictionaries.
        timestamp (str): Timestamp to include in the filename.
        
    Returns:
        str: Path to the generated CSV file.
    """
    if not ec2_instances:
        logger.warning("No EC2 instances to report")
        return None
    
    report_file = os.path.join(reports_dir, f'ec2_instances_{timestamp}.csv')
    
    try:
        with open(report_file, 'w', newline='') as csvfile:
            fieldnames = [
                'Name', 'InstanceId', 'InstanceType', 'State', 
                'PrivateIpAddress', 'PublicIpAddress', 'Region', 
                'OrganizationId', 'AccountId', 'AccountName'
            ]
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            
            writer.writeheader()
            for instance in ec2_instances:
                writer.writerow({
                    'Name': instance.get('Name', 'N/A'),
                    'InstanceId': instance.get('InstanceId', 'N/A'),
                    'InstanceType': instance.get('InstanceType', 'N/A'),
                    'State': instance.get('State', 'N/A'),
                    'PrivateIpAddress': instance.get('PrivateIpAddress', 'N/A'),
                    'PublicIpAddress': instance.get('PublicIpAddress', 'N/A'),
                    'Region': instance.get('Region', 'N/A'),
                    'OrganizationId': instance.get('OrganizationId', 'N/A'),
                    'AccountId': instance.get('AccountId', 'N/A'),
                    'AccountName': instance.get('AccountName', 'N/A')
                })
        
        logger.info(f"EC2 report generated: {report_file}")
        return report_file
    
    except Exception as e:
        logger.error(f"Error generating EC2 report: {e}")
        return None

def generate_volumes_report(volumes, timestamp):
    """
    Generate a CSV report for EBS volumes.
    
    Args:
        volumes (list): List of EBS volume dictionaries.
        timestamp (str): Timestamp to include in the filename.
        
    Returns:
        str: Path to the generated CSV file.
    """
    if not volumes:
        logger.warning("No EBS volumes to report")
        return None
    
    report_file = os.path.join(reports_dir, f'ebs_volumes_{timestamp}.csv')
    
    try:
        with open(report_file, 'w', newline='') as csvfile:
            fieldnames = [
                'Name', 'VolumeId', 'Size', 'VolumeType', 
                'State', 'CreateTime', 'AvailabilityZone',
                'InstanceId', 'InstanceName', 'Device',
                'AttachmentState', 'AttachmentInfo',
                'Region', 'AccountId', 'AccountName'
            ]
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            
            writer.writeheader()
            for volume in volumes:
                writer.writerow({
                    'Name': volume.get('Name', 'N/A'),
                    'VolumeId': volume.get('VolumeId', 'N/A'),
                    'Size': volume.get('Size', 'N/A'),
                    'VolumeType': volume.get('VolumeType', 'N/A'),
                    'State': volume.get('State', 'N/A'),
                    'CreateTime': volume.get('CreateTime', 'N/A'),
                    'AvailabilityZone': volume.get('AvailabilityZone', 'N/A'),
                    'InstanceId': volume.get('InstanceId', 'N/A'),
                    'InstanceName': volume.get('InstanceName', 'N/A'),
                    'Device': volume.get('Device', 'N/A'),
                    'AttachmentState': volume.get('AttachmentState', 'N/A'),
                    'AttachmentInfo': volume.get('AttachmentInfo', 'N/A'),
                    'Region': volume.get('Region', 'N/A'),
                    'AccountId': volume.get('AccountId', 'N/A'),
                    'AccountName': volume.get('AccountName', 'N/A')
                })
        
        logger.info(f"EBS volumes report generated: {report_file}")
        return report_file
    
    except Exception as e:
        logger.error(f"Error generating EBS volumes report: {e}")
        return None

def generate_unused_amis_report(unused_amis, timestamp):
    """
    Generate a CSV report for unused AMIs.
    
    Args:
        unused_amis (list): List of unused AMI dictionaries.
        timestamp (str): Timestamp to include in the filename.
        
    Returns:
        str: Path to the generated CSV file.
    """
    if not unused_amis:
        logger.warning("No unused AMIs to report")
        return None
    
    report_file = os.path.join(reports_dir, f'unused_amis_{timestamp}.csv')
    
    try:
        with open(report_file, 'w', newline='') as csvfile:
            fieldnames = [
                'Name', 'ImageId', 'Description', 'CreationDate', 
                'AgeDays', 'State', 'Region', 'AccountId', 'AccountName'
            ]
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            
            writer.writeheader()
            for ami in unused_amis:
                writer.writerow({
                    'Name': ami.get('Name', 'N/A'),
                    'ImageId': ami.get('ImageId', 'N/A'),
                    'Description': ami.get('Description', 'N/A'),
                    'CreationDate': ami.get('CreationDate', 'N/A'),
                    'AgeDays': ami.get('AgeDays', 'N/A'),
                    'State': ami.get('State', 'N/A'),
                    'Region': ami.get('Region', 'N/A'),
                    'AccountId': ami.get('AccountId', 'N/A'),
                    'AccountName': ami.get('AccountName', 'N/A')
                })
        
        logger.info(f"Unused AMIs report generated: {report_file}")
        return report_file
    
    except Exception as e:
        logger.error(f"Error generating unused AMIs report: {e}")
        return None

def generate_high_cost_services_reports(high_cost_services, timestamp):
    """
    Generate CSV reports for high-cost services.
    
    Args:
        high_cost_services (dict): Dictionary containing lists of high-cost services.
        timestamp (str): Timestamp to include in the filename.
        
    Returns:
        dict: Dictionary mapping service names to report file paths.
    """
    reports = {}
    
    # Generate ELB report
    if high_cost_services.get('elbs'):
        report_file = os.path.join(reports_dir, f'elbs_{timestamp}.csv')
        
        try:
            with open(report_file, 'w', newline='') as csvfile:
                fieldnames = [
                    'LoadBalancerName', 'DNSName', 'Type', 'Scheme', 
                    'CreatedTime', 'Region', 'AccountId', 'AccountName'
                ]
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                
                writer.writeheader()
                for elb in high_cost_services['elbs']:
                    writer.writerow({
                        'LoadBalancerName': elb.get('LoadBalancerName', 'N/A'),
                        'DNSName': elb.get('DNSName', 'N/A'),
                        'Type': elb.get('Type', 'N/A'),
                        'Scheme': elb.get('Scheme', 'N/A'),
                        'CreatedTime': elb.get('CreatedTime', 'N/A'),
                        'Region': elb.get('Region', 'N/A'),
                        'AccountId': elb.get('AccountId', 'N/A'),
                        'AccountName': elb.get('AccountName', 'N/A')
                    })
            
            logger.info(f"ELB report generated: {report_file}")
            reports['elb'] = report_file
        
        except Exception as e:
            logger.error(f"Error generating ELB report: {e}")
    
    # Generate NAT Gateway report
    if high_cost_services.get('nat_gateways'):
        report_file = os.path.join(reports_dir, f'nat_gateways_{timestamp}.csv')
        
        try:
            with open(report_file, 'w', newline='') as csvfile:
                fieldnames = [
                    'Name', 'NatGatewayId', 'State', 'SubnetId', 
                    'VpcId', 'CreatedTime', 'Region', 'AccountId', 'AccountName'
                ]
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                
                writer.writeheader()
                for nat in high_cost_services['nat_gateways']:
                    writer.writerow({
                        'Name': nat.get('Name', 'N/A'),
                        'NatGatewayId': nat.get('NatGatewayId', 'N/A'),
                        'State': nat.get('State', 'N/A'),
                        'SubnetId': nat.get('SubnetId', 'N/A'),
                        'VpcId': nat.get('VpcId', 'N/A'),
                        'CreatedTime': nat.get('CreatedTime', 'N/A'),
                        'Region': nat.get('Region', 'N/A'),
                        'AccountId': nat.get('AccountId', 'N/A'),
                        'AccountName': nat.get('AccountName', 'N/A')
                    })
            
            logger.info(f"NAT Gateway report generated: {report_file}")
            reports['nat'] = report_file
        
        except Exception as e:
            logger.error(f"Error generating NAT Gateway report: {e}")
    
    # Generate S3 Bucket report
    if high_cost_services.get('s3_buckets'):
        report_file = os.path.join(reports_dir, f's3_buckets_{timestamp}.csv')
        
        try:
            with open(report_file, 'w', newline='') as csvfile:
                fieldnames = [
                    'Name', 'CreationDate', 'Region', 'SizeGB', 
                    'StandardStorage', 'IntelligentTieringStorage', 
                    'StandardIAStorage', 'OneZoneIAStorage', 
                    'ReducedRedundancyStorage', 'GlacierStorage', 
                    'GlacierDeepArchiveStorage', 'GlacierIRStorage',
                    'AccountId', 'AccountName'
                ]
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                
                writer.writeheader()
                for bucket in high_cost_services['s3_buckets']:
                    # Extract storage tier information for CSV row
                    storage_tier = bucket.get('StorageTier', {})
                    
                    writer.writerow({
                        'Name': bucket.get('Name', 'N/A'),
                        'CreationDate': bucket.get('CreationDate', 'N/A'),
                        'Region': bucket.get('Region', 'N/A'),
                        'SizeGB': bucket.get('SizeGB', 0),
                        'StandardStorage': storage_tier.get('StandardStorage', 0),
                        'IntelligentTieringStorage': storage_tier.get('IntelligentTieringStorage', 0),
                        'StandardIAStorage': storage_tier.get('StandardIAStorage', 0),
                        'OneZoneIAStorage': storage_tier.get('OneZoneIAStorage', 0),
                        'ReducedRedundancyStorage': storage_tier.get('ReducedRedundancyStorage', 0),
                        'GlacierStorage': storage_tier.get('GlacierStorage', 0),
                        'GlacierDeepArchiveStorage': storage_tier.get('GlacierDeepArchiveStorage', 0),
                        'GlacierIRStorage': storage_tier.get('GlacierIRStorage', 0),
                        'AccountId': bucket.get('AccountId', 'N/A'),
                        'AccountName': bucket.get('AccountName', 'N/A')
                    })
            
            logger.info(f"S3 Bucket report generated: {report_file}")
            reports['s3'] = report_file
        
        except Exception as e:
            logger.error(f"Error generating S3 Bucket report: {e}")
    
    # Generate RDS Instance report
    if high_cost_services.get('rds_instances'):
        report_file = os.path.join(reports_dir, f'rds_instances_{timestamp}.csv')
        
        try:
            with open(report_file, 'w', newline='') as csvfile:
                fieldnames = [
                    'DBInstanceIdentifier', 'Engine', 'EngineVersion', 
                    'DBInstanceClass', 'AllocatedStorage', 'StorageType', 
                    'MultiAZ', 'Status', 'Region', 'AccountId', 'AccountName'
                ]
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                
                writer.writeheader()
                for instance in high_cost_services['rds_instances']:
                    writer.writerow({
                        'DBInstanceIdentifier': instance.get('DBInstanceIdentifier', 'N/A'),
                        'Engine': instance.get('Engine', 'N/A'),
                        'EngineVersion': instance.get('EngineVersion', 'N/A'),
                        'DBInstanceClass': instance.get('DBInstanceClass', 'N/A'),
                        'AllocatedStorage': instance.get('AllocatedStorage', 'N/A'),
                        'StorageType': instance.get('StorageType', 'N/A'),
                        'MultiAZ': instance.get('MultiAZ', 'N/A'),
                        'Status': instance.get('Status', 'N/A'),
                        'Region': instance.get('Region', 'N/A'),
                        'AccountId': instance.get('AccountId', 'N/A'),
                        'AccountName': instance.get('AccountName', 'N/A')
                    })
            
            logger.info(f"RDS Instance report generated: {report_file}")
            reports['rds'] = report_file
        
        except Exception as e:
            logger.error(f"Error generating RDS Instance report: {e}")
    
    return reports

# For testing purposes (will be commented out in production)
if __name__ == "__main__":
    # Configure logging for testing
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Test with sample data
    sample_instances = [
        {
            'InstanceId': 'i-12345678',
            'Name': 'test-instance',
            'InstanceType': 't2.micro',
            'State': 'running',
            'PrivateIpAddress': '10.0.0.1',
            'PublicIpAddress': '54.123.456.789',
            'Region': 'us-east-1',
            'OrganizationId': 'o-abcdefg',
            'AccountId': 'a-12345678',
            'AccountName': 'Test Account'
        }
    ]
    
    ec2_report = generate_ec2_report(sample_instances, datetime.now().strftime('%Y%m%d_%H%M%S'))
    print(f"EC2 report generated: {ec2_report}") 
