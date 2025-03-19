#!/usr/bin/env python3
"""
High-Cost Services Inventory Module

This module collects information about potentially high-cost AWS services:
- Elastic Load Balancers (ELB)
- NAT Gateways
- S3 Buckets
- RDS Instances
"""

import logging
import boto3
import botocore.exceptions
from botocore.config import Config
import concurrent.futures
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

# Configure retry strategy for AWS API rate limits
retry_config = Config(
    retries={
        'max_attempts': 10,
        'mode': 'adaptive'
    }
)

def collect_high_cost_services(profile_name=None, role_arn=None, regions=None, session=None, account_id=None, account_name=None):
    """
    Collect high-cost services across specified regions.
    
    Args:
        profile_name (str, optional): AWS profile name to use.
        role_arn (str, optional): Role ARN to assume or role name.
        regions (list, optional): List of regions to scan.
        session (boto3.Session, optional): Boto3 session to use.
        account_id (str, optional): AWS account ID.
        account_name (str, optional): AWS account name.
        
    Returns:
        dict: Dictionary containing lists of high-cost services.
    """
    high_cost_services = {
        'elbs': [],
        'nat_gateways': [],
        's3_buckets': [],
        'rds_instances': []
    }
    
    # Use provided session or create a new one
    if not session:
        try:
            if role_arn:
                # Check if role_arn is a full ARN or just a role name
                if not role_arn.startswith('arn:aws:iam::'):
                    # Get a session with the profile
                    temp_session = boto3.Session(profile_name=profile_name)
                    # Get the account ID
                    sts_client = temp_session.client('sts')
                    account_id = sts_client.get_caller_identity()['Account']
                    # Construct the full ARN
                    role_arn = f"arn:aws:iam::{account_id}:role/{role_arn}"
                
                # Assume role
                sts_client = boto3.Session(profile_name=profile_name).client('sts')
                assumed_role = sts_client.assume_role(
                    RoleArn=role_arn,
                    RoleSessionName="AWSResourceAuditor"
                )
                credentials = assumed_role['Credentials']
                
                session = boto3.Session(
                    aws_access_key_id=credentials['AccessKeyId'],
                    aws_secret_access_key=credentials['SecretAccessKey'],
                    aws_session_token=credentials['SessionToken']
                )
            else:
                session = boto3.Session(profile_name=profile_name)
        except Exception as e:
            logger.error(f"Error creating session: {e}")
            return high_cost_services
    
    # Get account ID if not provided
    if not account_id:
        try:
            sts_client = session.client('sts')
            account_id = sts_client.get_caller_identity()['Account']
        except Exception as e:
            logger.error(f"Error getting account ID: {e}")
            account_id = "Unknown"
    
    # Define worker functions for each service type
    def collect_elbs(region):
        elbs = []
        try:
            # Collect Classic Load Balancers
            elb_client = session.client('elb', region_name=region, config=retry_config)
            classic_lbs = elb_client.describe_load_balancers().get('LoadBalancerDescriptions', [])
            
            for lb in classic_lbs:
                lb_info = {
                    'LoadBalancerName': lb['LoadBalancerName'],
                    'DNSName': lb['DNSName'],
                    'Type': 'classic',
                    'Scheme': lb.get('Scheme', 'N/A'),
                    'Region': region,
                    'AccountId': account_id,
                    'AccountName': account_name if account_name else 'N/A'
                }
                elbs.append(lb_info)
            
            # Collect Application and Network Load Balancers
            elbv2_client = session.client('elbv2', region_name=region, config=retry_config)
            v2_lbs = elbv2_client.describe_load_balancers().get('LoadBalancers', [])
            
            for lb in v2_lbs:
                lb_info = {
                    'LoadBalancerName': lb['LoadBalancerName'],
                    'DNSName': lb['DNSName'],
                    'Type': lb['Type'],
                    'Scheme': lb.get('Scheme', 'N/A'),
                    'Region': region,
                    'AccountId': account_id,
                    'AccountName': account_name if account_name else 'N/A'
                }
                elbs.append(lb_info)
            
            logger.info(f"Found {len(elbs)} ELBs in region {region}")
            return elbs
        except botocore.exceptions.ClientError as e:
            if e.response['Error']['Code'] == 'AuthFailure':
                logger.warning(f"Authentication failure in region {region} for ELB. The region may not be enabled for your account.")
            elif e.response['Error']['Code'] == 'UnauthorizedOperation':
                logger.error(f"Unauthorized operation in region {region} for ELB. Check your IAM permissions.")
            else:
                logger.error(f"Error collecting ELBs in region {region}: {e}")
            return []
        except Exception as e:
            logger.error(f"Unexpected error collecting ELBs in region {region}: {e}")
            return []
    
    def collect_nat_gateways(region):
        nat_gateways = []
        try:
            ec2_client = session.client('ec2', region_name=region, config=retry_config)
            nats = ec2_client.describe_nat_gateways().get('NatGateways', [])
            
            for nat in nats:
                nat_info = {
                    'NatGatewayId': nat['NatGatewayId'],
                    'State': nat['State'],
                    'SubnetId': nat.get('SubnetId', 'N/A'),
                    'VpcId': nat.get('VpcId', 'N/A'),
                    'Region': region,
                    'AccountId': account_id,
                    'AccountName': account_name if account_name else 'N/A'
                }
                nat_gateways.append(nat_info)
            
            logger.info(f"Found {len(nat_gateways)} NAT Gateways in region {region}")
            return nat_gateways
        except botocore.exceptions.ClientError as e:
            if e.response['Error']['Code'] == 'AuthFailure':
                logger.warning(f"Authentication failure in region {region} for NAT Gateways. The region may not be enabled for your account.")
            elif e.response['Error']['Code'] == 'UnauthorizedOperation':
                logger.error(f"Unauthorized operation in region {region} for NAT Gateways. Check your IAM permissions.")
            else:
                logger.error(f"Error collecting NAT Gateways in region {region}: {e}")
            return []
        except Exception as e:
            logger.error(f"Unexpected error collecting NAT Gateways in region {region}: {e}")
            return []
    
    def collect_rds_instances(region):
        rds_instances = []
        try:
            rds_client = session.client('rds', region_name=region, config=retry_config)
            instances = rds_client.describe_db_instances().get('DBInstances', [])
            
            for instance in instances:
                instance_info = {
                    'DBInstanceIdentifier': instance['DBInstanceIdentifier'],
                    'Engine': instance['Engine'],
                    'EngineVersion': instance['EngineVersion'],
                    'DBInstanceClass': instance['DBInstanceClass'],
                    'AllocatedStorage': instance['AllocatedStorage'],
                    'MultiAZ': instance['MultiAZ'],
                    'Region': region,
                    'AccountId': account_id,
                    'AccountName': account_name if account_name else 'N/A'
                }
                rds_instances.append(instance_info)
            
            logger.info(f"Found {len(rds_instances)} RDS instances in region {region}")
            return rds_instances
        except botocore.exceptions.ClientError as e:
            if e.response['Error']['Code'] == 'AuthFailure':
                logger.warning(f"Authentication failure in region {region} for RDS. The region may not be enabled for your account.")
            elif e.response['Error']['Code'] == 'UnauthorizedOperation':
                logger.error(f"Unauthorized operation in region {region} for RDS. Check your IAM permissions.")
            else:
                logger.error(f"Error collecting RDS instances in region {region}: {e}")
            return []
        except Exception as e:
            logger.error(f"Unexpected error collecting RDS instances in region {region}: {e}")
            return []
    
    # Collect S3 buckets (global service, only need to do once)
    try:
        s3_client = session.client('s3', config=retry_config)
        buckets = s3_client.list_buckets().get('Buckets', [])
        
        for bucket in buckets:
            bucket_info = {
                'Name': bucket['Name'],
                'CreationDate': bucket['CreationDate'].strftime('%Y-%m-%d %H:%M:%S'),
                'Region': 'global',
                'AccountId': account_id,
                'AccountName': account_name if account_name else 'N/A',
                'SizeGB': 0,
                'StorageTier': {
                    'StandardStorage': 0,
                    'IntelligentTieringStorage': 0,
                    'StandardIAStorage': 0,
                    'OneZoneIAStorage': 0,
                    'ReducedRedundancyStorage': 0,
                    'GlacierStorage': 0,
                    'GlacierDeepArchiveStorage': 0,
                    'GlacierIRStorage': 0
                }
            }
            
            # Try to get bucket location
            try:
                location = s3_client.get_bucket_location(Bucket=bucket['Name'])
                region_name = location.get('LocationConstraint')
                if region_name is None:
                    region_name = 'us-east-1'  # Default region if None
                elif region_name == 'EU':
                    region_name = 'eu-west-1'  # Map EU to eu-west-1
                bucket_info['Region'] = region_name
                
                # Get bucket size and storage tier information using CloudWatch metrics
                try:
                    cloudwatch = session.client('cloudwatch', region_name=region_name, config=retry_config)
                    
                    # Get bucket size in bytes
                    size_response = cloudwatch.get_metric_statistics(
                        Namespace='AWS/S3',
                        MetricName='BucketSizeBytes',
                        Dimensions=[
                            {'Name': 'BucketName', 'Value': bucket['Name']},
                            {'Name': 'StorageType', 'Value': 'StandardStorage'}
                        ],
                        StartTime=datetime.now() - timedelta(days=2),
                        EndTime=datetime.now(),
                        Period=86400,  # 1 day in seconds
                        Statistics=['Average']
                    )
                    
                    # Get storage tier information
                    storage_types = [
                        'StandardStorage', 'IntelligentTieringStorage', 'StandardIAStorage', 
                        'OneZoneIAStorage', 'ReducedRedundancyStorage', 'GlacierStorage', 
                        'GlacierDeepArchiveStorage', 'GlacierIRStorage'
                    ]
                    
                    total_size_bytes = 0
                    for storage_type in storage_types:
                        try:
                            tier_response = cloudwatch.get_metric_statistics(
                                Namespace='AWS/S3',
                                MetricName='BucketSizeBytes',
                                Dimensions=[
                                    {'Name': 'BucketName', 'Value': bucket['Name']},
                                    {'Name': 'StorageType', 'Value': storage_type}
                                ],
                                StartTime=datetime.now() - timedelta(days=2),
                                EndTime=datetime.now(),
                                Period=86400,  # 1 day in seconds
                                Statistics=['Average']
                            )
                            
                            # Extract the latest data point if available
                            if tier_response['Datapoints']:
                                latest_datapoint = max(tier_response['Datapoints'], key=lambda x: x['Timestamp'])
                                size_bytes = latest_datapoint['Average']
                                size_gb = size_bytes / (1024 ** 3)  # Convert bytes to GB
                                bucket_info['StorageTier'][storage_type] = round(size_gb, 2)
                                total_size_bytes += size_bytes
                        except Exception as e:
                            logger.warning(f"Error getting {storage_type} metrics for bucket {bucket['Name']}: {e}")
                    
                    # Set total size in GB
                    bucket_info['SizeGB'] = round(total_size_bytes / (1024 ** 3), 2)
                    
                except Exception as e:
                    logger.warning(f"Error getting size metrics for bucket {bucket['Name']}: {e}")
                
            except Exception as e:
                logger.warning(f"Could not determine region for bucket {bucket['Name']}: {e}")
            
            high_cost_services['s3_buckets'].append(bucket_info)
        
        logger.info(f"Found {len(high_cost_services['s3_buckets'])} S3 buckets")
    except Exception as e:
        logger.error(f"Error collecting S3 buckets: {e}")
    
    # Process regional services in parallel
    def process_region(region):
        region_results = {
            'elbs': collect_elbs(region),
            'nat_gateways': collect_nat_gateways(region),
            'rds_instances': collect_rds_instances(region)
        }
        return region_results
    
    # Use ThreadPoolExecutor to process regions in parallel
    region_results_dict = {}
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(10, len(regions))) as executor:
        future_to_region = {executor.submit(process_region, region): region for region in regions}
        
        # Process results as they complete and store them in a dictionary keyed by region
        for future in concurrent.futures.as_completed(future_to_region):
            region = future_to_region[future]
            try:
                region_results = future.result()
                if region_results:
                    region_results_dict[region] = region_results
            except Exception as e:
                logger.error(f"Exception processing region {region}: {e}")
    
    # Only after all futures are complete, append the results to the main dictionary
    for region, results in region_results_dict.items():
        for service_key in ['elbs', 'nat_gateways', 'rds_instances']:
            if service_key in results and results[service_key]:
                high_cost_services[service_key].extend(results[service_key])
    
    return high_cost_services

# For testing purposes (will be commented out in production)
if __name__ == "__main__":
    # Configure logging for testing
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Test with default profile and us-east-1 region
    services = collect_high_cost_services(regions=['us-east-1'])
    
    # Print ELB details
    print("=== ELBs ===")
    for elb in services['elbs']:
        print(f"Name: {elb['LoadBalancerName']}")
        print(f"Type: {elb['Type']}")
        print(f"DNS Name: {elb['DNSName']}")
        print(f"Region: {elb['Region']}")
        print("-" * 50)
    
    # Print NAT Gateway details
    print("=== NAT Gateways ===")
    for nat in services['nat_gateways']:
        print(f"ID: {nat['NatGatewayId']}")
        print(f"State: {nat['State']}")
        print(f"Region: {nat['Region']}")
        print("-" * 50)
    
    # Print S3 bucket details
    print("=== S3 Buckets ===")
    for bucket in services['s3_buckets']:
        print(f"Name: {bucket['Name']}")
        print(f"Region: {bucket['Region']}")
        print(f"Creation Date: {bucket['CreationDate']}")
        print(f"Size: {bucket['SizeGB']} GB")
        print("Storage Tiers:")
        for tier_name, tier_size in bucket['StorageTier'].items():
            if tier_size > 0:
                print(f"  - {tier_name}: {tier_size} GB")
        print("-" * 50)
    
    # Print RDS instance details
    print("=== RDS Instances ===")
    for instance in services['rds_instances']:
        print(f"Identifier: {instance['DBInstanceIdentifier']}")
        print(f"Engine: {instance['Engine']} {instance['EngineVersion']}")
        print(f"Class: {instance['DBInstanceClass']}")
        print(f"Storage: {instance['AllocatedStorage']} GB")
        print(f"Multi-AZ: {instance['MultiAZ']}")
        print(f"Region: {instance['Region']}")
        print("-" * 50) 
