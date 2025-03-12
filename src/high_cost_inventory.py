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

logger = logging.getLogger(__name__)

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
    
    # Collect ELBs and NAT Gateways from each region
    for region in regions:
        # Collect Elastic Load Balancers (both Classic and Application/Network)
        try:
            # Classic Load Balancers
            elb_client = session.client('elb', region_name=region)
            classic_lbs = elb_client.describe_load_balancers().get('LoadBalancerDescriptions', [])
            
            for lb in classic_lbs:
                lb_info = {
                    'LoadBalancerName': lb['LoadBalancerName'],
                    'DNSName': lb['DNSName'],
                    'Type': 'classic',
                    'Scheme': lb.get('Scheme', 'N/A'),
                    'CreatedTime': lb['CreatedTime'].strftime('%Y-%m-%d %H:%M:%S'),
                    'Region': region,
                    'AccountId': account_id,
                    'AccountName': account_name if account_name else 'N/A'
                }
                high_cost_services['elbs'].append(lb_info)
            
            # Application and Network Load Balancers
            elbv2_client = session.client('elbv2', region_name=region)
            v2_lbs = elbv2_client.describe_load_balancers().get('LoadBalancers', [])
            
            for lb in v2_lbs:
                lb_info = {
                    'LoadBalancerName': lb['LoadBalancerName'],
                    'DNSName': lb['DNSName'],
                    'Type': lb['Type'].lower(),
                    'Scheme': lb.get('Scheme', 'N/A'),
                    'CreatedTime': lb['CreatedTime'].strftime('%Y-%m-%d %H:%M:%S'),
                    'Region': region,
                    'AccountId': account_id,
                    'AccountName': account_name if account_name else 'N/A'
                }
                high_cost_services['elbs'].append(lb_info)
            
            logger.info(f"Found {len(classic_lbs) + len(v2_lbs)} ELBs in region {region}")
        except Exception as e:
            logger.error(f"Error collecting ELBs in region {region}: {e}")
        
        # Collect NAT Gateways
        try:
            ec2_client = session.client('ec2', region_name=region)
            nat_gateways = ec2_client.describe_nat_gateways().get('NatGateways', [])
            
            for nat in nat_gateways:
                nat_info = {
                    'NatGatewayId': nat['NatGatewayId'],
                    'State': nat['State'],
                    'SubnetId': nat['SubnetId'],
                    'VpcId': nat['VpcId'],
                    'CreatedTime': nat['CreateTime'].strftime('%Y-%m-%d %H:%M:%S') if 'CreateTime' in nat else 'N/A',
                    'Region': region,
                    'AccountId': account_id,
                    'AccountName': account_name if account_name else 'N/A'
                }
                
                # Extract name from tags
                if 'Tags' in nat:
                    for tag in nat['Tags']:
                        if tag['Key'] == 'Name':
                            nat_info['Name'] = tag['Value']
                            break
                
                if 'Name' not in nat_info:
                    nat_info['Name'] = 'N/A'
                
                high_cost_services['nat_gateways'].append(nat_info)
            
            logger.info(f"Found {len(nat_gateways)} NAT Gateways in region {region}")
        except Exception as e:
            logger.error(f"Error collecting NAT Gateways in region {region}: {e}")
        
        # Collect RDS Instances
        try:
            rds_client = session.client('rds', region_name=region)
            rds_instances = rds_client.describe_db_instances().get('DBInstances', [])
            
            for instance in rds_instances:
                instance_info = {
                    'DBInstanceIdentifier': instance['DBInstanceIdentifier'],
                    'Engine': instance['Engine'],
                    'EngineVersion': instance['EngineVersion'],
                    'DBInstanceClass': instance['DBInstanceClass'],
                    'AllocatedStorage': instance['AllocatedStorage'],
                    'StorageType': instance['StorageType'],
                    'MultiAZ': instance['MultiAZ'],
                    'Status': instance['DBInstanceStatus'],
                    'Region': region,
                    'AccountId': account_id,
                    'AccountName': account_name if account_name else 'N/A'
                }
                high_cost_services['rds_instances'].append(instance_info)
            
            logger.info(f"Found {len(rds_instances)} RDS Instances in region {region}")
        except Exception as e:
            logger.error(f"Error collecting RDS Instances in region {region}: {e}")
    
    # Collect S3 Buckets (global service)
    try:
        s3_client = session.client('s3')
        buckets = s3_client.list_buckets().get('Buckets', [])
        
        for bucket in buckets:
            bucket_info = {
                'Name': bucket['Name'],
                'CreationDate': bucket['CreationDate'].strftime('%Y-%m-%d %H:%M:%S'),
                'AccountId': account_id,
                'AccountName': account_name if account_name else 'N/A'
            }
            
            # Get bucket region
            try:
                location = s3_client.get_bucket_location(Bucket=bucket['Name'])
                region = location.get('LocationConstraint', 'us-east-1')
                if region is None:  # us-east-1 returns None
                    region = 'us-east-1'
                bucket_info['Region'] = region
            except Exception:
                bucket_info['Region'] = 'unknown'
            
            # Get bucket size (optional, can be expensive for large buckets)
            # This is commented out as it can be expensive and slow for large buckets
            # try:
            #     metrics = cloudwatch_client.get_metric_statistics(
            #         Namespace='AWS/S3',
            #         MetricName='BucketSizeBytes',
            #         Dimensions=[
            #             {'Name': 'BucketName', 'Value': bucket['Name']},
            #             {'Name': 'StorageType', 'Value': 'StandardStorage'}
            #         ],
            #         StartTime=datetime.now() - timedelta(days=2),
            #         EndTime=datetime.now(),
            #         Period=86400,
            #         Statistics=['Average']
            #     )
            #     if metrics['Datapoints']:
            #         bucket_info['SizeBytes'] = metrics['Datapoints'][0]['Average']
            #     else:
            #         bucket_info['SizeBytes'] = 0
            # except Exception:
            #     bucket_info['SizeBytes'] = 'unknown'
            
            high_cost_services['s3_buckets'].append(bucket_info)
        
        logger.info(f"Found {len(buckets)} S3 Buckets")
    except Exception as e:
        logger.error(f"Error collecting S3 Buckets: {e}")
    
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
        print(f"Name: {nat['Name']}")
        print(f"State: {nat['State']}")
        print(f"Region: {nat['Region']}")
        print("-" * 50)
    
    # Print S3 bucket details
    print("=== S3 Buckets ===")
    for bucket in services['s3_buckets']:
        print(f"Name: {bucket['Name']}")
        print(f"Region: {bucket['Region']}")
        print(f"Creation Date: {bucket['CreationDate']}")
        print("-" * 50)
    
    # Print RDS instance details
    print("=== RDS Instances ===")
    for instance in services['rds_instances']:
        print(f"Identifier: {instance['DBInstanceIdentifier']}")
        print(f"Engine: {instance['Engine']} {instance['EngineVersion']}")
        print(f"Class: {instance['DBInstanceClass']}")
        print(f"Storage: {instance['AllocatedStorage']} GB ({instance['StorageType']})")
        print(f"Multi-AZ: {instance['MultiAZ']}")
        print(f"Region: {instance['Region']}")
        print("-" * 50) 
