#!/usr/bin/env python3
"""
Volumes Collector Module

This module provides functionality to collect information about EBS volumes
and map them to their associated EC2 instances.
"""

import logging
import boto3
import botocore.exceptions
from botocore.config import Config
import concurrent.futures

logger = logging.getLogger(__name__)

# Configure retry strategy for AWS API rate limits
retry_config = Config(
    retries={
        'max_attempts': 10,
        'mode': 'adaptive'
    }
)

def get_instance_name_map(session, region):
    """
    Create a mapping of instance IDs to instance names.
    
    Args:
        session (boto3.Session): The boto3 session to use.
        region (str): AWS region to scan.
        
    Returns:
        dict: Dictionary mapping instance IDs to instance names.
    """
    instance_map = {}
    
    try:
        ec2_client = session.client('ec2', region_name=region, config=retry_config)
        
        # Get all EC2 instances with pagination
        paginator = ec2_client.get_paginator('describe_instances')
        
        for page in paginator.paginate():
            for reservation in page['Reservations']:
                for instance in reservation['Instances']:
                    instance_id = instance['InstanceId']
                    instance_name = 'N/A'
                    
                    # Extract instance name from tags
                    if 'Tags' in instance:
                        for tag in instance['Tags']:
                            if tag['Key'] == 'Name':
                                instance_name = tag['Value']
                                break
                    
                    instance_map[instance_id] = instance_name
        
        return instance_map
    
    except botocore.exceptions.ClientError as e:
        logger.error(f"Error creating instance name map in region {region}: {e}")
        return {}
    except Exception as e:
        logger.error(f"Unexpected error in region {region}: {e}")
        return {}

def get_volumes(session, region):
    """
    Get EBS volumes in a specific region and map them to EC2 instances.
    
    Args:
        session (boto3.Session): The boto3 session to use.
        region (str): AWS region to scan.
        
    Returns:
        list: List of dictionaries containing volume information.
    """
    logger.info(f"Collecting EBS volumes in region {region}")
    
    try:
        ec2_client = session.client('ec2', region_name=region, config=retry_config)
        
        # Get instance name mapping
        instance_map = get_instance_name_map(session, region)
        
        # Get all volumes with pagination
        volumes = []
        paginator = ec2_client.get_paginator('describe_volumes')
        
        for page in paginator.paginate():
            for volume in page['Volumes']:
                # Extract volume information
                volume_info = {
                    'VolumeId': volume['VolumeId'],
                    'Size': volume['Size'],
                    'VolumeType': volume['VolumeType'],
                    'State': volume['State'],
                    'CreateTime': volume['CreateTime'].strftime('%Y-%m-%d %H:%M:%S'),
                    'AvailabilityZone': volume['AvailabilityZone'],
                    'Region': region,
                    'InstanceId': 'N/A',
                    'InstanceName': 'N/A'
                }
                
                # Map volume to instance if attached
                if 'Attachments' in volume and volume['Attachments']:
                    attachment = volume['Attachments'][0]  # Get the first attachment
                    instance_id = attachment.get('InstanceId', 'N/A')
                    volume_info['InstanceId'] = instance_id
                    volume_info['InstanceName'] = instance_map.get(instance_id, 'N/A')
                
                # Extract volume name from tags
                if 'Tags' in volume:
                    for tag in volume['Tags']:
                        if tag['Key'] == 'Name':
                            volume_info['Name'] = tag['Value']
                            break
                
                if 'Name' not in volume_info:
                    volume_info['Name'] = 'N/A'
                
                volumes.append(volume_info)
        
        logger.info(f"Found {len(volumes)} EBS volumes in region {region}")
        return volumes
    
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'AuthFailure':
            logger.warning(f"Authentication failure in region {region}. The region may not be enabled for your account.")
            return []
        elif e.response['Error']['Code'] == 'UnauthorizedOperation':
            logger.error(f"Unauthorized operation in region {region}. Check your IAM permissions.")
            return []
        else:
            logger.error(f"Error collecting EBS volumes in region {region}: {e}")
            return []
    except Exception as e:
        logger.error(f"Unexpected error in region {region}: {e}")
        return []

def collect_volumes(profile_name=None, role_arn=None, regions=None, session=None, account_id=None, account_name=None):
    """
    Collect EBS volumes across specified regions.
    
    Args:
        profile_name (str, optional): AWS profile name to use.
        role_arn (str, optional): Role ARN to assume or role name.
        regions (list, optional): List of regions to scan.
        session (boto3.Session, optional): Boto3 session to use.
        account_id (str, optional): AWS account ID.
        account_name (str, optional): AWS account name.
        
    Returns:
        list: List of EBS volumes.
    """
    volumes = []
    
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
            return volumes
    
    # Get account ID if not provided
    if not account_id:
        try:
            sts_client = session.client('sts')
            account_id = sts_client.get_caller_identity()['Account']
        except Exception as e:
            logger.error(f"Error getting account ID: {e}")
            account_id = "Unknown"
    
    # Define a worker function to process a single region
    def process_region(region):
        region_volumes = []
        try:
            # Get volumes in the region
            region_volumes = get_volumes(session, region)
            
            # Add account information to each volume
            for volume in region_volumes:
                volume['AccountId'] = account_id
                volume['AccountName'] = account_name if account_name else 'N/A'
            
            logger.info(f"Found {len(region_volumes)} EBS volumes in region {region}")
            return region_volumes
        except botocore.exceptions.ClientError as e:
            if e.response['Error']['Code'] == 'AuthFailure':
                logger.warning(f"Authentication failure in region {region}. The region may not be enabled for your account.")
            elif e.response['Error']['Code'] == 'UnauthorizedOperation':
                logger.error(f"Unauthorized operation in region {region}. Check your IAM permissions.")
            else:
                logger.error(f"Error collecting EBS volumes in region {region}: {e}")
            return []
        except Exception as e:
            logger.error(f"Unexpected error in region {region}: {e}")
            return []
    
    # Use ThreadPoolExecutor to process regions in parallel
    volumes = []  # Clear this to ensure we only have volumes from this function call
    region_results = {}
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(10, len(regions))) as executor:
        future_to_region = {executor.submit(process_region, region): region for region in regions}
        
        # Process results as they complete and store them in a dictionary keyed by region
        for future in concurrent.futures.as_completed(future_to_region):
            region = future_to_region[future]
            try:
                region_volumes = future.result()
                if region_volumes:
                    region_results[region] = region_volumes
            except Exception as e:
                logger.error(f"Exception processing region {region}: {e}")
    
    # Only after all futures are complete, append the results to the main list
    for region, region_volumes in region_results.items():
        volumes.extend(region_volumes)
    
    return volumes

# For testing purposes (will be commented out in production)
if __name__ == "__main__":
    # Configure logging for testing
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Test with default profile and us-east-1 region
    volumes = collect_volumes(regions=['us-east-1'])
    
    # Print volume details
    for volume in volumes:
        print(f"Volume ID: {volume['VolumeId']}")
        print(f"Name: {volume['Name']}")
        print(f"Size: {volume['Size']} GB")
        print(f"Type: {volume['VolumeType']}")
        print(f"State: {volume['State']}")
        print(f"Instance ID: {volume['InstanceId']}")
        print(f"Instance Name: {volume['InstanceName']}")
        print(f"Region: {volume['Region']}")
        print("-" * 50) 
