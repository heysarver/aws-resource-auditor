#!/usr/bin/env python3
"""
EC2 Collector Module

This module collects information about EC2 instances across regions.
"""

import logging
import boto3
import botocore.exceptions
import time
from botocore.config import Config

logger = logging.getLogger(__name__)

# Configure retry strategy for AWS API rate limits
retry_config = Config(
    retries={
        'max_attempts': 10,
        'mode': 'adaptive'
    }
)

def get_ec2_instances(session, region, org_id=None):
    """
    Get EC2 instances in a specific region.
    
    Args:
        session (boto3.Session): The boto3 session to use.
        region (str): AWS region to scan.
        org_id (str, optional): Organization ID to include in the results. Defaults to None.
        
    Returns:
        list: List of dictionaries containing EC2 instance information.
    """
    logger.info(f"Collecting EC2 instances in region {region}")
    
    try:
        ec2_client = session.client('ec2', region_name=region, config=retry_config)
        
        # Get all EC2 instances with pagination
        instances = []
        paginator = ec2_client.get_paginator('describe_instances')
        
        for page in paginator.paginate():
            for reservation in page['Reservations']:
                for instance in reservation['Instances']:
                    # Extract instance information
                    instance_info = {
                        'InstanceId': instance['InstanceId'],
                        'InstanceType': instance['InstanceType'],
                        'State': instance['State']['Name'],
                        'PrivateIpAddress': instance.get('PrivateIpAddress', 'N/A'),
                        'PublicIpAddress': instance.get('PublicIpAddress', 'N/A'),
                        'Region': region,
                        'OrganizationId': org_id if org_id else 'N/A'
                    }
                    
                    # Extract instance name from tags
                    if 'Tags' in instance:
                        for tag in instance['Tags']:
                            if tag['Key'] == 'Name':
                                instance_info['Name'] = tag['Value']
                                break
                    
                    if 'Name' not in instance_info:
                        instance_info['Name'] = 'N/A'
                    
                    instances.append(instance_info)
        
        logger.info(f"Found {len(instances)} EC2 instances in region {region}")
        return instances
    
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'AuthFailure':
            logger.warning(f"Authentication failure in region {region}. The region may not be enabled for your account.")
            return []
        elif e.response['Error']['Code'] == 'UnauthorizedOperation':
            logger.error(f"Unauthorized operation in region {region}. Check your IAM permissions.")
            return []
        else:
            logger.error(f"Error collecting EC2 instances in region {region}: {e}")
            return []
    except Exception as e:
        logger.error(f"Unexpected error in region {region}: {e}")
        return []

def collect_ec2_instances(profile_name=None, role_arn=None, regions=None, org_id=None, session=None, account_id=None, account_name=None):
    """
    Collect EC2 instances across specified regions.
    
    Args:
        profile_name (str, optional): AWS profile name to use.
        role_arn (str, optional): Role ARN to assume or role name.
        regions (list, optional): List of regions to scan.
        org_id (str, optional): Organization ID.
        session (boto3.Session, optional): Boto3 session to use.
        account_id (str, optional): AWS account ID.
        account_name (str, optional): AWS account name.
        
    Returns:
        list: List of EC2 instances.
    """
    ec2_instances = []
    
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
            return ec2_instances
    
    # Get account ID if not provided
    if not account_id:
        try:
            sts_client = session.client('sts')
            account_id = sts_client.get_caller_identity()['Account']
        except Exception as e:
            logger.error(f"Error getting account ID: {e}")
            account_id = "Unknown"
    
    # Iterate through regions
    for region in regions:
        try:
            ec2_client = session.client('ec2', region_name=region)
            paginator = ec2_client.get_paginator('describe_instances')
            
            for page in paginator.paginate():
                for reservation in page['Reservations']:
                    for instance in reservation['Instances']:
                        # Extract instance information
                        instance_info = {
                            'InstanceId': instance['InstanceId'],
                            'InstanceType': instance['InstanceType'],
                            'State': instance['State']['Name'],
                            'PrivateIpAddress': instance.get('PrivateIpAddress', 'N/A'),
                            'PublicIpAddress': instance.get('PublicIpAddress', 'N/A'),
                            'Region': region,
                            'OrganizationId': org_id if org_id else 'N/A',
                            'AccountId': account_id,
                            'AccountName': account_name if account_name else 'N/A'
                        }
                        
                        # Extract instance name from tags
                        if 'Tags' in instance:
                            for tag in instance['Tags']:
                                if tag['Key'] == 'Name':
                                    instance_info['Name'] = tag['Value']
                                    break
                        
                        if 'Name' not in instance_info:
                            instance_info['Name'] = 'N/A'
                        
                        ec2_instances.append(instance_info)
            
            logger.info(f"Found {len(ec2_instances)} EC2 instances in region {region}")
        except Exception as e:
            logger.error(f"Error collecting EC2 instances in region {region}: {e}")
    
    return ec2_instances

# For testing purposes (will be commented out in production)
if __name__ == "__main__":
    # Configure logging for testing
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Test with default profile and us-east-1 region
    instances = collect_ec2_instances(regions=['us-east-1'])
    
    # Print instance details
    for instance in instances:
        print(f"Instance ID: {instance['InstanceId']}")
        print(f"Name: {instance['Name']}")
        print(f"Type: {instance['InstanceType']}")
        print(f"State: {instance['State']}")
        print(f"Private IP: {instance['PrivateIpAddress']}")
        print(f"Public IP: {instance['PublicIpAddress']}")
        print(f"Region: {instance['Region']}")
        print(f"Organization ID: {instance['OrganizationId']}")
        print(f"Account ID: {instance['AccountId']}")
        print(f"Account Name: {instance['AccountName']}")
        print("-" * 50) 
