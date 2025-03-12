#!/usr/bin/env python3
"""
AMI Collector Module

This module collects information about unused AMIs across regions.
"""

import logging
import boto3
import botocore.exceptions
from botocore.config import Config
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

# Configure retry strategy for AWS API rate limits
retry_config = Config(
    retries={
        'max_attempts': 10,
        'mode': 'adaptive'
    }
)

def get_used_amis(session, region):
    """
    Get a set of AMI IDs that are currently in use by EC2 instances.
    
    Args:
        session (boto3.Session): The boto3 session to use.
        region (str): AWS region to scan.
        
    Returns:
        set: Set of AMI IDs in use.
    """
    used_amis = set()
    
    try:
        ec2_client = session.client('ec2', region_name=region, config=retry_config)
        
        # Get all EC2 instances with pagination
        paginator = ec2_client.get_paginator('describe_instances')
        
        for page in paginator.paginate():
            for reservation in page['Reservations']:
                for instance in reservation['Instances']:
                    if 'ImageId' in instance:
                        used_amis.add(instance['ImageId'])
        
        logger.info(f"Found {len(used_amis)} AMIs in use in region {region}")
        return used_amis
    
    except botocore.exceptions.ClientError as e:
        logger.error(f"Error getting used AMIs in region {region}: {e}")
        return set()
    except Exception as e:
        logger.error(f"Unexpected error in region {region}: {e}")
        return set()

def get_owned_amis(session, region):
    """
    Get AMIs owned by the account.
    
    Args:
        session (boto3.Session): The boto3 session to use.
        region (str): AWS region to scan.
        
    Returns:
        list: List of dictionaries containing AMI information.
    """
    logger.info(f"Collecting owned AMIs in region {region}")
    
    try:
        ec2_client = session.client('ec2', region_name=region, config=retry_config)
        
        # Get AMIs owned by the account
        response = ec2_client.describe_images(Owners=['self'])
        amis = response.get('Images', [])
        
        logger.info(f"Found {len(amis)} owned AMIs in region {region}")
        return amis
    
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'AuthFailure':
            logger.warning(f"Authentication failure in region {region}. The region may not be enabled for your account.")
            return []
        elif e.response['Error']['Code'] == 'UnauthorizedOperation':
            logger.error(f"Unauthorized operation in region {region}. Check your IAM permissions.")
            return []
        else:
            logger.error(f"Error collecting owned AMIs in region {region}: {e}")
            return []
    except Exception as e:
        logger.error(f"Unexpected error in region {region}: {e}")
        return []

def detect_unused_amis(session, region):
    """
    Detect unused AMIs in a specific region.
    
    Args:
        session (boto3.Session): The boto3 session to use.
        region (str): AWS region to scan.
        
    Returns:
        list: List of dictionaries containing unused AMI information.
    """
    logger.info(f"Detecting unused AMIs in region {region}")
    
    try:
        # Get AMIs in use
        used_amis = get_used_amis(session, region)
        
        # Get owned AMIs
        owned_amis = get_owned_amis(session, region)
        
        # Filter out unused AMIs
        unused_amis = []
        for ami in owned_amis:
            if ami['ImageId'] not in used_amis:
                # Extract AMI information
                ami_info = {
                    'ImageId': ami['ImageId'],
                    'Name': ami.get('Name', 'N/A'),
                    'Description': ami.get('Description', 'N/A'),
                    'State': ami['State'],
                    'CreationDate': ami.get('CreationDate', 'N/A'),
                    'Region': region
                }
                
                unused_amis.append(ami_info)
        
        logger.info(f"Found {len(unused_amis)} unused AMIs in region {region}")
        return unused_amis
    
    except Exception as e:
        logger.error(f"Error detecting unused AMIs in region {region}: {e}")
        return []

def collect_unused_amis(profile_name=None, role_arn=None, regions=None, session=None, account_id=None, account_name=None):
    """
    Collect unused AMIs across specified regions.
    
    Args:
        profile_name (str, optional): AWS profile name to use.
        role_arn (str, optional): Role ARN to assume or role name.
        regions (list, optional): List of regions to scan.
        session (boto3.Session, optional): Boto3 session to use.
        account_id (str, optional): AWS account ID.
        account_name (str, optional): AWS account name.
        
    Returns:
        list: List of unused AMIs.
    """
    unused_amis = []
    
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
            return unused_amis
    
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
            
            # Get all AMIs owned by this account
            response = ec2_client.describe_images(Owners=['self'])
            amis = response.get('Images', [])
            
            # Get all EC2 instances
            instances_response = ec2_client.describe_instances()
            instances = []
            for reservation in instances_response.get('Reservations', []):
                instances.extend(reservation.get('Instances', []))
            
            # Extract AMI IDs used by instances
            used_ami_ids = set()
            for instance in instances:
                if 'ImageId' in instance:
                    used_ami_ids.add(instance['ImageId'])
            
            # Find unused AMIs
            for ami in amis:
                if ami['ImageId'] not in used_ami_ids:
                    # Calculate age in days
                    creation_date = datetime.strptime(ami['CreationDate'], '%Y-%m-%dT%H:%M:%S.%fZ')
                    age_days = (datetime.now(timezone.utc) - creation_date.replace(tzinfo=timezone.utc)).days
                    
                    ami_info = {
                        'ImageId': ami['ImageId'],
                        'Name': ami.get('Name', 'N/A'),
                        'Description': ami.get('Description', 'N/A'),
                        'CreationDate': ami['CreationDate'],
                        'AgeDays': age_days,
                        'State': ami['State'],
                        'Region': region,
                        'AccountId': account_id,
                        'AccountName': account_name if account_name else 'N/A'
                    }
                    
                    unused_amis.append(ami_info)
            
            logger.info(f"Found {len(unused_amis)} unused AMIs in region {region}")
        except Exception as e:
            logger.error(f"Error collecting unused AMIs in region {region}: {e}")
    
    return unused_amis

# For testing purposes (will be commented out in production)
if __name__ == "__main__":
    # Configure logging for testing
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Test with default profile and us-east-1 region
    unused_amis = collect_unused_amis(regions=['us-east-1'])
    
    # Print unused AMI details
    for ami in unused_amis:
        print(f"AMI ID: {ami['ImageId']}")
        print(f"Name: {ami['Name']}")
        print(f"Description: {ami['Description']}")
        print(f"State: {ami['State']}")
        print(f"Creation Date: {ami['CreationDate']}")
        print(f"Region: {ami['Region']}")
        print(f"Account ID: {ami['AccountId']}")
        print(f"Account Name: {ami['AccountName']}")
        print("-" * 50) 
