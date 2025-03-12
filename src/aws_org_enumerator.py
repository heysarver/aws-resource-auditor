#!/usr/bin/env python3
"""
AWS Organization Enumerator

This module provides functionality to enumerate AWS accounts and sub-accounts
within an AWS Organization.
"""

import logging
import boto3
import botocore.exceptions
import time
import error_reporter

logger = logging.getLogger(__name__)

def get_organization_accounts(profile_name=None, role_arn=None):
    """
    List all AWS accounts in the organization.
    
    Args:
        profile_name (str, optional): AWS profile name to use. Defaults to None.
        role_arn (str, optional): Role ARN to assume or role name. Defaults to None.
        
    Returns:
        list: List of dictionaries containing account information.
    """
    logger.info("Enumerating AWS Organization accounts")
    
    try:
        session = boto3.Session(profile_name=profile_name)
    except Exception as e:
        error_reporter.error_collector.add_error(
            'Boto3', 'CreateSession', 'global', 'current', str(e)
        )
        logger.error(f"Failed to create boto3 session: {e}")
        return []
    
    # Get the current account ID
    try:
        sts_client = session.client('sts')
        current_account_id = sts_client.get_caller_identity()['Account']
    except Exception as e:
        error_reporter.error_collector.add_error(
            'STS', 'GetCallerIdentity', 'global', 'current', str(e)
        )
        logger.error(f"Failed to get current account ID: {e}")
        current_account_id = None
    
    # If a role ARN is provided, assume that role
    if role_arn:
        # Check if role_arn is a full ARN or just a role name
        if not role_arn.startswith('arn:aws:iam::'):
            try:
                # Construct the full ARN using the current account ID
                role_arn = f"arn:aws:iam::{current_account_id}:role/{role_arn}"
            except Exception as e:
                error_reporter.error_collector.add_error(
                    'STS', 'GetCallerIdentity', 'global', 'current', str(e)
                )
                logger.error(f"Failed to get account ID for role ARN construction: {e}")
                return []
        
        # Extract the account ID from the role ARN
        try:
            role_account_id = role_arn.split(':')[4]
        except Exception:
            role_account_id = None
        
        # Skip role assumption if it's the current account
        if role_account_id and role_account_id == current_account_id:
            logger.info(f"Using current session for account {current_account_id} (current account)")
            # Use the existing session
        else:
            logger.info(f"Assuming role: {role_arn}")
            try:
                sts_client = session.client('sts')
                response = sts_client.assume_role(
                    RoleArn=role_arn,
                    RoleSessionName='AWSResourceAuditor'
                )
                credentials = response['Credentials']
                session = boto3.Session(
                    aws_access_key_id=credentials['AccessKeyId'],
                    aws_secret_access_key=credentials['SecretAccessKey'],
                    aws_session_token=credentials['SessionToken']
                )
            except botocore.exceptions.ClientError as e:
                error_reporter.error_collector.add_error(
                    'STS', 'AssumeRole', 'global', 'current', str(e)
                )
                logger.error(f"Failed to assume role: {e}")
                return []
            except Exception as e:
                error_reporter.error_collector.add_error(
                    'STS', 'AssumeRole', 'global', 'current', str(e)
                )
                logger.error(f"Unexpected error assuming role: {e}")
                return []
    
    # Create Organizations client
    try:
        org_client = session.client('organizations')
        
        # List accounts with pagination
        accounts = []
        paginator = org_client.get_paginator('list_accounts')
        
        for page in paginator.paginate():
            accounts.extend(page['Accounts'])
        
        logger.info(f"Found {len(accounts)} accounts in the organization")
        return accounts
    
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'AWSOrganizationsNotInUseException':
            logger.warning("AWS Organizations is not in use for this account")
            # Return the current account only
            try:
                sts_client = session.client('sts')
                identity = sts_client.get_caller_identity()
                return [{
                    'Id': identity['Account'],
                    'Name': 'Current Account',
                    'Status': 'ACTIVE'
                }]
            except Exception as e2:
                error_reporter.error_collector.add_error(
                    'STS', 'GetCallerIdentity', 'global', 'current', str(e2)
                )
                logger.error(f"Failed to get current account identity: {e2}")
                return []
        else:
            error_reporter.error_collector.add_error(
                'Organizations', 'ListAccounts', 'global', 'current', str(e)
            )
            logger.error(f"Error listing organization accounts: {e}")
            return []
    except Exception as e:
        error_reporter.error_collector.add_error(
            'Organizations', 'ListAccounts', 'global', 'current', str(e)
        )
        logger.error(f"Unexpected error: {e}")
        return []

def get_organization_id(profile_name=None, role_arn=None):
    """
    Get the AWS Organization ID.
    
    Args:
        profile_name (str, optional): AWS profile name to use. Defaults to None.
        role_arn (str, optional): Role ARN to assume or role name. Defaults to None.
        
    Returns:
        str: Organization ID or None if not found.
    """
    logger.info("Getting AWS Organization ID")
    
    try:
        session = boto3.Session(profile_name=profile_name)
    except Exception as e:
        error_reporter.error_collector.add_error(
            'Boto3', 'CreateSession', 'global', 'current', str(e)
        )
        logger.error(f"Failed to create boto3 session: {e}")
        return None
    
    # Get the current account ID
    try:
        sts_client = session.client('sts')
        current_account_id = sts_client.get_caller_identity()['Account']
    except Exception as e:
        error_reporter.error_collector.add_error(
            'STS', 'GetCallerIdentity', 'global', 'current', str(e)
        )
        logger.error(f"Failed to get current account ID: {e}")
        current_account_id = None
    
    # If a role ARN is provided, assume that role
    if role_arn:
        # Check if role_arn is a full ARN or just a role name
        if not role_arn.startswith('arn:aws:iam::'):
            try:
                # Construct the full ARN using the current account ID
                role_arn = f"arn:aws:iam::{current_account_id}:role/{role_arn}"
            except Exception as e:
                error_reporter.error_collector.add_error(
                    'STS', 'GetCallerIdentity', 'global', 'current', str(e)
                )
                logger.error(f"Failed to get account ID for role ARN construction: {e}")
                return None
        
        # Extract the account ID from the role ARN
        try:
            role_account_id = role_arn.split(':')[4]
        except Exception:
            role_account_id = None
        
        # Skip role assumption if it's the current account
        if role_account_id and role_account_id == current_account_id:
            logger.info(f"Using current session for account {current_account_id} (current account)")
            # Use the existing session
        else:
            logger.info(f"Assuming role: {role_arn}")
            try:
                sts_client = session.client('sts')
                response = sts_client.assume_role(
                    RoleArn=role_arn,
                    RoleSessionName='AWSResourceAuditor'
                )
                credentials = response['Credentials']
                session = boto3.Session(
                    aws_access_key_id=credentials['AccessKeyId'],
                    aws_secret_access_key=credentials['SecretAccessKey'],
                    aws_session_token=credentials['SessionToken']
                )
            except botocore.exceptions.ClientError as e:
                error_reporter.error_collector.add_error(
                    'STS', 'AssumeRole', 'global', 'current', str(e)
                )
                logger.error(f"Failed to assume role: {e}")
                return None
            except Exception as e:
                error_reporter.error_collector.add_error(
                    'STS', 'AssumeRole', 'global', 'current', str(e)
                )
                logger.error(f"Unexpected error assuming role: {e}")
                return None
    
    # Create Organizations client
    try:
        org_client = session.client('organizations')
        response = org_client.describe_organization()
        org_id = response['Organization']['Id']
        logger.info(f"Organization ID: {org_id}")
        return org_id
    
    except botocore.exceptions.ClientError as e:
        error_reporter.error_collector.add_error(
            'Organizations', 'DescribeOrganization', 'global', 'current', str(e)
        )
        logger.error(f"Error getting organization ID: {e}")
        return None
    except Exception as e:
        error_reporter.error_collector.add_error(
            'Organizations', 'DescribeOrganization', 'global', 'current', str(e)
        )
        logger.error(f"Unexpected error: {e}")
        return None

def assume_role_for_account(profile_name, role_name, account_id):
    """
    Assume a role in a specific account.
    
    Args:
        profile_name (str): AWS profile name to use.
        role_name (str): Name of the role to assume (without the full ARN).
        account_id (str): AWS account ID to assume the role in.
        
    Returns:
        boto3.Session: A new boto3 session with the assumed role credentials.
    """
    # Construct the role ARN
    role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"
    logger.info(f"Assuming role {role_arn}")
    
    try:
        # Create a session with the profile
        session = boto3.Session(profile_name=profile_name)
        sts_client = session.client('sts')
        
        # Assume the role
        response = sts_client.assume_role(
            RoleArn=role_arn,
            RoleSessionName='AWSResourceAuditor'
        )
        
        # Create a new session with the assumed role credentials
        credentials = response['Credentials']
        new_session = boto3.Session(
            aws_access_key_id=credentials['AccessKeyId'],
            aws_secret_access_key=credentials['SecretAccessKey'],
            aws_session_token=credentials['SessionToken']
        )
        
        return new_session
    
    except botocore.exceptions.ClientError as e:
        error_reporter.error_collector.add_error(
            'STS', 'AssumeRole', 'global', account_id, str(e)
        )
        logger.error(f"Failed to assume role {role_arn}: {e}")
        return None
    except Exception as e:
        error_reporter.error_collector.add_error(
            'STS', 'AssumeRole', 'global', account_id, str(e)
        )
        logger.error(f"Unexpected error assuming role {role_arn}: {e}")
        return None

# For testing purposes (will be commented out in production)
if __name__ == "__main__":
    # Configure logging for testing
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Test with default profile
    accounts = get_organization_accounts()
    for account in accounts:
        print(f"Account ID: {account['Id']}, Name: {account.get('Name', 'N/A')}, Status: {account.get('Status', 'N/A')}")
    
    # Get organization ID
    org_id = get_organization_id()
    if org_id:
        print(f"Organization ID: {org_id}")
    else:
        print("Failed to get organization ID") 
