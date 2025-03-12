#!/usr/bin/env python3
"""
Test script to verify that all modules can be imported correctly.
"""

import sys
import os

# Add the src directory to the Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import all modules
try:
    import aws_org_enumerator
    import ec2_collector
    import volumes_collector
    import ami_collector
    import high_cost_inventory
    import csv_reporter
    
    print("All modules imported successfully!")
    
    # Print module versions
    import boto3
    print(f"boto3 version: {boto3.__version__}")
    
except ImportError as e:
    print(f"Error importing modules: {e}")
    sys.exit(1) 
