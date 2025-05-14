import boto3
import time
from datetime import datetime, timedelta
import pandas as pd
import botocore.exceptions
import os
import json
from typing import List, Dict, Any, Optional, Tuple, Union, TypedDict
from dotenv import load_dotenv
from pathlib import Path
from cloudtrail_query import CloudTrailQuery

class EventData(TypedDict):
    timestamp: str
    event_name: str
    source_ip: str
    resource: str
    request_parameters: Dict[str, Any]
    response_elements: Dict[str, Any]
    user: str
    errorCode: str
    errorMessage: str

class UserInfo(TypedDict):
    username: str
    arn: str

class SSOUserInfo(TypedDict):
    username: str
    user_id: str
    display_name: str
    email: str

class CloudTrailHelper:
    def __init__(self, log_group: str = "/aws/cloudtrail") -> None:
        # Find and load the .env file
        env_path = None
        
        # Try current directory
        if os.path.exists('.env'):
            env_path = '.env'
        # Try parent directory
        elif os.path.exists('../.env'):
            env_path = '../.env'
        # Try absolute path from project root
        else:
            project_root = Path(__file__).resolve().parent
            env_file = project_root / '.env'
            if env_file.exists():
                env_path = str(env_file)
        
        if env_path:
            load_dotenv(dotenv_path=env_path)
        else:
            print("Warning: No .env file found")
        
        # Get credentials from environment variables
        aws_access_key: Optional[str] = os.getenv('AWS_ACCESS_KEY_ID')
        aws_secret_key: Optional[str] = os.getenv('AWS_SECRET_ACCESS_KEY')
        aws_region: Optional[str] = os.getenv('AWS_DEFAULT_REGION', 'us-east-1')  # Default to us-east-1 if not specified
        session_token: Optional[str] = os.getenv('AWS_SESSION_TOKEN')
        
        if not aws_access_key or not aws_secret_key:
            raise ValueError("AWS credentials not found. Please either:\n1. Check your .env file, or\n2. Enter credentials in the sidebar")
        
        # Create session with explicit credentials
        if aws_access_key and aws_secret_key:
            if session_token:
                self.client = boto3.client(
                    "logs",
                    aws_access_key_id=aws_access_key,
                    aws_secret_access_key=aws_secret_key,
                    aws_session_token=session_token,
                    region_name=aws_region
                )
                self.iam_client = boto3.client(
                    "iam",
                    aws_access_key_id=aws_access_key,
                    aws_secret_access_key=aws_secret_key,
                    aws_session_token=session_token,
                    region_name=aws_region
                )
                self.sso_client = boto3.client(
                    "identitystore",
                    aws_access_key_id=aws_access_key,
                    aws_secret_access_key=aws_secret_key,
                    aws_session_token=session_token,
                    region_name=aws_region
                )
                self.sso_admin_client = boto3.client(
                    "sso-admin",
                    aws_access_key_id=aws_access_key,
                    aws_secret_access_key=aws_secret_key,
                    aws_session_token=session_token,
                    region_name=aws_region
                )
            else:
                self.client = boto3.client(
                    "logs",
                    aws_access_key_id=aws_access_key,
                    aws_secret_access_key=aws_secret_key,
                    region_name=aws_region
                )
                self.iam_client = boto3.client(
                    "iam",
                    aws_access_key_id=aws_access_key,
                    aws_secret_access_key=aws_secret_key,
                    region_name=aws_region
                )
                self.sso_client = boto3.client(
                    "identitystore",
                    aws_access_key_id=aws_access_key,
                    aws_secret_access_key=aws_secret_key,
                    region_name=aws_region
                )
                self.sso_admin_client = boto3.client(
                    "sso-admin",
                    aws_access_key_id=aws_access_key,
                    aws_secret_access_key=aws_secret_key,
                    region_name=aws_region
                )
        else:
            # Fall back to default credential provider chain
            self.client = boto3.client("logs")
            self.iam_client = boto3.client("iam")
            self.sso_client = boto3.client("identitystore")
            self.sso_admin_client = boto3.client("sso-admin")
            
        self.log_group: str = log_group
        self.query_helper = CloudTrailQuery()
    
    def run_insights_query(self, query: str, start_time: int, end_time: int) -> Optional[List[Dict[str, Any]]]:
        """Run a CloudWatch Logs Insights query and return the results.
        
        Args:
            query: The CloudWatch Logs Insights query string
            start_time: Start time in milliseconds since epoch
            end_time: End time in milliseconds since epoch
            
        Returns:
            List of query results or None if query fails
            
        Raises:
            Exception: If AWS credentials are invalid or other errors occur
        """
        try:
            response = self.client.start_query(
                logGroupName=self.log_group,
                startTime=start_time,
                endTime=end_time,
                queryString=query
            )
            query_id = response['queryId']
            
            # Wait for query to complete
            status = 'Running'
            while status == 'Running':
                time.sleep(1)
                result = self.client.get_query_results(queryId=query_id)
                status = result['status']
            
            return result['results']
        except botocore.exceptions.ClientError as e:
            if e.response['Error']['Code'] == 'InvalidClientTokenId':
                raise Exception("Invalid AWS credentials. Please check your AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY in the .env file.")
            raise

    def search_events(self, query: str, hours: int = 24) -> Tuple[str, List[EventData]]:
        """Search for CloudTrail events based on a natural language query.
        
        Args:
            query: A natural language query
            hours: Time window in hours to search
            
        Returns:
            Tuple containing:
            - Formatted summary string
            - List of raw event dictionaries
        """
        # Use ChatGPT to translate the natural language query
        insights_query = self.query_helper.generate_query(query, hours=hours)
        if not insights_query:
            return "Error translating query. Please try rephrasing your question.", []
        
        # Calculate time range
        end_time = int(datetime.now().timestamp() * 1000)
        start_time = int((datetime.now() - timedelta(hours=hours)).timestamp() * 1000)
        
        # Execute the query
        try:
            response = self.client.start_query(
                logGroupName=self.log_group,
                startTime=start_time,
                endTime=end_time,
                queryString=insights_query
            )
            query_id = response['queryId']
            
            # Wait for query to complete
            status = 'Running'
            while status == 'Running':
                result = self.client.get_query_results(queryId=query_id)
                status = result['status']
            
            # Format the results
            formatted_results: List[EventData] = []
            for result in result.get('results', []):
                try:
                    # Extract fields from CloudWatch Logs Insights results
                    event_data: Dict[str, Any] = {}
                    for field in result:
                        if 'field' in field and 'value' in field:
                            event_data[field['field']] = field['value']
                    
                    # Parse the message JSON
                    message_str = event_data.get('@message', '{}')
                    try:
                        message = json.loads(message_str)
                    except json.JSONDecodeError:
                        continue
                    
                    # Extract timestamp and format it
                    timestamp = event_data.get('@timestamp', 0)
                    try:
                        if isinstance(timestamp, (int, str)) and str(timestamp).isdigit():
                            dt = datetime.fromtimestamp(int(timestamp)/1000)
                        else:
                            dt = datetime.fromisoformat(str(timestamp).replace('Z', '+00:00'))
                        formatted_time = dt.strftime('%Y-%m-%d %I:%M %p')  # 12-hour format with AM/PM
                    except (ValueError, TypeError, AttributeError):
                        formatted_time = datetime.now().strftime('%Y-%m-%d %I:%M %p')
                    
                    # Double-check that the event is within the specified time window
                    event_time = int(timestamp) if isinstance(timestamp, (int, str)) and str(timestamp).isdigit() else int(dt.timestamp() * 1000)
                    if event_time < start_time or event_time > end_time:
                        continue  # Skip events outside the time window
                    
                    # Extract user information
                    user_identity = message.get('userIdentity', {})
                    username = "Unknown"
                    
                    if isinstance(user_identity, dict):
                        if 'userName' in user_identity:
                            username = user_identity['userName']
                        elif 'principalId' in user_identity:
                            username = user_identity['principalId']
                        elif 'type' in user_identity:
                            username = f"{user_identity['type']} User"
                    
                    # Extract event information
                    event_name = message.get('eventName', 'Unknown')
                    source_ip = message.get('sourceIPAddress', 'Unknown')
                    
                    # Extract error information
                    error_code = message.get('errorCode', '')
                    error_message = message.get('errorMessage', '')
                    
                    # Extract resource information
                    request_params = message.get('requestParameters', {}) or {}
                    resource_name = 'Unknown'
                    
                    # Try to extract resource name based on event type
                    if request_params:
                        # Common resource fields
                        resource_fields = {
                            'bucketName': 'S3 Bucket',
                            'BucketName': 'S3 Bucket',
                            'instanceId': 'EC2 Instance',
                            'functionName': 'Lambda Function',
                            'roleName': 'IAM Role',
                            'userName': 'IAM User',
                            'groupName': 'Security Group',
                            'clusterName': 'ECS Cluster',
                            'tableName': 'DynamoDB Table',
                            'queueName': 'SQS Queue',
                            'topicName': 'SNS Topic',
                            'logGroupName': 'CloudWatch Log Group',
                            'distributionId': 'CloudFront Distribution',
                            'loadBalancerName': 'Load Balancer',
                            'autoScalingGroupName': 'Auto Scaling Group',
                            'dbInstanceIdentifier': 'RDS Instance',
                            'cacheClusterId': 'ElastiCache Cluster',
                            'streamName': 'Kinesis Stream',
                            'domainName': 'Route 53 Domain',
                            'certificateId': 'ACM Certificate',
                            'keyId': 'KMS Key',
                            'secretId': 'Secrets Manager Secret',
                            'parameterName': 'Systems Manager Parameter',
                            'repositoryName': 'ECR Repository',
                            'clusterName': 'EKS Cluster',
                            'taskDefinition': 'ECS Task Definition',
                            'serviceName': 'ECS Service',
                            'apiId': 'API Gateway',
                            'restApiId': 'API Gateway',
                            'stageName': 'API Gateway Stage',
                            'functionName': 'Lambda Function',
                            'ruleName': 'EventBridge Rule',
                            'queueUrl': 'SQS Queue',
                            'topicArn': 'SNS Topic',
                            'bucketName': 'S3 Bucket',
                            'objectKey': 'S3 Object'
                        }
                        
                        for field, resource_type in resource_fields.items():
                            if field in request_params:
                                resource_name = f"{resource_type}: {request_params[field]}"
                                break
                    
                    # Create formatted event data
                    formatted_event: EventData = {
                        'timestamp': formatted_time,
                        'event_name': event_name,
                        'source_ip': source_ip,
                        'resource': resource_name,
                        'request_parameters': request_params,
                        'response_elements': message.get('responseElements', {}),
                        'user': username,  # Add user information to the formatted results
                        'errorCode': error_code,  # Add error information
                        'errorMessage': error_message
                    }
                    
                    formatted_results.append(formatted_event)
                    
                except Exception:
                    continue
            
            # Format the results using ChatGPT
            summary = self.query_helper.format_results(formatted_results)
            return summary, formatted_results
            
        except Exception:
            return "Error executing query. Please try again.", []

    def list_iam_users(self) -> List[UserInfo]:
        """Get a list of IAM users.
        
        Returns:
            List of dictionaries containing user information
        """
        try:
            users: List[UserInfo] = []
            paginator = self.iam_client.get_paginator('list_users')
            
            for page in paginator.paginate():
                for user in page['Users']:
                    users.append({
                        'username': user['UserName'],
                        'arn': user['Arn']
                    })
            
            return users
        except botocore.exceptions.ClientError as e:
            if e.response['Error']['Code'] == 'InvalidClientTokenId':
                raise Exception("Invalid AWS credentials. Please check your AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY in the .env file.")
            raise Exception(f"Error listing IAM users: {str(e)}")

    def get_user_events(self, username: str, hours: int = 24) -> List[EventData]:
        """Get events for a specific user within the last N hours.
        
        Args:
            username: IAM username to search for
            hours: Time window in hours to search
            
        Returns:
            List of event dictionaries
        """
        try:
            end_time = int(datetime.now().timestamp() * 1000)
            start_time = int((datetime.now() - timedelta(hours=hours)).timestamp() * 1000)
            
            query = f"""
            fields @timestamp, @message
            | filter @message like /{username}/
            | sort @timestamp desc
            """
            
            results = self.run_insights_query(query, start_time, end_time)
            
            # Format the results similar to search_events
            formatted_results: List[EventData] = []
            for result in results:
                try:
                    # Extract fields from CloudWatch Logs Insights results
                    event_data: Dict[str, Any] = {}
                    for field in result:
                        if 'field' in field and 'value' in field:
                            event_data[field['field']] = field['value']
                    
                    # Parse the message JSON
                    message_str = event_data.get('@message', '{}')
                    message = json.loads(message_str)
                    
                    # Extract timestamp and format it
                    timestamp = event_data.get('@timestamp', 0)
                    try:
                        if isinstance(timestamp, (int, str)) and str(timestamp).isdigit():
                            dt = datetime.fromtimestamp(int(timestamp)/1000)
                        else:
                            dt = datetime.fromisoformat(str(timestamp).replace('Z', '+00:00'))
                        formatted_time = dt.strftime('%Y-%m-%d %I:%M %p')  # 12-hour format with AM/PM
                    except (ValueError, TypeError, AttributeError):
                        formatted_time = datetime.now().strftime('%Y-%m-%d %I:%M %p')
                    
                    # Extract event information
                    event_name = message.get('eventName', 'Unknown')
                    source_ip = message.get('sourceIPAddress', 'Unknown')
                    
                    # Extract resource information
                    request_params = message.get('requestParameters', {})
                    resource_name = 'Unknown'
                    
                    # Try to extract resource name based on event type
                    if request_params:  # Check if request_params is not None
                        if 'bucketName' in request_params:
                            resource_name = request_params['bucketName']
                        elif 'BucketName' in request_params:
                            resource_name = request_params['BucketName']
                        elif 'instanceId' in request_params:
                            resource_name = request_params['instanceId']
                        elif 'userName' in request_params:
                            resource_name = request_params['userName']
                        elif 'roleName' in request_params:
                            resource_name = request_params['roleName']
                        elif 'functionName' in request_params:
                            resource_name = request_params['functionName']
                    
                    formatted_results.append({
                        'timestamp': formatted_time,
                        'event_name': event_name,
                        'source_ip': source_ip,
                        'resource': resource_name,
                        'request_parameters': request_params,
                        'response_elements': message.get('responseElements', {})
                    })
                except Exception as e:
                    print(f"Error parsing event: {str(e)}")
                    continue
            
            return formatted_results
        except Exception as e:
            raise Exception(f"Error getting user events: {str(e)}")

    def list_sso_users(self) -> List[SSOUserInfo]:
        """Get a list of SSO users from the users.json file.
        
        Returns:
            List of dictionaries containing SSO user information
        """
        try:
            users: List[SSOUserInfo] = []
            # Read users from the users.json file
            with open('users.json', 'r') as f:
                data = json.loads(f.read())
                for user in data.get('Users', []):
                    users.append({
                        'username': user['UserName'],
                        'user_id': user['UserId'],
                        'display_name': user.get('DisplayName', user['UserName']),
                        'email': user.get('Emails', [{}])[0].get('Value', '')
                    })
            
            return users
        except Exception as e:
            raise Exception(f"Error reading SSO users from file: {str(e)}")

    def get_sso_user_events(self, username: str, hours: int = 24) -> List[EventData]:
        """Get events for a specific SSO user within the last N hours.
        
        Args:
            username: SSO username to search for
            hours: Time window in hours to search
            
        Returns:
            List of event dictionaries
        """
        try:
            end_time = int(datetime.now().timestamp() * 1000)
            start_time = int((datetime.now() - timedelta(hours=hours)).timestamp() * 1000)
            
            # SSO users typically appear in CloudTrail with their email or username
            query = f"""
            fields @timestamp, @message
            | filter @message like /{username}/
            | sort @timestamp desc
            """
            
            results = self.run_insights_query(query, start_time, end_time)
            
            # Format the results similar to get_user_events
            formatted_results: List[EventData] = []
            for result in results:
                try:
                    # Extract fields from CloudWatch Logs Insights results
                    event_data: Dict[str, Any] = {}
                    for field in result:
                        if 'field' in field and 'value' in field:
                            event_data[field['field']] = field['value']
                    
                    # Parse the message JSON
                    message_str = event_data.get('@message', '{}')
                    message = json.loads(message_str)
                    
                    # Extract timestamp and format it
                    timestamp = event_data.get('@timestamp', 0)
                    try:
                        if isinstance(timestamp, (int, str)) and str(timestamp).isdigit():
                            dt = datetime.fromtimestamp(int(timestamp)/1000)
                        else:
                            dt = datetime.fromisoformat(str(timestamp).replace('Z', '+00:00'))
                        formatted_time = dt.strftime('%Y-%m-%d %I:%M %p')  # 12-hour format with AM/PM
                    except (ValueError, TypeError, AttributeError):
                        formatted_time = datetime.now().strftime('%Y-%m-%d %I:%M %p')
                    
                    # Extract event information
                    event_name = message.get('eventName', 'Unknown')
                    source_ip = message.get('sourceIPAddress', 'Unknown')
                    
                    # Extract resource information
                    request_params = message.get('requestParameters', {})
                    resource_name = 'Unknown'
                    
                    # Try to extract resource name based on event type
                    if request_params:  # Check if request_params is not None
                        if 'bucketName' in request_params:
                            resource_name = request_params['bucketName']
                        elif 'BucketName' in request_params:
                            resource_name = request_params['BucketName']
                        elif 'instanceId' in request_params:
                            resource_name = request_params['instanceId']
                        elif 'userName' in request_params:
                            resource_name = request_params['userName']
                        elif 'roleName' in request_params:
                            resource_name = request_params['roleName']
                        elif 'functionName' in request_params:
                            resource_name = request_params['functionName']
                    
                    formatted_results.append({
                        'timestamp': formatted_time,
                        'event_name': event_name,
                        'source_ip': source_ip,
                        'resource': resource_name,
                        'request_parameters': request_params,
                        'response_elements': message.get('responseElements', {})
                    })
                except Exception as e:
                    print(f"Error parsing event: {str(e)}")
                    continue
            
            return formatted_results
        except Exception as e:
            raise Exception(f"Error getting SSO user events: {str(e)}")



if __name__ == "__main__":
    cloudtrail_helper = CloudTrailHelper()
    cloudtrail_helper.run_insights_query(
        "fields @timestamp, @message | filter @message like /jason.davis/",
        'sdf',
        'sdf'
    )