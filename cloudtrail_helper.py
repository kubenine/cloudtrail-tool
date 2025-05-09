import boto3
import time
from datetime import datetime, timedelta
import pandas as pd
import botocore.exceptions
import os
import json
from query_helper import QueryHelper

class CloudTrailHelper:
    def __init__(self, log_group="/aws/cloudtrail"):
        # Get credentials from environment variables
        aws_access_key = os.getenv('AWS_ACCESS_KEY_ID')
        aws_secret_key = os.getenv('AWS_SECRET_ACCESS_KEY')
        aws_region = os.getenv('AWS_DEFAULT_REGION')
        session_token = os.getenv('AWS_SESSION_TOKEN')
        
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
            
        self.log_group = log_group
        self.query_helper = QueryHelper()
    
    def run_insights_query(self, query: str, start_time: int, end_time: int) -> list[dict] | None:
        """Run a CloudWatch Logs Insights query and return the results."""
        # Exceptions:
        # - botocore.exceptions.ClientError: When AWS credentials are invalid
        # - Exception: For other errors
        """Run a CloudWatch Logs Insights query and return the results."""
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

    def search_events(self, query, hours=24):
        """
        Search for CloudTrail events based on a natural language query.
        
        Args:
            query (str): A natural language query
            hours (int): Time window in hours to search
            
        Returns:
            tuple: (formatted_summary, raw_events)
        """
        # Use ChatGPT to translate the natural language query
        insights_query = self.query_helper.translate_to_cloudtrail_query(query)
        if not insights_query:
            return "Error translating query. Please try rephrasing your question.", []
        
        # Log the generated query
        print("\n=== Generated CloudWatch Logs Insights Query ===")
        print(f"Natural Language Query: {query}")
        print("Generated Query:")
        print(insights_query)
        print("=============================================\n")
        
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
            formatted_results = []
            for result in result.get('results', []):
                try:
                    # Extract fields from CloudWatch Logs Insights results
                    event_data = {}
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
                    
                    # Double-check that the event is within the specified time window
                    event_time = int(timestamp) if isinstance(timestamp, (int, str)) and str(timestamp).isdigit() else int(dt.timestamp() * 1000)
                    if event_time < start_time or event_time > end_time:
                        continue  # Skip events outside the time window
                    
                    # Extract user information
                    user_identity = message.get('userIdentity', {})
                    username = user_identity.get('userName', 'Unknown')
                    user_type = user_identity.get('type', 'Unknown')
                    
                    # Handle SSO users
                    if user_type == 'SSOUser':
                        # Try to get display name from SSO user data
                        try:
                            with open('users.json', 'r') as f:
                                sso_users = json.loads(f.read())
                                for user in sso_users.get('Users', []):
                                    if user['UserName'] == username:
                                        username = f"{user.get('DisplayName', username)} ({username})"
                                        break
                        except Exception:
                            pass
                    elif username == 'Unknown' and 'arn' in user_identity:
                        arn_parts = user_identity['arn'].split('/')
                        if len(arn_parts) > 1:
                            username = arn_parts[-1]
                    
                    # Extract event information
                    event_name = message.get('eventName', 'Unknown')
                    source_ip = message.get('sourceIPAddress', 'Unknown')
                    
                    # Extract resource information
                    request_params = message.get('requestParameters', {})
                    resource_name = 'Unknown'
                    resource_details = {}
                    
                    # Try to extract resource name and details based on event type
                    if request_params:
                        # Common resource fields
                        resource_fields = {
                            'bucketName': 'S3 Bucket',
                            'instanceId': 'EC2 Instance',
                            'functionName': 'Lambda Function',
                            'roleName': 'IAM Role',
                            'userName': 'IAM User',
                            'groupName': 'Security Group',
                            'clusterName': 'ECS Cluster',
                            'tableName': 'DynamoDB Table',
                            'queueName': 'SQS Queue',
                            'topicName': 'SNS Topic'
                        }
                        
                        for field, resource_type in resource_fields.items():
                            if field in request_params:
                                resource_name = f"{resource_type}: {request_params[field]}"
                                resource_details[field] = request_params[field]
                                break
                        
                        # If no common field found, try to extract any meaningful resource information
                        if resource_name == 'Unknown':
                            for key, value in request_params.items():
                                if isinstance(value, str) and len(value) > 3:
                                    resource_name = f"{key}: {value}"
                                    resource_details[key] = value
                                    break
                    
                    formatted_results.append({
                        'timestamp': formatted_time,
                        'user': username,
                        'user_type': user_type,
                        'source_ip': source_ip,
                        'event_type': event_name,
                        'resource': resource_name,
                        'resource_details': resource_details,
                        'request_parameters': request_params
                    })
                except Exception as e:
                    print(f"Error parsing event: {str(e)}")
                    continue
            
            # Use ChatGPT to format the results into a natural language summary
            summary = self.query_helper.format_results(formatted_results)
            
            return summary, formatted_results
        except Exception as e:
            print(f"Error executing query: {str(e)}")
            return "Error executing query. Please try again.", []

    def list_iam_users(self):
        """Get a list of IAM users."""
        try:
            users = []
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

    def get_user_events(self, username, hours=24):
        """Get events for a specific user within the last N hours."""
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
            formatted_results = []
            for result in results:
                try:
                    # Extract fields from CloudWatch Logs Insights results
                    event_data = {}
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

    def list_sso_users(self):
        """Get a list of SSO users from the users.json file."""
        try:
            users = []
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

    def get_sso_user_events(self, username, hours=24):
        """Get events for a specific SSO user within the last N hours."""
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
            formatted_results = []
            for result in results:
                try:
                    # Extract fields from CloudWatch Logs Insights results
                    event_data = {}
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