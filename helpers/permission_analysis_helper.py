import boto3
from typing import Dict, List, Any
import pandas as pd
from datetime import datetime, timedelta

class PermissionAnalysisHelper:
    def __init__(self, session: boto3.Session):
        """Initialize the PermissionAnalysisHelper with AWS session."""
        self.session = session
        self.iam_client = session.client('iam')
        self.cloudtrail_client = session.client('cloudtrail')

    def get_user_permissions(self, username: str) -> Dict[str, Any]:
        """Get all permissions associated with a user."""
        try:
            # Get user's attached policies
            attached_policies = self.iam_client.list_attached_user_policies(UserName=username)
            inline_policies = self.iam_client.list_user_policies(UserName=username)
            
            # Get user's groups and their policies
            groups = self.iam_client.list_groups_for_user(UserName=username)
            
            permissions = {
                'attached_policies': attached_policies['AttachedPolicies'],
                'inline_policies': inline_policies['PolicyNames'],
                'groups': groups['Groups']
            }
            
            return permissions
        except Exception as e:
            print(f"Error getting permissions for user {username}: {str(e)}")
            return {}

    def analyze_unused_permissions(self, username: str, days: int = 90) -> Dict[str, List[str]]:
        """Analyze permissions that haven't been used in the specified time period."""
        try:
            # Get user's permissions
            permissions = self.get_user_permissions(username)
            
            # Get user's CloudTrail events
            start_time = datetime.now() - timedelta(days=days)
            
            used_actions = set()
            
            # Populate used_actions from CloudTrail events
            try:
                response = self.cloudtrail_client.lookup_events(
                    StartTime=start_time,
                    EndTime=datetime.now(),
                    LookupAttributes=[
                        {
                            'AttributeKey': 'Username',
                            'AttributeValue': username
                        }
                    ]
                )
                
                for event in response['Events']:
                    # Extract action from event name (e.g., "CreateBucket" -> "s3:CreateBucket")
                    event_name = event['EventName']
                    event_source = event.get('EventSource', '').replace('.amazonaws.com', '')
                    if event_source:
                        action = f"{event_source}:{event_name}"
                        used_actions.add(action)
                        used_actions.add(event_name)  # Also add without service prefix
            except Exception as e:
                print(f"Warning: Could not retrieve CloudTrail events for {username}: {str(e)}")
            
            unused_permissions = []
            
            # Analyze each policy
            for policy in permissions['attached_policies']:
                try:
                    policy_details = self.iam_client.get_policy(PolicyArn=policy['PolicyArn'])
                    policy_version = self.iam_client.get_policy_version(
                        PolicyArn=policy['PolicyArn'],
                        VersionId=policy_details['Policy']['DefaultVersionId']
                    )
                    
                    # Handle both single statement (dict) and multiple statements (list)
                    statements = policy_version['PolicyVersion']['Document']['Statement']
                    if isinstance(statements, dict):
                        statements = [statements]
                    
                    # Compare policy permissions with used actions
                    for statement in statements:
                        if 'Action' in statement:
                            actions = statement['Action']
                            if isinstance(actions, str):
                                actions = [actions]
                            
                            for action in actions:
                                if action not in used_actions and action != '*':
                                    unused_permissions.append(action)
                except Exception as e:
                    print(f"Error analyzing policy {policy['PolicyArn']}: {str(e)}")
            
            return {
                'unused_permissions': list(set(unused_permissions)),  # Remove duplicates
                'days_analyzed': days
            }
        except Exception as e:
            print(f"Error analyzing unused permissions: {str(e)}")
            return {'unused_permissions': [], 'days_analyzed': days}

    def check_overprivileged_accounts(self) -> List[Dict[str, Any]]:
        """Identify potentially over-privileged accounts based on policy analysis."""
        try:
            users = self.iam_client.list_users()['Users']
            overprivileged = []
            
            for user in users:
                user_permissions = self.get_user_permissions(user['UserName'])
                
                # Check for admin access or high-risk permissions
                for policy in user_permissions['attached_policies']:
                    if 'AdministratorAccess' in policy['PolicyName']:
                        overprivileged.append({
                            'username': user['UserName'],
                            'reason': 'Has AdministratorAccess policy',
                            'risk_level': 'High'
                        })
                
            return overprivileged
        except Exception as e:
            print(f"Error checking over-privileged accounts: {str(e)}")
            return []

    def track_permission_changes(self, days: int = 30) -> pd.DataFrame:
        """Track permission changes over time."""
        try:
            end_time = datetime.now()
            start_time = end_time - timedelta(days=days)
            
            response = self.cloudtrail_client.lookup_events(
                StartTime=start_time,
                EndTime=end_time,
                LookupAttributes=[
                    {
                        'AttributeKey': 'EventName',
                        'AttributeValue': 'AttachUserPolicy'
                    }
                ]
            )
            
            changes = []
            for event in response['Events']:
                changes.append({
                    'timestamp': event['EventTime'],
                    'username': event['Username'],
                    'event_name': event['EventName'],
                    'resources': event['Resources']
                })
            
            return pd.DataFrame(changes)
        except Exception as e:
            print(f"Error tracking permission changes: {str(e)}")
            return pd.DataFrame() 