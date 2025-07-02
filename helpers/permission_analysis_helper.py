import boto3
from typing import Dict, List, Any, Tuple, Optional
import pandas as pd
from datetime import datetime, timedelta
import json
import os
from openai import OpenAI
from utils import token_counter

class PermissionAnalysisHelper:
    def __init__(self, session: boto3.Session):
        """Initialize the PermissionAnalysisHelper with AWS session."""
        self.session = session
        self.iam_client = session.client('iam')
        self.cloudtrail_client = session.client('cloudtrail')
        
        # Initialize OpenAI client for risk assessment
        self.openai_client = None
        if os.getenv('OPENAI_API_KEY'):
            self.openai_client = OpenAI(api_key=os.getenv('OPENAI_API_KEY'))
        
        # Define high-risk permissions and actions
        self.high_risk_permissions = {
            'iam:*': 'Full IAM access - can modify all permissions',
            'iam:CreateUser': 'Can create new users',
            'iam:CreateRole': 'Can create new roles',
            'iam:AttachUserPolicy': 'Can attach policies to users',
            'iam:AttachRolePolicy': 'Can attach policies to roles',
            'iam:PutUserPolicy': 'Can create inline policies for users',
            'iam:PutRolePolicy': 'Can create inline policies for roles',
            'iam:DeleteUser': 'Can delete users',
            'iam:DeleteRole': 'Can delete roles',
            'sts:AssumeRole': 'Can assume other roles',
            'ec2:*': 'Full EC2 access - can launch/terminate instances',
            's3:*': 'Full S3 access - can read/write all buckets',
            'rds:*': 'Full RDS access - can modify databases',
            'lambda:*': 'Full Lambda access - can execute code',
            'cloudformation:*': 'Full CloudFormation access - can deploy infrastructure',
            'cloudtrail:*': 'Full CloudTrail access - can disable logging',
            'kms:*': 'Full KMS access - can access encrypted data',
            'secretsmanager:*': 'Full Secrets Manager access - can read secrets',
            'ssm:*': 'Full Systems Manager access - can execute commands',
            'organizations:*': 'Full Organizations access - can modify account structure'
        }
        
        # Define critical AWS managed policies
        self.critical_policies = {
            'AdministratorAccess': 'Full access to all AWS services',
            'PowerUserAccess': 'Full access except IAM and Organizations',
            'IAMFullAccess': 'Full access to IAM',
            'SecurityAudit': 'Read-only access for security auditing',
            'ReadOnlyAccess': 'Read-only access to all services'
        }

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

    def analyze_user_risk_profile(self, username: str) -> Dict[str, Any]:
        """Perform comprehensive risk analysis for a specific user."""
        try:
            risk_profile = {
                'username': username,
                'overall_risk_score': 0,
                'risk_level': 'Low',
                'high_risk_permissions': [],
                'critical_policies': [],
                'unused_permissions': [],
                'access_patterns': {},
                'recommendations': [],
                'policy_details': {},
                'group_inherited_risks': [],
                'last_activity': None,
                'console_access': False,
                'mfa_enabled': False,
                'access_keys': [],
                'detailed_analysis': ''
            }
            
            # Get user basic info
            try:
                user_info = self.iam_client.get_user(UserName=username)
                risk_profile['user_created'] = user_info['User']['CreateDate']
            except Exception:
                pass
            
            # Check console access
            try:
                self.iam_client.get_login_profile(UserName=username)
                risk_profile['console_access'] = True
            except Exception:
                risk_profile['console_access'] = False
            
            # Check MFA status
            try:
                mfa_devices = self.iam_client.list_mfa_devices(UserName=username)
                risk_profile['mfa_enabled'] = len(mfa_devices['MFADevices']) > 0
            except Exception:
                risk_profile['mfa_enabled'] = False
            
            # Get access keys
            try:
                access_keys = self.iam_client.list_access_keys(UserName=username)
                for key in access_keys['AccessKeyMetadata']:
                    key_age = (datetime.now().replace(tzinfo=None) - key['CreateDate'].replace(tzinfo=None)).days
                    risk_profile['access_keys'].append({
                        'access_key_id': key['AccessKeyId'],
                        'status': key['Status'],
                        'age_days': key_age,
                        'needs_rotation': key_age > 90
                    })
            except Exception:
                pass
            
            # Get user permissions
            permissions = self.get_user_permissions(username)
            risk_profile['policy_details'] = permissions
            
            # Analyze attached policies
            risk_score = 0
            for policy in permissions['attached_policies']:
                policy_name = policy['PolicyName']
                policy_arn = policy['PolicyArn']
                
                # Check if it's a critical AWS managed policy
                if policy_name in self.critical_policies:
                    risk_profile['critical_policies'].append({
                        'name': policy_name,
                        'description': self.critical_policies[policy_name],
                        'arn': policy_arn
                    })
                    
                    # Assign risk scores based on policy criticality
                    if policy_name == 'AdministratorAccess':
                        risk_score += 50
                    elif policy_name == 'PowerUserAccess':
                        risk_score += 35
                    elif policy_name == 'IAMFullAccess':
                        risk_score += 40
                    else:
                        risk_score += 20
                
                # Analyze policy permissions
                try:
                    policy_details = self.iam_client.get_policy(PolicyArn=policy_arn)
                    policy_version = self.iam_client.get_policy_version(
                        PolicyArn=policy_arn,
                        VersionId=policy_details['Policy']['DefaultVersionId']
                    )
                    
                    statements = policy_version['PolicyVersion']['Document']['Statement']
                    if isinstance(statements, dict):
                        statements = [statements]
                    
                    for statement in statements:
                        if statement.get('Effect') == 'Allow' and 'Action' in statement:
                            actions = statement['Action']
                            if isinstance(actions, str):
                                actions = [actions]
                            
                            for action in actions:
                                if action in self.high_risk_permissions:
                                    risk_profile['high_risk_permissions'].append({
                                        'action': action,
                                        'description': self.high_risk_permissions[action],
                                        'policy': policy_name
                                    })
                                    risk_score += 10
                                elif action == '*':
                                    risk_profile['high_risk_permissions'].append({
                                        'action': '*',
                                        'description': 'Full access to all services and actions',
                                        'policy': policy_name
                                    })
                                    risk_score += 30
                except Exception as e:
                    print(f"Error analyzing policy {policy_arn}: {str(e)}")
            
            # Analyze group inherited permissions
            for group in permissions['groups']:
                group_name = group['GroupName']
                try:
                    group_policies = self.iam_client.list_attached_group_policies(GroupName=group_name)
                    for group_policy in group_policies['AttachedPolicies']:
                        if group_policy['PolicyName'] in self.critical_policies:
                            risk_profile['group_inherited_risks'].append({
                                'group': group_name,
                                'policy': group_policy['PolicyName'],
                                'description': self.critical_policies[group_policy['PolicyName']]
                            })
                            risk_score += 15
                except Exception:
                    pass
            
            # Additional risk factors
            if risk_profile['console_access'] and not risk_profile['mfa_enabled']:
                risk_score += 20
                risk_profile['recommendations'].append("Enable MFA for console access")
            
            if any(key['needs_rotation'] for key in risk_profile['access_keys']):
                risk_score += 10
                risk_profile['recommendations'].append("Rotate old access keys")
            
            if len(risk_profile['access_keys']) > 2:
                risk_score += 5
                risk_profile['recommendations'].append("Consider reducing number of access keys")
            
            # Get unused permissions
            unused_analysis = self.analyze_unused_permissions(username, days=90)
            risk_profile['unused_permissions'] = unused_analysis['unused_permissions']
            
            if len(risk_profile['unused_permissions']) > 10:
                risk_score += 15
                risk_profile['recommendations'].append("Remove unused permissions to follow principle of least privilege")
            
            # Determine risk level
            risk_profile['overall_risk_score'] = min(risk_score, 100)
            
            if risk_score >= 70:
                risk_profile['risk_level'] = 'Critical'
            elif risk_score >= 50:
                risk_profile['risk_level'] = 'High'
            elif risk_score >= 30:
                risk_profile['risk_level'] = 'Medium'
            else:
                risk_profile['risk_level'] = 'Low'
            
            # Generate AI-powered detailed analysis if OpenAI is available
            if self.openai_client:
                risk_profile['detailed_analysis'] = self._generate_ai_risk_analysis(risk_profile)
            
            return risk_profile
            
        except Exception as e:
            print(f"Error analyzing user risk profile: {str(e)}")
            return {}

    def _generate_ai_risk_analysis(self, risk_profile: Dict[str, Any]) -> str:
        """Generate AI-powered detailed risk analysis."""
        try:
            if not self.openai_client:
                return "AI analysis unavailable: OpenAI API key not configured"
                
            # Prepare data for AI analysis
            user_summary = {
                'username': risk_profile['username'],
                'risk_score': risk_profile['overall_risk_score'],
                'risk_level': risk_profile['risk_level'],
                'console_access': risk_profile['console_access'],
                'mfa_enabled': risk_profile['mfa_enabled'],
                'critical_policies': [p['name'] for p in risk_profile['critical_policies']],
                'high_risk_permissions': [p['action'] for p in risk_profile['high_risk_permissions']],
                'access_keys_count': len(risk_profile['access_keys']),
                'old_keys': sum(1 for key in risk_profile['access_keys'] if key['needs_rotation']),
                'unused_permissions_count': len(risk_profile['unused_permissions'])
            }
            
            prompt = f"""
            As a cloud security expert, analyze this AWS IAM user's risk profile and provide a comprehensive assessment:

            User: {user_summary['username']}
            Risk Score: {user_summary['risk_score']}/100
            Risk Level: {user_summary['risk_level']}
            Console Access: {user_summary['console_access']}
            MFA Enabled: {user_summary['mfa_enabled']}
            Critical Policies: {user_summary['critical_policies']}
            High-Risk Permissions: {user_summary['high_risk_permissions'][:10]}  # First 10 to avoid token limits
            Access Keys: {user_summary['access_keys_count']} total, {user_summary['old_keys']} need rotation
            Unused Permissions: {user_summary['unused_permissions_count']} found

            Please provide:
            1. **Risk Summary**: Brief overview of the main security concerns
            2. **Key Vulnerabilities**: Top 3-5 specific security risks
            3. **Impact Assessment**: Potential damage if this account is compromised
            4. **Immediate Actions**: Priority steps to reduce risk
            5. **Long-term Recommendations**: Strategic improvements for better security posture

            Keep the response concise but comprehensive, focusing on actionable insights.
            """
            
            response = self.openai_client.chat.completions.create(
                model="gpt-4",
                messages=[
                    {"role": "system", "content": "You are a cloud security expert specializing in AWS IAM risk assessment. Provide clear, actionable security recommendations."},
                    {"role": "user", "content": prompt}
                ],
                max_tokens=1000,
                temperature=0.3
            )
            
            # Update token counter
            token_counter.update_from_response(response)
            
            return response.choices[0].message.content
            
        except Exception as e:
            return f"AI analysis unavailable: {str(e)}"

    def generate_risk_summary_report(self, usernames: Optional[List[str]] = None) -> Dict[str, Any]:
        """Generate a comprehensive risk summary for multiple users or all users."""
        try:
            if usernames is None:
                users = self.iam_client.list_users()['Users']
                usernames = [user['UserName'] for user in users]
            
            risk_summary = {
                'total_users': len(usernames),
                'risk_distribution': {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0},
                'high_risk_users': [],
                'common_vulnerabilities': [],
                'overall_security_score': 0,
                'recommendations': []
            }
            
            total_risk_score = 0
            all_vulnerabilities = []
            
            for username in usernames:
                user_risk = self.analyze_user_risk_profile(username)
                if user_risk:
                    risk_level = user_risk['risk_level']
                    risk_summary['risk_distribution'][risk_level] += 1
                    total_risk_score += user_risk['overall_risk_score']
                    
                    if risk_level in ['Critical', 'High']:
                        risk_summary['high_risk_users'].append({
                            'username': username,
                            'risk_level': risk_level,
                            'risk_score': user_risk['overall_risk_score'],
                            'key_issues': user_risk['recommendations'][:3]
                        })
                    
                    # Collect vulnerabilities for analysis
                    all_vulnerabilities.extend(user_risk['recommendations'])
            
            # Calculate overall security score
            if len(usernames) > 0:
                avg_risk_score = total_risk_score / len(usernames)
                risk_summary['overall_security_score'] = max(0, 100 - avg_risk_score)
            
            # Identify common vulnerabilities
            vulnerability_counts = {}
            for vuln in all_vulnerabilities:
                vulnerability_counts[vuln] = vulnerability_counts.get(vuln, 0) + 1
            
            risk_summary['common_vulnerabilities'] = sorted(
                vulnerability_counts.items(), 
                key=lambda x: x[1], 
                reverse=True
            )[:5]
            
            return risk_summary
            
        except Exception as e:
            print(f"Error generating risk summary: {str(e)}")
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