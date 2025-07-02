import boto3
from typing import Dict, List, Any
import pandas as pd
from datetime import datetime, timedelta
import json
import os

class PermissionAnalysisHelper:
    def __init__(self, session):
        """Initialize the PermissionAnalysisHelper with AWS session."""
        self.session = session
        self.iam = session.client('iam')
        self.cloudtrail = session.client('cloudtrail')
        # Fix for linter - assign the client attributes correctly
        self.iam_client = self.iam
        self.cloudtrail_client = self.cloudtrail

    def analyze_all_user_permissions(self) -> Dict[str, Any]:
        """Analyze permissions for all users with detailed policy summaries."""
        try:
            users = self.iam_client.list_users()['Users']
            user_analyses = []
            summary_stats = {
                'total_users': len(users),
                'users_with_admin_access': 0,
                'users_with_custom_policies': 0,
                'total_attached_policies': 0,
                'total_inline_policies': 0,
                'high_risk_users': 0,
                'medium_risk_users': 0,
                'low_risk_users': 0
            }
            
            for user in users:
                username = user['UserName']
                user_analysis = self._analyze_single_user_comprehensive(username)
                
                # Update summary stats
                if user_analysis['has_admin_access']:
                    summary_stats['users_with_admin_access'] += 1
                
                if user_analysis['inline_policies']:
                    summary_stats['users_with_custom_policies'] += 1
                
                summary_stats['total_attached_policies'] += len(user_analysis['attached_policies'])
                summary_stats['total_inline_policies'] += len(user_analysis['inline_policies'])
                
                # Risk categorization
                if user_analysis['risk_level'] == 'High':
                    summary_stats['high_risk_users'] += 1
                elif user_analysis['risk_level'] == 'Medium':
                    summary_stats['medium_risk_users'] += 1
                else:
                    summary_stats['low_risk_users'] += 1
                
                user_analyses.append(user_analysis)
            
            # Generate AI summary if OpenAI is available
            ai_summary = ""
            openai_api_key = os.getenv('OPENAI_API_KEY')
            if openai_api_key:
                ai_summary = self._generate_permission_summary(user_analyses, summary_stats)
            
            return {
                'timestamp': datetime.now().isoformat(),
                'summary_stats': summary_stats,
                'user_analyses': user_analyses,
                'ai_summary': ai_summary
            }
            
        except Exception as e:
            return {'error': f"Error analyzing all user permissions: {str(e)}"}

    def _analyze_single_user_comprehensive(self, username: str) -> Dict[str, Any]:
        """Comprehensive analysis of a single user's permissions."""
        try:
            # Get basic user info
            user_info = self.iam_client.get_user(UserName=username)
            
            # Get attached policies
            attached_policies_response = self.iam_client.list_attached_user_policies(UserName=username)
            attached_policies = []
            
            for policy in attached_policies_response['AttachedPolicies']:
                policy_details = self._analyze_policy(policy['PolicyArn'], policy['PolicyName'])
                attached_policies.append(policy_details)
            
            # Get inline policies
            inline_policies_response = self.iam_client.list_user_policies(UserName=username)
            inline_policies = []
            
            for policy_name in inline_policies_response['PolicyNames']:
                policy_doc = self.iam_client.get_user_policy(UserName=username, PolicyName=policy_name)
                policy_analysis = self._analyze_inline_policy(policy_doc['PolicyDocument'], policy_name)
                inline_policies.append(policy_analysis)
            
            # Get group memberships and their policies
            groups_response = self.iam_client.list_groups_for_user(UserName=username)
            group_policies = []
            
            for group in groups_response['Groups']:
                group_name = group['GroupName']
                
                # Get attached group policies
                group_attached = self.iam_client.list_attached_group_policies(GroupName=group_name)
                for policy in group_attached['AttachedPolicies']:
                    policy_details = self._analyze_policy(policy['PolicyArn'], policy['PolicyName'])
                    policy_details['inherited_from_group'] = group_name
                    group_policies.append(policy_details)
                
                # Get inline group policies
                group_inline = self.iam_client.list_group_policies(GroupName=group_name)
                for policy_name in group_inline['PolicyNames']:
                    policy_doc = self.iam_client.get_group_policy(GroupName=group_name, PolicyName=policy_name)
                    policy_analysis = self._analyze_inline_policy(policy_doc['PolicyDocument'], policy_name)
                    policy_analysis['inherited_from_group'] = group_name
                    group_policies.append(policy_analysis)
            
            # Determine risk level and capabilities
            has_admin_access = self._has_admin_access(attached_policies, inline_policies, group_policies)
            risk_level = self._determine_risk_level(attached_policies, inline_policies, group_policies)
            capabilities = self._extract_user_capabilities(attached_policies, inline_policies, group_policies)
            
            # Get user creation date
            creation_date = user_info['User']['CreateDate'].isoformat() if 'CreateDate' in user_info['User'] else 'Unknown'
            
            return {
                'username': username,
                'creation_date': creation_date,
                'attached_policies': attached_policies,
                'inline_policies': inline_policies,
                'group_policies': group_policies,
                'has_admin_access': has_admin_access,
                'risk_level': risk_level,
                'capabilities': capabilities,
                'total_policies': len(attached_policies) + len(inline_policies) + len(group_policies)
            }
            
        except Exception as e:
            return {
                'username': username,
                'error': f"Error analyzing user {username}: {str(e)}",
                'attached_policies': [],
                'inline_policies': [],
                'group_policies': [],
                'has_admin_access': False,
                'risk_level': 'Unknown',
                'capabilities': [],
                'total_policies': 0
            }

    def _analyze_policy(self, policy_arn: str, policy_name: str) -> Dict[str, Any]:
        """Analyze an AWS managed or customer managed policy."""
        try:
            # Get policy details
            policy_response = self.iam_client.get_policy(PolicyArn=policy_arn)
            policy = policy_response['Policy']
            
            # Get policy version
            policy_version = self.iam_client.get_policy_version(
                PolicyArn=policy_arn,
                VersionId=policy['DefaultVersionId']
            )
            
            policy_document = policy_version['PolicyVersion']['Document']
            
            # Analyze policy content
            analysis = self._analyze_policy_document(policy_document)
            
            return {
                'name': policy_name,
                'arn': policy_arn,
                'type': 'AWS Managed' if policy_arn.startswith('arn:aws:iam::aws:') else 'Customer Managed',
                'description': policy.get('Description', 'No description available'),
                'create_date': policy['CreateDate'].isoformat(),
                'update_date': policy['UpdateDate'].isoformat(),
                'version': policy['DefaultVersionId'],
                'analysis': analysis
            }
            
        except Exception as e:
            return {
                'name': policy_name,
                'arn': policy_arn,
                'error': f"Error analyzing policy: {str(e)}",
                'type': 'Unknown',
                'analysis': {}
            }

    def _analyze_inline_policy(self, policy_document: Dict, policy_name: str) -> Dict[str, Any]:
        """Analyze an inline policy."""
        try:
            analysis = self._analyze_policy_document(policy_document)
            
            return {
                'name': policy_name,
                'type': 'Inline Policy',
                'description': 'Custom inline policy',
                'analysis': analysis
            }
            
        except Exception as e:
            return {
                'name': policy_name,
                'type': 'Inline Policy',
                'error': f"Error analyzing inline policy: {str(e)}",
                'analysis': {}
            }

    def _analyze_policy_document(self, policy_document: Dict) -> Dict[str, Any]:
        """Analyze a policy document and extract meaningful information."""
        try:
            statements = policy_document.get('Statement', [])
            if isinstance(statements, dict):
                statements = [statements]
            
            analysis = {
                'total_statements': len(statements),
                'allows_actions': [],
                'denies_actions': [],
                'services_accessed': set(),
                'resource_types': set(),
                'has_wildcard_actions': False,
                'has_wildcard_resources': False,
                'conditional_access': False,
                'risk_indicators': []
            }
            
            for statement in statements:
                effect = statement.get('Effect', 'Allow')
                actions = statement.get('Action', [])
                resources = statement.get('Resource', [])
                conditions = statement.get('Condition', {})
                
                # Normalize actions to list
                if isinstance(actions, str):
                    actions = [actions]
                
                # Normalize resources to list
                if isinstance(resources, str):
                    resources = [resources]
                
                # Process actions
                for action in actions:
                    if effect == 'Allow':
                        analysis['allows_actions'].append(action)
                    else:
                        analysis['denies_actions'].append(action)
                    
                    # Check for wildcards
                    if '*' in action:
                        analysis['has_wildcard_actions'] = True
                        if action == '*':
                            analysis['risk_indicators'].append('Full administrative access (*)')
                    
                    # Extract service
                    if ':' in action:
                        service = action.split(':')[0]
                        analysis['services_accessed'].add(service)
                
                # Process resources
                for resource in resources:
                    if '*' in resource:
                        analysis['has_wildcard_resources'] = True
                    
                    # Extract resource type
                    if ':' in resource:
                        parts = resource.split(':')
                        if len(parts) >= 5:
                            resource_type = parts[5].split('/')[0] if '/' in parts[5] else parts[5]
                            analysis['resource_types'].add(resource_type)
                
                # Check for conditions
                if conditions:
                    analysis['conditional_access'] = True
            
            # Convert sets to lists for JSON serialization
            analysis['services_accessed'] = list(analysis['services_accessed'])
            analysis['resource_types'] = list(analysis['resource_types'])
            
            # Add risk assessment
            if analysis['has_wildcard_actions'] and analysis['has_wildcard_resources']:
                analysis['risk_indicators'].append('Broad permissions with wildcard actions and resources')
            
            if len(analysis['services_accessed']) > 10:
                analysis['risk_indicators'].append(f'Access to {len(analysis["services_accessed"])} different AWS services')
            
            return analysis
            
        except Exception as e:
            return {'error': f"Error analyzing policy document: {str(e)}"}

    def _has_admin_access(self, attached_policies: List, inline_policies: List, group_policies: List) -> bool:
        """Check if user has administrative access."""
        all_policies = attached_policies + inline_policies + group_policies
        
        for policy in all_policies:
            if 'analysis' in policy:
                analysis = policy['analysis']
                if '*' in analysis.get('allows_actions', []):
                    return True
                if 'AdministratorAccess' in policy.get('name', ''):
                    return True
        
        return False

    def _determine_risk_level(self, attached_policies: List, inline_policies: List, group_policies: List) -> str:
        """Determine user risk level based on permissions."""
        all_policies = attached_policies + inline_policies + group_policies
        
        high_risk_indicators = 0
        medium_risk_indicators = 0
        
        for policy in all_policies:
            if 'analysis' in policy:
                analysis = policy['analysis']
                risk_indicators = analysis.get('risk_indicators', [])
                
                # High risk checks
                if '*' in analysis.get('allows_actions', []):
                    high_risk_indicators += 1
                
                if analysis.get('has_wildcard_actions') and analysis.get('has_wildcard_resources'):
                    high_risk_indicators += 1
                
                if len(risk_indicators) > 2:
                    high_risk_indicators += 1
                
                # Medium risk checks
                if len(analysis.get('services_accessed', [])) > 5:
                    medium_risk_indicators += 1
                
                if policy.get('type') == 'Inline Policy':
                    medium_risk_indicators += 1
        
        if high_risk_indicators > 0:
            return 'High'
        elif medium_risk_indicators > 2:
            return 'Medium'
        else:
            return 'Low'

    def _extract_user_capabilities(self, attached_policies: List, inline_policies: List, group_policies: List) -> List[str]:
        """Extract high-level capabilities from user's policies."""
        all_policies = attached_policies + inline_policies + group_policies
        capabilities = set()
        
        service_capability_map = {
            'ec2': 'EC2 Instance Management',
            's3': 'S3 Storage Management',
            'iam': 'Identity and Access Management',
            'rds': 'Database Management',
            'lambda': 'Serverless Computing',
            'cloudformation': 'Infrastructure as Code',
            'cloudwatch': 'Monitoring and Logging',
            'ecs': 'Container Management',
            'eks': 'Kubernetes Management',
            'sqs': 'Message Queuing',
            'sns': 'Notifications',
            'dynamodb': 'NoSQL Database',
            'kms': 'Key Management',
            'secretsmanager': 'Secrets Management',
            'ssm': 'Systems Manager',
            'route53': 'DNS Management',
            'cloudfront': 'Content Delivery',
            'apigateway': 'API Management',
            'logs': 'Log Management'
        }
        
        for policy in all_policies:
            if 'analysis' in policy:
                analysis = policy['analysis']
                services = analysis.get('services_accessed', [])
                
                # Check for full admin access
                if '*' in analysis.get('allows_actions', []):
                    capabilities.add('Full Administrative Access')
                    continue
                
                # Map services to capabilities
                for service in services:
                    if service in service_capability_map:
                        capabilities.add(service_capability_map[service])
                
                # Check for specific high-level permissions
                actions = analysis.get('allows_actions', [])
                
                # Check for destructive actions
                destructive_actions = [action for action in actions if any(destructive in action.lower() 
                                     for destructive in ['delete', 'terminate', 'destroy'])]
                if destructive_actions:
                    capabilities.add('Resource Deletion/Termination')
                
                # Check for creation actions
                create_actions = [action for action in actions if any(create in action.lower() 
                                for create in ['create', 'run', 'launch'])]
                if create_actions:
                    capabilities.add('Resource Creation')
                
                # Check for policy management
                policy_actions = [action for action in actions if 'policy' in action.lower()]
                if policy_actions:
                    capabilities.add('Policy Management')
        
        return list(capabilities)

    def _generate_permission_summary(self, user_analyses: List, summary_stats: Dict) -> str:
        """Generate AI-powered summary of user permissions."""
        try:
            from openai import OpenAI
            client = OpenAI(api_key=os.getenv('OPENAI_API_KEY'))
            
            # Prepare data for AI analysis
            high_risk_users = [user for user in user_analyses if user['risk_level'] == 'High']
            users_with_admin = [user for user in user_analyses if user['has_admin_access']]
            custom_policy_users = [user for user in user_analyses if user['inline_policies']]
            
            prompt = f"""
            As an AWS security expert, analyze this IAM permission summary for {summary_stats['total_users']} users:

            SUMMARY STATISTICS:
            - Total Users: {summary_stats['total_users']}
            - Users with Admin Access: {summary_stats['users_with_admin_access']}
            - Users with Custom Policies: {summary_stats['users_with_custom_policies']}
            - Total Attached Policies: {summary_stats['total_attached_policies']}
            - Total Inline Policies: {summary_stats['total_inline_policies']}
            - High Risk Users: {summary_stats['high_risk_users']}
            - Medium Risk Users: {summary_stats['medium_risk_users']}
            - Low Risk Users: {summary_stats['low_risk_users']}

            HIGH RISK USERS:
            {chr(10).join([f"- {user['username']}: {len(user['capabilities'])} capabilities, {user['total_policies']} total policies" 
                          for user in high_risk_users[:10]])}

            USERS WITH ADMIN ACCESS:
            {chr(10).join([f"- {user['username']}: Created {user.get('creation_date', 'Unknown')}" 
                          for user in users_with_admin[:10]])}

            USERS WITH CUSTOM POLICIES:
            {chr(10).join([f"- {user['username']}: {len(user['inline_policies'])} custom policies" 
                          for user in custom_policy_users[:10]])}

            Provide a comprehensive security assessment with:
            1. Overall risk assessment
            2. Key security concerns
            3. Recommendations for improvement
            4. Policy optimization suggestions
            5. Compliance considerations

            Keep the response concise but thorough, focusing on actionable insights.
            """
            
            response = client.chat.completions.create(
                model="gpt-4",
                messages=[{"role": "user", "content": prompt}],
                max_tokens=1000,
                temperature=0.2
            )
            
            return response.choices[0].message.content
            
        except Exception as e:
            return f"AI summary unavailable: {str(e)}"

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
        """Check for overprivileged accounts."""
        try:
            overprivileged = []
            
            # Get all IAM users
            users = self.iam_client.list_users()['Users']
            
            for user in users:
                username = user['UserName']
                
                # Check for admin policies
                attached_policies = self.iam_client.list_attached_user_policies(UserName=username)
                
                for policy in attached_policies['AttachedPolicies']:
                    if 'Administrator' in policy['PolicyName']:
                        overprivileged.append({
                            'username': username,
                            'reason': f"Has administrator policy: {policy['PolicyName']}",
                            'risk_level': 'High'
                        })
                        break
                
                # Check for inline policies with broad permissions
                inline_policies = self.iam_client.list_user_policies(UserName=username)
                for policy_name in inline_policies['PolicyNames']:
                    policy_doc = self.iam_client.get_user_policy(
                        UserName=username, 
                        PolicyName=policy_name
                    )
                    
                    # Check for wildcards in actions
                    if self._has_wildcard_permissions(policy_doc['PolicyDocument']):
                        overprivileged.append({
                            'username': username,
                            'reason': f"Has wildcard permissions in policy: {policy_name}",
                            'risk_level': 'Medium'
                        })
            
            return overprivileged
            
        except Exception as e:
            print(f"Error checking overprivileged accounts: {e}")
            return []

    def track_permission_changes(self, days: int = 7) -> pd.DataFrame:
        """Track recent permission changes."""
        try:
            end_time = datetime.utcnow()
            start_time = end_time - timedelta(days=days)
            
            # Look for IAM-related events
            events = self.cloudtrail_client.lookup_events(
                LookupAttributes=[
                    {
                        'AttributeKey': 'EventSource',
                        'AttributeValue': 'iam.amazonaws.com'
                    }
                ],
                StartTime=start_time,
                EndTime=end_time
            )
            
            changes = []
            for event in events.get('Events', []):
                if any(action in event['EventName'] for action in [
                    'AttachUserPolicy', 'DetachUserPolicy', 'CreateUser', 
                    'DeleteUser', 'CreateRole', 'DeleteRole', 'AttachRolePolicy'
                ]):
                    changes.append({
                        'Timestamp': event['EventTime'],
                        'Event': event['EventName'],
                        'User': event.get('Username', 'Unknown'),
                        'Source IP': event.get('SourceIPAddress', 'Unknown')
                    })
            
            return pd.DataFrame(changes)
            
        except Exception as e:
            print(f"Error tracking permission changes: {e}")
            return pd.DataFrame()

    def _has_wildcard_permissions(self, policy_doc: Dict) -> bool:
        """Check if policy document has wildcard permissions."""
        try:
            for statement in policy_doc.get('Statement', []):
                if isinstance(statement.get('Action'), str):
                    if '*' in statement['Action']:
                        return True
                elif isinstance(statement.get('Action'), list):
                    for action in statement['Action']:
                        if '*' in action:
                            return True
            return False
        except:
            return False 