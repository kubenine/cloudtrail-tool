import boto3
from typing import Dict, List, Any
import pandas as pd
from datetime import datetime, timedelta

class SecurityComplianceHelper:
    def __init__(self, session: boto3.Session):
        """Initialize the SecurityComplianceHelper with AWS session."""
        self.session = session
        self.iam_client = session.client('iam')
        self.cloudtrail_client = session.client('cloudtrail')

    def check_password_policy(self) -> Dict[str, Any]:
        """Check the account password policy against best practices."""
        try:
            policy = self.iam_client.get_account_password_policy()['PasswordPolicy']
            
            compliance_status = {
                'minimum_password_length': {
                    'current': policy.get('MinimumPasswordLength', 0),
                    'recommended': 14,
                    'compliant': policy.get('MinimumPasswordLength', 0) >= 14
                },
                'require_symbols': {
                    'current': policy.get('RequireSymbols', False),
                    'recommended': True,
                    'compliant': policy.get('RequireSymbols', False)
                },
                'require_numbers': {
                    'current': policy.get('RequireNumbers', False),
                    'recommended': True,
                    'compliant': policy.get('RequireNumbers', False)
                },
                'require_uppercase': {
                    'current': policy.get('RequireUppercaseCharacters', False),
                    'recommended': True,
                    'compliant': policy.get('RequireUppercaseCharacters', False)
                },
                'require_lowercase': {
                    'current': policy.get('RequireLowercaseCharacters', False),
                    'recommended': True,
                    'compliant': policy.get('RequireLowercaseCharacters', False)
                },
                'password_reuse_prevention': {
                    'current': policy.get('PasswordReusePrevention', 0),
                    'recommended': 24,
                    'compliant': policy.get('PasswordReusePrevention', 0) >= 24
                },
                'max_password_age': {
                    'current': policy.get('MaxPasswordAge', 0),
                    'recommended': 90,
                    'compliant': 0 < policy.get('MaxPasswordAge', 0) <= 90
                }
            }
            
            return compliance_status
        except self.iam_client.exceptions.NoSuchEntityException:
            return {'error': 'No password policy is set'}
        except Exception as e:
            return {'error': str(e)}

    def check_mfa_status(self) -> Dict[str, Any]:
        """Check MFA status for all IAM users, considering only console users."""
        try:
            users = self.iam_client.list_users()['Users']
            mfa_status = {
                'total_users': len(users),
                'console_users': 0,
                'cli_only_users': 0,
                'console_mfa_enabled': 0,
                'console_mfa_disabled': 0,
                'console_users_without_mfa': [],
                'cli_users': []
            }
            
            for user in users:
                username = user['UserName']
                
                # Check if user has console access (login profile)
                has_console_access = False
                try:
                    self.iam_client.get_login_profile(UserName=username)
                    has_console_access = True
                except self.iam_client.exceptions.NoSuchEntityException:
                    # User doesn't have console access
                    has_console_access = False
                
                if has_console_access:
                    mfa_status['console_users'] += 1
                    
                    # Check MFA for console users only
                    mfa_devices = self.iam_client.list_mfa_devices(UserName=username)
                    if not mfa_devices['MFADevices']:
                        mfa_status['console_mfa_disabled'] += 1
                        mfa_status['console_users_without_mfa'].append(username)
                    else:
                        mfa_status['console_mfa_enabled'] += 1
                else:
                    mfa_status['cli_only_users'] += 1
                    mfa_status['cli_users'].append(username)
            
            return mfa_status
        except Exception as e:
            return {'error': str(e)}

    def check_access_key_rotation(self, max_age_days: int = 90) -> Dict[str, Any]:
        """Check access key rotation status for all IAM users."""
        try:
            users = self.iam_client.list_users()['Users']
            rotation_status = {
                'total_keys': 0,
                'keys_requiring_rotation': [],
                'compliant_keys': 0,
                'non_compliant_keys': 0
            }
            
            for user in users:
                access_keys = self.iam_client.list_access_keys(UserName=user['UserName'])
                for key in access_keys['AccessKeyMetadata']:
                    rotation_status['total_keys'] += 1
                    key_age = (datetime.now(key['CreateDate'].tzinfo) - key['CreateDate']).days
                    
                    if key_age > max_age_days:
                        rotation_status['non_compliant_keys'] += 1
                        rotation_status['keys_requiring_rotation'].append({
                            'username': user['UserName'],
                            'access_key_id': key['AccessKeyId'],
                            'age_days': key_age
                        })
                    else:
                        rotation_status['compliant_keys'] += 1
            
            return rotation_status
        except Exception as e:
            return {'error': str(e)}

    def monitor_root_account_usage(self, days: int = 30) -> List[Dict[str, Any]]:
        """Monitor root account usage over specified period."""
        try:
            end_time = datetime.now()
            start_time = end_time - timedelta(days=days)
            
            response = self.cloudtrail_client.lookup_events(
                StartTime=start_time,
                EndTime=end_time,
                LookupAttributes=[
                    {
                        'AttributeKey': 'Username',
                        'AttributeValue': 'root'
                    }
                ]
            )
            
            root_activities = []
            for event in response['Events']:
                root_activities.append({
                    'timestamp': event['EventTime'],
                    'event_name': event['EventName'],
                    'event_source': event['EventSource'],
                    'resources': event['Resources']
                })
            
            return root_activities
        except Exception as e:
            return [{'error': str(e)}]

    def get_security_score(self) -> Dict[str, Any]:
        """Calculate overall security score based on various compliance checks."""
        score = 100
        findings = []
        
        # Check password policy
        password_policy = self.check_password_policy()
        if isinstance(password_policy, dict) and 'error' not in password_policy:
            non_compliant = sum(1 for item in password_policy.values() if not item['compliant'])
            score -= (non_compliant * 5)
            if non_compliant > 0:
                findings.append(f"Password policy has {non_compliant} non-compliant settings")
        
        # Check MFA status (only for console users)
        mfa_status = self.check_mfa_status()
        if 'error' not in mfa_status and mfa_status['console_users'] > 0:
            mfa_percentage = (mfa_status['console_mfa_enabled'] / mfa_status['console_users']) * 100
            if mfa_percentage < 100:
                score -= (15 * (100 - mfa_percentage) / 100)  # Increased weight for MFA
                findings.append(f"{mfa_status['console_mfa_disabled']} console users without MFA")
        
        # Check access key rotation
        key_rotation = self.check_access_key_rotation()
        if 'error' not in key_rotation:
            if key_rotation['non_compliant_keys'] > 0:
                score -= (key_rotation['non_compliant_keys'] * 3)  # Reduced weight since it's less critical
                findings.append(f"{key_rotation['non_compliant_keys']} access keys need rotation")
        
        # Check root account usage
        root_usage = self.monitor_root_account_usage(days=7)
        if root_usage and 'error' not in root_usage[0]:
            if len(root_usage) > 0:
                score -= (len(root_usage) * 10)  # Increased weight for root usage
                findings.append(f"Root account used {len(root_usage)} times in past week")
        
        return {
            'score': max(0, score),
            'findings': findings,
            'last_updated': datetime.now().isoformat()
        } 