import boto3
from typing import Dict, List, Any
import pandas as pd
from datetime import datetime, timedelta, timezone

class SecurityComplianceHelper:
    def __init__(self, session: boto3.Session):
        """Initialize the SecurityComplianceHelper with AWS session."""
        self.session = session
        self.iam = session.client('iam')
        self.cloudtrail = session.client('cloudtrail')

    def check_password_policy(self) -> Dict[str, Any]:
        """Check IAM password policy compliance."""
        try:
            policy = self.iam.get_account_password_policy()['PasswordPolicy']
            
            requirements = {
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
                'max_password_age': {
                    'current': policy.get('MaxPasswordAge', 'No limit'),
                    'recommended': 90,
                    'compliant': policy.get('MaxPasswordAge', 999) <= 90
                }
            }
            
            return requirements
            
        except Exception as e:
            return {'error': f"Error checking password policy: {e}"}

    def check_mfa_status(self) -> Dict[str, Any]:
        """Check MFA status for all users."""
        try:
            users = self.iam.list_users()['Users']
            
            console_users = []
            cli_users = []
            console_mfa_enabled = 0
            
            for user in users:
                username = user['UserName']
                
                # Check if user has console access
                try:
                    self.iam.get_login_profile(UserName=username)
                    console_users.append(username)
                    
                    # Check MFA devices
                    mfa_devices = self.iam.list_mfa_devices(UserName=username)
                    if mfa_devices['MFADevices']:
                        console_mfa_enabled += 1
                    
                except self.iam.exceptions.NoSuchEntityException:
                    # User doesn't have console access
                    cli_users.append(username)
            
            console_users_without_mfa = []
            for user in console_users:
                mfa_devices = self.iam.list_mfa_devices(UserName=user)
                if not mfa_devices['MFADevices']:
                    console_users_without_mfa.append(user)
            
            return {
                'total_users': len(users),
                'console_users': len(console_users),
                'cli_only_users': len(cli_users),
                'console_mfa_enabled': console_mfa_enabled,
                'console_mfa_disabled': len(console_users) - console_mfa_enabled,
                'console_users_without_mfa': console_users_without_mfa,
                'cli_users': cli_users
            }
            
        except Exception as e:
            return {'error': f"Error checking MFA status: {e}"}

    def check_access_key_rotation(self, max_age_days: int = 90) -> Dict[str, Any]:
        """Check access key rotation compliance."""
        try:
            users = self.iam.list_users()['Users']
            
            total_keys = 0
            non_compliant_keys = 0
            keys_requiring_rotation = []
            
            for user in users:
                username = user['UserName']
                
                access_keys = self.iam.list_access_keys(UserName=username)
                
                for key in access_keys['AccessKeyMetadata']:
                    total_keys += 1
                    
                    # Calculate age
                    key_age = (datetime.now(key['CreateDate'].tzinfo) - key['CreateDate']).days
                    
                    if key_age > max_age_days:
                        non_compliant_keys += 1
                        keys_requiring_rotation.append({
                            'username': username,
                            'access_key_id': key['AccessKeyId'],
                            'age_days': key_age,
                            'status': key['Status']
                        })
            
            return {
                'total_keys': total_keys,
                'compliant_keys': total_keys - non_compliant_keys,
                'non_compliant_keys': non_compliant_keys,
                'keys_requiring_rotation': keys_requiring_rotation
            }
            
        except Exception as e:
            return {'error': f"Error checking access key rotation: {e}"}

    def monitor_root_account_usage(self, days: int = 7) -> List[Dict[str, Any]]:
        """Monitor root account usage."""
        try:
            end_time = datetime.utcnow()
            start_time = end_time - timedelta(days=days)
            
            events = self.cloudtrail.lookup_events(
                LookupAttributes=[
                    {
                        'AttributeKey': 'UserName',
                        'AttributeValue': 'root'
                    }
                ],
                StartTime=start_time,
                EndTime=end_time
            )
            
            root_activities = []
            for event in events.get('Events', []):
                root_activities.append({
                    'timestamp': event['EventTime'],
                    'event_name': event['EventName'],
                    'event_source': event.get('EventSource', 'Unknown'),
                    'source_ip': event.get('SourceIPAddress', 'Unknown')
                })
            
            return root_activities
            
        except Exception as e:
            return [{'error': f"Error monitoring root account usage: {e}"}]

    def get_security_score(self) -> Dict[str, Any]:
        """Calculate overall security score."""
        try:
            score = 100
            findings = []
            
            # Password policy check (20 points)
            password_policy = self.check_password_policy()
            if 'error' not in password_policy:
                non_compliant = sum(1 for setting in password_policy.values() if not setting['compliant'])
                score -= non_compliant * 5
                if non_compliant > 0:
                    findings.append(f"Password policy has {non_compliant} non-compliant settings")
            
            # MFA check (15 points)
            mfa_status = self.check_mfa_status()
            if 'error' not in mfa_status and mfa_status['console_users'] > 0:
                mfa_percentage = (mfa_status['console_mfa_enabled'] / mfa_status['console_users']) * 100
                if mfa_percentage < 100:
                    points_lost = int(15 * (100 - mfa_percentage) / 100)
                    score -= points_lost
                    findings.append(f"{mfa_status['console_mfa_disabled']} console users without MFA")
            
            # Access key rotation check (25 points)
            key_rotation = self.check_access_key_rotation()
            if 'error' not in key_rotation:
                score -= key_rotation['non_compliant_keys'] * 3
                if key_rotation['non_compliant_keys'] > 0:
                    findings.append(f"{key_rotation['non_compliant_keys']} access keys need rotation")
            
            # Root account usage check (40 points)
            root_usage = self.monitor_root_account_usage()
            if root_usage and 'error' not in root_usage[0]:
                score -= len(root_usage) * 10
                if len(root_usage) > 0:
                    findings.append(f"Root account used {len(root_usage)} times in past week")
            
            # Ensure score doesn't go below 0
            score = max(0, score)
            
            return {
                'score': score,
                'findings': findings
            }
            
        except Exception as e:
            return {'score': 0, 'findings': [f"Error calculating security score: {e}"]} 