import pandas as pd
from typing import Dict, List, Any
from datetime import datetime, timezone
import plotly.graph_objects as go
import plotly.express as px
from .permission_analysis_helper import PermissionAnalysisHelper
from .security_compliance_helper import SecurityComplianceHelper

class AuditReportHelper:
    def __init__(self, permission_helper: PermissionAnalysisHelper, security_helper: SecurityComplianceHelper):
        """Initialize the AuditReportHelper with required helper instances."""
        self.permission_helper = permission_helper
        self.security_helper = security_helper

    def generate_security_overview(self) -> Dict[str, Any]:
        """Generate comprehensive security overview."""
        try:
            # Get all security data
            security_score = self.security_helper.get_security_score()
            password_policy = self.security_helper.check_password_policy()
            mfa_status = self.security_helper.check_mfa_status()
            key_rotation = self.security_helper.check_access_key_rotation()
            root_usage = self.security_helper.monitor_root_account_usage()
            overprivileged = self.permission_helper.check_overprivileged_accounts()
            
            overview = {
                'timestamp': datetime.now().isoformat(),
                'security_score': security_score,
                'password_policy': password_policy,
                'mfa_status': mfa_status,
                'access_key_rotation': key_rotation,
                'root_account_usage': root_usage,
                'overprivileged_accounts': overprivileged
            }
            
            return overview
            
        except Exception as e:
            return {'error': f"Error generating security overview: {e}"}

    def generate_user_analysis(self) -> Dict[str, Any]:
        """Generate user access analysis."""
        try:
            # Get user-related data
            mfa_status = self.security_helper.check_mfa_status()
            key_rotation = self.security_helper.check_access_key_rotation()
            overprivileged = self.permission_helper.check_overprivileged_accounts()
            permission_changes = self.permission_helper.track_permission_changes()
            
            analysis = {
                'timestamp': datetime.now().isoformat(),
                'total_users': mfa_status.get('total_users', 0),
                'console_users': mfa_status.get('console_users', 0),
                'cli_users': mfa_status.get('cli_only_users', 0),
                'mfa_compliance': {
                    'enabled': mfa_status.get('console_mfa_enabled', 0),
                    'disabled': mfa_status.get('console_mfa_disabled', 0),
                    'users_without_mfa': mfa_status.get('console_users_without_mfa', [])
                },
                'access_key_status': {
                    'total_keys': key_rotation.get('total_keys', 0),
                    'compliant_keys': key_rotation.get('compliant_keys', 0),
                    'keys_needing_rotation': key_rotation.get('keys_requiring_rotation', [])
                },
                'overprivileged_accounts': overprivileged,
                'recent_permission_changes': permission_changes.to_dict('records') if not permission_changes.empty else []
            }
            
            return analysis
            
        except Exception as e:
            return {'error': f"Error generating user analysis: {e}"}

    def generate_compliance_report(self) -> Dict[str, Any]:
        """Generate compliance report."""
        try:
            # Get compliance data
            security_score = self.security_helper.get_security_score()
            password_policy = self.security_helper.check_password_policy()
            mfa_status = self.security_helper.check_mfa_status()
            root_usage = self.security_helper.monitor_root_account_usage()
            
            # Calculate compliance metrics
            compliance_metrics = {
                'overall_score': security_score.get('score', 0),
                'findings': security_score.get('findings', []),
                'password_policy_compliance': self._calculate_policy_compliance(password_policy),
                'mfa_compliance_rate': self._calculate_mfa_compliance(mfa_status),
                'root_usage_incidents': len(root_usage) if root_usage else 0
            }
            
            # Generate recommendations
            recommendations = self._generate_recommendations(security_score, password_policy, mfa_status, root_usage)
            
            report = {
                'timestamp': datetime.now().isoformat(),
                'compliance_metrics': compliance_metrics,
                'recommendations': recommendations,
                'detailed_findings': {
                    'password_policy': password_policy,
                    'mfa_status': mfa_status,
                    'root_usage': root_usage
                }
            }
            
            return report
            
        except Exception as e:
            return {'error': f"Error generating compliance report: {e}"}

    def _calculate_policy_compliance(self, password_policy: Dict) -> float:
        """Calculate password policy compliance percentage."""
        if 'error' in password_policy:
            return 0.0
        
        total_settings = len(password_policy)
        compliant_settings = sum(1 for setting in password_policy.values() if setting.get('compliant', False))
        
        return (compliant_settings / total_settings) * 100 if total_settings > 0 else 0.0

    def _calculate_mfa_compliance(self, mfa_status: Dict) -> float:
        """Calculate MFA compliance percentage."""
        if 'error' in mfa_status or mfa_status.get('console_users', 0) == 0:
            return 100.0  # If no console users, consider it compliant
        
        enabled = mfa_status.get('console_mfa_enabled', 0)
        total = mfa_status.get('console_users', 1)
        
        return (enabled / total) * 100

    def _generate_recommendations(self, security_score: Dict, password_policy: Dict, 
                                 mfa_status: Dict, root_usage: List) -> List[str]:
        """Generate security recommendations based on findings."""
        recommendations = []
        
        # Password policy recommendations
        if 'error' not in password_policy:
            for setting, details in password_policy.items():
                if not details.get('compliant', True):
                    recommendations.append(f"Update password policy: {setting} should be {details['recommended']}")
        
        # MFA recommendations
        if 'error' not in mfa_status and mfa_status.get('console_mfa_disabled', 0) > 0:
            recommendations.append(f"Enable MFA for {mfa_status['console_mfa_disabled']} console users")
        
        # Root usage recommendations
        if root_usage and len(root_usage) > 0:
            recommendations.append("Minimize root account usage - use IAM users with appropriate permissions instead")
        
        # Security score recommendations
        if security_score.get('score', 100) < 80:
            recommendations.append("Overall security score is below 80 - review and address security findings")
        
        return recommendations

    def generate_summary_report(self) -> Dict[str, Any]:
        """Generate a comprehensive summary report of all security and compliance metrics."""
        report = {
            'timestamp': datetime.now().isoformat(),
            'security_score': self.security_helper.get_security_score(),
            'mfa_status': self.security_helper.check_mfa_status(),
            'password_policy': self.security_helper.check_password_policy(),
            'access_keys': self.security_helper.check_access_key_rotation(),
            'root_usage': self.security_helper.monitor_root_account_usage(days=30),
            'overprivileged_accounts': self.permission_helper.check_overprivileged_accounts()
        }
        return report

    def generate_security_score_chart(self) -> go.Figure:
        """Generate a gauge chart for the security score."""
        score = self.security_helper.get_security_score()
        
        fig = go.Figure(go.Indicator(
            mode = "gauge+number",
            value = score['score'],
            domain = {'x': [0, 1], 'y': [0, 1]},
            title = {'text': "Security Score"},
            gauge = {
                'axis': {'range': [0, 100]},
                'bar': {'color': "darkblue"},
                'steps': [
                    {'range': [0, 50], 'color': "red"},
                    {'range': [50, 75], 'color': "yellow"},
                    {'range': [75, 100], 'color': "green"}
                ]
            }
        ))
        
        return fig

    def generate_mfa_status_chart(self) -> go.Figure:
        """Generate a pie chart for MFA status (console users only)."""
        mfa_status = self.security_helper.check_mfa_status()
        
        if 'error' in mfa_status:
            return None
        
        # Only show MFA status for console users
        if mfa_status['console_users'] == 0:
            # No console users, show a message chart
            fig = go.Figure()
            fig.add_annotation(
                text="No console users found<br>Only CLI users exist",
                xref="paper", yref="paper",
                x=0.5, y=0.5, xanchor='center', yanchor='middle',
                showarrow=False, font=dict(size=16)
            )
            fig.update_layout(title="MFA Status - Console Users Only")
            return fig
            
        labels = ['MFA Enabled', 'MFA Disabled']
        values = [mfa_status['console_mfa_enabled'], mfa_status['console_mfa_disabled']]
        
        fig = go.Figure(data=[go.Pie(labels=labels, values=values)])
        fig.update_layout(title=f"MFA Status - Console Users Only ({mfa_status['console_users']} users)")
        
        return fig

    def generate_access_key_age_chart(self) -> go.Figure:
        """Generate a histogram of access key ages."""
        key_status = self.security_helper.check_access_key_rotation()
        
        if 'error' in key_status or not key_status['keys_requiring_rotation']:
            return None
            
        ages = [key['age_days'] for key in key_status['keys_requiring_rotation']]
        
        fig = px.histogram(
            x=ages,
            nbins=20,
            title="Access Key Age Distribution"
        )
        fig.update_layout(
            xaxis_title="Age (days)",
            yaxis_title="Number of Keys"
        )
        
        return fig

    def generate_detailed_user_report(self, username: str) -> Dict[str, Any]:
        """Generate a detailed report for a specific user."""
        report = {
            'timestamp': datetime.now().isoformat(),
            'username': username,
            'permissions': self.permission_helper.get_user_permissions(username),
            'unused_permissions': self.permission_helper.analyze_unused_permissions(username),
            'mfa_devices': self.security_helper.iam_client.list_mfa_devices(UserName=username)['MFADevices'],
            'access_keys': []
        }
        
        # Get access key details
        access_keys = self.security_helper.iam_client.list_access_keys(UserName=username)['AccessKeyMetadata']
        for key in access_keys:
            key_age = (datetime.now(timezone.utc) - key['CreateDate']).days
            report['access_keys'].append({
                'access_key_id': key['AccessKeyId'],
                'status': key['Status'],
                'age_days': key_age,
                'needs_rotation': key_age > 90
            })
        
        return report

    def export_to_excel(self, output_path: str) -> None:
        """Export all audit data to an Excel file with multiple sheets."""
        with pd.ExcelWriter(output_path) as writer:
            # Summary sheet
            summary = self.generate_summary_report()
            summary_df = pd.DataFrame([summary])
            summary_df.to_excel(writer, sheet_name='Summary', index=False)
            
            # MFA Status sheet
            mfa_status = self.security_helper.check_mfa_status()
            if 'error' not in mfa_status:
                mfa_df = pd.DataFrame({
                    'Status': ['Enabled', 'Disabled'],
                    'Count': [mfa_status['mfa_enabled'], mfa_status['mfa_disabled']]
                })
                mfa_df.to_excel(writer, sheet_name='MFA Status', index=False)
            
            # Access Keys sheet
            key_status = self.security_helper.check_access_key_rotation()
            if 'error' not in key_status and key_status['keys_requiring_rotation']:
                keys_df = pd.DataFrame(key_status['keys_requiring_rotation'])
                keys_df.to_excel(writer, sheet_name='Access Keys', index=False)
            
            # Root Usage sheet
            root_usage = self.security_helper.monitor_root_account_usage()
            if root_usage and 'error' not in root_usage[0]:
                root_df = pd.DataFrame(root_usage)
                root_df.to_excel(writer, sheet_name='Root Usage', index=False)
            
            # Overprivileged Accounts sheet
            overprivileged = self.permission_helper.check_overprivileged_accounts()
            if overprivileged:
                overprivileged_df = pd.DataFrame(overprivileged)
                overprivileged_df.to_excel(writer, sheet_name='Overprivileged Accounts', index=False) 