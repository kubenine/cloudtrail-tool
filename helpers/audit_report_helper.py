import pandas as pd
from typing import Dict, List, Any
from datetime import datetime
import plotly.graph_objects as go
import plotly.express as px
from .permission_analysis_helper import PermissionAnalysisHelper
from .security_compliance_helper import SecurityComplianceHelper

class AuditReportHelper:
    def __init__(self, permission_helper: PermissionAnalysisHelper, security_helper: SecurityComplianceHelper):
        """Initialize the AuditReportHelper with required helper instances."""
        self.permission_helper = permission_helper
        self.security_helper = security_helper

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
            key_age = (datetime.now(key['CreateDate'].tzinfo) - key['CreateDate']).days
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