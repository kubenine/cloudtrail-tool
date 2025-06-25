import streamlit as st
import pandas as pd
from datetime import datetime, timedelta
from helpers.cloudtrail_helper import CloudTrailHelper
from helpers.cloudtrail_query import CloudTrailQuery
from helpers.user_activity_helper import UserActivityHelper
from helpers.sso_activity_helper import SSOActivityHelper
from helpers.resource_activity_helper import ResourceActivityHelper
from helpers.permission_analysis_helper import PermissionAnalysisHelper
from helpers.security_compliance_helper import SecurityComplianceHelper
from helpers.audit_report_helper import AuditReportHelper
from helpers.aws_auth import AWSAuth
from utils import token_counter
import os
from dotenv import load_dotenv
from collections import defaultdict

def display_token_metrics():
    """Display token usage metrics in the sidebar."""
    if token_counter.total_tokens > 0:
        st.sidebar.markdown("---")
        st.sidebar.markdown("### Token Usage")
        st.sidebar.metric("Total Tokens", token_counter.total_tokens)
        st.sidebar.metric("Prompt Tokens", token_counter.prompt_tokens)
        st.metric(
            label="Completion Tokens",
            value=f"{token_counter.completion_tokens:,}",
            delta=f"Output: {token_counter.completion_tokens:,}"
        )
        
        # Calculate estimated cost (rough estimate for GPT-4)
        estimated_cost = (token_counter.prompt_tokens * 0.03 + token_counter.completion_tokens * 0.06) / 1000
        st.sidebar.metric("Estimated Cost", f"${estimated_cost:.4f}")

# Page config - MUST BE THE FIRST STREAMLIT COMMAND
st.set_page_config(
    page_title="CloudTrail Intelligence Dashboard",
    page_icon="🔍",
    layout="wide"
)

# Load environment variables
load_dotenv()

# Initialize AWS authentication
aws_auth = AWSAuth()

# Check for AWS credentials
openai_api_key = os.getenv('OPENAI_API_KEY')

# AWS Credentials section in sidebar
st.sidebar.header("AWS Credentials")

# Show current authentication status
auth_info = aws_auth.get_auth_info()
if auth_info['using_explicit_credentials']:
    st.sidebar.success(f"✅ Using explicit credentials")
    if auth_info['access_key_id']:
        st.sidebar.text(f"Access Key: {auth_info['access_key_id']}")
    st.sidebar.text(f"Region: {auth_info['region']}")
else:
    st.sidebar.info("🔄 Using default AWS authentication")
    st.sidebar.text(f"Region: {auth_info['region']}")

# Allow manual credential override
auth_method = st.sidebar.radio(
    "Authentication Method",
    ["Use Default", "Manual Override"],
    index=0
)

if auth_method == "Manual Override":
    aws_access_key = st.sidebar.text_input("AWS Access Key ID")
    aws_secret_key = st.sidebar.text_input("AWS Secret Access Key", type="password")
    aws_region = st.sidebar.text_input("AWS Region", value=auth_info['region'])
    
    # Set credentials if provided
    if aws_access_key and aws_secret_key:
        os.environ['AWS_ACCESS_KEY_ID'] = aws_access_key
        os.environ['AWS_SECRET_ACCESS_KEY'] = aws_secret_key
        os.environ['AWS_DEFAULT_REGION'] = aws_region
        st.sidebar.success("✅ Manual credentials set")
        # Reinitialize auth with new credentials
        aws_auth = AWSAuth()

# Allow OpenAI key to be entered if not in environment
if not openai_api_key:
    openai_api_key = st.sidebar.text_input("OpenAI API Key", type="password")
    if openai_api_key:
        os.environ['OPENAI_API_KEY'] = openai_api_key

# Test AWS credentials
try:
    # Try to create a simple client to test credentials
    test_client = aws_auth.create_client('sts')
    has_credentials = True
except Exception as e:
    has_credentials = False
    st.sidebar.error(f"❌ AWS credentials error: {str(e)}")

if not has_credentials:
    st.error("""
    AWS credentials not found or invalid. Please either:
    1. Configure AWS credentials using AWS CLI (`aws configure`)
    2. Set up IAM roles (if running on EC2/ECS/Lambda)
    3. Use manual credential override in the sidebar
    4. Set environment variables (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
    """)
    st.stop()

if not openai_api_key:
    st.warning("""
    OpenAI API key not found. Natural language search features will be limited.
    Please either:
    1. Add OPENAI_API_KEY to your .env file, or
    2. Enter the key in the sidebar
    """)

# Initialize helpers
try:
    cloudtrail = CloudTrailHelper()
    user_activity = UserActivityHelper()
    sso_activity = SSOActivityHelper()
    resource_activity = ResourceActivityHelper()
    permission_analysis = PermissionAnalysisHelper(aws_auth.create_session())
    security_compliance = SecurityComplianceHelper(aws_auth.create_session())
    audit_report = AuditReportHelper(permission_analysis, security_compliance)
except Exception as e:
    st.error(f"Error initializing helpers: {str(e)}")
    st.stop()

# Title and description
st.title("CloudTrail Intelligence Dashboard")
st.markdown("""
This dashboard helps you explore AWS CloudTrail logs using natural language queries and AI-powered summaries.
""")

# Sidebar settings
st.sidebar.header("Settings")
time_window = st.sidebar.slider(
    "Time Window (hours)",
    min_value=1,
    max_value=168,
    value=24
)

# Main content
tab1, tab2, tab3, tab4, tab5 = st.tabs([
    "SSO User Activity", 
    "IAM User Activity", 
    "Natural Language Search", 
    "Resource Activity",
    "Account Audit"
])

# SSO User Activity Tab
with tab1:
    st.header("SSO User Activity")
    
    # Get list of SSO users
    try:
        with st.spinner("Loading SSO users..."):
            users = cloudtrail.list_sso_users()
            if not users:
                st.warning("No SSO users found. Please ensure you have AWS SSO configured.")
                st.stop()
            
            user_options = {f"{user['display_name']} ({user['email']})": user['username'] for user in users}
        
        selected_user = st.selectbox(
            "Select SSO User",
            options=list(user_options.keys())
        )
        
        if st.button("View Activity", key="sso_activity_button"):
            if selected_user:
                try:
                    with st.spinner("Fetching user activity..."):
                        username = user_options[selected_user]
                        events = cloudtrail.get_sso_user_events(username, hours=time_window)
                        
                        if events:
                            st.success(f"Found {len(events)} events for {selected_user}.")
                            
                            # Display events in a more user-friendly format
                            st.subheader(f"Activity for {selected_user}")
                            
                            # Generate and display a natural language summary
                            st.markdown("### Summary")
                            summary = sso_activity.format_sso_activity(events, selected_user)
                            st.write(summary)
                            
                            # Display token usage metrics
                            display_token_metrics()
                            
                            st.markdown("---")
                            
                            # Group events by date
                            grouped_events = defaultdict(list)
                            for event in events:
                                date = event['timestamp'].split(' ')[0]
                                grouped_events[date].append(event)
                            
                            # Display events by date
                            for date, day_events in sorted(grouped_events.items(), reverse=True):
                                st.markdown(f"**{date}**")
                                for event in day_events:
                                    # Create a human-readable action description
                                    action_desc = f"{event['event_name']}"
                                    if event['resource'] != 'Unknown':
                                        action_desc += f" on {event['resource']}"
                                    
                                    # Create a clean expander title
                                    expander_title = f"🕒 {event['timestamp'].split(' ')[1]} - {action_desc}"
                                    
                                    with st.expander(expander_title):
                                        # Only show relevant information
                                        if event['source_ip'] != 'Unknown':
                                            st.write(f"**From IP:** {event['source_ip']}")
                                        
                                        # Only show request parameters if they contain meaningful information
                                        if event['request_parameters'] and len(str(event['request_parameters'])) > 2:
                                            st.write("**Details:**")
                                            st.json(event['request_parameters'])
                                
                                st.markdown("---")
                            
                            # Display raw data in a collapsible section
                            with st.expander("View Raw Data"):
                                df = pd.DataFrame(events)
                                st.dataframe(df)
                        else:
                            st.warning(f"No events found for {selected_user} in the specified time window.")
                except Exception as e:
                    st.error(f"Error fetching user activity: {str(e)}")
            else:
                st.warning("Please select a user.")
    except Exception as e:
        st.error(f"Error loading SSO users: {str(e)}")

# IAM User Activity Tab
with tab2:
    st.header("IAM User Activity")
    
    # Get list of IAM users
    try:
        with st.spinner("Loading IAM users..."):
            users = cloudtrail.list_iam_users()
            user_options = {user['username']: user['arn'] for user in users}
        
        selected_user = st.selectbox(
            "Select IAM User",
            options=list(user_options.keys())
        )
        
        if st.button("View Activity", key="iam_activity_button"):
            if selected_user:
                try:
                    with st.spinner("Fetching user activity..."):
                        events = cloudtrail.get_user_events(selected_user, hours=time_window)
                        
                        if events:
                            st.success(f"Found {len(events)} events for {selected_user}.")
                            
                            # Display events in a more user-friendly format
                            st.subheader(f"Activity for {selected_user}")
                            
                            # Generate and display a natural language summary
                            st.markdown("### Summary")
                            summary = user_activity.format_user_activity(events, selected_user)
                            st.write(summary)
                            
                            # Display token usage metrics
                            display_token_metrics()
                            
                            st.markdown("---")
                            
                            # Group events by date
                            grouped_events = defaultdict(list)
                            for event in events:
                                date = event['timestamp'].split(' ')[0]
                                grouped_events[date].append(event)
                            
                            # Display events by date
                            for date, day_events in sorted(grouped_events.items(), reverse=True):
                                st.markdown(f"**{date}**")
                                for event in day_events:
                                    # Create a human-readable action description
                                    action_desc = f"{event['event_name']}"
                                    if event['resource'] != 'Unknown':
                                        action_desc += f" on {event['resource']}"
                                    
                                    # Create a clean expander title
                                    expander_title = f"🕒 {event['timestamp'].split(' ')[1]} - {action_desc}"
                                    
                                    with st.expander(expander_title):
                                        # Only show relevant information
                                        if event['source_ip'] != 'Unknown':
                                            st.write(f"**From IP:** {event['source_ip']}")
                                        
                                        # Only show request parameters if they contain meaningful information
                                        if event['request_parameters'] and len(str(event['request_parameters'])) > 2:
                                            st.write("**Details:**")
                                            st.json(event['request_parameters'])
                                
                                st.markdown("---")
                            
                            # Display raw data in a collapsible section
                            with st.expander("View Raw Data"):
                                df = pd.DataFrame(events)
                                st.dataframe(df)
                        else:
                            st.warning(f"No events found for {selected_user} in the specified time window.")
                except Exception as e:
                    st.error(f"Error fetching user activity: {str(e)}")
            else:
                st.warning("Please select a user.")
    except Exception as e:
        st.error(f"Error loading IAM users: {str(e)}")

# Natural Language Search Tab
with tab3:
    st.header("Natural Language Search")
    
    # Add example queries
    st.markdown("### Try these example queries:")
    col1, col2 = st.columns(2)
    
    with col1:
        if st.button("🔍 Show cluster interactions"):
            query = "Who interacted with EKS or ECS clusters in the last 24 hours?"
            st.session_state['query'] = query
            st.rerun()
            
        if st.button("🪣 List S3 bucket operations"):
            query = "Show me all S3 bucket operations including creation, deletion, and modifications"
            st.session_state['query'] = query
            st.rerun()
            
        if st.button("🛑 Show EC2 instance changes"):
            query = "What changes were made to EC2 instances, including starts, stops, and terminations?"
            st.session_state['query'] = query
            st.rerun()
            
        if st.button("🔒 Show security changes"):
            query = "Show me all security-related changes including IAM, security groups, and KMS key operations"
            st.session_state['query'] = query
            st.rerun()
    
    with col2:
        if st.button("👤 Show root user activities"):
            query = "Show me all actions performed by the root user account"
            st.session_state['query'] = query
            st.rerun()
            
        if st.button("⏰ Show today's activities"):
            query = "What happened today in my AWS account? Show me all significant changes"
            st.session_state['query'] = query
            st.rerun()
            
        if st.button("🔐 Show IAM changes"):
            query = "Show me all IAM-related changes including user, role, and policy modifications"
            st.session_state['query'] = query
            st.rerun()
            
        if st.button("🌐 Show network changes"):
            query = "Show me all network-related changes including VPC, subnet, and security group modifications"
            st.session_state['query'] = query
            st.rerun()
    
    st.markdown("---")
    
    # Initialize session state for query if not exists
    if 'query' not in st.session_state:
        st.session_state['query'] = ""
    
    query = st.text_input(
        "Or enter your own query",
        value=st.session_state['query'],
        placeholder="e.g., Who created an S3 bucket today?"
    )
    
    if st.button("Search", key="search_button"):
        if query:
            try:
                with st.spinner("Searching CloudTrail logs..."):
                    summary, results = cloudtrail.search_events(query, hours=time_window)
                    
                st.success(f"Search completed! Found {len(results)} results.")
                
                # Display the natural language summary first
                st.markdown("### Summary")
                st.write(summary)
                
                # Display token usage metrics
                display_token_metrics()
                
                st.markdown("---")  # Add a visual separator
                
                # Continue with the rest of the display (User Activity, etc.)
                st.markdown("### User Activity")
                # Group events by user
                user_events = defaultdict(list)
                for result in results:
                    user = result.get('user', 'Unknown')
                    user_events[user].append(result)
                
                # Display activity for each user
                for user, events in user_events.items():
                    with st.expander(f"Activity for {user}"):
                        for event in events:
                            st.markdown(f"• {event['timestamp']} - {event['event_name']} on {event['resource']}")
                            if event['source_ip'] != 'Unknown':
                                st.markdown(f"  - From IP: {event['source_ip']}")
                    
                    # Display the generated query in a collapsible section
                    with st.expander("View Generated CloudWatch Logs Insights Query"):
                        st.code(cloudtrail.query_helper.generate_query(query, hours=time_window), language="sql")
                    
                    # Display raw data in a collapsible section
                    with st.expander("View Raw Data"):
                        # Convert results to a format that can be safely displayed
                        display_results = []
                        for result in results:
                            display_result = {
                                'timestamp': result['timestamp'],
                                'user': result.get('user', 'Unknown'),
                                'action': result['event_name'],
                                'resource': result['resource'],
                                'source_ip': result['source_ip'],
                                'request_parameters': str(result.get('request_parameters', ''))  # Convert to string
                            }
                            display_results.append(display_result)
                        
                        df = pd.DataFrame(display_results)
                        st.dataframe(df)
            except Exception as e:
                st.error(f"Error performing search: {str(e)}")
        else:
            st.warning("Please enter a search query.")

# Resource Activity Tab
with tab4:
    st.header("Resource Activity")
    
    # Get list of AWS services
    service_options = resource_activity.get_service_list()
    selected_service = st.selectbox(
        "Select AWS Service",
        options=[service[0] for service in service_options],
        format_func=lambda x: next((service[1] for service in service_options if service[0] == x), x)
    )
    
    # Get resource types for selected service
    resource_types = resource_activity.get_resource_types(selected_service)
    selected_resource_type = st.selectbox(
        "Select Resource Type (Optional)",
        options=["All"] + resource_types
    )
    
    # Get common actions for selected service
    actions = resource_activity.get_actions(selected_service)
    st.markdown("### Common Actions for this Service")
    st.markdown("• " + "\n• ".join(actions))
    
    if st.button("View Resource Activity", key="resource_activity_button"):
        try:
            with st.spinner("Fetching resource activity..."):
                # Construct query based on service and resource type
                query = f"Show me all {selected_service} activity"
                if selected_resource_type != "All":
                    query += f" for {selected_resource_type} resources"
                
                summary, results = cloudtrail.search_events(query, hours=time_window)
                
                if results:
                    st.success(f"Found {len(results)} events for {selected_service} resources.")
                    
                    # Display events in a more user-friendly format
                    st.subheader(f"Activity for {resource_activity.aws_services[selected_service]['name']}")
                    
                    # Generate and display a natural language summary
                    st.markdown("### Summary")
                    summary = resource_activity.format_resource_activity(
                        results,
                        selected_service,
                        selected_resource_type if selected_resource_type != "All" else None
                    )
                    st.write(summary)
                    
                    # Display token usage metrics
                    display_token_metrics()
                    
                    st.markdown("---")
                    
                    # Group events by date
                    grouped_events = defaultdict(list)
                    for event in results:
                        date = event['timestamp'].split(' ')[0]
                        grouped_events[date].append(event)
                    
                    # Display events by date
                    for date, day_events in sorted(grouped_events.items(), reverse=True):
                        st.markdown(f"**{date}**")
                        for event in day_events:
                            # Create a human-readable action description
                            action_desc = f"{event['event_type']}"
                            if event['resource'] != 'Unknown':
                                action_desc += f" on {event['resource']}"
                            
                            # Create a clean expander title
                            expander_title = f"🕒 {event['timestamp'].split(' ')[1]} - {action_desc}"
                            
                            with st.expander(expander_title):
                                # Only show relevant information
                                if event['source_ip'] != 'Unknown':
                                    st.write(f"**From IP:** {event['source_ip']}")
                                
                                # Only show request parameters if they contain meaningful information
                                if event['request_parameters'] and len(str(event['request_parameters'])) > 2:
                                    st.write("**Details:**")
                                    st.json(event['request_parameters'])
                        
                        st.markdown("---")
                    
                    # Display raw data in a collapsible section
                    with st.expander("View Raw Data"):
                        df = pd.DataFrame(results)
                        st.dataframe(df)
                else:
                    st.warning(f"No events found for {selected_service} resources in the specified time window.")
        except Exception as e:
            st.error(f"Error fetching resource activity: {str(e)}")

# Account Audit Tab
with tab5:
    st.header("Account Audit")
    
    # Create sub-tabs for different audit features
    audit_tab1, audit_tab2, audit_tab3, audit_tab4 = st.tabs([
        "Security Overview",
        "User Analysis",
        "Permission Analysis",
        "Compliance Reports"
    ])
    
    # Security Overview Tab
    with audit_tab1:
        st.subheader("Security Overview")
        
        # Security Score
        try:
            with st.spinner("Calculating security score..."):
                security_score = security_compliance.get_security_score()
                
                # Display score in a metric
                st.metric(
                    "Security Score",
                    f"{security_score['score']}/100",
                    delta=None if security_score['score'] >= 90 else f"{90 - security_score['score']} points below target"
                )
                
                # Display detailed breakdown of score issues with fixes
                if security_score['score'] < 100:
                    st.markdown("### 🔍 Security Score Breakdown & Recommended Fixes")
                    
                    # Get detailed information for each category
                    password_policy = security_compliance.check_password_policy()
                    mfa_status = security_compliance.check_mfa_status()
                    key_rotation = security_compliance.check_access_key_rotation()
                    root_usage = security_compliance.monitor_root_account_usage(days=7)
                    
                    # Password Policy Issues
                    if isinstance(password_policy, dict) and 'error' not in password_policy:
                        non_compliant_policies = {k: v for k, v in password_policy.items() if not v['compliant']}
                        if non_compliant_policies:
                            with st.expander(f"❌ Password Policy Issues (-{len(non_compliant_policies) * 5} points)", expanded=True):
                                st.markdown("**Issues Found:**")
                                for policy_name, details in non_compliant_policies.items():
                                    st.markdown(f"• **{policy_name.replace('_', ' ').title()}**: Current: `{details['current']}`, Recommended: `{details['recommended']}`")
                                
                                st.markdown("**How to Fix:**")
                                st.code("""
# Update account password policy using AWS CLI:
aws iam update-account-password-policy \\
    --minimum-password-length 14 \\
    --require-symbols \\
    --require-numbers \\
    --require-uppercase-characters \\
    --require-lowercase-characters \\
    --password-reuse-prevention 24 \\
    --max-password-age 90
                                """, language="bash")
                                st.markdown("**Or via AWS Console:** IAM → Account settings → Password policy → Edit")
                    
                    # MFA Issues (Console Users Only)
                    if 'error' not in mfa_status and mfa_status['console_users'] > 0:
                        mfa_percentage = (mfa_status['console_mfa_enabled'] / mfa_status['console_users']) * 100
                        if mfa_percentage < 100:
                            points_lost = int(15 * (100 - mfa_percentage) / 100)
                            with st.expander(f"❌ MFA Not Enabled for Console Users (-{points_lost} points)", expanded=True):
                                st.markdown("**Issues Found:**")
                                st.markdown(f"• {mfa_status['console_mfa_disabled']} console users without MFA:")
                                for user in mfa_status['console_users_without_mfa']:
                                    st.markdown(f"  - {user}")
                                
                                st.markdown("**How to Fix:**")
                                st.markdown("**For each user via AWS Console:**")
                                st.markdown("1. Go to IAM → Users → [Username] → Security credentials")
                                st.markdown("2. In 'Multi-factor authentication (MFA)' section, click 'Assign MFA device'")
                                st.markdown("3. Choose device type (Virtual MFA device recommended)")
                                st.markdown("4. Follow the setup wizard")
                                
                                st.markdown("**Via AWS CLI:**")
                                st.code("""
# Create virtual MFA device
aws iam create-virtual-mfa-device --virtual-mfa-device-name <username>-mfa --outfile qr-code.png --bootstrap-method QRCodePNG

# Enable MFA device (after scanning QR code)
aws iam enable-mfa-device --user-name <username> --serial-number <mfa-device-arn> --authentication-code-1 <code1> --authentication-code-2 <code2>
                                """, language="bash")
                    
                    # Access Key Rotation Issues
                    if 'error' not in key_rotation and key_rotation['non_compliant_keys'] > 0:
                        points_lost = key_rotation['non_compliant_keys'] * 3
                        with st.expander(f"⚠️ Access Keys Need Rotation (-{points_lost} points)", expanded=True):
                            st.markdown("**Issues Found:**")
                            st.markdown(f"• {key_rotation['non_compliant_keys']} access keys older than 90 days:")
                            for key in key_rotation['keys_requiring_rotation']:
                                st.markdown(f"  - User: `{key['username']}`, Key: `{key['access_key_id']}`, Age: {key['age_days']} days")
                            
                            st.markdown("**How to Fix:**")
                            st.markdown("**For each user via AWS Console:**")
                            st.markdown("1. Go to IAM → Users → [Username] → Security credentials")
                            st.markdown("2. In 'Access keys' section, click 'Create access key'")
                            st.markdown("3. Update applications with new key")
                            st.markdown("4. Test applications with new key")
                            st.markdown("5. Delete old access key")
                            
                            st.markdown("**Via AWS CLI:**")
                            st.code("""
# Create new access key
aws iam create-access-key --user-name <username>

# After updating applications, delete old key
aws iam delete-access-key --user-name <username> --access-key-id <old-access-key-id>
                            """, language="bash")
                    
                    # Root Account Usage Issues
                    if root_usage and 'error' not in root_usage[0] and len(root_usage) > 0:
                        points_lost = len(root_usage) * 10
                        with st.expander(f"🚨 Root Account Usage Detected (-{points_lost} points)", expanded=True):
                            st.markdown("**Issues Found:**")
                            st.markdown(f"• Root account used {len(root_usage)} times in the past week:")
                            for activity in root_usage[:5]:  # Show first 5 activities
                                st.markdown(f"  - {activity['timestamp'].strftime('%Y-%m-%d %H:%M')}: {activity['event_name']}")
                            if len(root_usage) > 5:
                                st.markdown(f"  - ... and {len(root_usage) - 5} more activities")
                            
                            st.markdown("**How to Fix:**")
                            st.markdown("**Immediate Actions:**")
                            st.markdown("1. **Stop using root account** for daily activities")
                            st.markdown("2. **Create admin IAM user** if not already exists")
                            st.markdown("3. **Enable MFA on root account**")
                            st.markdown("4. **Remove root access keys** if any exist")
                            
                            st.markdown("**Create Admin User via AWS CLI:**")
                            st.code("""
# Create admin user
aws iam create-user --user-name admin-user

# Attach admin policy
aws iam attach-user-policy --user-name admin-user --policy-arn arn:aws:iam::aws:policy/AdministratorAccess

# Create login profile
aws iam create-login-profile --user-name admin-user --password '<secure-password>' --password-reset-required

# Create access key if needed
aws iam create-access-key --user-name admin-user
                            """, language="bash")
                
                else:
                    st.success("🎉 Perfect Security Score! No issues found.")
                
                # Display findings
                if security_score['findings']:
                    st.warning("Security Findings Summary")
                    for finding in security_score['findings']:
                        st.markdown(f"- {finding}")
                else:
                    st.success("No critical security findings")
                
                # Display charts
                col1, col2 = st.columns(2)
                
                with col1:
                    st.plotly_chart(audit_report.generate_security_score_chart(), use_container_width=True)
                
                with col2:
                    st.plotly_chart(audit_report.generate_mfa_status_chart(), use_container_width=True)
        
        except Exception as e:
            st.error(f"Error generating security overview: {str(e)}")
    
    # User Analysis Tab
    with audit_tab2:
        st.subheader("User Analysis")
        
        analysis_type = st.radio(
            "Select Analysis Type",
            ["All Users Overview", "Individual User Analysis"]
        )
        
        try:
            if analysis_type == "All Users Overview":
                with st.spinner("Analyzing all users..."):
                    # Get list of all IAM users
                    users = aws_auth.create_client('iam').list_users()['Users']
                    
                    # Create summary metrics
                    total_users = len(users)
                    
                    # Initialize counters
                    total_mfa_enabled = 0
                    total_access_keys = 0
                    total_active_keys = 0
                    users_with_admin = 0
                    users_without_mfa = []
                    users_with_old_keys = []
                    console_users = 0
                    cli_only_users = 0
                    
                    # Create a list to store all user reports for the detailed table
                    all_user_reports = []
                    
                    for user in users:
                        user_report = audit_report.generate_detailed_user_report(user['UserName'])
                        all_user_reports.append(user_report)
                        
                        # Check if user has console access
                        has_console_access = False
                        try:
                            aws_auth.create_client('iam').get_login_profile(UserName=user['UserName'])
                            has_console_access = True
                            console_users += 1
                        except Exception:
                            cli_only_users += 1
                        
                        # Update MFA counter (only for console users)
                        if has_console_access:
                            if user_report['mfa_devices']:
                                total_mfa_enabled += 1
                            else:
                                users_without_mfa.append(user['UserName'])
                        
                        total_access_keys += len(user_report['access_keys'])
                        total_active_keys += sum(1 for key in user_report['access_keys'] if key['status'] == 'Active')
                        
                        # Check for admin access
                        for policy in user_report['permissions']['attached_policies']:
                            if 'AdministratorAccess' in policy['PolicyName']:
                                users_with_admin += 1
                                break
                        
                        # Check for old access keys
                        for key in user_report['access_keys']:
                            if key['needs_rotation']:
                                users_with_old_keys.append({
                                    'username': user['UserName'],
                                    'key_id': key['access_key_id'],
                                    'age_days': key['age_days']
                                })
                    
                    # Display summary metrics in columns
                    col1, col2, col3, col4 = st.columns(4)
                    
                    with col1:
                        st.metric("Total Users", total_users)
                    
                    with col2:
                        if console_users > 0:
                            st.metric("Console MFA Adoption", f"{(total_mfa_enabled/console_users)*100:.1f}%")
                        else:
                            st.metric("Console Users", "0")
                    
                    with col3:
                        st.metric("Active Access Keys", total_active_keys)
                    
                    with col4:
                        st.metric("Admin Users", users_with_admin)
                    
                    # Additional metrics row
                    col5, col6, col7, col8 = st.columns(4)
                    
                    with col5:
                        st.metric("Console Users", console_users)
                    
                    with col6:
                        st.metric("CLI-Only Users", cli_only_users)
                    
                    with col7:
                        st.metric("Keys Needing Rotation", len(users_with_old_keys))
                    
                    with col8:
                        st.metric("Users Without MFA", len(users_without_mfa))
                    
                    # Display security warnings if any
                    if users_without_mfa:
                        st.warning("Console Users Without MFA (Security Risk)")
                        for user in users_without_mfa:
                            st.markdown(f"- {user}")
                    
                    if users_with_old_keys:
                        st.warning("Users With Keys Needing Rotation")
                        for entry in users_with_old_keys:
                            st.markdown(f"- {entry['username']}: Key {entry['key_id']} ({entry['age_days']} days old)")
                    
                    # Create a detailed table of all users
                    st.markdown("### Detailed User Overview")
                    
                    # Convert user reports to a DataFrame for better display
                    user_data = []
                    for report in all_user_reports:
                        # Check if user has console access
                        has_console_access = False
                        try:
                            aws_auth.create_client('iam').get_login_profile(UserName=report['username'])
                            has_console_access = True
                        except Exception:
                            has_console_access = False
                        
                        user_data.append({
                            'Username': report['username'],
                            'User Type': 'Console' if has_console_access else 'CLI-Only',
                            'MFA Enabled': 'Yes' if (has_console_access and bool(report['mfa_devices'])) else ('No' if has_console_access else 'N/A'),
                            'Access Keys': len(report['access_keys']),
                            'Active Keys': sum(1 for key in report['access_keys'] if key['status'] == 'Active'),
                            'Keys Needing Rotation': sum(1 for key in report['access_keys'] if key['needs_rotation']),
                            'Attached Policies': len(report['permissions']['attached_policies']),
                            'Group Memberships': len(report['permissions']['groups']),
                            'Has Admin Access': 'Yes' if any('AdministratorAccess' in p['PolicyName'] 
                                                 for p in report['permissions']['attached_policies']) else 'No'
                        })
                    
                    df = pd.DataFrame(user_data)
                    st.dataframe(df, use_container_width=True)
                    
                    # Add export functionality
                    if st.button("Export User Analysis"):
                        try:
                            with st.spinner("Generating detailed report..."):
                                output_path = "user_analysis_report.xlsx"
                                
                                with pd.ExcelWriter(output_path, engine='xlsxwriter') as writer:
                                    # Summary sheet
                                    summary_data = {
                                        'Metric': ['Total Users', 'MFA Enabled Users', 'Total Access Keys', 
                                                 'Active Access Keys', 'Admin Users'],
                                        'Value': [total_users, total_mfa_enabled, total_access_keys, 
                                                total_active_keys, users_with_admin]
                                    }
                                    pd.DataFrame(summary_data).to_excel(writer, sheet_name='Summary', index=False)
                                    
                                    # Detailed user data
                                    df.to_excel(writer, sheet_name='User Details', index=False)
                                    
                                    # Users without MFA
                                    pd.DataFrame(users_without_mfa, columns=['Username'])\
                                        .to_excel(writer, sheet_name='Users Without MFA', index=False)
                                    
                                    # Old access keys
                                    if users_with_old_keys:
                                        pd.DataFrame(users_with_old_keys)\
                                            .to_excel(writer, sheet_name='Keys Needing Rotation', index=False)
                                
                                with open(output_path, "rb") as f:
                                    st.download_button(
                                        label="Download User Analysis Report",
                                        data=f.read(),
                                        file_name="user_analysis_report.xlsx",
                                        mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
                                    )
                        except Exception as e:
                            st.error(f"Error exporting report: {str(e)}")
            
            else:  # Individual User Analysis
                # Get list of IAM users
                users = aws_auth.create_client('iam').list_users()['Users']
                selected_user = st.selectbox(
                    "Select User",
                    options=[user['UserName'] for user in users]
                )
                
                if selected_user:
                    with st.spinner("Analyzing user..."):
                        user_report = audit_report.generate_detailed_user_report(selected_user)
                        
                        # Display user details
                        col1, col2, col3 = st.columns(3)
                        
                        with col1:
                            st.metric("MFA Devices", len(user_report['mfa_devices']))
                        
                        with col2:
                            st.metric("Access Keys", len(user_report['access_keys']))
                        
                        with col3:
                            active_keys = sum(1 for key in user_report['access_keys'] if key['status'] == 'Active')
                            st.metric("Active Access Keys", active_keys)
                        
                        # Display permissions
                        st.markdown("### Permissions")
                        st.json(user_report['permissions'])
                        
                        # Display unused permissions
                        st.markdown("### Unused Permissions")
                        if user_report['unused_permissions']['unused_permissions']:
                            st.warning(f"Found {len(user_report['unused_permissions']['unused_permissions'])} unused permissions")
                            for perm in user_report['unused_permissions']['unused_permissions']:
                                st.markdown(f"- `{perm}`")
                        else:
                            st.success("No unused permissions found")
                        
                        # Display access key details
                        st.markdown("### Access Keys")
                        for key in user_report['access_keys']:
                            status_color = "🟢" if key['status'] == 'Active' else "🔴"
                            rotation_warning = "⚠️ Needs rotation" if key['needs_rotation'] else "✅ Up to date"
                            st.markdown(f"{status_color} {key['access_key_id']} - Age: {key['age_days']} days - {rotation_warning}")
        
        except Exception as e:
            st.error(f"Error analyzing users: {str(e)}")
    
    # Permission Analysis Tab
    with audit_tab3:
        st.subheader("Permission Analysis")
        
        try:
            # Check for overprivileged accounts
            with st.spinner("Analyzing permissions..."):
                overprivileged = permission_analysis.check_overprivileged_accounts()
                
                if overprivileged:
                    st.warning(f"Found {len(overprivileged)} overprivileged accounts")
                    for account in overprivileged:
                        st.markdown(f"- **{account['username']}**: {account['reason']} (Risk: {account['risk_level']})")
                else:
                    st.success("No overprivileged accounts found")
                
                # Display permission changes
                st.markdown("### Recent Permission Changes")
                changes_df = permission_analysis.track_permission_changes()
                if not changes_df.empty:
                    st.dataframe(changes_df)
                else:
                    st.info("No recent permission changes found")
        
        except Exception as e:
            st.error(f"Error analyzing permissions: {str(e)}")
    
    # Compliance Reports Tab
    with audit_tab4:
        st.subheader("Compliance Reports")
        
        try:
            # Password Policy
            st.markdown("### Password Policy")
            password_policy = security_compliance.check_password_policy()
            
            if 'error' not in password_policy:
                for setting, details in password_policy.items():
                    status = "✅" if details['compliant'] else "❌"
                    st.markdown(f"{status} **{setting}**: Current: {details['current']} (Recommended: {details['recommended']})")
            else:
                st.warning(password_policy['error'])
            
            # MFA Status
            st.markdown("### MFA Status")
            mfa_status = security_compliance.check_mfa_status()
            
            if 'error' not in mfa_status:
                col1, col2, col3 = st.columns(3)
                
                with col1:
                    st.metric("Total Users", mfa_status['total_users'])
                
                with col2:
                    st.metric("Console Users", mfa_status['console_users'])
                
                with col3:
                    st.metric("CLI-Only Users", mfa_status['cli_only_users'])
                
                if mfa_status['console_users'] > 0:
                    st.metric("Console MFA Adoption", 
                             f"{(mfa_status['console_mfa_enabled'] / mfa_status['console_users']) * 100:.1f}%")
                    
                    if mfa_status['console_users_without_mfa']:
                        st.warning("Console Users without MFA (Security Risk)")
                        for user in mfa_status['console_users_without_mfa']:
                            st.markdown(f"- {user}")
                    else:
                        st.success("All console users have MFA enabled")
                else:
                    st.info("No console users found - all users are CLI-only")
                
                # Show CLI users for information
                if mfa_status['cli_users']:
                    with st.expander("CLI-Only Users (MFA not required)"):
                        for user in mfa_status['cli_users']:
                            st.markdown(f"- {user}")
            else:
                st.error(mfa_status['error'])
            
            # Access Key Rotation
            st.markdown("### Access Key Rotation")
            key_status = security_compliance.check_access_key_rotation()
            
            if 'error' not in key_status:
                st.plotly_chart(audit_report.generate_access_key_age_chart(), use_container_width=True)
                
                if key_status['keys_requiring_rotation']:
                    st.warning("Keys Requiring Rotation")
                    for key in key_status['keys_requiring_rotation']:
                        st.markdown(f"- User: {key['username']}, Key: {key['access_key_id']}, Age: {key['age_days']} days")
            else:
                st.error(key_status['error'])
            
            # Root Account Usage
            st.markdown("### Root Account Usage")
            root_usage = security_compliance.monitor_root_account_usage(days=7)
            
            if root_usage and 'error' not in root_usage[0]:
                if len(root_usage) > 0:
                    st.warning(f"Found {len(root_usage)} root account activities in the past week")
                    for activity in root_usage:
                        st.markdown(f"- {activity['timestamp']}: {activity['event_name']} ({activity['event_source']})")
                else:
                    st.success("No root account usage detected in the past week")
            else:
                st.error("Error checking root account usage")
            
            # Export Report
            st.markdown("### Export Report")
            if st.button("Export to Excel"):
                try:
                    with st.spinner("Generating Excel report..."):
                        output_path = "audit_report.xlsx"
                        audit_report.export_to_excel(output_path)
                        
                        with open(output_path, "rb") as f:
                            st.download_button(
                                label="Download Report",
                                data=f.read(),
                                file_name="audit_report.xlsx",
                                mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
                            )
                except Exception as e:
                    st.error(f"Error exporting report: {str(e)}")
        
        except Exception as e:
            st.error(f"Error generating compliance reports: {str(e)}")

# Footer
st.markdown("---")
st.markdown("Built with ❤️ using Streamlit and AWS CloudTrail")
