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
    
    # Create sub-tabs for different audit features - ADD ACCOUNT SUMMARY TAB
    audit_tab1, audit_tab2, audit_tab3, audit_tab4, audit_tab5 = st.tabs([
        "Account Summary",  # NEW TAB
        "Security Overview",
        "User Analysis", 
        "Permission Analysis",
        "Compliance Reports"
    ])
    
    # NEW: Account Summary Tab
    with audit_tab1:
        st.subheader("📊 30-Day Account Summary")
        st.markdown("*Comprehensive overview of account activities, users, and resource usage over the past 30 days*")
        
        # Generate Account Summary Button
        if st.button("🔍 Generate Account Summary", type="primary"):
            try:
                with st.spinner("🔄 Analyzing 30 days of account activity... This may take a few minutes"):
                    
                    # Progress tracking
                    progress_bar = st.progress(0)
                    status_text = st.empty()
                    
                    # Step 1: Get account information
                    status_text.text("📋 Gathering account information...")
                    progress_bar.progress(10)
                    
                    account_info = aws_auth.create_client('sts').get_caller_identity()
                    account_id = account_info['Account']
                    
                    # Step 2: Get all users (IAM + SSO)
                    status_text.text("👥 Analyzing user accounts...")
                    progress_bar.progress(20)
                    
                    iam_users = cloudtrail.list_iam_users()
                    try:
                        sso_users = cloudtrail.list_sso_users()
                    except:
                        sso_users = []
                    
                    total_users = len(iam_users) + len(sso_users)
                    
                    # Step 3: Get major activities for all users (limited to top 100)
                    status_text.text("🔍 Analyzing user activities (last 30 days)...")
                    progress_bar.progress(40)
                    
                    all_activities = []
                    user_activity_summary = {}
                    
                    # Get IAM user activities
                    for user in iam_users[:50]:  # Limit to 50 IAM users for performance
                        try:
                            user_events = cloudtrail.get_user_events(user['username'], hours=720)  # 30 days
                            if user_events:
                                # Keep only significant events (not Read-only operations)
                                significant_events = [
                                    event for event in user_events 
                                    if not any(read_only in event['event_name'].lower() 
                                             for read_only in ['describe', 'list', 'get', 'lookup'])
                                ]
                                all_activities.extend(significant_events[:20])  # Top 20 per user
                                user_activity_summary[user['username']] = {
                                    'type': 'IAM',
                                    'total_events': len(user_events),
                                    'significant_events': len(significant_events),
                                    'most_recent': user_events[0]['timestamp'] if user_events else 'No activity'
                                }
                        except:
                            user_activity_summary[user['username']] = {
                                'type': 'IAM',
                                'total_events': 0,
                                'significant_events': 0,
                                'most_recent': 'No activity'
                            }
                    
                    # Get SSO user activities
                    for user in sso_users[:50]:  # Limit to 50 SSO users for performance
                        try:
                            user_events = cloudtrail.get_sso_user_events(user['username'], hours=720)  # 30 days
                            if user_events:
                                significant_events = [
                                    event for event in user_events 
                                    if not any(read_only in event['event_name'].lower() 
                                             for read_only in ['describe', 'list', 'get', 'lookup'])
                                ]
                                all_activities.extend(significant_events[:20])  # Top 20 per user
                                user_activity_summary[user['username']] = {
                                    'type': 'SSO',
                                    'total_events': len(user_events),
                                    'significant_events': len(significant_events),
                                    'most_recent': user_events[0]['timestamp'] if user_events else 'No activity'
                                }
                        except:
                            user_activity_summary[user['username']] = {
                                'type': 'SSO',
                                'total_events': 0,
                                'significant_events': 0,
                                'most_recent': 'No activity'
                            }
                    
                    progress_bar.progress(60)
                    
                    # Step 4: Get resource activities
                    status_text.text("🏗️ Analyzing resource activities...")
                    
                    # Get major resource changes
                    resource_query = "Show me all resource creation, deletion, and modification activities in the last 30 days"
                    try:
                        _, resource_events = cloudtrail.search_events(resource_query, hours=720)
                        # Filter to significant resource events only
                        significant_resource_events = [
                            event for event in resource_events
                            if any(action in event['event_name'].lower() 
                                  for action in ['create', 'delete', 'terminate', 'modify', 'update', 'attach', 'detach'])
                        ]
                        all_activities.extend(significant_resource_events[:30])  # Top 30 resource events
                    except:
                        significant_resource_events = []
                    
                    progress_bar.progress(80)
                    
                    # Step 5: Sort and limit to top 100 activities
                    status_text.text("📈 Generating summary...")
                    
                    # Sort all activities by timestamp (most recent first)
                    all_activities.sort(key=lambda x: x['timestamp'], reverse=True)
                    top_activities = all_activities[:100]  # Limit to top 100 as requested
                    
                    # Step 6: Generate AI summary
                    if openai_api_key and top_activities:
                        # Prepare comprehensive data for security audit analysis
                        security_data = {
                            'account_overview': {
                                'account_id': account_id,
                                'total_users': total_users,
                                'iam_users': len(iam_users),
                                'sso_users': len(sso_users),
                                'total_activities': len(all_activities),
                                'significant_activities': len(top_activities),
                                'resource_changes': len(significant_resource_events)
                            },
                            'user_activity_patterns': user_activity_summary,
                            'critical_activities': [activity for activity in top_activities 
                                                  if any(critical in activity['event_name'].lower() 
                                                        for critical in ['delete', 'terminate', 'destroy', 'remove'])],
                            'admin_activities': [activity for activity in top_activities 
                                               if any(admin in activity['event_name'].lower() 
                                                     for admin in ['policy', 'role', 'user', 'group', 'permission'])],
                            'network_activities': [activity for activity in top_activities 
                                                 if any(network in activity['event_name'].lower() 
                                                       for network in ['vpc', 'subnet', 'security', 'route', 'gateway'])],
                            'access_activities': [activity for activity in top_activities 
                                                if any(access in activity['event_name'].lower() 
                                                      for access in ['login', 'assume', 'switch', 'federate'])],
                            'data_activities': [activity for activity in top_activities 
                                              if any(data in activity['event_name'].lower() 
                                                    for data in ['s3', 'bucket', 'object', 'database', 'rds'])],
                            'recent_activities': top_activities[:50]  # Most recent 50 for detailed analysis
                        }
                        
                        # Enhanced security auditor prompt
                        summary_prompt = f"""
                        You are a senior AWS security auditor conducting a comprehensive 30-day security assessment for AWS Account {account_id}. 
                        Based on the following detailed activity data, provide a thorough security audit report:

                        ACCOUNT OVERVIEW:
                        - Account ID: {account_id}
                        - Total Users: {total_users} (IAM: {len(iam_users)}, SSO: {len(sso_users)})
                        - Total Activities Analyzed: {len(all_activities)}
                        - Significant Activities: {len(top_activities)}
                        - Critical Resource Changes: {len(significant_resource_events)}

                        USER ACTIVITY ANALYSIS:
                        {chr(10).join([f"- {username}: {data['type']} user, {data['significant_events']} significant activities, last seen: {data['most_recent']}" 
                                      for username, data in list(user_activity_summary.items())[:20]])}

                        CRITICAL SECURITY ACTIVITIES (Deletions/Terminations):
                        {chr(10).join([f"- {activity['timestamp']}: {activity.get('user', 'Unknown')} performed {activity['event_name']} on {activity['resource']}" 
                                      for activity in security_data['critical_activities'][:20]]) if security_data['critical_activities'] else "No critical destructive activities detected"}

                        ADMINISTRATIVE ACTIVITIES (IAM/Policy Changes):
                        {chr(10).join([f"- {activity['timestamp']}: {activity.get('user', 'Unknown')} performed {activity['event_name']} on {activity['resource']}" 
                                      for activity in security_data['admin_activities'][:20]]) if security_data['admin_activities'] else "No administrative changes detected"}

                        NETWORK SECURITY ACTIVITIES:
                        {chr(10).join([f"- {activity['timestamp']}: {activity.get('user', 'Unknown')} performed {activity['event_name']} on {activity['resource']}" 
                                      for activity in security_data['network_activities'][:15]]) if security_data['network_activities'] else "No network security changes detected"}

                        ACCESS PATTERN ANALYSIS:
                        {chr(10).join([f"- {activity['timestamp']}: {activity.get('user', 'Unknown')} performed {activity['event_name']} from {activity.get('source_ip', 'Unknown IP')}" 
                                      for activity in security_data['access_activities'][:15]]) if security_data['access_activities'] else "No unusual access patterns detected"}

                        DATA SECURITY ACTIVITIES:
                        {chr(10).join([f"- {activity['timestamp']}: {activity.get('user', 'Unknown')} performed {activity['event_name']} on {activity['resource']}" 
                                      for activity in security_data['data_activities'][:20]]) if security_data['data_activities'] else "No data-related security activities detected"}

                        MOST RECENT SIGNIFICANT ACTIVITIES (Last 50):
                        {chr(10).join([f"- {activity['timestamp']}: {activity.get('user', 'Unknown')} - {activity['event_name']} on {activity['resource']} from {activity.get('source_ip', 'Unknown')}" 
                                      for activity in security_data['recent_activities']])}

                        As a security auditor, provide a comprehensive report with the following sections:

                        ## EXECUTIVE SUMMARY
                        - Overall security posture assessment (3-4 sentences)
                        - Key risk indicators identified
                        - Immediate attention items
                        - Compliance status overview

                        ## DETAILED SECURITY FINDINGS

                        ### 1. USER ACCESS PATTERNS & ANOMALIES
                        - Analysis of user behavior patterns
                        - Identification of unusual or suspicious activities
                        - Dormant vs. highly active accounts
                        - After-hours or unusual timezone activities
                        - Multiple failed attempts or suspicious IPs

                        ### 2. PRIVILEGE ESCALATION & ADMINISTRATIVE CHANGES
                        - IAM policy modifications and their implications
                        - Role assumption patterns
                        - Administrative privilege usage
                        - New user/role creations
                        - Permission boundary changes

                        ### 3. RESOURCE SECURITY ASSESSMENT
                        - Critical resource deletions or modifications
                        - Security group and network ACL changes
                        - Public exposure risks (S3 buckets, EC2 instances)
                        - Encryption and key management activities
                        - Database and storage security changes

                        ### 4. NETWORK SECURITY ANALYSIS
                        - VPC and network configuration changes
                        - Security group rule modifications
                        - Gateway and routing changes
                        - Potential security perimeter breaches

                        ### 5. DATA PROTECTION & COMPLIANCE
                        - Data access patterns and anomalies
                        - Encryption status changes
                        - Backup and disaster recovery activities
                        - Cross-region data movements
                        - Potential data exfiltration indicators

                        ### 6. ACCESS CONTROL EFFECTIVENESS
                        - MFA usage patterns
                        - Cross-account access activities
                        - Service-linked role activities
                        - API key and credential usage

                        ## RISK ASSESSMENT
                        - HIGH RISK: Critical security issues requiring immediate action
                        - MEDIUM RISK: Important security concerns needing attention
                        - LOW RISK: Minor issues for routine remediation
                        - INFORMATIONAL: Notable activities for awareness

                        ## RECOMMENDATIONS
                        ### Immediate Actions (0-7 days)
                        - Critical security fixes
                        - Account lockdowns if needed
                        - Emergency policy changes

                        ### Short-term Actions (1-4 weeks)
                        - Security enhancements
                        - Process improvements
                        - Monitoring enhancements

                        ### Long-term Strategic Actions (1-3 months)
                        - Architecture improvements
                        - Security automation
                        - Compliance framework enhancements

                        ## COMPLIANCE OBSERVATIONS
                        - Alignment with security frameworks (SOC2, ISO 27001, PCI-DSS)
                        - Regulatory compliance gaps
                        - Industry best practice adherence

                        ## MONITORING & ALERTING RECOMMENDATIONS
                        - CloudWatch alerts to implement
                        - GuardDuty findings to investigate
                        - Config rules to establish
                        - CloudTrail improvements needed

                        Provide specific, actionable insights with technical details. Include severity levels for each finding.
                        Format in clear sections with bullet points and specific examples from the data.
                        Be thorough but concise - this is for C-level executives and security teams.
                        """
                        
                        try:
                            from openai import OpenAI
                            client = OpenAI(api_key=openai_api_key)
                            response = client.chat.completions.create(
                                model="gpt-4",
                                messages=[{"role": "user", "content": summary_prompt}],
                                max_tokens=4000,  # Increased for comprehensive analysis
                                temperature=0.2  # Lower for more factual, professional tone
                            )
                            ai_summary = response.choices[0].message.content
                            
                            # Generate additional security metrics summary
                            metrics_prompt = f"""
                            Based on the AWS account activity data provided, generate a concise security metrics summary:
                            
                            - Risk Score (1-100): Based on activities detected
                            - Activity Volume: Classification of account activity level
                            - User Behavior: Assessment of user activity patterns
                            - Resource Changes: Impact assessment of resource modifications
                            - Security Posture: Overall security health indicator
                            
                            Account has {len(security_data['critical_activities'])} critical activities, 
                            {len(security_data['admin_activities'])} admin changes, 
                            {len(security_data['network_activities'])} network changes in 30 days.
                            
                            Provide: Risk Score: X/100, Activity Level: [Low/Medium/High], Primary Concerns: [List top 3]
                            Format as: "Risk Score: XX/100 | Activity Level: XXX | Top Concerns: 1) XXX 2) XXX 3) XXX"
                            """
                            
                            metrics_response = client.chat.completions.create(
                                model="gpt-4",
                                messages=[{"role": "user", "content": metrics_prompt}],
                                max_tokens=200,
                                temperature=0.1
                            )
                            security_metrics = metrics_response.choices[0].message.content
                            
                        except Exception as e:
                            ai_summary = f"Detailed AI security analysis unavailable. Error: {str(e)}"
                            security_metrics = "Security metrics calculation unavailable."
                    else:
                        ai_summary = "Comprehensive security analysis requires OpenAI API key configuration."
                        security_metrics = "Security metrics unavailable."
                    
                    progress_bar.progress(100)
                    status_text.text("✅ Summary generated successfully!")
                    
                    # Clear progress indicators
                    progress_bar.empty()
                    status_text.empty()
                    
                    # DISPLAY RESULTS
                    st.success(f"📊 Account Summary Generated for Account: {account_id}")
                    
                    # Account Overview Cards
                    col1, col2, col3, col4 = st.columns(4)
                    with col1:
                        st.metric("👥 Total Users", total_users)
                    with col2:
                        st.metric("📊 Total Activities", len(all_activities))
                    with col3:
                        st.metric("🔄 Significant Activities", len(top_activities))
                    with col4:
                        st.metric("🏗️ Resource Changes", len(significant_resource_events))
                    
                    # AI-Generated Executive Summary
                    st.markdown("### 🤖 Executive Summary")
                    st.write(ai_summary)
                    
                    # Security Metrics Summary
                    st.markdown("### 🛡️ Security Risk Assessment")
                    if 'security_metrics' in locals():
                        st.info(security_metrics)
                        
                        # Additional security breakdown
                        if 'security_data' in locals():
                            col1, col2, col3, col4 = st.columns(4)
                            
                            with col1:
                                st.metric(
                                    "🔴 Critical Activities",
                                    len(security_data['critical_activities']),
                                    delta="Deletions/Terminations"
                                )
                            
                            with col2:
                                st.metric(
                                    "⚙️ Admin Changes",
                                    len(security_data['admin_activities']),
                                    delta="IAM/Policy Changes"
                                )
                            
                            with col3:
                                st.metric(
                                    "🟡 Network Changes",
                                    len(security_data['network_activities']),
                                    delta="VPC/Security Groups"
                                )
                            
                            with col4:
                                st.metric(
                                    "🟢 Access Events",
                                    len(security_data['access_activities']),
                                    delta="Login/Assume Role"
                                )
                    
                    # User Activity Overview
                    st.markdown("### 👥 User Activity Overview (Last 30 Days)")
                    
                    if user_activity_summary:
                        # Create user activity dataframe
                        user_df_data = []
                        for username, data in user_activity_summary.items():
                            user_df_data.append({
                                'Username': username,
                                'Type': data['type'],
                                'Total Events': data['total_events'],
                                'Significant Events': data['significant_events'],
                                'Most Recent Activity': data['most_recent']
                            })
                        
                        user_df = pd.DataFrame(user_df_data)
                        user_df = user_df.sort_values('Significant Events', ascending=False)
                        
                        # Display top active users
                        st.markdown("#### 🔝 Most Active Users")
                        top_active_users = user_df[user_df['Significant Events'] > 0].head(10)
                        if not top_active_users.empty:
                            st.dataframe(top_active_users, use_container_width=True)
                        else:
                            st.info("No significant user activities found in the last 30 days.")
                        
                        # Display all users with expandable section
                        with st.expander("📋 All User Activity Summary"):
                            st.dataframe(user_df, use_container_width=True)
                    
                    # Top 100 Activities Detail
                    st.markdown(f"### 🔍 Top {len(top_activities)} Significant Activities")
                    st.markdown("*Showing the most important account activities, excluding read-only operations*")
                    
                    if top_activities:
                        # Group activities by date for better presentation
                        activities_by_date = defaultdict(list)
                        for activity in top_activities:
                            date = activity['timestamp'].split(' ')[0]
                            activities_by_date[date].append(activity)
                        
                        # Show activities by date (most recent first)
                        for date, day_activities in sorted(activities_by_date.items(), reverse=True):
                            with st.expander(f"📅 {date} ({len(day_activities)} activities)"):
                                for activity in day_activities:
                                    time_part = activity['timestamp'].split(' ')[1] if ' ' in activity['timestamp'] else activity['timestamp']
                                    user = activity.get('user', 'Unknown')
                                    
                                    # Color code by activity type
                                    if any(critical in activity['event_name'].lower() for critical in ['delete', 'terminate']):
                                        st.markdown(f"🔴 **{time_part}** - `{user}` performed **{activity['event_name']}** on `{activity['resource']}`")
                                    elif any(create in activity['event_name'].lower() for create in ['create', 'run']):
                                        st.markdown(f"🟢 **{time_part}** - `{user}` performed **{activity['event_name']}** on `{activity['resource']}`")
                                    elif any(modify in activity['event_name'].lower() for modify in ['modify', 'update', 'attach', 'detach']):
                                        st.markdown(f"🟡 **{time_part}** - `{user}` performed **{activity['event_name']}** on `{activity['resource']}`")
                                    else:
                                        st.markdown(f"🔵 **{time_part}** - `{user}` performed **{activity['event_name']}** on `{activity['resource']}`")
                    else:
                        st.info("No significant activities found in the last 30 days.")
                    
                    # Export Option
                    st.markdown("### 📥 Export Summary")
                    if st.button("📊 Export to Excel"):
                        try:
                            # Create Excel file with summary
                            from io import BytesIO
                            import xlsxwriter
                            
                            output = BytesIO()
                            workbook = xlsxwriter.Workbook(output, {'in_memory': True})
                            
                            # Summary sheet
                            summary_sheet = workbook.add_worksheet('Account Summary')
                            summary_sheet.write('A1', f'Account Summary for {account_id}')
                            summary_sheet.write('A2', f'Generated on: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}')
                            summary_sheet.write('A4', 'Total Users:')
                            summary_sheet.write('B4', total_users)
                            summary_sheet.write('A5', 'Total Activities:')
                            summary_sheet.write('B5', len(top_activities))
                            
                            # User activity sheet
                            if user_activity_summary:
                                user_sheet = workbook.add_worksheet('User Activities')
                                user_df.to_excel(output, sheet_name='User Activities', index=False, engine='xlsxwriter')
                            
                            # Activities sheet
                            if top_activities:
                                activities_df = pd.DataFrame(top_activities)
                                activities_df.to_excel(output, sheet_name='Top Activities', index=False, engine='xlsxwriter')
                            
                            workbook.close()
                            
                            st.download_button(
                                label="📥 Download Account Summary Report",
                                data=output.getvalue(),
                                file_name=f"account_summary_{account_id}_{datetime.now().strftime('%Y%m%d')}.xlsx",
                                mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
                            )
                        except Exception as e:
                            st.error(f"Error creating Excel export: {str(e)}")
                    
                    # Display token usage for this operation
                    display_token_metrics()
                    
            except Exception as e:
                st.error(f"Error generating account summary: {str(e)}")
                st.error("Please ensure you have proper AWS permissions and CloudTrail is configured.")

    # Security Overview Tab
    with audit_tab2:
        st.subheader("🛡️ Security Overview")
        st.markdown("*Comprehensive security posture analysis for your AWS account*")
        
        if st.button("🔍 Generate Security Overview", type="primary"):
            try:
                with st.spinner("🔄 Analyzing security posture..."):
                    # Generate security overview using the audit helper
                    security_overview = audit_report.generate_security_overview()
                    
                    if 'error' not in security_overview:
                        st.success("✅ Security overview generated successfully!")
                        # Add more security overview content here
                    else:
                        st.error(f"Error generating security overview: {security_overview['error']}")
            
            except Exception as e:
                st.error(f"Error generating security overview: {str(e)}")

    # User Analysis Tab  
    with audit_tab3:
        st.subheader("👥 User Analysis")
        st.markdown("*Detailed analysis of user access patterns and compliance*")
        
        if st.button("🔍 Generate User Analysis", type="primary"):
            try:
                with st.spinner("🔄 Analyzing user access patterns..."):
                    # Generate user analysis using the audit helper
                    user_analysis = audit_report.generate_user_analysis()
                    
                    if 'error' not in user_analysis:
                        st.success("✅ User analysis generated successfully!")
                        # Add more user analysis content here
                    else:
                        st.error(f"Error generating user analysis: {user_analysis['error']}")
            
            except Exception as e:
                st.error(f"Error generating user analysis: {str(e)}")

    # Permission Analysis Tab
    with audit_tab4:
        st.subheader("🔐 Permission Analysis")
        st.markdown("*Advanced analysis of user permissions and access patterns*")
        
        # User selection for detailed analysis
        st.markdown("### 👤 Individual User Analysis")
        try:
            # Get list of IAM users
            iam_users = permission_analysis.iam_client.list_users()['Users']
            user_names = [user['UserName'] for user in iam_users]
            
            if user_names:
                selected_user = st.selectbox("Select a user for detailed permission analysis:", user_names)
                
                if st.button("🔍 Analyze User Permissions"):
                    with st.spinner(f"🔄 Analyzing permissions for {selected_user}..."):
                        # Get detailed user report
                        user_report = audit_report.generate_detailed_user_report(selected_user)
                        
                        if 'error' not in user_report:
                            st.success(f"✅ Permission analysis completed for {selected_user}")
                            
                            # User basic info
                            st.markdown(f"#### 👤 User: {selected_user}")
                            
                            # MFA devices
                            mfa_devices = user_report.get('mfa_devices', [])
                            if mfa_devices:
                                st.markdown("##### 🔐 MFA Devices")
                                for device in mfa_devices:
                                    st.write(f"- {device['SerialNumber']} (Enabled: {device.get('EnableDate', 'Unknown')})")
                            else:
                                st.warning("⚠️ No MFA devices configured for this user")
                            
                            # Access keys
                            access_keys = user_report.get('access_keys', [])
                            if access_keys:
                                st.markdown("##### 🔑 Access Keys")
                                keys_df = pd.DataFrame(access_keys)
                                st.dataframe(keys_df, use_container_width=True)
                            
                            # User permissions
                            permissions = user_report.get('permissions', {})
                            if permissions:
                                st.markdown("##### 🛡️ Attached Policies")
                                attached_policies = permissions.get('attached_policies', [])
                                if attached_policies:
                                    for policy in attached_policies:
                                        st.write(f"- {policy['PolicyName']} (ARN: {policy['PolicyArn']})")
                                
                                st.markdown("##### 📜 Inline Policies")
                                inline_policies = permissions.get('inline_policies', [])
                                if inline_policies:
                                    for policy in inline_policies:
                                        st.write(f"- {policy}")
                                else:
                                    st.info("No inline policies found")
                                
                                st.markdown("##### 👥 Group Memberships")
                                groups = permissions.get('groups', [])
                                if groups:
                                    for group in groups:
                                        st.write(f"- {group['GroupName']}")
                                else:
                                    st.info("User is not a member of any groups")
                        else:
                            st.error("Error analyzing user permissions")
            else:
                st.info("No IAM users found in this account")
        
        except Exception as e:
            st.error(f"Error loading users: {str(e)}")
        
        # Overall Permission Analysis
        st.markdown("### 🔍 Account-Wide Permission Analysis")
        
        # Initialize session state for permission analysis
        if 'permission_analysis_complete' not in st.session_state:
            st.session_state.permission_analysis_complete = False
        if 'permission_analysis_data' not in st.session_state:
            st.session_state.permission_analysis_data = {}
        
        # Analysis button
        col1, col2 = st.columns([3, 1])
        with col1:
            analyze_button = st.button("🔍 Analyze All User Permissions", type="primary")
        with col2:
            if st.session_state.permission_analysis_complete:
                if st.button("🔄 Re-analyze", help="Clear current results and run analysis again"):
                    st.session_state.permission_analysis_complete = False
                    st.session_state.permission_analysis_data = {}
                    st.rerun()
        
        # Run analysis if button clicked or show cached results
        if analyze_button and not st.session_state.permission_analysis_complete:
            try:
                with st.spinner("🔄 Analyzing account-wide permissions... This may take a few minutes"):
                    # Progress tracking
                    progress_bar = st.progress(0)
                    status_text = st.empty()
                    
                    status_text.text("📊 Analyzing user permissions and policies...")
                    progress_bar.progress(20)
                    
                    # Get comprehensive permission analysis
                    permission_analysis_result = permission_analysis.analyze_all_user_permissions()
                    
                    progress_bar.progress(100)
                    status_text.text("✅ Analysis completed!")
                    
                    # Clear progress indicators
                    progress_bar.empty()
                    status_text.empty()
                    
                    if 'error' not in permission_analysis_result:
                        # Store results in session state
                        st.session_state.permission_analysis_data = permission_analysis_result
                        st.session_state.permission_analysis_complete = True
                        st.success("✅ Analysis completed! Results are now cached and will persist across page interactions.")
                        st.rerun()
                    else:
                        st.error(f"Error analyzing permissions: {permission_analysis_result['error']}")
            
            except Exception as e:
                st.error(f"Error analyzing permissions: {str(e)}")
        
        # Display results if analysis is complete
        if st.session_state.permission_analysis_complete and st.session_state.permission_analysis_data:
            permission_analysis_result = st.session_state.permission_analysis_data
            summary_stats = permission_analysis_result['summary_stats']
            user_analyses = permission_analysis_result['user_analyses']
            ai_summary = permission_analysis_result.get('ai_summary', '')
            
            # Add timestamp info
            analysis_time = permission_analysis_result.get('timestamp', 'Unknown')
            st.info(f"📅 **Analysis completed at:** {analysis_time}")
            
            # Summary Statistics Cards
            st.markdown("### 📊 Account Overview")
            col1, col2, col3, col4 = st.columns(4)
            with col1:
                st.metric("👥 Total Users", summary_stats['total_users'])
            with col2:
                high_risk = len([u for u in user_analyses if u['risk_level'] == 'High'])
                st.metric("🔴 High Risk Users", high_risk)
            with col3:
                admin_users = len([u for u in user_analyses if u['has_admin_access']])
                st.metric("⚡ Admin Users", admin_users)
            with col4:
                inactive_users = len([u for u in user_analyses if not u.get('last_activity_date')])
                st.metric("💤 Inactive Users", inactive_users)
            
            # AI-Generated Summary
            if ai_summary:
                with st.expander("🤖 AI Security Assessment", expanded=True):
                    st.write(ai_summary)
                    # Display token usage metrics
                    display_token_metrics()
            
            # Detailed permissions view
            st.markdown("### 🔑 User Permissions Analysis")
            
            # Add CSS for permission cards
            st.markdown(
                """
                <style>
                .permission-card {
                    border-radius: 10px;
                    padding: 20px;
                    margin: 10px 0;
                    border: 1px solid rgba(49, 51, 63, 0.2);
                    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                }
                .permission-card-high {
                    background-color: #2c2c34;
                    border-top: 4px solid #ff4b4b;
                    color: white;
                }
                .permission-card-medium {
                    background-color: #1f1f27;
                    border-top: 4px solid #ffa726;
                    color: white;
                }
                .permission-card-low {
                    background-color: #1a1a22;
                    border-top: 4px solid #2e7d32;
                    color: white;
                }
                .metric-container {
                    background-color: rgba(255, 255, 255, 0.05);
                    padding: 10px;
                    border-radius: 6px;
                    margin: 5px 0;
                    border: 1px solid rgba(255, 255, 255, 0.1);
                }
                </style>
                """,
                unsafe_allow_html=True
            )
            
            # Create columns for the grid layout
            cols = st.columns(3)
            col_idx = 0
            
            for user in user_analyses:
                with cols[col_idx]:
                    risk_class = {
                        "High": "permission-card-high",
                        "Medium": "permission-card-medium",
                        "Low": "permission-card-low"
                    }.get(user['risk_level'], "")
                    
                    total_policies = len(user['attached_policies']) + len(user['inline_policies']) + len(user['group_policies'])
                    
                    st.markdown(
                        f"""<div class="permission-card {risk_class}">
                            <h4>👤 {user['username']}</h4>
                            <div class="metric-container">
                                <strong>Risk Level:</strong> {user['risk_level']}<br>
                                <strong>Admin Access:</strong> {'Yes ⚠️' if user['has_admin_access'] else 'No ✅'}<br>
                                <strong>Last Activity:</strong> {user.get('last_activity_date') or 'Never'}
                            </div>
                            <div class="metric-container">
                                <strong>Policy Summary:</strong><br>
                                Attached: {len(user['attached_policies'])}<br>
                                Inline: {len(user['inline_policies'])}<br>
                                Group: {len(user['group_policies'])}<br>
                                Total: {total_policies}
                            </div>
                        </div>""",
                        unsafe_allow_html=True
                    )
                    
                    # Show capabilities summary
                    if user['capabilities']:
                        with st.expander("🛠️ Key Capabilities"):
                            caps_to_show = user['capabilities'][:5]
                            for cap in caps_to_show:
                                st.markdown(f"- {cap}")
                            if len(user['capabilities']) > 5:
                                st.markdown(f"- ... and {len(user['capabilities']) - 5} more")
                    
                    # Show detailed policies button
                    if st.button(f"📜 View Policies", key=f"view_policies_{user['username']}"):
                        with st.expander("Detailed Policies", expanded=True):
                            policy_tab1, policy_tab2, policy_tab3 = st.tabs([
                                "Attached",
                                "Inline",
                                "Group"
                            ])
                            
                            with policy_tab1:
                                if user['attached_policies']:
                                    for policy in user['attached_policies']:
                                        st.code(policy, language="json")
                                else:
                                    st.info("No attached policies")
                            
                            with policy_tab2:
                                if user['inline_policies']:
                                    for policy in user['inline_policies']:
                                        st.code(policy, language="json")
                                else:
                                    st.info("No inline policies")
                            
                            with policy_tab3:
                                if user['group_policies']:
                                    for policy in user['group_policies']:
                                        st.code(policy, language="json")
                                else:
                                    st.info("No group policies")
                    
                col_idx = (col_idx + 1) % 3
                
                # Add a separator between rows
                if col_idx == 0:
                    st.markdown("---")
            
            # Export Option
            st.markdown("### 📥 Export Analysis")
            if st.button("📊 Export User Analysis to Excel"):
                try:
                    # Create Excel file with summary
                    from io import BytesIO
                    import xlsxwriter
                    
                    output = BytesIO()
                    workbook = xlsxwriter.Workbook(output, {'in_memory': True})
                    
                    # Risk Analysis sheet
                    risk_sheet = workbook.add_worksheet('Risk Analysis')
                    risk_data = []
                    for user in user_analyses:
                        risk_data.append({
                            'Username': user['username'],
                            'Risk Level': user['risk_level'],
                            'Admin Access': user['has_admin_access'],
                            'Last Activity': user['last_activity_date'] or 'Never',
                            'Attached Policies': len(user['attached_policies']),
                            'Inline Policies': len(user['inline_policies']),
                            'Group Policies': len(user['group_policies']),
                            'Risk Factors': ', '.join(user.get('risk_factors', []))
                        })
                    pd.DataFrame(risk_data).to_excel(writer=workbook, sheet_name='Risk Analysis', index=False)
                    
                    # Detailed Permissions sheet
                    details_sheet = workbook.add_worksheet('Detailed Permissions')
                    details_data = []
                    for user in user_analyses:
                        details_data.append({
                            'Username': user['username'],
                            'Capabilities': ', '.join(user['capabilities']),
                            'Attached Policies': ', '.join([str(p) for p in user['attached_policies']]),
                            'Inline Policies': ', '.join([str(p) for p in user['inline_policies']]),
                            'Group Policies': ', '.join([str(p) for p in user['group_policies']])
                        })
                    pd.DataFrame(details_data).to_excel(writer=workbook, sheet_name='Detailed Permissions', index=False)
                    
                    workbook.close()
                    
                    st.download_button(
                        label="📥 Download User Analysis Report",
                        data=output.getvalue(),
                        file_name=f"user_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx",
                        mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
                    )
                except Exception as e:
                    st.error(f"Error creating Excel export: {str(e)}")
            
            elif not st.session_state.permission_analysis_complete:
                st.info("👆 Click 'Analyze All User Permissions' to start the comprehensive analysis of user permissions and policies.")

    # Compliance Reports Tab
    with audit_tab5:
        st.subheader("📋 Compliance Reports")
        st.markdown("*Generate comprehensive compliance reports for auditing purposes*")
        
        if st.button("📋 Generate Compliance Report", type="primary"):
            try:
                with st.spinner("🔄 Generating compliance report..."):
                    # Generate compliance report using the audit helper
                    compliance_report = audit_report.generate_compliance_report()
                    
                    if 'error' not in compliance_report:
                        st.success("✅ Compliance report generated successfully!")
                        
                        # Display compliance metrics
                        metrics = compliance_report.get('compliance_metrics', {})
                        if metrics:
                            st.markdown("### 📊 Compliance Summary")
                            col1, col2, col3, col4 = st.columns(4)
                            
                            with col1:
                                overall_score = metrics.get('overall_score', 0)
                                st.metric("🎯 Overall Score", f"{overall_score}/100")
                            
                            with col2:
                                findings_count = len(metrics.get('findings', []))
                                st.metric("⚠️ Total Findings", findings_count)
                            
                            with col3:
                                policy_compliance = metrics.get('password_policy_compliance', 0)
                                st.metric("🔑 Password Policy", f"{policy_compliance:.1f}%")
                            
                            with col4:
                                mfa_compliance = metrics.get('mfa_compliance_rate', 0)
                                st.metric("🔐 MFA Compliance", f"{mfa_compliance:.1f}%")
                            
                            # Root usage incidents
                            root_incidents = metrics.get('root_usage_incidents', 0)
                            if root_incidents > 0:
                                st.warning(f"⚠️ {root_incidents} root account usage incidents detected")
                            else:
                                st.success("✅ No root account usage incidents")
                        
                        # Recommendations
                        recommendations = compliance_report.get('recommendations', [])
                        if recommendations:
                            st.markdown("### 💡 Security Recommendations")
                            for i, recommendation in enumerate(recommendations, 1):
                                st.write(f"{i}. {recommendation}")
                        
                        # Detailed findings
                        detailed_findings = compliance_report.get('detailed_findings', {})
                        
                        # Password Policy Details
                        password_policy = detailed_findings.get('password_policy', {})
                        if password_policy and 'error' not in password_policy:
                            st.markdown("### 🔑 Password Policy Details")
                            policy_df = []
                            for setting, details in password_policy.items():
                                if isinstance(details, dict):
                                    policy_df.append({
                                        'Setting': setting.replace('_', ' ').title(),
                                        'Current': str(details.get('current', 'N/A')),
                                        'Recommended': str(details.get('recommended', 'N/A')),
                                        'Compliant': '✅' if details.get('compliant', False) else '❌'
                                    })
                            
                            if policy_df:
                                st.dataframe(pd.DataFrame(policy_df), use_container_width=True)
                        
                        # MFA Status Details
                        mfa_status = detailed_findings.get('mfa_status', {})
                        if mfa_status and 'error' not in mfa_status:
                            st.markdown("### 🔐 MFA Status Details")
                            
                            # MFA metrics
                            col1, col2, col3 = st.columns(3)
                            with col1:
                                st.metric("Console Users", mfa_status.get('console_users', 0))
                            with col2:
                                st.metric("MFA Enabled", mfa_status.get('console_mfa_enabled', 0))
                            with col3:
                                st.metric("MFA Disabled", mfa_status.get('console_mfa_disabled', 0))
                            
                            # Users without MFA
                            users_without_mfa = mfa_status.get('console_users_without_mfa', [])
                            if users_without_mfa:
                                st.markdown("#### Users Without MFA")
                                for user in users_without_mfa:
                                    st.warning(f"⚠️ {user}")
                        
                        # Root Usage Details
                        root_usage = detailed_findings.get('root_usage', [])
                        if root_usage and len(root_usage) > 0 and 'error' not in root_usage[0]:
                            st.markdown("### 👑 Root Account Usage Details")
                            root_df = pd.DataFrame(root_usage)
                            st.dataframe(root_df, use_container_width=True)
                        
                        # Export compliance report
                        st.markdown("### 📥 Export Report")
                        if st.button("📊 Export Compliance Report to Excel"):
                            try:
                                # Create a temporary file for export
                                temp_filename = f"compliance_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx"
                                audit_report.export_to_excel(temp_filename)
                                
                                # Read the file for download
                                with open(temp_filename, 'rb') as f:
                                    excel_data = f.read()
                                
                                st.download_button(
                                    label="📥 Download Compliance Report",
                                    data=excel_data,
                                    file_name=temp_filename,
                                    mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
                                )
                                
                                # Clean up temporary file
                                import os
                                if os.path.exists(temp_filename):
                                    os.remove(temp_filename)
                                
                            except Exception as e:
                                st.error(f"Error exporting report: {str(e)}")
                    
                    else:
                        st.error(f"Error generating compliance report: {compliance_report['error']}")
            
            except Exception as e:
                st.error(f"Error generating compliance report: {str(e)}")

# Footer
st.markdown("---")
st.markdown("Built with ❤️ using Streamlit and AWS CloudTrail")
