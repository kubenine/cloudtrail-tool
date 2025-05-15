import streamlit as st
import pandas as pd
from datetime import datetime, timedelta
from cloudtrail_helper import CloudTrailHelper
from user_activity_helper import UserActivityHelper
from sso_activity_helper import SSOActivityHelper
from resource_activity_helper import ResourceActivityHelper
import os
from dotenv import load_dotenv

# Page config - MUST BE THE FIRST STREAMLIT COMMAND
st.set_page_config(
    page_title="CloudTrail Intelligence Dashboard",
    page_icon="🔍",
    layout="wide"
)

# Load environment variables
load_dotenv()


# Debug: Check if environment variables are loaded
aws_access_key = os.getenv('AWS_ACCESS_KEY_ID')
aws_secret_key = os.getenv('AWS_SECRET_ACCESS_KEY')
aws_region = os.getenv('AWS_DEFAULT_REGION')
openai_api_key = os.getenv('OPENAI_API_KEY')

# Sidebar for credentials (for testing only)
st.sidebar.header("AWS Credentials (Testing)")
use_env_credentials = st.sidebar.checkbox("Use credentials from .env file", value=True)

if not use_env_credentials:
    aws_access_key = st.sidebar.text_input("AWS Access Key ID", value=aws_access_key or "")
    aws_secret_key = st.sidebar.text_input("AWS Secret Access Key", value=aws_secret_key or "", type="password")
    aws_region = st.sidebar.text_input("AWS Region", value=aws_region or "us-east-1")
    openai_api_key = st.sidebar.text_input("OpenAI API Key", value=openai_api_key or "", type="password")
    
    # Set environment variables for the session
    if aws_access_key and aws_secret_key and aws_region:
        os.environ['AWS_ACCESS_KEY_ID'] = aws_access_key
        os.environ['AWS_SECRET_ACCESS_KEY'] = aws_secret_key
        os.environ['AWS_DEFAULT_REGION'] = aws_region
    if openai_api_key:
        os.environ['OPENAI_API_KEY'] = openai_api_key

if not all([aws_access_key, aws_secret_key, aws_region]):
    st.error("""
    AWS credentials not found. Please either:
    1. Check your .env file, or
    2. Enter credentials in the sidebar
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
tab1, tab2, tab3, tab4 = st.tabs(["Natural Language Search", "IAM User Activity", "SSO User Activity", "Resource Activity"])

# Natural Language Search Tab
with tab1:
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
                    
                    if results:
                        st.success(f"Search completed! Found {len(results)} results.")
                        
                        # Display the natural language summary
                        st.markdown("### Summary")
                        st.write(summary)
                        
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
                    else:
                        # Enhanced empty results handling
                        st.info("🔍 No events found matching your query.")
                        
                        # Show the generated query for transparency
                        with st.expander("View Generated CloudWatch Logs Insights Query"):
                            st.code(cloudtrail.query_helper.generate_query(query, hours=time_window), language="sql")
                        
                        # Provide helpful suggestions
                        st.markdown("### Suggestions to improve your search:")
                        col1, col2 = st.columns(2)
                        
                        with col1:
                            st.markdown("**Try adjusting the time window:**")
                            st.markdown("- Increase the time window in the sidebar")
                            st.markdown("- Try a different time period (e.g., 'today' instead of 'last week')")
                            st.markdown("- To query a specific user, give their name with single quotes (e.g., 'John Doe')")
                        
                        with col2:
                            st.markdown("**Try modifying your query:**")
                            st.markdown("- Use more general terms")
                            st.markdown("- Check for typos or specific resource names")
                            st.markdown("- Try one of the example queries above")
            except Exception as e:
                st.error(f"Error performing search: {str(e)}")
        else:
            st.warning("Please enter a search query.")

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
                            
                            st.markdown("---")
                            
                            # Group events by date
                            from collections import defaultdict
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

# SSO User Activity Tab
with tab3:
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
                            
                            st.markdown("---")
                            
                            # Group events by date
                            from collections import defaultdict
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
                    
                    st.markdown("---")
                    
                    # Group events by date
                    from collections import defaultdict
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

# Footer
st.markdown("---")
st.markdown("Built with ❤️ using Streamlit and AWS CloudTrail")
