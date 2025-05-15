from dotenv import load_dotenv
import openai
import boto3
import os
import json
from datetime import datetime, timedelta
import time
from typing import Optional, List, Dict, Any, Tuple
import re

class CloudTrailQuery:
    def __init__(self):
        # Load environment variables
        load_dotenv()
        
        # Initialize OpenAI client with a stronger model
        api_key = os.getenv('OPENAI_API_KEY')
        if not api_key:
            raise ValueError("OpenAI API key not found in environment variables")
        self.client = openai.OpenAI(api_key=api_key)
        self.model = "gpt-4"  # Using GPT-4 model
        self.max_retries = 3
        
        # Initialize AWS clients with error handling
        try:
            self.cloudtrail = boto3.client('cloudtrail')
            self.logs = boto3.client('logs')
        except Exception as e:
            print(f"Error initializing AWS clients: {str(e)}")
            print("Please ensure you have the required AWS SDK dependencies installed:")
            print("pip install boto3 pandas pyarrow")
            raise

    def generate_query(self, query: str, hours: int = 24) -> Optional[str]:
        """Generate a CloudWatch Logs Insights query from natural language.
        
        Args:
            query: Natural language query
            hours: Time window in hours
            
        Returns:
            CloudWatch Logs Insights query string or None if generation fails
        """
        # Calculate time range
        end_time = datetime.now()
        start_time = end_time - timedelta(hours=hours)
        
        # Convert to milliseconds since epoch
        start_time_ms = int(start_time.timestamp() * 1000)
        end_time_ms = int(end_time.timestamp() * 1000)
        
        # Construct a simple, direct prompt
        prompt = f"""Convert this natural language query into a CloudWatch Logs Insights query.
Time range: {start_time_ms} to {end_time_ms}

Rules:
1. Start with: fields @timestamp, @message
2. Add time filter: filter @timestamp >= {start_time_ms} and @timestamp <= {end_time_ms}
3. Add your specific filters
4. End with: sort @timestamp desc | limit 1000

Example:
Input: "Show me all S3 bucket creations"
Output: fields @timestamp, @message | filter @timestamp >= {start_time_ms} and @timestamp <= {end_time_ms} | filter @message like /CreateBucket/ | sort @timestamp desc | limit 1000

Now convert this query: "{query}"

Respond with ONLY the query, nothing else."""

        try:
            # Generate query using GPT-4
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "You are a CloudWatch Logs Insights query generator."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.3,
                max_tokens=500
            )
            
            return response.choices[0].message.content.strip()
            
        except Exception as e:
            print(f"Error generating query: {str(e)}")
            return None

    def execute_query(self, query):
        """Execute CloudWatch Logs Insights query and return results."""
        try:
            print(f"Executing query:\n{query}")
            
            # Calculate time range
            end_time = datetime.now()
            start_time = end_time - timedelta(hours=24)
            start_time_ms = int(start_time.timestamp() * 1000)
            end_time_ms = int(end_time.timestamp() * 1000)
            
            response = self.logs.start_query(
                logGroupName='/aws/cloudtrail/events',
                startTime=start_time_ms,
                endTime=end_time_ms,
                queryString=query
            )
            query_id = response['queryId']
            
            # Wait for query completion
            while True:
                status = self.logs.get_query_results(queryId=query_id)
                if status['status'] == 'Complete':
                    if not status['results']:
                        return "No events found matching your query."
                    
                    # Log raw results
                    print("\nRaw Results:")
                    print("===========")
                    for result in status['results']:
                        print(json.dumps(result, indent=2))
                    print("===========")
                    
                    return self.format_results(status['results'])
                elif status['status'] == 'Failed':
                    return f"Query failed: {status.get('errorMessage', 'Unknown error')}"
                
                time.sleep(1)
            
        except Exception as e:
            return f"Error executing query: {str(e)}"

    def format_results(self, results: List[Dict[str, Any]]) -> str:
        """Format the query results into a natural language summary."""
        if not results:
            return "No events found matching your query."
            
        try:
            # Initialize data structures for analysis
            events_by_type = {}
            events_by_user = {}
            events_by_resource = {}
            events_by_hour = {}
            error_events = []
            timestamps = []
            
            # Process each event
            for idx, event in enumerate(results):
                try:
                    # Extract timestamp
                    timestamp = event.get('timestamp')
                    if not timestamp:
                        continue
                        
                    timestamps.append(timestamp)
                    # Group by hour for time-based analysis
                    hour = timestamp.split(' ')[1].split(':')[0]  # Extract hour from "2025-05-15 11:17 AM"
                    events_by_hour[hour] = events_by_hour.get(hour, 0) + 1
                    
                    # Track event types
                    event_name = event.get('event_name', 'Unknown')
                    events_by_type[event_name] = events_by_type.get(event_name, 0) + 1
                    
                    # Track users
                    user = event.get('user', 'Unknown')
                    events_by_user[user] = events_by_user.get(user, 0) + 1
                    
                    # Track resources
                    resource = event.get('resource', 'Unknown')
                    events_by_resource[resource] = events_by_resource.get(resource, 0) + 1
                    
                    # Track errors
                    if event.get('errorCode') or event.get('errorMessage'):
                        error_events.append({
                            'timestamp': timestamp,
                            'event_name': event_name,
                            'error_code': event.get('errorCode', 'Unknown'),
                            'error_message': event.get('errorMessage', 'Unknown'),
                            'user': user
                        })
                        
                except Exception as e:
                    print(f"DEBUG: Error processing event {idx + 1}: {str(e)}")
                    continue
            
            if not timestamps:
                return "No valid events found in the results."
            
            # Sort and get top items
            top_events = sorted(events_by_type.items(), key=lambda x: x[1], reverse=True)
            top_users = sorted(events_by_user.items(), key=lambda x: x[1], reverse=True)
            top_resources = sorted(events_by_resource.items(), key=lambda x: x[1], reverse=True)
            
            # Create a conversational summary
            summary_parts = []
            
            # Overview
            summary_parts.append(f"Here's what I found in the last {len(results)} events:")
            
            # User Activity Summary
            if top_users:
                summary_parts.append("\nUser Activity:")
                for user, count in top_users:
                    user_events = [e for e in results if e.get('user') == user]
                    
                    # Group events by type and count
                    event_counts = {}
                    for event in user_events:
                        event_name = event.get('event_name', 'Unknown')
                        event_counts[event_name] = event_counts.get(event_name, 0) + 1
                    
                    # Get unique resources
                    user_resources = set(e.get('resource', 'Unknown') for e in user_events if e.get('resource') != 'Unknown')
                    
                    summary_parts.append(f"\n• {user.split('/')[-1]} was active:")
                    
                    # List their actions in a grouped format
                    if event_counts:
                        summary_parts.append("  Actions performed:")
                        for event_name, event_count in sorted(event_counts.items(), key=lambda x: x[1], reverse=True):
                            summary_parts.append(f"  - {event_name}: {event_count} times")
                    
                    # List resources they interacted with
                    if user_resources:
                        summary_parts.append("  Resources accessed:")
                        for resource in user_resources:
                            summary_parts.append(f"  - {resource}")
            
            # Resource Activity Summary
            if top_resources:
                summary_parts.append("\nResource Activity:")
                for resource, count in top_resources:
                    if resource == 'Unknown':
                        continue
                    resource_events = [e for e in results if e.get('resource') == resource]
                    
                    # Group events by type and count
                    event_counts = {}
                    for event in resource_events:
                        event_name = event.get('event_name', 'Unknown')
                        event_counts[event_name] = event_counts.get(event_name, 0) + 1
                    
                    summary_parts.append(f"\n• {resource}:")
                    if event_counts:
                        for event_name, event_count in sorted(event_counts.items(), key=lambda x: x[1], reverse=True):
                            summary_parts.append(f"  - {event_name}: {event_count} times")
            
            # Error Summary
            if error_events:
                summary_parts.append("\nNotable Issues:")
                for error in error_events:
                    summary_parts.append(f"\n• {error['timestamp']}:")
                    summary_parts.append(f"  - {error['user'].split('/')[-1]} encountered an error while {error['event_name']}")
                    summary_parts.append(f"  - Error: {error['error_message']}")
            
            # Add note about raw data
            summary_parts.append("\nNote: For complete event details, please check the raw results above.")
            
            return "\n".join(summary_parts)
            
        except Exception as e:
            print(f"Error formatting results: {str(e)}")
            return f"Error processing results. Raw results available above. Error: {str(e)}"

# Example usage:
if __name__ == "__main__":
    query_helper = CloudTrailQuery()
    
    # Example query
    query = query_helper.generate_query("Show me all S3 bucket creations in the last 24 hours")
    results = query_helper.execute_query(query)
    print("\nFormatted Results:")
    print(results) 