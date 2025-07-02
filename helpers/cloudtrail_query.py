from dotenv import load_dotenv
import openai
import os
import json
import time
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
from collections import defaultdict
from utils import token_counter
from .aws_auth import AWSAuth

class CloudTrailQuery:
    def __init__(self):
        # Load environment variables
        load_dotenv()
        
        # Initialize OpenAI client with a stronger model
        api_key = os.getenv('OPENAI_API_KEY')
        if not api_key:
            raise ValueError("OpenAI API key not found in environment variables")
        self.client = openai.OpenAI(api_key=api_key)
        self.model = "gpt-4.1"
        self.max_retries = 3
        
        # Initialize AWS clients with error handling
        try:
            self.aws_auth = AWSAuth()
            self.cloudtrail = self.aws_auth.create_client('cloudtrail')
            self.logs = self.aws_auth.create_client('logs')
        except Exception as e:
            print(f"Error initializing AWS clients: {str(e)}")
            print("Please ensure you have valid AWS credentials configured.")
            raise

    def generate_query(self, natural_language_query: str, hours: int = 24) -> str:
        """Generate CloudWatch Logs Insights query from natural language."""
        # This is a simplified implementation
        # In practice, you'd use NLP to parse the query and generate appropriate CloudWatch query
        
        base_query = f"""
        fields @timestamp, eventName, userIdentity.userName, sourceIPAddress, awsRegion
        | filter @timestamp > now() - {hours}h
        | sort @timestamp desc
        | limit 100
        """
        
        # Add filters based on common query patterns
        query_lower = natural_language_query.lower()
        
        if "s3" in query_lower:
            base_query += "| filter eventSource = 's3.amazonaws.com'"
        elif "ec2" in query_lower:
            base_query += "| filter eventSource = 'ec2.amazonaws.com'"
        elif "iam" in query_lower:
            base_query += "| filter eventSource = 'iam.amazonaws.com'"
        elif "root" in query_lower:
            base_query += "| filter userIdentity.type = 'Root'"
        
        if "create" in query_lower:
            base_query += "| filter eventName like /Create/"
        elif "delete" in query_lower:
            base_query += "| filter eventName like /Delete/"
        
        return base_query

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
            # Process events and group by user and action
            events_by_user = defaultdict(lambda: defaultdict(list))
            for event in results:
                user = event.get('user', 'Unknown')
                action = event.get('event_name', 'Unknown')
                events_by_user[user][action].append(event)
            
            # Create a natural language summary
            summary_parts = []
            
            # Overall summary
            total_users = len(events_by_user)
            total_events = len(results)
            summary_parts.append(f"Found {total_events} events from {total_users} {'user' if total_users == 1 else 'users'} in the specified time window.\n")
            
            # Summarize activity by user
            for user, actions in events_by_user.items():
                user_display = user.split('/')[-1] if '/' in user else user
                summary_parts.append(f"• {user_display}'s activity:")
                
                for action, events in actions.items():
                    # Group by resource
                    resources = defaultdict(int)
                    for event in events:
                        resources[event.get('resource', 'Unknown')] += 1
                    
                    # Summarize action and resources
                    if len(resources) == 1:
                        resource, count = next(iter(resources.items()))
                        if count == 1:
                            summary_parts.append(f"  - Performed {action} on {resource}")
                        else:
                            summary_parts.append(f"  - Performed {action} {count} times on {resource}")
                    else:
                        summary_parts.append(f"  - Performed {action} on multiple resources:")
                        for resource, count in resources.items():
                            summary_parts.append(f"    • {resource}: {count} {'time' if count == 1 else 'times'}")
            
            # Add any error events at the end
            error_events = [e for e in results if e.get('errorCode') or e.get('errorMessage')]
            if error_events:
                summary_parts.append("\n⚠️ Notable Issues:")
                for error in error_events:
                    user = error.get('user', 'Unknown').split('/')[-1]
                    summary_parts.append(f"• {user} encountered an error while performing {error.get('event_name', 'Unknown')}")
                    summary_parts.append(f"  - Error: {error.get('errorMessage', 'Unknown')}")
            
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