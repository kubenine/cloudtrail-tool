from dotenv import load_dotenv
import openai
import boto3
import os
import json
from datetime import datetime, timedelta
import time
from typing import Optional, List, Dict, Any, Tuple
import re
from utils import token_counter
from collections import defaultdict

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
        # Reset token counter for new query
        token_counter.reset()
        
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
            
            # Update token usage
            token_counter.update_from_response(response)
            
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