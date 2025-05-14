from dotenv import load_dotenv
from openai import OpenAI
import boto3
import os
import json
from datetime import datetime, timedelta
import time

class CloudTrailQuery:
    def __init__(self):
        # Load environment variables
        load_dotenv()
        
        # Initialize OpenAI client
        api_key = os.getenv('OPENAI_API_KEY')
        if not api_key:
            raise ValueError("OpenAI API key not found in environment variables")
        self.client = OpenAI(api_key=api_key)
        
        # Initialize AWS clients
        self.cloudtrail = boto3.client('cloudtrail')
        self.logs = boto3.client('logs')

    def generate_query(self, natural_query, hours: int = 24):
        """Generate CloudTrail query using OpenAI."""
        prompt = f"""You are an expert AWS CloudTrail query generator. Convert natural language questions into accurate, production-ready CloudTrail queries.

Use CloudWatch Logs Insights format. Your output should:
- Include fields: @timestamp, eventName, eventSource, userIdentity.arn, sourceIPAddress, awsRegion
- Use correct eventName (e.g., "AuthorizeSecurityGroupIngress")
- Use eventSource like 'ec2.amazonaws.com', 's3.amazonaws.com'
- Use 'ago(24h)' or other correct date filters
- Filter on userIdentity.arn if user is specified
- Sort by @timestamp desc and limit to 1000
- Return ONLY the query (no explanation, no markdown)

Examples:

Prompt: Who modified security groups recently?
Output:
fields @timestamp, eventName, eventSource, userIdentity.arn, sourceIPAddress, awsRegion
| filter eventSource = 'ec2.amazonaws.com'
| filter eventName in ['AuthorizeSecurityGroupIngress', 'AuthorizeSecurityGroupEgress', 'RevokeSecurityGroupIngress', 'RevokeSecurityGroupEgress']
| filter @timestamp >= ago(24h)
| sort @timestamp desc
| limit 1000

Prompt: What did user arn:aws:iam::123456789012:user/Alice do in the last 2 days?
Output:
fields @timestamp, eventName, eventSource, userIdentity.arn, sourceIPAddress, awsRegion
| filter userIdentity.arn = 'arn:aws:iam::123456789012:user/Alice'
| filter @timestamp >= ago(48h)
| sort @timestamp desc
| limit 1000

Prompt: {natural_query}
Output:"""

        try:
            response = self.client.chat.completions.create(
                model="gpt-3.5-turbo",
                messages=[
                    {"role": "system", "content": "You are an expert AWS CloudTrail query generator."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.1
            )
            
            query = response.choices[0].message.content.strip()
            if hours != 24:
                query = query.replace('ago(24h)', f'ago({hours}h)')
            
            return query
            
        except Exception as e:
            return f"Error generating query: {str(e)}"

    def execute_query(self, query):
        """Execute CloudWatch Logs Insights query and return results."""
        try:
            print(f"Executing query:\n{query}")
            
            response = self.logs.start_query(
                logGroupName='/aws/cloudtrail/events',
                startTime=int((datetime.now() - timedelta(hours=24)).timestamp() * 1000),
                endTime=int(datetime.now().timestamp() * 1000),
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

    def format_results(self, results):
        """Format query results into a readable summary."""
        try:
            events = []
            for result in results:
                try:
                    # Parse the message field
                    message = result.get('@message', '{}')
                    if isinstance(message, str):
                        event = json.loads(message)
                    else:
                        event = message
                    
                    # Extract relevant fields
                    events.append({
                        'time': result.get('@timestamp', 'Unknown'),
                        'event': event.get('eventName', 'Unknown'),
                        'service': event.get('eventSource', 'Unknown').split('.')[0],
                        'user': event.get('userIdentity', {}).get('arn', 'Unknown'),
                        'ip': event.get('sourceIPAddress', 'Unknown'),
                        'region': event.get('awsRegion', 'Unknown'),
                        'error': event.get('errorCode', '')
                    })
                except Exception as e:
                    print(f"Error parsing event: {str(e)}")
                    continue
            
            if not events:
                return "No valid events found."
            
            # Group events by service and action
            summary = []
            current_service = None
            
            for event in events:
                if current_service != event['service']:
                    current_service = event['service']
                    summary.append(f"\n{current_service.upper()} Events:")
                
                # Format the event line
                event_line = f"• [{event['time']}] {event['event']}"
                if event['error']:
                    event_line += f" (Error: {event['error']})"
                
                summary.append(event_line)
            
            return "\n".join(summary)
            
        except Exception as e:
            return f"Error formatting results: {str(e)}"

# Example usage:
if __name__ == "__main__":
    query_helper = CloudTrailQuery()
    
    # Example query
    query = query_helper.generate_query("Show me all S3 bucket creations in the last 24 hours")
    results = query_helper.execute_query(query)
    print("\nFormatted Results:")
    print(results) 