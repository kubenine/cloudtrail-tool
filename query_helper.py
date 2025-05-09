import os
from openai import OpenAI
import json
from datetime import datetime
from collections import defaultdict

class QueryHelper:
    def __init__(self):
        self.client = OpenAI(api_key=os.getenv('OPENAI_API_KEY'))

    def translate_to_cloudtrail_query(self, natural_query):
        """Convert natural language query to CloudWatch Logs Insights query."""
        prompt = f"""Convert this natural language query into a valid CloudWatch Logs Insights query.
The query should search CloudTrail logs and extract relevant information.
Focus on identifying the service (S3, EC2, IAM), action (create, delete, modify), and resource type.

Important rules:
1. Always start with 'fields @timestamp, @message'
2. Use only valid CloudWatch Logs Insights syntax
3. Do not use any functions like timestamp() or date()
4. If not specified any general operations like created, deleted, modified, etc, use the a query that can cover all the cases and display it in the output.
5. If no query is found, try to find the most relevant query using the natural language query, but do not deviate from what is being asked.
6. Use only basic operators: like, not like, and, or
7. Always end with '| sort @timestamp desc'
8. For SSO user queries, include both the user's email and display name in the filter
9. For resource-focused queries, include detailed resource information in the fields
10. Always include userIdentity information to capture both IAM and SSO users

Natural Language Query: {natural_query}

Return ONLY the CloudWatch Logs Insights query string, nothing else.
Example format:
fields @timestamp, @message, userIdentity.userName, userIdentity.principalId, userIdentity.type, requestParameters
| filter @message like /S3/ and @message like /DeleteBucket/
| sort @timestamp desc
"""

        try:
            response = self.client.chat.completions.create(
                model="gpt-3.5-turbo",
                messages=[
                    {"role": "system", "content": "You are a CloudWatch Logs Insights query expert. You only return valid query strings without any explanations."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.3
            )
            query = response.choices[0].message.content.strip()
            
            # Validate the query structure
            if not query.startswith('fields @timestamp, @message'):
                query = 'fields @timestamp, @message, userIdentity.userName, userIdentity.principalId, userIdentity.type, requestParameters\n' + query
            
            if not query.endswith('| sort @timestamp desc'):
                query = query + '\n| sort @timestamp desc'
            
            # Remove any timestamp() or date() functions
            query = query.replace('timestamp(', '@timestamp')
            query = query.replace('date(', '@timestamp')
            
            return query
        except Exception as e:
            print(f"Error translating query: {str(e)}")
            return None

    def format_results(self, results):
        """Format CloudTrail events into a natural language summary using ChatGPT."""
        if not results:
            return "No events found matching your query."
        
        # Prepare events for ChatGPT
        events_data = []
        for event in results:
            # Extract user information
            user = event['user']
            if user == 'Unknown':
                # Try to extract user from ARN or other fields
                if 'request_parameters' in event and isinstance(event['request_parameters'], dict):
                    if 'userName' in event['request_parameters']:
                        user = event['request_parameters']['userName']
                    elif 'roleName' in event['request_parameters']:
                        user = f"Role: {event['request_parameters']['roleName']}"
                    elif 'assumedRole' in event['request_parameters']:
                        user = f"Assumed Role: {event['request_parameters']['assumedRole']}"
                
                # If still unknown, use a more descriptive label
                if user == 'Unknown':
                    user = "System/AWS Service"
            
            # Extract resource information
            resource_info = event['resource']
            if resource_info == 'Unknown' and 'request_parameters' in event:
                params = event['request_parameters']
                if isinstance(params, dict):
                    # Try to extract resource information from common fields
                    resource_fields = ['bucketName', 'instanceId', 'functionName', 'roleName', 'userName', 'groupName']
                    for field in resource_fields:
                        if field in params:
                            resource_info = f"{field}: {params[field]}"
                            break
            
            events_data.append({
                'timestamp': event['timestamp'],
                'user': user,
                'action': event['event_type'],
                'resource': resource_info,
                'source_ip': event['source_ip'],
                'request_parameters': event.get('request_parameters', {})
            })

        prompt = f"""Create a natural, conversational summary of these AWS CloudTrail events.
Focus on describing the resources and actions performed on them in detail.
Write it as if you're explaining to someone what happened, using simple language.
Break down the summary into clear bullet points, where each point tells a complete story.

For example:
• User 'john.doe@company.com' created an S3 bucket named 'my-data-bucket' yesterday at 2:30 PM
• Role 'AdminRole' modified security group 'web-servers' to allow inbound traffic on port 80
• SSO user 'Jane Smith' launched 3 EC2 instances of type t2.micro throughout the day

Events:
{json.dumps(events_data, indent=2)}

Write a clear, natural summary that:
1. Uses bullet points (•) for each main event or group of related events
2. Groups similar events together and summarizes the number of occurrences
3. ALWAYS identifies who performed each action (IAM user, SSO user, or role)
4. Includes detailed resource information (names, IDs, configurations)
5. Describes the specific actions performed on each resource
6. Includes a general time reference like "today", "yesterday", or the full date
7. Omits listing each individual timestamp
8. Uses simple, conversational language
9. Focuses on the impact of the actions on the resources

Return ONLY the bullet-pointed summary, nothing else."""

        try:
            response = self.client.chat.completions.create(
                model="gpt-4-turbo",
                messages=[
                    {"role": "system", "content": "You are a friendly AWS expert explaining CloudTrail events in simple, conversational language using bullet points. Always identify who performed each action and focus on describing the resources and actions in detail."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.7
            )
            summary = response.choices[0].message.content.strip()
            
            # Ensure each bullet point is on a new line
            summary = summary.replace("• ", "\n• ")
            if summary.startswith("\n"):
                summary = summary[1:]  # Remove leading newline if present
            
            return summary
        except Exception as e:
            print(f"Error formatting results: {str(e)}")
            return self._format_basic_summary(results)

    def _format_basic_summary(self, results):
        """Basic formatting fallback if ChatGPT is unavailable."""
        summary = "# Event Summary\n\n"
        
        # Group events by date
        grouped_events = defaultdict(list)
        for event in results:
            date = event['timestamp'].split(' ')[0]
            grouped_events[date].append(event)
        
        # Format each day's events
        for date, events in sorted(grouped_events.items(), reverse=True):
            summary += f"## {date}\n\n"
            
            # Group similar events
            event_groups = defaultdict(list)
            for event in events:
                key = f"{event['event_type']}_{event['resource']}"
                event_groups[key].append(event)
            
            # Format each group of similar events
            for key, group in event_groups.items():
                if len(group) == 1:
                    event = group[0]
                    summary += f"• **{event['event_type']}** by {event['user']} at {event['timestamp'].split(' ')[1]}\n"
                    summary += f"  - Resource: {event['resource']}\n"
                    if event.get('request_parameters'):
                        summary += f"  - Details: {str(event['request_parameters'])[:100]}...\n"
                else:
                    event = group[0]
                    summary += f"• **{event['event_type']}** performed {len(group)} times by {event['user']}\n"
                    summary += f"  - Resource: {event['resource']}\n"
                    summary += f"  - Times: {', '.join(e['timestamp'].split(' ')[1] for e in group)}\n"
            
            summary += "\n"
        
        return summary 