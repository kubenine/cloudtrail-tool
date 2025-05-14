import os
from openai import OpenAI
import json
from datetime import datetime, timedelta
from collections import defaultdict
from dotenv import load_dotenv
from pathlib import Path

class QueryHelper:
    def __init__(self):
        # Find and load the .env file
        env_path = None
        
        # Try current directory
        if os.path.exists('.env'):
            env_path = '.env'
        # Try parent directory
        elif os.path.exists('../.env'):
            env_path = '../.env'
        # Try absolute path from project root
        else:
            project_root = Path(__file__).resolve().parent
            env_file = project_root / '.env'
            if env_file.exists():
                env_path = str(env_file)
        
        if env_path:
            load_dotenv(dotenv_path=env_path)
        else:
            print("Warning: No .env file found")
        
        # Get OpenAI API key from environment
        api_key = os.getenv('OPENAI_API_KEY')
        if not api_key:
            raise ValueError("OPENAI_API_KEY not found. Please either:\n1. Check your .env file, or\n2. Enter API key in the sidebar")
            
        self.client = OpenAI(api_key=api_key)

    def translate_to_cloudtrail_query(self, natural_query, hours: int = 24):
        """Convert natural language query to CloudWatch Logs Insights query.
        
        Args:
            natural_query: The natural language query to convert
            hours: Number of hours to look back (from slider)
        """
        # Calculate the time range in milliseconds
        end_time = int(datetime.now().timestamp() * 1000)
        start_time = int((datetime.now() - timedelta(hours=hours)).timestamp() * 1000)
        
        prompt = f"""Convert this natural language query into a valid CloudWatch Logs Insights query.
The query should search CloudTrail logs and extract relevant information.
Focus on identifying the service (S3, EC2, IAM), action (create, delete, modify), and resource type.

Important rules:
1. Always start with 'fields @timestamp, @message, userIdentity.userName, userIdentity.principalId, userIdentity.type, requestParameters, eventName'
2. Use only valid CloudWatch Logs Insights syntax
3. Do not use any functions like timestamp() or date()
4. Use only basic operators: like, not like, and, or
5. Always end with '| sort @timestamp desc'
6. For SSO user queries, include both the user's email and display name in the filter
7. For resource-focused queries, include detailed resource information in the fields
8. Always include userIdentity information to capture both IAM and SSO users
9. Keep the query simple and focused on the main intent
10. Use exact matches when possible instead of partial matches
11. For general queries without specific service/action, use broader filters
12. Include error information when relevant
13. Consider both successful and failed actions
14. Handle time-based queries appropriately
15. Include relevant AWS service names in filters
16. Always use 'eventName' instead of 'event_type' for event filtering
17. Use parse @message as @message when filtering on specific fields
18. Always include time range filter based on @timestamp

Time Range:
- Start Time (Unix ms): {start_time}
- End Time (Unix ms): {end_time}
- Looking back {hours} hours

Common query patterns:
- "show all" or "list all" -> Return all events with basic filtering
- Service specific (e.g., "s3", "ec2", "iam") -> Filter for that service
- Action specific (e.g., "create", "delete", "modify") -> Filter eventName
- Resource specific (e.g., "bucket", "instance", "role") -> Filter for that resource type
- User specific (e.g., "user", "admin") -> Filter userIdentity.userName
- Time specific (e.g., "today", "yesterday", "last hour") -> Add time-based filter
- Error specific (e.g., "error", "failed", "denied") -> Include error information

Natural Language Query: {natural_query}

Return ONLY the CloudWatch Logs Insights query string, nothing else.
Example formats:
1. General query:
fields @timestamp, @message, userIdentity.userName, userIdentity.principalId, userIdentity.type, requestParameters, errorCode, errorMessage, eventName
| parse @message as @message
| filter @timestamp >= {start_time} and @timestamp <= {end_time}
| filter @message like /.*/
| sort @timestamp desc

2. Service specific:
fields @timestamp, @message, userIdentity.userName, userIdentity.principalId, userIdentity.type, requestParameters, errorCode, errorMessage, eventName
| parse @message as @message
| filter @timestamp >= {start_time} and @timestamp <= {end_time}
| filter @message like /S3/
| sort @timestamp desc

3. Action specific:
fields @timestamp, @message, userIdentity.userName, userIdentity.principalId, userIdentity.type, requestParameters, errorCode, errorMessage, eventName
| parse @message as @message
| filter @timestamp >= {start_time} and @timestamp <= {end_time}
| filter eventName like /Create/
| sort @timestamp desc

4. User specific:
fields @timestamp, @message, userIdentity.userName, userIdentity.principalId, userIdentity.type, requestParameters, errorCode, errorMessage, eventName
| parse @message as @message
| filter @timestamp >= {start_time} and @timestamp <= {end_time}
| filter userIdentity.userName like /admin/
| sort @timestamp desc"""

        try:
            response = self.client.chat.completions.create(
                model="gpt-3.5-turbo",
                messages=[
                    {"role": "system", "content": """You are a CloudWatch Logs Insights query expert. You only return valid query strings without any explanations.
Keep queries simple and focused. Handle both specific and general queries effectively.
For simple or vague queries, return a more general query that will show relevant results.
For service names (S3, EC2, etc.), always include variations in the filter (e.g., 's3' and 'S3').
Always use 'eventName' instead of 'event_type' in your queries.
Always include time range filters using @timestamp."""},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.3
            )
            query = response.choices[0].message.content.strip()
            
            # Validate and enhance the query structure
            if not query.startswith('fields @timestamp, @message'):
                query = 'fields @timestamp, @message, userIdentity.userName, userIdentity.principalId, userIdentity.type, requestParameters, eventName\n' + query
            
            if not query.endswith('| sort @timestamp desc'):
                query = query + '\n| sort @timestamp desc'
            
            # Remove any timestamp() or date() functions
            query = query.replace('timestamp(', '@timestamp')
            query = query.replace('date(', '@timestamp')
            
            # Add error information if not present
            if 'errorCode' not in query and 'errorMessage' not in query:
                query = query.replace('fields @timestamp, @message', 'fields @timestamp, @message, errorCode, errorMessage')
            
            # Ensure eventName is included in fields
            if 'eventName' not in query:
                query = query.replace('fields @timestamp', 'fields @timestamp, eventName')
            
            # Add parse @message if not present
            if 'parse @message' not in query:
                query = query.replace('filter', '| parse @message as @message\n| filter')
            
            # Ensure time range filter is present
            time_filter = f"| filter @timestamp >= {start_time} and @timestamp <= {end_time}"
            if '@timestamp >=' not in query:
                if '| filter' in query:
                    query = query.replace('| filter', f'{time_filter}\n| filter')
                else:
                    query = query + f'\n{time_filter}'
            
            # For general queries without specific filters, add a basic filter
            if 'filter' not in query.lower():
                query = query.replace('fields @timestamp, @message', f'fields @timestamp, @message\n| parse @message as @message\n{time_filter}\n| filter @message like /.*/')
            
            # Replace any instances of event_type with eventName
            query = query.replace('event_type', 'eventName')
            
            # For service-specific queries, ensure both lowercase and uppercase variations are included
            for service in ['s3', 'ec2', 'iam', 'lambda', 'dynamodb', 'rds']:
                if service in query.lower():
                    query = query.replace(f'like /{service}/', f'like /{service.upper()}/ or @message like /{service.lower()}/')
            
            return query
        except Exception as e:
            print(f"Error generating query: {str(e)}")
            return None

    def format_results(self, results):
        """Format CloudTrail events into a natural language summary using ChatGPT."""
        if not results:
            return "No events found matching your query."
        
        # Prepare events for ChatGPT with limited data
        events_data = []
        for event in results:
            try:
                # Extract user information from event data
                user = event.get('user', 'Unknown')
                
                # Extract resource information
                resource_info = event.get('resource', 'Unknown')
                
                # Extract event name (use eventName instead of event_type)
                event_name = event.get('eventName', event.get('event_name', 'Unknown'))
                
                # Extract error information if present
                error_info = ""
                if 'errorCode' in event:
                    error_info = f" (Error: {event['errorCode']})"
                
                # Only include essential fields to reduce token count
                events_data.append({
                    'time': event.get('timestamp', 'Unknown'),
                    'user': user,
                    'action': event_name + error_info,
                    'resource': resource_info,
                    'service': self._extract_service_from_event(event_name)
                })
            except Exception as e:
                print(f"Error processing event: {str(e)}")
                continue

        # Limit the number of events to process
        max_events = 50
        if len(events_data) > max_events:
            events_data = events_data[:max_events]
            events_data.append({
                'note': f"... and {len(results) - max_events} more events"
            })

        prompt = f"""Summarize these AWS CloudTrail events in a clear, concise format.
Focus on who did what to which resource and when.

Events:
{json.dumps(events_data, indent=2)}

Rules for summary:
1. Use bullet points (•)
2. Each bullet point should follow this format: "User [username] [action] [resource] at [time]"
3. Group similar events together with a count
4. Keep descriptions simple and direct
5. Include exact times for important actions
6. Skip redundant information
7. Focus on the most important details
8. Use consistent formatting
9. Keep it concise and to the point
10. Avoid technical jargon unless necessary
11. Include error information when present
12. Group events by user when possible
13. Highlight unusual or important actions
14. Include time ranges for grouped events
15. Maintain chronological order
16. For general queries, group by service type
17. Include service names for clarity
18. Highlight patterns in user behavior

Example format:
• User john.doe@company.com created S3 bucket my-bucket at 2:30 PM
• User admin-role modified IAM policy admin-policy at 3:15 PM
• User jane.smith@company.com deleted 3 EC2 instances between 4:00 PM and 4:30 PM
• User system-role failed to create Lambda function (Error: AccessDenied) at 5:00 PM"""

        try:
            response = self.client.chat.completions.create(
                model="gpt-3.5-turbo",
                messages=[
                    {"role": "system", "content": "You are an AWS expert explaining CloudTrail events in a clear, concise format. Focus on who did what to which resource and when. Include error information when relevant. Group similar events and highlight patterns."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.7,
                max_tokens=1000
            )
            summary = response.choices[0].message.content.strip()
            
            # Ensure each bullet point is on a new line
            summary = summary.replace("• ", "\n• ")
            if summary.startswith("\n"):
                summary = summary[1:]  # Remove leading newline if present
            
            return summary
        except Exception:
            return self._format_basic_summary(results)

    def _format_basic_summary(self, results):
        """Basic formatting fallback if ChatGPT is unavailable."""
        summary = "# Event Summary\n\n"
        
        # Group events by date
        grouped_events = defaultdict(list)
        for event in results:
            try:
                date = event.get('timestamp', '').split(' ')[0]
                if date:
                    grouped_events[date].append(event)
            except Exception:
                continue
        
        # Format each day's events
        for date, events in sorted(grouped_events.items(), reverse=True):
            summary += f"## {date}\n\n"
            
            # Group similar events
            event_groups = defaultdict(list)
            for event in events:
                try:
                    key = f"{event.get('event_name', 'Unknown')}_{event.get('resource', 'Unknown')}"
                    event_groups[key].append(event)
                except Exception:
                    continue
            
            # Format each group of similar events
            for key, group in event_groups.items():
                if len(group) == 1:
                    event = group[0]
                    error_info = f" (Error: {event.get('errorCode', '')})" if 'errorCode' in event else ""
                    summary += f"• User {event.get('user', 'Unknown')} {event.get('event_name', 'Unknown')}{error_info} {event.get('resource', 'Unknown')} at {event.get('timestamp', '').split(' ')[1]}\n"
                else:
                    event = group[0]
                    error_info = f" (Error: {event.get('errorCode', '')})" if 'errorCode' in event else ""
                    summary += f"• User {event.get('user', 'Unknown')} {event.get('event_name', 'Unknown')}{error_info} {event.get('resource', 'Unknown')} {len(group)} times\n"
                    times = []
                    for e in group[:3]:
                        try:
                            time = e.get('timestamp', '').split(' ')[1]
                            if time:
                                times.append(time)
                        except Exception:
                            continue
                    if times:
                        summary += f"  - Times: {', '.join(times)}"
                        if len(group) > 3:
                            summary += f" and {len(group) - 3} more times\n"
                        else:
                            summary += "\n"
            
            summary += "\n"
        
        return summary 

    def _extract_service_from_event(self, event_name: str) -> str:
        """Extract AWS service name from event name."""
        service_mappings = {
            'S3': ['Bucket', 'Object'],
            'EC2': ['Instance', 'SecurityGroup', 'Volume'],
            'IAM': ['Role', 'User', 'Policy', 'Group'],
            'Lambda': ['Function'],
            'DynamoDB': ['Table'],
            'RDS': ['DBInstance', 'DBCluster'],
            'CloudWatch': ['LogGroup', 'Alarm'],
            'SNS': ['Topic'],
            'SQS': ['Queue'],
            'ECS': ['Cluster', 'Service', 'Task'],
            'EKS': ['Cluster'],
            'CloudFront': ['Distribution'],
            'Route53': ['HostedZone', 'Domain'],
            'KMS': ['Key'],
            'Secrets': ['Secret'],
            'SSM': ['Parameter'],
            'ECR': ['Repository']
        }
        
        for service, keywords in service_mappings.items():
            if any(keyword in event_name for keyword in keywords):
                return service
        return 'AWS'  # Default if no specific service is identified 