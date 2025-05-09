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
1. Always start with 'fields @timestamp, @message, userIdentity.userName, userIdentity.principalId, userIdentity.type, requestParameters'
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
                    {"role": "system", "content": "You are a CloudWatch Logs Insights query expert. You only return valid query strings without any explanations. Keep queries simple and focused. Handle both specific and general queries effectively."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.3
            )
            query = response.choices[0].message.content.strip()
            
            # Validate and enhance the query structure
            if not query.startswith('fields @timestamp, @message'):
                query = 'fields @timestamp, @message, userIdentity.userName, userIdentity.principalId, userIdentity.type, requestParameters\n' + query
            
            if not query.endswith('| sort @timestamp desc'):
                query = query + '\n| sort @timestamp desc'
            
            # Remove any timestamp() or date() functions
            query = query.replace('timestamp(', '@timestamp')
            query = query.replace('date(', '@timestamp')
            
            # Add error information if not present
            if 'errorCode' not in query and 'errorMessage' not in query:
                query = query.replace('fields @timestamp, @message', 'fields @timestamp, @message, errorCode, errorMessage')
            
            return query
        except Exception:
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
                
                # Extract event name
                event_name = event.get('event_name', 'Unknown')
                
                # Extract error information if present
                error_info = ""
                if 'errorCode' in event:
                    error_info = f" (Error: {event['errorCode']})"
                
                # Only include essential fields to reduce token count
                events_data.append({
                    'time': event.get('timestamp', 'Unknown'),
                    'user': user,
                    'action': event_name + error_info,
                    'resource': resource_info
                })
            except Exception:
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

Example format:
• User john.doe@company.com created S3 bucket my-bucket at 2:30 PM
• User admin-role modified IAM policy admin-policy at 3:15 PM
• User jane.smith@company.com deleted 3 EC2 instances between 4:00 PM and 4:30 PM
• User system-role failed to create Lambda function (Error: AccessDenied) at 5:00 PM"""

        try:
            response = self.client.chat.completions.create(
                model="gpt-3.5-turbo",
                messages=[
                    {"role": "system", "content": "You are an AWS expert explaining CloudTrail events in a clear, concise format. Focus on who did what to which resource and when. Include error information when relevant."},
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