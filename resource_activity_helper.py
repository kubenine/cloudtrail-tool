import os
from openai import OpenAI
import json
from collections import defaultdict

class ResourceActivityHelper:
    def __init__(self):
        self.client = OpenAI(api_key=os.getenv('OPENAI_API_KEY'))
        
        # Define AWS services and their resource types
        self.aws_services = {
            'S3': {
                'name': 'Amazon S3',
                'resource_types': ['bucket'],
                'actions': ['CreateBucket', 'DeleteBucket', 'PutObject', 'DeleteObject', 'GetObject']
            },
            'EC2': {
                'name': 'Amazon EC2',
                'resource_types': ['instance', 'security-group', 'volume', 'snapshot'],
                'actions': ['RunInstances', 'TerminateInstances', 'CreateSecurityGroup', 'ModifySecurityGroup']
            },
            'IAM': {
                'name': 'AWS IAM',
                'resource_types': ['user', 'role', 'group', 'policy'],
                'actions': ['CreateUser', 'DeleteUser', 'CreateRole', 'AttachRolePolicy']
            },
            'Lambda': {
                'name': 'AWS Lambda',
                'resource_types': ['function'],
                'actions': ['CreateFunction', 'DeleteFunction', 'InvokeFunction', 'UpdateFunction']
            },
            'DynamoDB': {
                'name': 'Amazon DynamoDB',
                'resource_types': ['table'],
                'actions': ['CreateTable', 'DeleteTable', 'UpdateTable', 'PutItem', 'DeleteItem']
            },
            'RDS': {
                'name': 'Amazon RDS',
                'resource_types': ['db-instance', 'db-snapshot'],
                'actions': ['CreateDBInstance', 'DeleteDBInstance', 'CreateDBSnapshot']
            },
            'CloudWatch': {
                'name': 'Amazon CloudWatch',
                'resource_types': ['alarm', 'dashboard', 'log-group'],
                'actions': ['PutMetricAlarm', 'DeleteAlarms', 'PutDashboard']
            },
            'SNS': {
                'name': 'Amazon SNS',
                'resource_types': ['topic', 'subscription'],
                'actions': ['CreateTopic', 'DeleteTopic', 'Subscribe', 'Publish']
            },
            'SQS': {
                'name': 'Amazon SQS',
                'resource_types': ['queue'],
                'actions': ['CreateQueue', 'DeleteQueue', 'SendMessage', 'ReceiveMessage']
            }
        }

    def get_service_list(self):
        """Return a list of AWS services for the dropdown."""
        return [(service, info['name']) for service, info in self.aws_services.items()]

    def get_resource_types(self, service):
        """Return resource types for a given service."""
        return self.aws_services.get(service, {}).get('resource_types', [])

    def get_actions(self, service):
        """Return common actions for a given service."""
        return self.aws_services.get(service, {}).get('actions', [])

    def format_resource_activity(self, events, service, resource_type=None):
        """Format resource activity events into a natural language summary."""
        if not events:
            return f"No activity found for {self.aws_services[service]['name']} resources in the specified time window."

        # Prepare events for ChatGPT
        events_data = []
        for event in events:
            try:
                # Extract user information
                user = event.get('user', 'Unknown')
                if user == 'Unknown':
                    user = "System/AWS Service"

                # Extract resource information
                resource_info = event.get('resource', 'Unknown')
                if resource_info == 'Unknown' and 'request_parameters' in event:
                    params = event.get('request_parameters', {})
                    if isinstance(params, dict):
                        # Try to extract resource information from common fields
                        for field in self.aws_services[service]['resource_types']:
                            if field in params:
                                resource_info = f"{field}: {params[field]}"
                                break

                events_data.append({
                    'timestamp': event.get('timestamp', 'Unknown'),
                    'user': user,
                    'action': event.get('event_name', 'Unknown'),
                    'resource': resource_info,
                    'source_ip': event.get('source_ip', 'Unknown'),
                    'request_parameters': event.get('request_parameters', {})
                })
            except Exception as e:
                # Silently continue on error to prevent error messages from showing
                continue

        prompt = f"""Create a natural, conversational summary of AWS {self.aws_services[service]['name']} resource activity.
Focus on describing who interacted with the resources and what actions they performed.
Write it as if you're explaining to someone what happened, using simple language.
Break down the summary into clear bullet points, where each point tells a complete story.

For example:
• User 'john.doe@company.com' created a new {resource_type if resource_type else 'resource'} named 'my-resource' yesterday at 2:30 PM
• Role 'AdminRole' modified the configuration of 'existing-resource' to allow new permissions
• SSO user 'Jane Smith' deleted 3 resources of type '{resource_type if resource_type else 'resource'}' throughout the day

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
10. Groups events by resource when possible

Return ONLY the bullet-pointed summary, nothing else."""

        try:
            # Use gpt-4-turbo for resource activity summaries as it provides better understanding of AWS services and actions
            response = self.client.chat.completions.create(
                model="gpt-4-turbo",
                messages=[
                    {"role": "system", "content": f"You are a friendly AWS expert explaining {self.aws_services[service]['name']} resource activity in simple, conversational language using bullet points. Always identify who performed each action and focus on describing the resources and actions in detail."},
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
            # Silently fall back to basic summary without printing error
            return self._format_basic_summary(events, service, resource_type)

    def _format_basic_summary(self, events, service, resource_type=None):
        """Basic formatting fallback if ChatGPT is unavailable."""
        summary = f"# {self.aws_services[service]['name']} Resource Activity Summary\n\n"
        
        # Group events by date
        grouped_events = defaultdict(list)
        for event in events:
            try:
                date = event.get('timestamp', '').split(' ')[0]
                if date:
                    grouped_events[date].append(event)
            except Exception:
                continue
        
        # Format each day's events
        for date, day_events in sorted(grouped_events.items(), reverse=True):
            summary += f"## {date}\n\n"
            
            # Group similar events
            event_groups = defaultdict(list)
            for event in day_events:
                try:
                    key = f"{event.get('event_name', 'Unknown')}_{event.get('resource', 'Unknown')}"
                    event_groups[key].append(event)
                except Exception:
                    continue
            
            # Format each group of similar events
            for key, group in event_groups.items():
                if len(group) == 1:
                    event = group[0]
                    summary += f"• **{event.get('event_name', 'Unknown')}** by {event.get('user', 'Unknown')} at {event.get('timestamp', '').split(' ')[1]}\n"
                    summary += f"  - Resource: {event.get('resource', 'Unknown')}\n"
                    if event.get('request_parameters'):
                        summary += f"  - Details: {str(event['request_parameters'])[:100]}...\n"
                else:
                    event = group[0]
                    summary += f"• **{event.get('event_name', 'Unknown')}** performed {len(group)} times by {event.get('user', 'Unknown')}\n"
                    summary += f"  - Resource: {event.get('resource', 'Unknown')}\n"
                    times = []
                    for e in group:
                        try:
                            time = e.get('timestamp', '').split(' ')[1]
                            if time:
                                times.append(time)
                        except Exception:
                            continue
                    if times:
                        summary += f"  - Times: {', '.join(times[:3])}"
                        if len(times) > 3:
                            summary += f" and {len(times) - 3} more times\n"
                        else:
                            summary += "\n"
            
            summary += "\n"
        
        return summary 