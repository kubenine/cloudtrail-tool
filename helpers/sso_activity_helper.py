import os
from typing import List, Dict, Any, Optional
from openai import OpenAI
import json
from collections import defaultdict
from utils import token_counter, sample_events

class SSOActivityHelper:
    def __init__(self) -> None:
        self.client = OpenAI(api_key=os.getenv('OPENAI_API_KEY'))
    
    def format_sso_activity(self, events: List[Dict[str, Any]], username: str) -> str:
        """Format SSO user activity events into a natural language summary.
        
        Args:
            events: List of event dictionaries containing SSO user activity data
            username: Name of the SSO user whose activity is being summarized
            
        Returns:
            A formatted string containing the activity summary
        """
        if not events:
            return "No activity found for this SSO user in the specified time window."
        
        # Reset token counter for new query
        token_counter.reset()
        
        # sample events - to avoid token limits
        events = sample_events(events, 60)
        
        # Prepare events for ChatGPT
        events_data: List[Dict[str, str]] = []
        for event in events:
            # Create a human-readable action description
            action_desc = event['event_name']
            if event['resource'] != 'Unknown':
                action_desc += f" on {event['resource']}"
            
            events_data.append({
                'timestamp': event['timestamp'],
                'action': action_desc,
                'source_ip': event['source_ip'],
                'user': event.get('user', 'Unknown'),
                'errorCode': event.get('errorCode', ''),
                'errorMessage': event.get('errorMessage', '')
            })

        prompt = f"""Create a natural, conversational summary of AWS CloudTrail events for SSO user '{username}'.
Write it as if you're explaining to someone what this user has been doing, using simple language.
Break down the summary into clear bullet points, where each point tells a complete story.

For example:
• Created an S3 bucket named 'my-data-bucket' yesterday at 2:30 PM
• Modified security group 'web-servers' to allow inbound traffic on port 80
• Launched 3 EC2 instances of type t2.micro throughout the day

Events:
{json.dumps(events_data, indent=2)}

Write a clear, natural summary that:
1. Uses bullet points (•) for each main event or group of related events
2. Groups similar events together and summarizes the number of occurrences
3. Includes a general time reference like "today", "yesterday", or the full date
4. Limits listing each individual timestamp
5. Uses simple, conversational language
6. Focuses on what the user did, not technical details

Return ONLY the bullet-pointed summary, nothing else."""

        try:
            response = self.client.chat.completions.create(
                model="gpt-4.1",
                messages=[
                    {"role": "system", "content": "You are a friendly AWS expert explaining SSO user activity in simple, conversational language using bullet points."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.7
            )
            
            # Update token usage
            token_counter.update_from_response(response)
            
            summary = response.choices[0].message.content.strip()
            
            # Ensure each bullet point is on a new line
            summary = summary.replace("• ", "\n• ")
            if summary.startswith("\n"):
                summary = summary[1:]  # Remove leading newline if present
            
            return summary
        except Exception as e:
            print(f"Error formatting SSO user activity: {str(e)}")
            return self._format_basic_summary(events, username)

    def _format_basic_summary(self, events: List[Dict[str, Any]], username: str) -> str:
        """Basic formatting fallback if ChatGPT is unavailable.
        
        Args:
            events: List of event dictionaries containing SSO user activity data
            username: Name of the SSO user whose activity is being summarized
            
        Returns:
            A formatted string containing the basic activity summary
        """
        summary = f"# Activity Summary for SSO User: {username}\n\n"
        
        # Group events by date
        grouped_events: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        for event in events:
            date = event['timestamp'].split(' ')[0]
            grouped_events[date].append(event)
        
        # Format each day's events
        for date, day_events in sorted(grouped_events.items(), reverse=True):
            summary += f"## {date}\n\n"
            
            # Group similar events
            event_groups: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
            for event in day_events:
                key = f"{event['event_name']}_{event['resource']}"
                event_groups[key].append(event)
            
            # Format each group of similar events
            for key, group in event_groups.items():
                if len(group) == 1:
                    event = group[0]
                    summary += f"• **{event['event_name']}** at {event['timestamp'].split(' ')[1]}\n"
                    if event['resource'] != 'Unknown':
                        summary += f"  - Resource: {event['resource']}\n"
                    if event['source_ip'] != 'Unknown':
                        summary += f"  - From IP: {event['source_ip']}\n"
                else:
                    event = group[0]
                    summary += f"• **{event['event_name']}** performed {len(group)} times\n"
                    if event['resource'] != 'Unknown':
                        summary += f"  - Resource: {event['resource']}\n"
                    summary += f"  - Times: {', '.join(e['timestamp'].split(' ')[1] for e in group)}\n"
            
            summary += "\n"
        
        return summary 