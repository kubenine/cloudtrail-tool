import os
from typing import List, Dict
from utils import token_counter


class SSOActivityHelper:
    def __init__(self):
        self.openai_api_key = os.getenv('OPENAI_API_KEY')
    
    def format_sso_activity(self, events: List[Dict], username: str) -> str:
        """Format SSO user activity events into a natural language summary."""
        if not events:
            return f"No SSO activity found for user {username}."
        
        if not self.openai_api_key:
            # Fallback to simple formatting if no OpenAI key
            summary = f"Found {len(events)} SSO activities for {username}:\n"
            for event in events[:5]:  # Show first 5
                summary += f"- {event['timestamp']}: {event['event_name']}\n"
            if len(events) > 5:
                summary += f"... and {len(events) - 5} more activities"
            return summary
        
        try:
            from openai import OpenAI
            client = OpenAI(api_key=self.openai_api_key)
            
            # Prepare event summary for AI
            event_summary = "\n".join([
                f"- {event['timestamp']}: {event['event_name']} on {event.get('resource', 'Unknown')} from IP {event.get('source_ip', 'Unknown')}"
                for event in events[:20]  # Limit to 20 events
            ])
            
            prompt = f"""
            Analyze the following AWS SSO CloudTrail activities for user '{username}' and provide a concise summary:

            {event_summary}

            Provide a brief summary highlighting:
            1. Total number of SSO activities
            2. Most common SSO actions
            3. Time period covered
            4. Login patterns and account access
            5. Any notable patterns or security concerns
            
            Keep it concise and professional, focusing on SSO-specific activities.
            """
            
            response = client.chat.completions.create(
                model="gpt-4",
                messages=[{"role": "user", "content": prompt}],
                max_tokens=300,
                temperature=0.3
            )
            
            # Update token usage
            token_counter.update_from_response(response)
            
            return response.choices[0].message.content
            
        except Exception as e:
            # Fallback to simple formatting
            summary = f"Found {len(events)} SSO activities for {username}. "
            summary += f"Most recent: {events[0]['event_name']} at {events[0]['timestamp']}."
            return summary 