import os
from typing import List, Dict, Tuple
from utils import token_counter


class ResourceActivityHelper:
    def __init__(self):
        self.openai_api_key = os.getenv('OPENAI_API_KEY')
        
        # AWS services mapping
        self.aws_services = {
            'ec2': {'name': 'Amazon EC2', 'types': ['Instance', 'VPC', 'Security Group', 'Volume']},
            's3': {'name': 'Amazon S3', 'types': ['Bucket', 'Object']},
            'iam': {'name': 'AWS IAM', 'types': ['User', 'Role', 'Policy', 'Group']},
            'lambda': {'name': 'AWS Lambda', 'types': ['Function', 'Layer']},
            'rds': {'name': 'Amazon RDS', 'types': ['DB Instance', 'DB Cluster', 'Snapshot']},
            'cloudformation': {'name': 'AWS CloudFormation', 'types': ['Stack', 'StackSet']},
            'ecs': {'name': 'Amazon ECS', 'types': ['Cluster', 'Service', 'Task Definition']},
            'eks': {'name': 'Amazon EKS', 'types': ['Cluster', 'Node Group']},
            'dynamodb': {'name': 'Amazon DynamoDB', 'types': ['Table', 'Global Table']},
            'cloudwatch': {'name': 'Amazon CloudWatch', 'types': ['Alarm', 'Log Group', 'Dashboard']},
            'sns': {'name': 'Amazon SNS', 'types': ['Topic', 'Subscription']},
            'sqs': {'name': 'Amazon SQS', 'types': ['Queue']},
            'route53': {'name': 'Amazon Route 53', 'types': ['Hosted Zone', 'Record Set']},
            'cloudfront': {'name': 'Amazon CloudFront', 'types': ['Distribution']},
            'apigateway': {'name': 'Amazon API Gateway', 'types': ['REST API', 'WebSocket API']}
        }
    
    def get_service_list(self) -> List[Tuple[str, str]]:
        """Get list of AWS services."""
        return [(key, value['name']) for key, value in self.aws_services.items()]
    
    def get_resource_types(self, service: str) -> List[str]:
        """Get resource types for a specific service."""
        return self.aws_services.get(service, {}).get('types', [])
    
    def get_actions(self, service: str) -> List[str]:
        """Get common actions for a specific service."""
        # This is a simplified mapping of common actions per service
        action_map = {
            'ec2': ['RunInstances', 'TerminateInstances', 'StartInstances', 'StopInstances', 'CreateVpc', 'DeleteVpc'],
            's3': ['CreateBucket', 'DeleteBucket', 'PutObject', 'DeleteObject', 'GetObject'],
            'iam': ['CreateUser', 'DeleteUser', 'CreateRole', 'DeleteRole', 'AttachUserPolicy', 'DetachUserPolicy'],
            'lambda': ['CreateFunction', 'DeleteFunction', 'UpdateFunctionCode', 'InvokeFunction'],
            'rds': ['CreateDBInstance', 'DeleteDBInstance', 'ModifyDBInstance', 'CreateDBSnapshot'],
            'cloudformation': ['CreateStack', 'DeleteStack', 'UpdateStack'],
            'ecs': ['CreateCluster', 'DeleteCluster', 'CreateService', 'DeleteService'],
            'eks': ['CreateCluster', 'DeleteCluster', 'CreateNodegroup', 'DeleteNodegroup'],
            'dynamodb': ['CreateTable', 'DeleteTable', 'UpdateTable', 'PutItem', 'DeleteItem'],
            'cloudwatch': ['PutMetricAlarm', 'DeleteAlarms', 'CreateLogGroup', 'DeleteLogGroup'],
            'sns': ['CreateTopic', 'DeleteTopic', 'Subscribe', 'Unsubscribe'],
            'sqs': ['CreateQueue', 'DeleteQueue', 'SendMessage', 'ReceiveMessage'],
            'route53': ['CreateHostedZone', 'DeleteHostedZone', 'ChangeResourceRecordSets'],
            'cloudfront': ['CreateDistribution', 'DeleteDistribution', 'UpdateDistribution'],
            'apigateway': ['CreateRestApi', 'DeleteRestApi', 'CreateDeployment']
        }
        return action_map.get(service, ['Various actions available'])
    
    def format_resource_activity(self, events: List[Dict], service: str, resource_type: str = None) -> str:
        """Format resource activity events into a natural language summary."""
        if not events:
            service_name = self.aws_services.get(service, {}).get('name', service)
            return f"No activity found for {service_name} resources."
        
        if not self.openai_api_key:
            # Fallback to simple formatting if no OpenAI key
            service_name = self.aws_services.get(service, {}).get('name', service)
            summary = f"Found {len(events)} activities for {service_name}:\n"
            for event in events[:5]:  # Show first 5
                summary += f"- {event['timestamp']}: {event['event_name']}\n"
            if len(events) > 5:
                summary += f"... and {len(events) - 5} more activities"
            return summary
        
        try:
            from openai import OpenAI
            client = OpenAI(api_key=self.openai_api_key)
            
            service_name = self.aws_services.get(service, {}).get('name', service)
            
            # Prepare event summary for AI
            event_summary = "\n".join([
                f"- {event['timestamp']}: {event['event_name']} on {event.get('resource', 'Unknown')} from IP {event.get('source_ip', 'Unknown')}"
                for event in events[:20]  # Limit to 20 events
            ])
            
            resource_filter = f" for {resource_type} resources" if resource_type else ""
            
            prompt = f"""
            Analyze the following AWS {service_name} activities{resource_filter} and provide a concise summary:

            {event_summary}

            Provide a brief summary highlighting:
            1. Total number of {service_name} activities
            2. Most common actions performed
            3. Resources affected
            4. Time period covered
            5. Any notable patterns or concerns specific to {service_name}
            
            Keep it concise and professional, focusing on {service_name}-specific activities.
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
            service_name = self.aws_services.get(service, {}).get('name', service)
            summary = f"Found {len(events)} activities for {service_name}. "
            summary += f"Most recent: {events[0]['event_name']} at {events[0]['timestamp']}."
            return summary 