# CloudTrail Lake Setup Guide

## Prerequisites
1. AWS CLI configured with appropriate permissions
2. Python 3.8+ installed
3. Required Python packages:
   ```bash
   pip install boto3 python-dotenv
   ```

## Step 1: Create Event Data Store

1. Create a new event data store using AWS CLI:
   ```bash
   aws cloudtrail create-event-data-store \
       --name "CloudTrailLakeStore" \
       --region us-east-1 \
       --retention-period 90
   ```

2. Note down the `EventDataStoreArn` from the response. You'll need it for the next steps.

## Step 2: Configure CloudTrail

1. Update your CloudTrail configuration to send events to the data store:
   ```bash
   aws cloudtrail update-trail \
       --name "YourTrailName" \
       --event-data-store "arn:aws:cloudtrail:region:account:eventdatastore/YourEventDataStoreId" \
       --region us-east-1
   ```

## Step 3: IAM Permissions

Create an IAM policy for CloudTrail Lake access:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "cloudtrail:StartQuery",
                "cloudtrail:GetQueryResults",
                "cloudtrail:DescribeQuery",
                "cloudtrail:ListQueries"
            ],
            "Resource": "arn:aws:cloudtrail:region:account:eventdatastore/YourEventDataStoreId"
        }
    ]
}
```

## Step 4: Python Implementation

Create a new file `cloudtrail_lake_helper.py`:

```python
import boto3
import os
from datetime import datetime, timedelta
from dotenv import load_dotenv

class CloudTrailLakeHelper:
    def __init__(self):
        load_dotenv()
        self.client = boto3.client('cloudtrail')
        self.event_data_store = os.getenv('CLOUDTRAIL_LAKE_STORE_ARN')
        
    def translate_to_lake_query(self, natural_query, hours: int = 24):
        """Convert natural language query to CloudTrail Lake query."""
        # Basic service mappings
        service_mappings = {
            'ec2': 'ec2.amazonaws.com',
            's3': 's3.amazonaws.com',
            'iam': 'iam.amazonaws.com',
            'lambda': 'lambda.amazonaws.com',
            'cloudtrail': 'cloudtrail.amazonaws.com',
            'cloudwatch': 'monitoring.amazonaws.com',
            'rds': 'rds.amazonaws.com',
            'dynamodb': 'dynamodb.amazonaws.com',
            'sns': 'sns.amazonaws.com',
            'sqs': 'sqs.amazonaws.com'
        }
        
        # Start with base query
        query = f"""
        SELECT 
            eventTime,
            eventName,
            eventSource,
            userIdentity.arn,
            sourceIPAddress,
            awsRegion,
            errorCode,
            errorMessage
        FROM {self.event_data_store}
        WHERE eventTime >= '{datetime.utcnow() - timedelta(hours=hours)}'
        """
        
        # Add service filter if mentioned
        for service, endpoint in service_mappings.items():
            if service in natural_query.lower():
                query += f"\nAND eventSource = '{endpoint}'"
                break
        
        # Add user filter if mentioned
        if 'user' in natural_query.lower():
            query += "\nAND userIdentity.arn LIKE '%user%'"
        
        # Add error filter if mentioned
        if 'error' in natural_query.lower() or 'failed' in natural_query.lower():
            query += "\nAND errorCode IS NOT NULL"
        
        # Add sorting and limit
        query += "\nORDER BY eventTime DESC\nLIMIT 1000"
        
        return query

    def execute_query(self, query):
        """Execute CloudTrail Lake query and return results."""
        try:
            # Start the query
            response = self.client.start_query(
                QueryString=query,
                EventDataStore=self.event_data_store
            )
            query_id = response['QueryId']
            
            # Wait for query completion
            while True:
                status = self.client.describe_query(QueryId=query_id)
                if status['QueryStatus'] == 'FINISHED':
                    break
                elif status['QueryStatus'] == 'FAILED':
                    raise Exception(f"Query failed: {status.get('ErrorMessage', 'Unknown error')}")
            
            # Get results
            results = []
            paginator = self.client.get_paginator('get_query_results')
            for page in paginator.paginate(QueryId=query_id):
                results.extend(page['QueryResultRows'])
            
            return self.format_results(results)
            
        except Exception as e:
            return f"Error executing query: {str(e)}"

    def format_results(self, results):
        """Format query results into a readable summary."""
        if not results:
            return "No events found matching your query."
        
        # Group events by service and action
        grouped_events = {}
        for row in results:
            service = row['eventSource'].split('.')[0]
            key = f"{service}:{row['eventName']}"
            if key not in grouped_events:
                grouped_events[key] = []
            grouped_events[key].append(row)
        
        # Generate summary
        summary = []
        for key, events in grouped_events.items():
            service, action = key.split(':')
            if len(events) == 1:
                event = events[0]
                summary.append(
                    f"• [{event['eventTime']}] User {event['userIdentity.arn']} {action} "
                    f"in {event['awsRegion']}"
                )
                if event.get('errorCode'):
                    summary.append(f"  Error: {event['errorCode']} - {event.get('errorMessage', '')}")
            else:
                users = set(event['userIdentity.arn'] for event in events)
                regions = set(event['awsRegion'] for event in events)
                summary.append(
                    f"• {len(events)} {action} events by {len(users)} users in {len(regions)} regions"
                )
                if any(event.get('errorCode') for event in events):
                    error_count = sum(1 for event in events if event.get('errorCode'))
                    summary.append(f"  {error_count} events had errors")
        
        return "\n".join(summary)
```

## Step 5: Environment Setup

Create or update your `.env` file:

```env
AWS_ACCESS_KEY_ID=your_access_key
AWS_SECRET_ACCESS_KEY=your_secret_key
AWS_REGION=us-east-1
CLOUDTRAIL_LAKE_STORE_ARN=arn:aws:cloudtrail:region:account:eventdatastore/YourEventDataStoreId
```

## Step 6: Usage Example

```python
from cloudtrail_lake_helper import CloudTrailLakeHelper

# Initialize helper
helper = CloudTrailLakeHelper()

# Example query
query = helper.translate_to_lake_query("Show me all EC2 events from the last 24 hours")
results = helper.execute_query(query)
print(results)
```

## Benefits of CloudTrail Lake Implementation

1. **Better Performance**
   - Optimized query execution
   - No result limits
   - Faster response times

2. **Advanced Query Capabilities**
   - SQL-like query language
   - Complex joins and aggregations
   - Better data filtering

3. **Cost Optimization**
   - Pay-per-query pricing
   - Better data retention
   - Optimized storage

## Migration Steps

1. Deploy the new CloudTrail Lake implementation
2. Run both implementations in parallel
3. Gradually migrate queries to CloudTrail Lake
4. Monitor performance and costs
5. Remove old implementation once migration is complete

## Cost Considerations

1. **Storage Costs**
   - Event data store storage
   - Data ingestion costs

2. **Query Costs**
   - Pay per query
   - Data scanned costs

3. **Optimization Tips**
   - Use appropriate time ranges
   - Filter data early in queries
   - Cache common queries 