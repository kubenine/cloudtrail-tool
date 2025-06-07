# Usage Guide

This guide explains how to use the CloudTrail Intelligence Dashboard effectively to analyze AWS CloudTrail logs and monitor user activities.

## Getting Started

Once you have the dashboard running (see the main README for setup instructions), you can access it at `http://localhost:8501` in your web browser.

## Dashboard Features

### 1. Natural Language Search

The dashboard allows you to query CloudTrail events using natural language, making it easy to find specific activities without writing complex queries.

#### How to Use:
1. Navigate to the main search interface
2. Enter your query in plain English
3. Click "Search" to execute the query

#### Example Queries:
- "Show me all S3 bucket creation events from last week"
- "Find all failed login attempts in the past 24 hours"
- "List all EC2 instance launches by user john.doe@company.com"
- "Show me all IAM policy changes from yesterday"
- "Find all API calls from IP address 192.168.1.100"

#### Query Tips:
- Be specific about time ranges (e.g., "last week", "past 24 hours", "yesterday")
- Include specific services (e.g., "S3", "EC2", "IAM", "RDS")
- Mention specific users or IP addresses when relevant
- Use action words like "created", "deleted", "modified", "accessed"

### 2. AI-Powered Activity Summarization

Get intelligent summaries of user activities and system events over specified time periods.

#### How to Use:
1. Select a time range using the date/time pickers
2. Optionally filter by specific users or services
3. Click "Generate Summary" to get AI-powered insights

#### What You'll Get:
- Overview of most active users
- Summary of key activities and events
- Identification of unusual or suspicious patterns
- Breakdown by AWS services used
- Timeline of significant events

### 3. User Activity Tracking

Monitor and analyze individual user activities across your AWS environment.

#### Features:
- **User Activity Timeline**: See chronological activities for specific users
- **Activity Patterns**: Identify normal vs. unusual behavior patterns
- **Service Usage**: Track which AWS services users are accessing
- **Geographic Analysis**: Monitor login locations and access patterns

#### How to Use:
1. Select a user from the dropdown (populated from your users.json file)
2. Choose a time range for analysis
3. Review the generated activity report
4. Look for anomalies or suspicious activities

### 4. Interactive Visualizations

The dashboard provides various charts and graphs to help visualize CloudTrail data:

- **Activity Timeline**: Shows events over time
- **Service Usage Charts**: Breakdown of AWS service usage
- **User Activity Heatmaps**: Visual representation of user activities
- **Geographic Maps**: Shows access locations (when available)

## Advanced Features

### Custom Time Ranges

You can specify custom time ranges for all queries:
- Use the date/time pickers in the sidebar
- Common presets: Last hour, Last 24 hours, Last week, Last month
- Custom ranges: Specify exact start and end times

### Filtering Options

Refine your searches using various filters:
- **User Filter**: Focus on specific users
- **Service Filter**: Limit to specific AWS services
- **Event Type Filter**: Filter by event categories (e.g., errors, warnings)
- **IP Address Filter**: Filter by source IP addresses

### Export Capabilities

Export your query results and reports:
- **CSV Export**: Download raw data for further analysis
- **PDF Reports**: Generate formatted reports for sharing
- **JSON Export**: Export structured data for integration with other tools

## Best Practices

### 1. Regular Monitoring

- Set up regular monitoring schedules
- Review daily summaries for unusual activities
- Monitor high-privilege user activities closely
- Check for failed authentication attempts

### 2. Effective Querying

- Start with broad queries and narrow down as needed
- Use specific time ranges to improve performance
- Combine multiple filters for precise results
- Save frequently used queries for quick access

### 3. Security Analysis

- Look for patterns in failed login attempts
- Monitor privilege escalation activities
- Track access from unusual locations
- Review changes to security-related resources

### 4. Performance Optimization

- Use shorter time ranges for faster queries
- Be specific in your natural language queries
- Use filters to reduce the amount of data processed
- Consider the cost implications of large queries

## Common Use Cases

### 1. Security Incident Investigation

When investigating a security incident:
1. Start with a broad time range around the incident
2. Use natural language to describe what you're looking for
3. Narrow down based on initial results
4. Generate detailed reports for documentation

### 2. Compliance Auditing

For compliance audits:
1. Generate activity summaries for specific time periods
2. Focus on high-privilege user activities
3. Document access patterns and changes
4. Export reports for audit documentation

### 3. Operational Monitoring

For day-to-day operations:
1. Set up regular monitoring dashboards
2. Track service usage patterns
3. Monitor for operational anomalies
4. Generate regular activity reports

### 4. Cost Analysis

To understand AWS usage costs:
1. Track service usage patterns over time
2. Identify heavy users of expensive services
3. Monitor resource creation and deletion patterns
4. Generate usage reports for cost optimization

## Troubleshooting

### Common Issues

1. **No Data Returned**
   - Check your time range settings
   - Verify CloudTrail is properly configured
   - Ensure your AWS credentials have the required permissions

2. **Slow Query Performance**
   - Reduce the time range
   - Use more specific filters
   - Check your CloudWatch Logs configuration

3. **Authentication Errors**
   - Verify your AWS credentials
   - Check the authentication status in the sidebar
   - Try the manual override option

4. **Missing User Information**
   - Ensure users.json is properly configured
   - Run the SSO users fetch script
   - Check for proper user permissions

### Getting Help

If you encounter issues:
1. Check the troubleshooting section in the main README
2. Review the authentication guide
3. Verify your CloudTrail setup
4. Check the application logs for error messages

## Tips for Success

1. **Start Simple**: Begin with basic queries and gradually use more advanced features
2. **Regular Updates**: Keep your user information and configurations up to date
3. **Monitor Regularly**: Set up regular monitoring routines for better security
4. **Document Findings**: Keep records of important discoveries and patterns
5. **Stay Informed**: Keep up with new features and best practices 