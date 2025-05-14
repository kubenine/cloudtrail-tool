# CloudTrail Intelligence Dashboard - Project Setup

## 1. Project Overview

The CloudTrail Intelligence Dashboard is a powerful tool that provides natural language querying and AI-powered analysis of AWS CloudTrail logs. This document outlines the complete setup process for both AWS configurations and local development environment.

## 2. AWS Configuration Requirements

### 2.1 AWS SSO Setup

1. **Enable AWS SSO**
   ```bash
   aws sso-admin create-instance --name "MySSOInstance" --region us-east-1
   ```

2. **Configure Identity Store**
   - Navigate to AWS SSO console
   - Create users and groups
   - Assign appropriate permissions

3. **Required IAM Permissions**
   ```json
   {
       "Version": "2012-10-17",
       "Statement": [
           {
               "Effect": "Allow",
               "Action": [
                   "logs:StartQuery",
                   "logs:GetQueryResults",
                   "logs:DescribeLogGroups",
                   "cloudtrail:LookupEvents",
                   "iam:ListUsers",
                   "identitystore:ListUsers",
                   "sso-admin:ListInstances"
               ],
               "Resource": "*"
           }
       ]
   }
   ```

### 2.2 CloudTrail Configuration

1. **Enable CloudTrail**
   ```bash
   aws cloudtrail create-trail \
       --name "MyCloudTrail" \
       --s3-bucket-name "my-cloudtrail-logs" \
       --include-global-service-events \
       --is-multi-region-trail
   ```

2. **Configure CloudWatch Logs Integration**
   ```bash
   aws cloudtrail update-trail \
       --name "MyCloudTrail" \
       --cloud-watch-logs-log-group-arn "arn:aws:logs:region:account-id:log-group:/aws/cloudtrail" \
       --cloud-watch-logs-role-arn "arn:aws:iam::account-id:role/CloudTrailCloudWatchLogsRole"
   ```

### 2.3 CloudWatch Logs Setup

1. **Create Log Group**
   ```bash
   aws logs create-log-group --log-group-name "/aws/cloudtrail"
   ```

2. **Set Retention Policy**
   ```bash
   aws logs put-retention-policy \
       --log-group-name "/aws/cloudtrail" \
       --retention-in-days 30
   ```

## 3. Local Development Environment Setup

### 3.1 Python Environment

1. **Create Virtual Environment**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

2. **Install Dependencies**
   ```bash
   pip install -r requirements.txt
   ```

### 3.2 Required Python Packages

Create a `requirements.txt` file with the following dependencies:
```
streamlit==1.32.0
boto3==1.34.34
pandas==2.2.1
python-dotenv==1.0.1
openai==1.12.0
```

### 3.3 Environment Variables

Create a `.env` file with the following variables:
```
AWS_ACCESS_KEY_ID=your_access_key
AWS_SECRET_ACCESS_KEY=your_secret_key
AWS_DEFAULT_REGION=your_region
OPENAI_API_KEY=your_openai_api_key
```

## 4. Project Structure

```
cloudtrail-project/
├── app.py                 # Main Streamlit application
├── cloudtrail_helper.py   # AWS CloudTrail operations
├── query_helper.py        # Natural language query processing
├── user_activity_helper.py # IAM user activity formatting
├── sso_activity_helper.py # SSO user activity formatting
├── users.json            # SSO user data
├── requirements.txt      # Python dependencies
├── .env                 # Environment variables
└── README.md            # Project documentation
```

## 5. Running the Application

1. **Start the Streamlit App**
   ```bash
   streamlit run app.py
   ```

2. **Access the Dashboard**
   - Open browser and navigate to `http://localhost:8501`
   - The dashboard will be available with three tabs:
     - Natural Language Search
     - IAM User Activity
     - SSO User Activity

## 6. Security Considerations

1. **AWS Credentials**
   - Never commit AWS credentials to version control
   - Use IAM roles with least privilege principle
   - Rotate access keys regularly

2. **API Keys**
   - Store OpenAI API key securely
   - Use environment variables for sensitive data
   - Implement rate limiting for API calls

3. **Data Protection**
   - Encrypt sensitive data at rest
   - Implement proper access controls
   - Regular security audits

## 7. Monitoring and Maintenance

1. **Log Monitoring**
   - Set up CloudWatch alarms for error rates
   - Monitor API usage and costs
   - Track application performance

2. **Regular Updates**
   - Keep dependencies updated
   - Monitor AWS service changes
   - Regular security patches

## 8. Troubleshooting Guide

### Common Issues and Solutions

1. **AWS Authentication Errors**
   - Verify AWS credentials in `.env`
   - Check IAM permissions
   - Ensure proper region configuration

2. **SSO User Loading Issues**
   - Verify `users.json` format
   - Check SSO configuration
   - Validate user permissions

3. **Query Performance**
   - Optimize time window
   - Use specific filters
   - Monitor query execution time

## 9. Future Enhancements

1. **Planned Features**
   - Custom alerting system
   - Advanced analytics dashboard
   - Automated report generation
   - Multi-account support

2. **Performance Optimizations**
   - Query caching
   - Batch processing
   - Parallel query execution

## 10. Support and Resources

1. **Documentation**
   - AWS CloudTrail Documentation
   - Streamlit Documentation
   - OpenAI API Documentation

2. **Contact Information**
   - Project maintainers
   - AWS Support
   - Development team

## 11. Appendix

### A. AWS CLI Commands Reference

```bash
# List CloudTrail trails
aws cloudtrail list-trails

# Get trail status
aws cloudtrail get-trail-status --name MyCloudTrail

# List CloudWatch log groups
aws logs describe-log-groups

# List SSO users
aws identitystore list-users --identity-store-id d-9f6708e41b
```

### B. Sample Queries

1. **Natural Language Queries**
   - "Show me all IAM users created in the last week"
   - "What S3 bucket operations happened today?"
   - "Who stopped any EC2 instances yesterday?"

2. **CloudWatch Logs Insights Queries**
   ```sql
   fields @timestamp, @message
   | filter @message like /CreateUser/
   | sort @timestamp desc
   ```

### C. Configuration Files

1. **Sample .env file**
   ```
   AWS_ACCESS_KEY_ID=AKIAXXXXXXXXXXXXXXXX
   AWS_SECRET_ACCESS_KEY=XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
   AWS_DEFAULT_REGION=us-east-1
   OPENAI_API_KEY=sk-XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
   ```

2. **Sample users.json structure**
   ```json
   {
       "Users": [
           {
               "UserName": "user@example.com",
               "UserId": "user-id",
               "DisplayName": "User Name",
               "Emails": [
                   {
                       "Value": "user@example.com",
                       "Type": "work",
                       "Primary": true
                   }
               ]
           }
       ]
   }
   ``` 