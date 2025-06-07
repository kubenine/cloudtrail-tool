# AWS Authentication Guide

This guide covers all the authentication methods supported by the CloudTrail Intelligence Dashboard and how to configure them properly.

## Authentication Methods

The application uses a flexible authentication system that automatically detects and uses the best available AWS credentials.

### Authentication Priority Order

1. **Explicit credentials** from environment variables or .env file
2. **AWS CLI credentials** (`~/.aws/credentials`)
3. **IAM roles** (when running on AWS infrastructure)
4. **AWS SSO credentials**
5. **Instance metadata** (EC2 instances)

## Configuration Options

### Option A: Default AWS Authentication (Recommended)

This is the most secure and flexible approach:

- **AWS CLI**: Run `aws configure` to set up credentials
- **IAM roles**: Automatically used when running on EC2/ECS/Lambda
- **AWS SSO**: Use `aws sso login` to authenticate
- **Environment variables**: Set `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, and `AWS_DEFAULT_REGION`

### Option B: Manual Credentials via .env file

Create a `.env` file in the project root:

```bash
# AWS Credentials (optional - only if not using default auth)
AWS_ACCESS_KEY_ID=your_aws_access_key
AWS_SECRET_ACCESS_KEY=your_aws_secret_key
AWS_DEFAULT_REGION=your_aws_region

# OpenAI API (required for natural language features)
OPENAI_API_KEY=your_openai_api_key
```

### Option C: Manual Override via UI

- Use the "Manual Override" option in the sidebar
- Enter credentials directly in the web interface
- This is useful for testing or when other methods fail

## Authentication Status Indicators

The sidebar shows your current authentication method:

- **Green checkmark (✅)**: Using explicit credentials
- **Blue info (🔄)**: Using default AWS authentication
- **Red error (❌)**: No valid credentials found

## Required AWS Permissions

Ensure your AWS IAM user/role has the following permissions:

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

## Troubleshooting Authentication

### Common Issues and Solutions

1. **AWS Credentials Not Found**
   - Check the sidebar for specific error messages
   - Try running `aws sts get-caller-identity` to test your AWS setup
   - Use the "Manual Override" option in the sidebar as a fallback
   - Verify your AWS credentials have the required permissions

2. **Permission Denied Errors**
   - Ensure your IAM user/role has the required permissions listed above
   - Check if your credentials have expired
   - Verify you're using the correct AWS region

3. **SSO Authentication Issues**
   - Run `aws sso login` to refresh your SSO session
   - Check if your SSO session has expired
   - Verify your SSO configuration in `~/.aws/config`

4. **Environment Variable Issues**
   - Check that environment variables are properly set
   - Ensure there are no typos in variable names
   - Verify the `.env` file is in the correct location

### Testing Your Authentication

To verify your AWS authentication is working:

```bash
# Test basic AWS access
aws sts get-caller-identity

# Test CloudWatch Logs access
aws logs describe-log-groups

# Test CloudTrail access
aws cloudtrail describe-trails
```

## Best Practices

1. **Use IAM Roles**: When running on AWS infrastructure, use IAM roles instead of hardcoded credentials
2. **Rotate Credentials**: Regularly rotate access keys and update them in your configuration
3. **Least Privilege**: Only grant the minimum permissions required for the application to function
4. **Secure Storage**: Never commit credentials to version control; use environment variables or AWS services
5. **Monitor Usage**: Regularly review CloudTrail logs to monitor credential usage

## AWS SSO Configuration

If you're using AWS SSO, ensure your `~/.aws/config` file is properly configured:

```ini
[default]
sso_start_url = https://your-sso-portal.awsapps.com/start
sso_region = us-east-1
sso_account_id = 123456789012
sso_role_name = YourRoleName
region = us-east-1
```

Then authenticate using:

```bash
aws sso login
``` 