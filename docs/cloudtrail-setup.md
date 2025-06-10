# CloudTrail Setup Guide

This guide provides complete instructions for setting up AWS CloudTrail with CloudWatch Logs integration for the CAX AWS account.

## Overview

This setup will:
- Create an S3 bucket for CloudTrail logs storage
- Configure CloudTrail to capture all AWS API calls
- Set up CloudWatch Logs integration for real-time log analysis
- Create necessary IAM roles and policies

## Prerequisites

- AWS CLI configured with appropriate permissions
- Administrative access to the AWS account

## Setup Instructions

### Step 1: Set Configuration Variables

```bash
# Configuration variables
ACCOUNT_ID=$(aws sts get-caller-identity --query "Account" --output text)
CLOUDTRAIL_BUCKET_NAME="cax-cloudtrail-logs"
CLOUDTRAIL_NAME="CloudTrail-CAX"
LOG_GROUP_NAME="/aws/cloudtrail"
IAM_ROLE_NAME="CloudTrailCloudWatchLogsRole"
IAM_POLICY_NAME="CloudTrailCloudWatchLogsPolicy"
```

### Step 2: Create S3 Bucket for CloudTrail Logs

```bash
# Create bucket
aws s3 mb s3://$CLOUDTRAIL_BUCKET_NAME
```

### Step 3: Configure S3 Bucket Policy

```bash
# Add bucket policy for CloudTrail
aws s3api put-bucket-policy \
    --bucket $CLOUDTRAIL_BUCKET_NAME \
    --policy '{
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AWSCloudTrailAclCheck",
                "Effect": "Allow",
                "Principal": {"Service": "cloudtrail.amazonaws.com"},
                "Action": "s3:GetBucketAcl",
                "Resource": "arn:aws:s3:::'$CLOUDTRAIL_BUCKET_NAME'"
            },
            {
                "Sid": "AWSCloudTrailWrite",
                "Effect": "Allow", 
                "Principal": {"Service": "cloudtrail.amazonaws.com"},
                "Action": "s3:PutObject",
                "Resource": "arn:aws:s3:::'$CLOUDTRAIL_BUCKET_NAME'/AWSLogs/*",
                "Condition": {
                    "StringEquals": {
                        "s3:x-amz-acl": "bucket-owner-full-control"
                    }
                }
            }
        ]
    }'
```

### Step 4: Create CloudTrail

```bash
# Create trail
aws cloudtrail create-trail \
    --name "$CLOUDTRAIL_NAME" \
    --s3-bucket-name $CLOUDTRAIL_BUCKET_NAME \
    --include-global-service-events \
    --is-multi-region-trail
```

### Step 5: Set Up CloudWatch Logs Integration

#### Create Log Group

```bash
# Create Log Group
aws logs create-log-group --log-group-name "$LOG_GROUP_NAME"

# Get log group ARN
LOG_GROUP_ARN=$(aws logs describe-log-groups --log-group-name-prefix "$LOG_GROUP_NAME" --query "logGroups[0].arn" --output text)
```

#### Create IAM Role for CloudTrail to CloudWatch Logs

```bash
# Create IAM role for CloudTrail to CloudWatch Logs
aws iam create-role \
    --role-name $IAM_ROLE_NAME \
    --assume-role-policy-document '{
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {
                "Service": "cloudtrail.amazonaws.com"
            },
            "Action": "sts:AssumeRole"
        }]
    }'
```

#### Attach Policy to IAM Role

```bash
# Attach policy to allow CloudTrail to write to CloudWatch Logs
aws iam put-role-policy \
    --role-name $IAM_ROLE_NAME \
    --policy-name $IAM_POLICY_NAME \
    --policy-document '{
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": [
                "logs:CreateLogStream",
                "logs:PutLogEvents"
            ],
            "Resource": "'$LOG_GROUP_ARN':*"
        }]
    }'
```

### Step 6: Update CloudTrail with CloudWatch Logs Configuration

```bash
# Update trail with the role (after creating and configuring it)
aws cloudtrail update-trail \
    --name "$CLOUDTRAIL_NAME" \
    --cloud-watch-logs-log-group-arn $LOG_GROUP_ARN \
    --cloud-watch-logs-role-arn "arn:aws:iam::${ACCOUNT_ID}:role/$IAM_ROLE_NAME"
```

### Step 7: Enable CloudTrail Logging

```bash
# Enable trail logging
aws cloudtrail start-logging \
    --name "$CLOUDTRAIL_NAME"
```

## Verification

After completing the setup, verify that everything is working correctly:

1. **Check CloudTrail Status**:
   ```bash
   aws cloudtrail get-trail-status --name "$CLOUDTRAIL_NAME"
   ```

2. **Verify Log Group**:
   ```bash
   aws logs describe-log-groups --log-group-name-prefix "$LOG_GROUP_NAME"
   ```

3. **Check for Log Streams** (may take a few minutes):
   ```bash
   aws logs describe-log-streams --log-group-name "$LOG_GROUP_NAME"
   ```

## Optional: Set Log Retention Policy

To manage costs, you may want to set a retention policy for the CloudWatch Logs:

```bash
# Set retention policy (e.g., 30 days)
aws logs put-retention-policy \
    --log-group-name "$LOG_GROUP_NAME" \
    --retention-in-days 30
```

## Troubleshooting

### Common Issues

1. **Permission Denied Errors**: Ensure your AWS credentials have the necessary permissions to create IAM roles, S3 buckets, and CloudTrail resources.

2. **Bucket Already Exists**: If the S3 bucket name is already taken, choose a different name by modifying the `CLOUDTRAIL_BUCKET_NAME` variable.

3. **Role Creation Fails**: Check if the IAM role already exists. You may need to delete it first or use a different name.

### Required Permissions

Your AWS user/role needs the following permissions:
- `s3:CreateBucket`
- `s3:PutBucketPolicy`
- `cloudtrail:CreateTrail`
- `cloudtrail:UpdateTrail`
- `cloudtrail:StartLogging`
- `logs:CreateLogGroup`
- `logs:DescribeLogGroups`
- `iam:CreateRole`
- `iam:PutRolePolicy`
- `sts:GetCallerIdentity`

## Next Steps

After setting up CloudTrail:
1. Configure the CloudTrail Intelligence Dashboard to use your new log group
2. Set up monitoring and alerting for suspicious activities
3. Consider setting up additional trails for specific services or regions if needed 
