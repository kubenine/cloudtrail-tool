# SSO Users Setup Guide

This guide explains how to set up and maintain SSO user information for the CloudTrail Intelligence Dashboard.

## Overview

The dashboard uses a `users.json` file to display and track SSO user activities. This file contains user information fetched from your AWS SSO Identity Store.

## Setup Process

### Step 1: Create SSO Users Script

Create a file named `fetch_sso_users.py` in the project root:

```python
import boto3
import json
import os
from dotenv import load_dotenv

def fetch_sso_users():
    # Load environment variables
    load_dotenv()

    # Initialize AWS clients
    sso_admin = boto3.client('sso-admin')
    identity_store = boto3.client('identitystore')

    try:
        # Get the Identity Store ID from SSO instance
        instances = sso_admin.list_instances()
        if not instances['Instances']:
            raise Exception("No SSO instance found")
        
        identity_store_id = instances['Instances'][0]['IdentityStoreId']

        # Fetch users from Identity Store
        users = []
        paginator = identity_store.get_paginator('list_users')
        
        for page in paginator.paginate(IdentityStoreId=identity_store_id):
            for user in page['Users']:
                # Get user's email
                emails = identity_store.list_user_attributes(
                    IdentityStoreId=identity_store_id,
                    UserId=user['UserId'],
                    AttributePath='emails'
                )
                
                user_info = {
                    'UserName': user['UserName'],
                    'UserId': user['UserId'],
                    'DisplayName': f"{user.get('Name', {}).get('GivenName', '')} {user.get('Name', {}).get('FamilyName', '')}".strip(),
                    'Emails': emails.get('Attributes', [])
                }
                users.append(user_info)

        # Save users to JSON file
        with open('users.json', 'w') as f:
            json.dump({'Users': users}, f, indent=2)
            
        print(f"Successfully fetched and saved {len(users)} SSO users to users.json")

    except Exception as e:
        print(f"Error fetching SSO users: {str(e)}")

if __name__ == "__main__":
    fetch_sso_users()
```

### Step 2: Run the Script

```bash
# Make sure you have AWS credentials configured
python fetch_sso_users.py
```

This script will:
- Connect to your AWS SSO instance
- Fetch all SSO users and their details
- Save the user information in `users.json`

### Step 3: Verify the Output

Check that `users.json` was created with the expected format:

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

## Automation and Maintenance

### Schedule Regular Updates

Set up a cron job to run the script periodically to keep user information current:

```bash
# Example cron entry (runs daily at midnight)
0 0 * * * cd /path/to/project && python fetch_sso_users.py
```

### Manual Updates

Run the script manually whenever:
- New users are added to your AWS SSO
- Users are removed from your AWS SSO
- User information changes (names, emails, etc.)

## Required Permissions

The AWS credentials used to run the script need the following permissions:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "sso-admin:ListInstances",
                "identitystore:ListUsers",
                "identitystore:ListUserAttributes"
            ],
            "Resource": "*"
        }
    ]
}
```

## Troubleshooting

### Common Issues

1. **No SSO Instance Found**
   - Verify that AWS SSO is enabled in your account
   - Check that you're using the correct AWS region
   - Ensure your credentials have access to SSO resources

2. **Permission Denied**
   - Verify your AWS credentials have the required permissions
   - Check if you're using the correct IAM role or user
   - Ensure SSO is properly configured in your account

3. **Empty Users List**
   - Check if there are actually users in your SSO Identity Store
   - Verify the Identity Store ID is correct
   - Check for any filtering or pagination issues

4. **Script Fails to Run**
   - Ensure all required Python packages are installed (`boto3`, `python-dotenv`)
   - Check that your AWS credentials are properly configured
   - Verify the script has the correct file permissions

### Testing the Setup

To test if your SSO setup is working:

```bash
# Test SSO admin access
aws sso-admin list-instances

# Test identity store access (replace with your identity store ID)
aws identitystore list-users --identity-store-id d-1234567890
```

## File Structure

After running the script, your project should have:

```
project-root/
├── fetch_sso_users.py    # The script to fetch users
├── users.json           # Generated user data
└── ...                  # Other project files
```

## Security Considerations

1. **Protect users.json**: This file contains user information, so ensure it's not exposed publicly
2. **Regular Updates**: Keep the user information current to maintain accurate tracking
3. **Access Control**: Limit who can run the fetch script and access the user data
4. **Audit Trail**: Monitor when and who updates the user information

## Integration with Dashboard

The CloudTrail Intelligence Dashboard automatically uses the `users.json` file to:
- Display user-friendly names instead of user IDs
- Track and analyze user activities
- Generate user-specific reports and summaries

Make sure the `users.json` file is in the same directory as your main application file for proper integration. 