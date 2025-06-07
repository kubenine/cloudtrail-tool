# CloudTrail Intelligence Dashboard

A powerful and intuitive dashboard for analyzing AWS CloudTrail logs using natural language queries and AI-powered insights. This tool helps you monitor, analyze, and understand AWS user activities through an easy-to-use web interface.

---

## 🌟 Features

- 🔍 Natural language search for CloudTrail events  
- 🤖 AI-powered user activity summarization  
- 📊 Interactive web interface built with Streamlit  
- ⚡ Real-time CloudWatch Logs Insights queries  
- 👥 IAM user activity tracking and monitoring  
- 📈 Activity trends and patterns visualization  

---

## 🚀 Quick Start

### 1. Clone the Repository

```bash
git clone <repository-url>
cd cloudtrail-project
```

### 2. Create Virtual Environment
   ```bash
   python -m venv .venv
   
   # On Linux/Mac
   source .venv/bin/activate
   
   # On Windows
   .venv\Scripts\activate
   ```

### 3. Install Dependencies
   ```bash
   pip install -r requirements.txt
   ```

### 4. Configure AWS Authentication
   
   The application supports multiple AWS authentication methods (in order of preference):
   
   **Option A: Default AWS Authentication (Recommended)**
   - Use AWS CLI: `aws configure`
   - Use IAM roles (if running on EC2/ECS/Lambda)
   - Use AWS SSO: `aws sso login`
   - Use environment variables (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
   
   **Option B: Manual Credentials via .env file**
   Create a `.env` file in the project root:
   ```bash
   # AWS Credentials (optional - only if not using default auth)
   AWS_ACCESS_KEY_ID=your_aws_access_key
   AWS_SECRET_ACCESS_KEY=your_aws_secret_key
   AWS_DEFAULT_REGION=your_aws_region

   # OpenAI API (required for natural language features)
   OPENAI_API_KEY=your_openai_api_key
   ```
   
   **Option C: Manual Override via UI**
   - Use the "Manual Override" option in the sidebar
   - Enter credentials directly in the web interface

### 5. Configure AWS Services
**Configuration Variables**

   ```bash
      ACCOUNT_ID=$(aws sts get-caller-identity --query "Account" --output text)
      CLOUDTRAIL_BUCKET_NAME="cax-cloudtrail-logs"
      CLOUDTRAIL_NAME="CloudTrail-CAX"
      LOG_GROUP_NAME="/aws/cloudtrail"
      IAM_ROLE_NAME="CloudTrailCloudWatchLogsRole"
      IAM_POLICY_NAME="CloudTrailCloudWatchLogsPolicy"
   ``` 
**create bucket**
```bash
aws s3 mb s3://$CLOUDTRAIL_BUCKET_NAME
``` 
   
**Add bucket policy for CloudTrail**
     
```bash
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
      
 **Create Trail**
 ```bash
aws cloudtrail create-trail \
    --name "$CLOUDTRAIL_NAME" \
    --s3-bucket-name $CLOUDTRAIL_BUCKET_NAME \
    --include-global-service-events \
    --is-multi-region-trail
```

**Create Log Group**
```bash
aws logs create-log-group --log-group-name "$LOG_GROUP_NAME"
```

**Get log group arn**
```bash
LOG_GROUP_ARN=$(aws logs describe-log-groups --log-group-name-prefix "$LOG_GROUP_NAME" --query "logGroups[0].arn" --output text)
```
**Configure cloudtrail to use log group**
***Create IAM role for CloudTrail to CloudWatch Logs***
```bash
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

**Attach policy to allow CloudTrail to write to CloudWatch Logs**
```bash
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

**Update trail with the role (after creating and configuring it)**
```bash
aws cloudtrail update-trail \
    --name "$CLOUDTRAIL_NAME" \
    --cloud-watch-logs-log-group-arn $LOG_GROUP_ARN \
    --cloud-watch-logs-role-arn "arn:aws:iam::${ACCOUNT_ID}:role/$IAM_ROLE_NAME"
```

**Enable trail logging**
```bash
aws cloudtrail start-logging \
    --name "$CLOUDTRAIL_NAME"
```

### 6. Launch the Application
   ```bash
   streamlit run app.py
   ```

### 7. Access the Dashboard
   Open your browser and navigate to `http://localhost:8501`

## 🔐 AWS Authentication

The application uses a flexible authentication system that automatically detects and uses the best available AWS credentials:

### Authentication Priority Order:
1. **Explicit credentials** from environment variables or .env file
2. **AWS CLI credentials** (`~/.aws/credentials`)
3. **IAM roles** (when running on AWS infrastructure)
4. **AWS SSO credentials**
5. **Instance metadata** (EC2 instances)

### Authentication Status:
- The sidebar shows your current authentication method
- Green checkmark (✅): Using explicit credentials
- Blue info (🔄): Using default AWS authentication
- Red error (❌): No valid credentials found

### Troubleshooting Authentication:
If you see authentication errors:
1. Check the sidebar for specific error messages
2. Try running `aws sts get-caller-identity` to test your AWS setup
3. Use the "Manual Override" option in the sidebar as a fallback
4. Ensure your AWS credentials have the required permissions (see below)

### 🔑 Required AWS Permissions

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

## 📋 SSO Users Setup

### 1. Create SSO Users Script
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

### 2. Run the Script
   ```bash
   # Make sure you have AWS credentials configured
   python fetch_sso_users.py
   ```
   **This script will:**
   - Connect to your AWS SSO instance
   - Fetch all SSO users and their details
   - Save the user information in `users.json`

### 3. Verify the Output
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

### 4. Schedule Regular Updates(Optional)
   - Set up a cron job to run the script periodically
   - Example cron entry (runs daily at midnight):
     ```bash
     0 0 * * * cd /path/to/project && python fetch_sso_users.py
     ```

**Note:** The `users.json` file is used by the dashboard to display and track SSO user activities. Make sure to keep it updated as users are added or removed from your AWS SSO.

## 🐳 Docker Usage

### 1. Build the Docker image

```bash
docker build -t cloudtrail-dashboard .
```

### 2. Run the Docker container

```bash
docker run -p 8551:8551 --env-file .env -v $(pwd)/users.json:/app/users.json cloudtrail-dashboard```
```
- `--env-file .env` loads your AWS and OpenAI credentials.
- `-v $(pwd)/users.json:/app/users.json` mounts your SSO users file (if needed).

### 3. Access the Dashboard

Open your browser and go to [http://localhost:8551](http://localhost:8551)

**Note:**  
- Make sure your `.env` and `users.json` are present in your project root.
- Never commit your `.env` file to version control.

## 📋 Usage Guide
1. **Natural Language Search**
   - Enter your query in natural language
   - Example: "Show me all S3 bucket creation events from last week"

2. **Activity Summarization**
   - Select a time range
   - Click "Generate Summary" to get AI-powered insights

3. **User Activity Tracking**
   - View IAM user activities
   - Monitor suspicious or unusual patterns

## 🛠️ Development

### Project Structure
```
cloudtrail-project/
├── app.py              # Main Streamlit application
├── requirements.txt    # Python dependencies
├── .env                # Environment variables
├── utils/              # Utility functions    
└── helpers/            # Helpers directory
```


## 🤝 Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚠️ Troubleshooting

Common issues and solutions:

1. **AWS Credentials Not Found**
   - Verify your `.env` file exists and contains correct credentials
   - Check AWS CLI configuration

2. **OpenAI API Issues**
   - Verify your API key is valid
   - Check your API usage limits

3. **Streamlit Connection Issues**
   - Ensure port 8551 is available
   - Check your firewall settings

## 📞 Support

For support, please:
1. Check the [Issues](https://github.com/kubenine/cloudtrail-project/issues) section
2. Create a new issue if your problem isn't already listed
3. Include detailed information about your setup and the problem you're experiencing

