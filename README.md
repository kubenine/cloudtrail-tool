# CloudTrail Intelligence Dashboard

A powerful and intuitive dashboard for analyzing AWS CloudTrail logs using natural language queries and AI-powered insights. This tool helps you monitor, analyze, and understand AWS user activities through an easy-to-use web interface.

## 🌟 Features

- 🔍 Natural language search for CloudTrail events
- 🤖 AI-powered user activity summarization
- 📊 Interactive web interface built with Streamlit
- ⚡ Real-time CloudWatch Logs Insights queries
- 👥 IAM user activity tracking and monitoring
- 📈 Activity trends and patterns visualization

## 🚀 Quick Start

1. **Clone the Repository**
   ```bash
   git clone <repository-url>
   cd cloudtrail-project
   ```

2. **Create Virtual Environment**
   ```bash
   python -m venv .venv
   
   # On Linux/Mac
   source .venv/bin/activate
   
   # On Windows
   .venv\Scripts\activate
   ```

3. **Install Dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Configure AWS Authentication**
   
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

5. **Configure AWS Services**

   a. **Enable CloudTrail**
   ```bash
   aws cloudtrail create-trail \
       --name "MyCloudTrail" \
       --s3-bucket-name "my-cloudtrail-logs" \
       --include-global-service-events \
       --is-multi-region-trail
   ```

   b. **Set Up CloudWatch Logs**
   ```bash
   # Create Log Group
   aws logs create-log-group --log-group-name "/aws/cloudtrail"

   # Set Retention Policy (optional)
   aws logs put-retention-policy \
       --log-group-name "/aws/cloudtrail" \
       --retention-in-days 30

   # Configure CloudTrail to CloudWatch Integration
   aws cloudtrail update-trail \
       --name "MyCloudTrail" \
       --cloud-watch-logs-log-group-arn "arn:aws:logs:region:account-id:log-group:/aws/cloudtrail" \
       --cloud-watch-logs-role-arn "arn:aws:iam::account-id:role/CloudTrailCloudWatchLogsRole"
   ```

6. **Launch the Application**
   ```bash
   streamlit run app.py
   ```

7. **Access the Dashboard**
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

## 🔑 Required AWS Permissions

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

1. **Create SSO Users Script**
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

2. **Run the Script**
   ```bash
   # Make sure you have AWS credentials configured
   python fetch_sso_users.py
   ```
   This script will:
   - Connect to your AWS SSO instance
   - Fetch all SSO users and their details
   - Save the user information in `users.json`

3. **Verify the Output**
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

4. **Schedule Regular Updates**
   - Set up a cron job to run the script periodically
   - Example cron entry (runs daily at midnight):
     ```bash
     0 0 * * * cd /path/to/project && python fetch_sso_users.py
     ```

Note: The `users.json` file is used by the dashboard to display and track SSO user activities. Make sure to keep it updated as users are added or removed from your AWS SSO.

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
└── helpers/            # Helpers directory
```

### Running Tests
```bash
pytest tests/
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
   - Ensure port 8501 is available
   - Check your firewall settings

## 📞 Support

For support, please:
1. Check the [Issues](https://github.com/kubenine/cloudtrail-project/issues) section
2. Create a new issue if your problem isn't already listed
3. Include detailed information about your setup and the problem you're experiencing

