# CloudTrail Intelligence Dashboard

A powerful and intuitive dashboard for analyzing AWS CloudTrail logs using natural language queries and AI-powered insights. Monitor, analyze, and understand AWS user activities through an easy-to-use web interface.

## 🌟 Features

- 🔍 **Natural Language Search** - Query CloudTrail events in plain English
- 🤖 **AI-Powered Insights** - Get intelligent summaries of user activities
- 📊 **Interactive Dashboard** - Built with Streamlit for real-time analysis
- ⚡ **CloudWatch Integration** - Direct integration with CloudWatch Logs Insights
- 👥 **User Activity Tracking** - Monitor IAM and SSO user activities
- 📈 **Visualizations** - Activity trends, patterns, and timeline charts

## 🚀 Quick Start

### 1. Installation

```bash
# Clone the repository
git clone <repository-url>
cd cloudtrail-tool

# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### 2. Configuration

Create a `.env` file in the project root:

```bash
# AWS Credentials (optional - uses default AWS auth if not provided)
AWS_ACCESS_KEY_ID=your_aws_access_key
AWS_SECRET_ACCESS_KEY=your_aws_secret_key
AWS_DEFAULT_REGION=your_aws_region

# OpenAI API (required for natural language features)
OPENAI_API_KEY=your_openai_api_key
```

### 3. Launch

```bash
streamlit run app.py
```

Access the dashboard at `http://localhost:8501`

## 📚 Documentation

Detailed documentation is available in the `docs/` folder:

- **[CloudTrail Setup Guide](docs/cloudtrail-setup.md)** - Complete CloudTrail configuration with CloudWatch Logs integration
- **[AWS Authentication Guide](docs/aws-authentication.md)** - Authentication methods and troubleshooting
- **[SSO Users Setup](docs/sso-users-setup.md)** - Configure SSO user tracking
- **[Usage Guide](docs/usage-guide.md)** - How to use the dashboard effectively
- **[Development Guide](docs/development.md)** - For contributors and developers

## 🔧 Prerequisites

### AWS Services Setup

1. **CloudTrail** - Must be configured and logging to CloudWatch Logs
2. **CloudWatch Logs** - Log group for CloudTrail events
3. **IAM Permissions** - Required permissions for accessing logs and services

> **⚠️ Important**: CloudTrail must be properly configured with CloudWatch Logs integration. See the [CloudTrail Setup Guide](docs/cloudtrail-setup.md) for complete instructions.

### Required AWS Permissions

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

## 🔐 Authentication

The dashboard supports multiple authentication methods:

- **Default AWS Authentication** (Recommended) - Uses AWS CLI, IAM roles, or SSO
- **Environment Variables** - Via `.env` file
- **Manual Override** - Direct credential input in the UI

See the [AWS Authentication Guide](docs/aws-authentication.md) for detailed setup instructions.

## 📋 Example Queries

Once set up, you can query your CloudTrail logs using natural language:

- "Show me all S3 bucket creation events from last week"
- "Find all failed login attempts in the past 24 hours"
- "List all EC2 instance launches by user john.doe@company.com"
- "Show me all IAM policy changes from yesterday"

## 🐳 Docker Support

```bash
# Build the image
docker build -t cloudtrail-dashboard .

# Run the container
docker run -p 8501:8501 \
  -e AWS_ACCESS_KEY_ID=your_key \
  -e AWS_SECRET_ACCESS_KEY=your_secret \
  -e OPENAI_API_KEY=your_openai_key \
  cloudtrail-dashboard
```

## 🤝 Contributing

We welcome contributions! Please see the [Development Guide](docs/development.md) for:

- Development setup instructions
- Code style guidelines
- Testing procedures
- Pull request process

## ⚠️ Troubleshooting

Common issues and solutions:

1. **No Data Returned** - Verify CloudTrail is configured and logging to CloudWatch
2. **Authentication Errors** - Check AWS credentials and permissions
3. **Slow Queries** - Use shorter time ranges and specific filters

For detailed troubleshooting, see the individual documentation files in the `docs/` folder.

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 📞 Support

- 📖 Check the [documentation](docs/) for detailed guides
- 🐛 [Report issues](https://github.com/your-repo/issues) on GitHub
- 💬 Join discussions in pull requests and issues

