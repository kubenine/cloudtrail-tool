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

### Prerequisites

- Python 3.8 or higher
- AWS Account with appropriate permissions
- OpenAI API key
- Git

### Step-by-Step Setup

1. **Clone the Repository**
   ```bash
   git clone https://github.com/yourusername/cloudtrail-project.git
   cd cloudtrail-project
   ```

2. **Set Up Python Virtual Environment**
   ```bash
   # Create virtual environment
   python -m venv .venv

   # Activate virtual environment
   # On macOS/Linux:
   source .venv/bin/activate
   # On Windows:
   .venv\Scripts\activate
   ```

3. **Install Dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Configure Environment Variables**
   Create a `.env` file in the project root:
   ```bash
   # AWS Credentials
   AWS_ACCESS_KEY_ID=your_aws_access_key
   AWS_SECRET_ACCESS_KEY=your_aws_secret_key
   AWS_DEFAULT_REGION=your_aws_region

   # OpenAI API
   OPENAI_API_KEY=your_openai_api_key
   ```

5. **Launch the Application**
   ```bash
   streamlit run app.py
   ```

6. **Access the Dashboard**
   Open your browser and navigate to `http://localhost:8501`

## 🔑 Required AWS Permissions

Ensure your AWS IAM user/role has the following permissions:
- `logs:StartQuery`
- `logs:GetQueryResults`
- `iam:ListUsers`
- `cloudtrail:LookupEvents`
- `cloudtrail:GetTrail`

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
├── .env               # Environment variables
└── src/               # Source code directory
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
1. Check the [Issues](https://github.com/yourusername/cloudtrail-project/issues) section
2. Create a new issue if your problem isn't already listed
3. Include detailed information about your setup and the problem you're experiencing
