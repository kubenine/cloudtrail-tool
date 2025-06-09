# Development Guide

This guide is for developers who want to contribute to or modify the CloudTrail Intelligence Dashboard.

## Project Structure

```
cloudtrail-tool/
├── app.py                    # Main Streamlit application
├── utils.py                  # Utility functions
├── requirements.txt          # Python dependencies
├── Dockerfile               # Docker configuration
├── .env                     # Environment variables (not in git)
├── .gitignore              # Git ignore rules
├── README.md               # Main project documentation
├── helpers/                # Helper modules directory
├── docs/                   # Documentation files
│   ├── cloudtrail-setup.md    # CloudTrail setup guide
│   ├── aws-authentication.md  # AWS auth guide
│   ├── sso-users-setup.md     # SSO users setup
│   ├── usage-guide.md         # Usage instructions
│   └── development.md         # This file
└── .github/                # GitHub workflows and templates
```

## Development Setup

### Prerequisites

- Python 3.8 or higher
- AWS CLI configured
- Git

### Local Development Setup

1. **Clone the Repository**
   ```bash
   git clone <repository-url>
   cd cloudtrail-tool
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

4. **Set Up Environment Variables**
   Create a `.env` file in the project root:
   ```bash
   # AWS Credentials (optional - only if not using default auth)
   AWS_ACCESS_KEY_ID=your_aws_access_key
   AWS_SECRET_ACCESS_KEY=your_aws_secret_key
   AWS_DEFAULT_REGION=your_aws_region

   # OpenAI API (required for natural language features)
   OPENAI_API_KEY=your_openai_api_key
   ```

5. **Run the Application**
   ```bash
   streamlit run app.py
   ```

## Code Architecture

### Main Components

#### app.py
The main Streamlit application file containing:
- User interface components
- Authentication handling
- Query processing
- Results display

#### utils.py
Utility functions for:
- AWS service interactions
- Data processing
- Helper functions

#### helpers/
Directory for modular helper functions:
- Authentication helpers
- Query builders
- Data formatters

### Key Functions

#### Authentication System
- Flexible authentication with multiple fallback options
- Automatic credential detection
- Manual override capabilities

#### Query Processing
- Natural language to CloudWatch Logs Insights query translation
- Query optimization and validation
- Result formatting and display

#### Data Visualization
- Interactive charts and graphs
- Timeline visualizations
- User activity heatmaps

## Development Workflow

### Making Changes

1. **Create a Feature Branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make Your Changes**
   - Follow the existing code style
   - Add comments for complex logic
   - Update documentation as needed

3. **Test Your Changes**
   ```bash
   # Run the application locally
   streamlit run app.py
   
   # Test different authentication methods
   # Test various query types
   # Verify UI responsiveness
   ```

4. **Commit Your Changes**
   ```bash
   git add .
   git commit -m "Add: description of your changes"
   ```

5. **Push and Create Pull Request**
   ```bash
   git push origin feature/your-feature-name
   ```

### Code Style Guidelines

#### Python Code Style
- Follow PEP 8 guidelines
- Use meaningful variable and function names
- Add docstrings for functions and classes
- Keep functions focused and small

#### Streamlit Best Practices
- Use session state for persistent data
- Implement proper error handling
- Provide user feedback for long operations
- Use caching where appropriate

#### Example Code Structure
```python
def process_cloudtrail_query(query: str, time_range: dict) -> dict:
    """
    Process a natural language CloudTrail query.
    
    Args:
        query (str): Natural language query
        time_range (dict): Time range parameters
        
    Returns:
        dict: Query results and metadata
    """
    try:
        # Implementation here
        pass
    except Exception as e:
        st.error(f"Error processing query: {str(e)}")
        return {}
```

## Testing

### Manual Testing Checklist

- [ ] Authentication works with different methods
- [ ] Natural language queries return expected results
- [ ] Time range filtering works correctly
- [ ] User activity tracking displays properly
- [ ] Export functionality works
- [ ] Error handling displays appropriate messages

### Test Cases to Cover

1. **Authentication Tests**
   - Default AWS credentials
   - Environment variable credentials
   - Manual override credentials
   - Invalid credentials handling

2. **Query Tests**
   - Simple natural language queries
   - Complex queries with multiple filters
   - Invalid query handling
   - Empty result handling

3. **UI Tests**
   - Responsive design on different screen sizes
   - Loading states and progress indicators
   - Error message display
   - Data export functionality

## Adding New Features

### Natural Language Query Enhancement

To add new query types:

1. **Update Query Processing Logic**
   ```python
   # In utils.py or appropriate helper
   def enhance_query_processing(query: str) -> str:
       # Add new query pattern recognition
       # Convert to CloudWatch Logs Insights syntax
       pass
   ```

2. **Add UI Components**
   ```python
   # In app.py
   if st.button("New Feature"):
       # Implement new feature UI
       pass
   ```

3. **Update Documentation**
   - Add examples to usage guide
   - Update feature list in README

### Adding New Visualizations

1. **Create Visualization Function**
   ```python
   def create_new_chart(data: dict) -> None:
       """Create a new type of chart."""
       # Use plotly, matplotlib, or streamlit native charts
       pass
   ```

2. **Integrate with Main App**
   ```python
   # In app.py
   if visualization_type == "new_chart":
       create_new_chart(query_results)
   ```

## Docker Development

### Building the Docker Image

```bash
docker build -t cloudtrail-dashboard .
```

### Running with Docker

```bash
docker run -p 8501:8501 \
  -e AWS_ACCESS_KEY_ID=your_key \
  -e AWS_SECRET_ACCESS_KEY=your_secret \
  -e OPENAI_API_KEY=your_openai_key \
  cloudtrail-dashboard
```

### Docker Compose (Optional)

Create a `docker-compose.yml` for easier development:

```yaml
version: '3.8'
services:
  dashboard:
    build: .
    ports:
      - "8501:8501"
    environment:
      - AWS_ACCESS_KEY_ID=${AWS_ACCESS_KEY_ID}
      - AWS_SECRET_ACCESS_KEY=${AWS_SECRET_ACCESS_KEY}
      - OPENAI_API_KEY=${OPENAI_API_KEY}
    volumes:
      - .:/app
```

## Performance Optimization

### Query Optimization
- Use specific time ranges
- Implement query result caching
- Optimize CloudWatch Logs Insights queries

### UI Performance
- Use Streamlit caching decorators
- Implement lazy loading for large datasets
- Optimize chart rendering

### Memory Management
- Clear large variables when not needed
- Use generators for large data processing
- Monitor memory usage during development

## Debugging

### Common Issues

1. **Streamlit Caching Issues**
   ```bash
   # Clear Streamlit cache
   streamlit cache clear
   ```

2. **AWS Credential Issues**
   ```bash
   # Test AWS credentials
   aws sts get-caller-identity
   ```

3. **Module Import Issues**
   ```bash
   # Check Python path
   python -c "import sys; print(sys.path)"
   ```

### Debugging Tools

- Use `st.write()` for debugging output
- Add logging statements for complex operations
- Use browser developer tools for frontend issues

## Contributing Guidelines

### Before Contributing

1. Check existing issues and pull requests
2. Discuss major changes in an issue first
3. Ensure your development environment is set up correctly

### Pull Request Process

1. **Update Documentation**
   - Update relevant documentation files
   - Add examples for new features
   - Update the changelog if applicable

2. **Code Review Checklist**
   - Code follows style guidelines
   - Functions are properly documented
   - Error handling is implemented
   - No hardcoded credentials or sensitive data

3. **Testing**
   - Test with different AWS configurations
   - Verify UI works on different screen sizes
   - Test error scenarios

### Commit Message Format

Use clear, descriptive commit messages:
- `Add: new feature description`
- `Fix: bug description`
- `Update: what was updated`
- `Refactor: what was refactored`

## Release Process

### Version Management

- Use semantic versioning (MAJOR.MINOR.PATCH)
- Update version in relevant files
- Tag releases in Git

### Release Checklist

- [ ] All tests pass
- [ ] Documentation is updated
- [ ] Version numbers are updated
- [ ] Release notes are prepared
- [ ] Docker image is built and tested

## Getting Help

### Resources

- [Streamlit Documentation](https://docs.streamlit.io/)
- [AWS SDK for Python (Boto3)](https://boto3.amazonaws.com/v1/documentation/api/latest/index.html)
- [CloudWatch Logs Insights Query Syntax](https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/CWL_QuerySyntax.html)

### Community

- Create issues for bugs or feature requests
- Join discussions in pull requests
- Share your use cases and feedback 