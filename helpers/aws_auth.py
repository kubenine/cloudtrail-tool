import boto3
import os
from typing import Optional
from dotenv import load_dotenv
from pathlib import Path

class AWSAuth:
    """Centralized AWS authentication helper that uses default AWS auth unless explicit credentials are provided."""
    
    def __init__(self):
        # Find and load the .env file
        env_path = None
        
        # Try current directory
        if os.path.exists('.env'):
            env_path = '.env'
        # Try parent directory
        elif os.path.exists('../.env'):
            env_path = '../.env'
        # Try absolute path from project root
        else:
            project_root = Path(__file__).resolve().parent.parent
            env_file = project_root / '.env'
            if env_file.exists():
                env_path = str(env_file)
        
        if env_path:
            load_dotenv(dotenv_path=env_path)
        
        # Get credentials from environment variables
        self.aws_access_key: Optional[str] = os.getenv('AWS_ACCESS_KEY_ID')
        self.aws_secret_key: Optional[str] = os.getenv('AWS_SECRET_ACCESS_KEY')
        self.aws_region: str = os.getenv('AWS_DEFAULT_REGION', 'us-east-1')
        self.session_token: Optional[str] = os.getenv('AWS_SESSION_TOKEN')
        
        # Determine if we should use explicit credentials or default auth
        self.use_explicit_credentials = bool(self.aws_access_key and self.aws_secret_key)
    
    def create_client(self, service_name: str, region_name: Optional[str] = None) -> boto3.client:
        """Create a boto3 client with appropriate authentication.
        
        Args:
            service_name: AWS service name (e.g., 'logs', 'iam', 'identitystore')
            region_name: AWS region name (optional, defaults to configured region)
            
        Returns:
            Configured boto3 client
        """
        region = region_name or self.aws_region
        
        if self.use_explicit_credentials:
            # Use explicit credentials from environment/config
            client_kwargs = {
                'aws_access_key_id': self.aws_access_key,
                'aws_secret_access_key': self.aws_secret_key,
                'region_name': region
            }
            
            if self.session_token:
                client_kwargs['aws_session_token'] = self.session_token
                
            return boto3.client(service_name, **client_kwargs)
        else:
            # Use default AWS credential provider chain
            # This includes: environment variables, AWS credentials file, IAM roles, etc.
            return boto3.client(service_name, region_name=region)
    
    def has_credentials(self) -> bool:
        """Check if AWS credentials are available (either explicit or default).
        
        Returns:
            True if credentials are available, False otherwise
        """
        if self.use_explicit_credentials:
            return True
        
        # Try to create a simple client to test default credentials
        try:
            # Use STS to test credentials without making actual API calls
            sts_client = boto3.client('sts', region_name=self.aws_region)
            # This will raise an exception if no credentials are available
            sts_client._make_request.__defaults__
            return True
        except Exception:
            return False
    
    def get_auth_info(self) -> dict:
        """Get information about the current authentication method.
        
        Returns:
            Dictionary with authentication information
        """
        return {
            'using_explicit_credentials': self.use_explicit_credentials,
            'region': self.aws_region,
            'has_session_token': bool(self.session_token),
            'access_key_id': self.aws_access_key[:8] + '...' if self.aws_access_key else None
        } 