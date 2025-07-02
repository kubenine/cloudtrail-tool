import boto3
import os
from typing import Dict, Any, Optional
from dotenv import load_dotenv
from pathlib import Path

class AWSAuth:
    """Centralized AWS authentication helper that uses default AWS auth unless explicit credentials are provided."""
    
    def __init__(self):
        """Initialize AWS authentication."""
        self.session = None
        self._initialize_session()
    
    def _initialize_session(self):
        """Initialize boto3 session with available credentials."""
        try:
            # Try to create session with environment variables first
            if os.getenv('AWS_ACCESS_KEY_ID') and os.getenv('AWS_SECRET_ACCESS_KEY'):
                self.session = boto3.Session(
                    aws_access_key_id=os.getenv('AWS_ACCESS_KEY_ID'),
                    aws_secret_access_key=os.getenv('AWS_SECRET_ACCESS_KEY'),
                    region_name=os.getenv('AWS_DEFAULT_REGION', 'us-east-1')
                )
            else:
                # Fall back to default credential chain
                self.session = boto3.Session(
                    region_name=os.getenv('AWS_DEFAULT_REGION', 'us-east-1')
                )
        except Exception as e:
            raise Exception(f"Failed to initialize AWS session: {e}")
    
    def create_client(self, service_name: str, region_name: Optional[str] = None):
        """Create AWS service client."""
        try:
            if region_name:
                return self.session.client(service_name, region_name=region_name)
            return self.session.client(service_name)
        except Exception as e:
            raise Exception(f"Failed to create {service_name} client: {e}")
    
    def create_resource(self, service_name: str, region_name: Optional[str] = None):
        """Create AWS service resource."""
        try:
            if region_name:
                return self.session.resource(service_name, region_name=region_name)
            return self.session.resource(service_name)
        except Exception as e:
            raise Exception(f"Failed to create {service_name} resource: {e}")
    
    def create_session(self):
        """Return the boto3 session."""
        return self.session
    
    def get_auth_info(self) -> Dict[str, Any]:
        """Get current authentication information."""
        try:
            # Try to get caller identity to verify credentials
            sts = self.create_client('sts')
            identity = sts.get_caller_identity()
            
            return {
                'using_explicit_credentials': bool(os.getenv('AWS_ACCESS_KEY_ID')),
                'access_key_id': os.getenv('AWS_ACCESS_KEY_ID', '').replace(os.getenv('AWS_ACCESS_KEY_ID', '')[:4], '****') if os.getenv('AWS_ACCESS_KEY_ID') else None,
                'region': self.session.region_name,
                'account_id': identity.get('Account'),
                'user_id': identity.get('UserId'),
                'arn': identity.get('Arn')
            }
        except Exception as e:
            return {
                'using_explicit_credentials': bool(os.getenv('AWS_ACCESS_KEY_ID')),
                'access_key_id': None,
                'region': self.session.region_name if self.session else 'Unknown',
                'error': str(e)
            }
    
    def has_credentials(self) -> bool:
        """Check if AWS credentials are available."""
        try:
            # Try to get caller identity to verify credentials
            sts = self.create_client('sts')
            sts.get_caller_identity()
            return True
        except Exception:
            return False 