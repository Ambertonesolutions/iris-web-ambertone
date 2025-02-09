import os
import time
import logging
from datetime import datetime, timedelta
from functools import wraps
from typing import Optional, Dict, Any
import requests
from flask import session
from flask_login import current_user
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
console_handler.setFormatter(formatter)
logger.addHandler(console_handler)

class TokenError(Exception):
    """Custom exception for token-related errors"""
    pass

class APIError(Exception):
    """Custom exception for API-related errors"""
    pass

class AmbertoneAPI:
    def __init__(self):
        self.base_url = ('https://api.ambertonesecurity.com:55000')
        self.username = ('wazuh')
        self.password = ('Qll873moq5OpZMJsuKL29ubd?M65YcJf')
        self.session = requests.Session()
        self.max_retries = 3
        self.token_lifetime = timedelta(hours=1)

    @property
    def token(self) -> Optional[str]:
        """Get token from Flask session"""
        return session.get('ambertone_token')

    @token.setter
    def token(self, value: str):
        """Store token in Flask session"""
        session['ambertone_token'] = value
        session['ambertone_token_expiry'] = (datetime.now() + self.token_lifetime).isoformat()

    @property
    def token_expiry(self) -> Optional[datetime]:
        """Get token expiry from Flask session"""
        expiry_str = session.get('ambertone_token_expiry')
        return datetime.fromisoformat(expiry_str) if expiry_str else None

    def requires_token(f):
        """Decorator to ensure valid token before making requests"""
        @wraps(f)
        def wrapper(self, *args, **kwargs):
            self.ensure_valid_token()
            return f(self, *args, **kwargs)
        return wrapper

    def authenticate(self) -> None:
        """Authenticate and get a new token"""
        try:
            # Clear any existing token
            session.pop('ambertone_token', None)
            session.pop('ambertone_token_expiry', None)

            response = self.session.post(
                f"{self.base_url}/security/user/authenticate",
                auth=(self.username, self.password),
                verify=True
            )
            response.raise_for_status()
            
            data = response.json()
            # Change here to access the nested token
            if not data.get('data', {}).get('token'):
                raise TokenError("No token in authentication response")
                
            self.token = data['data']['token']  # This will store in session
            self.session.headers.update({'Authorization': f'Bearer {self.token}'})
            
            # Log successful authentication
            logger.info(f"Successfully authenticated user to Ambertone API")
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Authentication failed: {str(e)}")
            raise APIError(f"Authentication failed: {str(e)}")
            
    def ensure_valid_token(self) -> None:
        """Ensure we have a valid token, refresh if needed"""
        if not self.token or not self.token_expiry or \
           datetime.now() >= self.token_expiry - timedelta(minutes=5):
            self.authenticate()

    @requires_token
    def get_agents(self) -> Dict[str, Any]:
        """Get agents data with retry logic"""
        for attempt in range(self.max_retries):
            try:
                response = self.session.get(f"{self.base_url}/agents")
                response.raise_for_status()
                return response.json()
            except requests.exceptions.RequestException as e:
                if attempt == self.max_retries - 1:
                    logger.error(f"Failed to get agents after {self.max_retries} attempts: {str(e)}")
                    raise APIError(f"Failed to get agents: {str(e)}")
                time.sleep(2 ** attempt)  # Exponential backoff
                continue

    def process_agents_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Process raw agents data into chart-friendly format"""
        agents = data.get('data', {}).get('affected_items', [])
        
        # Process OS distribution
        os_counts = {}
        for agent in agents:
            os_name = agent.get('os', {}).get('name', 'Unknown')
            os_counts[os_name] = os_counts.get(os_name, 0) + 1
            
        # Process status distribution
        status_counts = {}
        for agent in agents:
            status = agent.get('status', 'Unknown')
            status_counts[status] = status_counts.get(status, 0) + 1
            
        # Process heartbeat distribution
        now = datetime.now()
        heartbeat_ranges = {
            '0-7 days': 0,
            '7-15 days': 0,
            '15-30 days': 0,
            '30+ days': 0
        }
        
        for agent in agents:
            try:
                last_keepalive = datetime.fromisoformat(agent.get('lastKeepAlive', '').replace('Z', '+00:00'))
                days_diff = (now - last_keepalive).days
                
                if days_diff <= 7:
                    heartbeat_ranges['0-7 days'] += 1
                elif days_diff <= 15:
                    heartbeat_ranges['7-15 days'] += 1
                elif days_diff <= 30:
                    heartbeat_ranges['15-30 days'] += 1
                else:
                    heartbeat_ranges['30+ days'] += 1
            except (ValueError, TypeError):
                heartbeat_ranges['30+ days'] += 1
        
        return {
            'os_distribution': os_counts,
            'status_distribution': status_counts,
            'heartbeat_distribution': heartbeat_ranges,
            'total_agents': len(agents)
        }

    @requires_token
    def get_agents_analytics(self) -> Dict[str, Any]:
        """Get processed agents analytics data"""
        logger.info("Getting agents analytics data")
        raw_data = self.get_agents()
        return self.process_agents_data(raw_data)