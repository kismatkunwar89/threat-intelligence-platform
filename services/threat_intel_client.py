"""
Base threat intelligence client with retry logic.

This module demonstrates:
- Abstract base classes (ABC)
- Decorators for retry logic
- Exponential backoff algorithm
- HTTP request handling
- Error handling and logging
"""

import time
import requests
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, Callable
from functools import wraps
import logging
from config import Config

logger = logging.getLogger(__name__)


class APIError(Exception):
    """Base exception for API-related errors."""
    pass


class RateLimitError(APIError):
    """Exception raised when API rate limit is exceeded."""
    pass


class APITimeoutError(APIError):
    """Exception raised when API request times out."""
    pass


def retry_with_backoff(max_retries: int = 3, base_delay: float = 1.0):
    """
    Decorator that implements retry logic with exponential backoff.

    This demonstrates:
    - Function decorators
    - Closures
    - Exponential backoff algorithm
    - Error handling

    Args:
        max_retries: Maximum number of retry attempts
        base_delay: Base delay in seconds for exponential backoff

    Returns:
        Decorated function with retry logic

    Example:
        @retry_with_backoff(max_retries=3, base_delay=2.0)
        def fetch_data():
            return requests.get(url)
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            retries = 0

            while retries < max_retries:
                try:
                    return func(*args, **kwargs)

                except (requests.exceptions.Timeout, requests.exceptions.ConnectionError) as e:
                    retries += 1

                    if retries >= max_retries:
                        logger.error(f"Max retries ({max_retries}) reached for {func.__name__}")
                        raise APITimeoutError(f"Request failed after {max_retries} retries") from e

                    # Exponential backoff: delay = base_delay * (2 ** retries)
                    delay = base_delay * (2 ** retries)
                    logger.warning(
                        f"Request failed, retrying in {delay}s "
                        f"(attempt {retries}/{max_retries}): {e}"
                    )
                    time.sleep(delay)

                except requests.exceptions.RequestException as e:
                    logger.error(f"Request exception in {func.__name__}: {e}")
                    raise APIError(f"API request failed: {e}") from e

            return None  # Should never reach here

        return wrapper
    return decorator


class ThreatIntelClient(ABC):
    """
    Abstract base class for threat intelligence API clients.

    This demonstrates:
    - Abstract base class (ABC) pattern
    - Template method pattern
    - OOP inheritance
    - Common interface for different API providers

    Subclasses must implement:
    - get_ip_reputation(ip_address: str) -> Dict[str, Any]
    """

    def __init__(self, api_key: str, base_url: str, timeout: int = None):
        """
        Initialize the threat intelligence client.

        Args:
            api_key: API key for authentication
            base_url: Base URL for the API
            timeout: Request timeout in seconds (default from config)
        """
        self.api_key = api_key
        self.base_url = base_url.rstrip('/')
        self.timeout = timeout or Config.API_TIMEOUT_SECONDS
        self.session = self._create_session()

    def _create_session(self) -> requests.Session:
        """
        Create a requests session with default headers.

        Returns:
            requests.Session: Configured session object
        """
        session = requests.Session()
        session.headers.update(self._get_default_headers())
        return session

    def _get_default_headers(self) -> Dict[str, str]:
        """
        Get default HTTP headers for requests.

        Returns:
            dict: Default headers
        """
        return {
            'User-Agent': 'ThreatIntelLookup/1.0',
            'Accept': 'application/json'
        }

    @retry_with_backoff(max_retries=Config.MAX_RETRIES, base_delay=1.0)
    def _make_request(self, method: str, endpoint: str,
                      params: Optional[Dict] = None,
                      headers: Optional[Dict] = None) -> Dict[str, Any]:
        """
        Make an HTTP request with retry logic.

        This method is decorated with retry_with_backoff for automatic retries.

        Args:
            method: HTTP method (GET, POST, etc.)
            endpoint: API endpoint (will be appended to base_url)
            params: Query parameters
            headers: Additional headers

        Returns:
            dict: JSON response from API

        Raises:
            APIError: If request fails
            RateLimitError: If rate limit is exceeded
        """
        url = f"{self.base_url}/{endpoint.lstrip('/')}"

        # Merge additional headers with session headers
        request_headers = self.session.headers.copy()
        if headers:
            request_headers.update(headers)

        logger.debug(f"Making {method} request to {url}")

        response = self.session.request(
            method=method,
            url=url,
            params=params,
            headers=request_headers,
            timeout=self.timeout
        )

        # Check for rate limiting
        if response.status_code == 429:
            logger.warning(f"Rate limit exceeded for {url}")
            raise RateLimitError("API rate limit exceeded")

        # Raise for other HTTP errors
        response.raise_for_status()

        logger.debug(f"Successfully received response from {url}")
        return response.json()

    def _get(self, endpoint: str, params: Optional[Dict] = None,
             headers: Optional[Dict] = None) -> Dict[str, Any]:
        """
        Make a GET request.

        Args:
            endpoint: API endpoint
            params: Query parameters
            headers: Additional headers

        Returns:
            dict: JSON response
        """
        return self._make_request('GET', endpoint, params=params, headers=headers)

    def _post(self, endpoint: str, data: Optional[Dict] = None,
              headers: Optional[Dict] = None) -> Dict[str, Any]:
        """
        Make a POST request.

        Args:
            endpoint: API endpoint
            data: Request body data
            headers: Additional headers

        Returns:
            dict: JSON response
        """
        return self._make_request('POST', endpoint, params=data, headers=headers)

    @abstractmethod
    def get_ip_reputation(self, ip_address: str) -> Dict[str, Any]:
        """
        Get threat intelligence reputation for an IP address.

        This is an abstract method that must be implemented by subclasses.

        Args:
            ip_address: IP address to query

        Returns:
            dict: Threat intelligence data

        Raises:
            NotImplementedError: If not implemented by subclass
        """
        pass

    @abstractmethod
    def get_service_name(self) -> str:
        """
        Get the name of the threat intelligence service.

        Returns:
            str: Service name (e.g., "AbuseIPDB", "AlienVault OTX")
        """
        pass

    def __repr__(self) -> str:
        """String representation of the client."""
        return f"{self.__class__.__name__}(service={self.get_service_name()})"
