"""
AlienVault OTX (Open Threat Exchange) API client implementation.

This module demonstrates:
- Inheritance and polymorphism
- API integration with different authentication methods
- Error handling for different API responses
"""

from typing import Dict, Any, List
import logging
from services.threat_intel_client import ThreatIntelClient, APIError
from config import Config

logger = logging.getLogger(__name__)


class OTXClient(ThreatIntelClient):
    """
    Client for AlienVault OTX (Open Threat Exchange) API.

    API Documentation: https://otx.alienvault.com/api

    AlienVault OTX provides community-driven threat intelligence
    with unlimited free API access.
    """

    # OTX API base URL
    BASE_URL = 'https://otx.alienvault.com/api/v1'

    def __init__(self, api_key: str = None):
        """
        Initialize OTX client.

        Args:
            api_key: OTX API key (defaults to config)
        """
        key = api_key or Config.OTX_API_KEY
        if not key:
            raise ValueError("OTX API key is required")

        super().__init__(
            api_key=key,
            base_url=self.BASE_URL,
            timeout=Config.API_TIMEOUT_SECONDS
        )

        logger.info("AlienVault OTX client initialized")

    def _get_default_headers(self) -> Dict[str, str]:
        """
        Get OTX-specific headers.

        OTX uses X-OTX-API-KEY header for authentication.

        Returns:
            dict: Headers including API key
        """
        headers = super()._get_default_headers()
        headers['X-OTX-API-KEY'] = self.api_key
        return headers

    def get_ip_reputation(self, ip_address: str) -> Dict[str, Any]:
        """
        Get IP reputation data from AlienVault OTX.

        This method queries the general endpoint which contains most data.
        Optimized to make only 1 API call instead of 4 to avoid timeouts.

        Args:
            ip_address: IP address to query

        Returns:
            dict: Aggregated threat intelligence data

        Raises:
            APIError: If the API request fails
        """
        logger.info(f"Querying AlienVault OTX for IP: {ip_address}")

        try:
            # Only query general endpoint - it has most of the important data
            # This reduces API calls from 4 to 1, avoiding timeout issues
            general = self._get_general_info(ip_address)

            # Combine all data
            combined_data = {
                'ip_address': ip_address,
                'general': general,
                'pulse_count': general.get('pulse_info', {}).get('count', 0),
                'reputation': general.get('reputation', 0)
            }

            logger.info(
                f"OTX response for {ip_address}: "
                f"pulses={combined_data['pulse_count']}, "
                f"reputation={combined_data.get('reputation', 'N/A')}"
            )

            return combined_data

        except APIError as e:
            logger.error(f"OTX API error for {ip_address}: {e}")
            raise

    def _get_general_info(self, ip_address: str) -> Dict[str, Any]:
        """
        Get general IP information including pulse data.

        Args:
            ip_address: IP address to query

        Returns:
            dict: General IP information
        """
        endpoint = f"indicators/IPv4/{ip_address}/general"
        return self._get(endpoint)

    def _get_reputation(self, ip_address: str) -> Dict[str, Any]:
        """
        Get IP reputation score.

        Args:
            ip_address: IP address to query

        Returns:
            dict: Reputation information
        """
        endpoint = f"indicators/IPv4/{ip_address}/reputation"
        return self._get(endpoint)

    def _get_geo_info(self, ip_address: str) -> Dict[str, Any]:
        """
        Get geographic information for IP.

        Args:
            ip_address: IP address to query

        Returns:
            dict: Geographic data
        """
        endpoint = f"indicators/IPv4/{ip_address}/geo"
        return self._get(endpoint)

    def _get_malware_info(self, ip_address: str) -> Dict[str, Any]:
        """
        Get malware samples associated with IP.

        Args:
            ip_address: IP address to query

        Returns:
            dict: Malware information
        """
        endpoint = f"indicators/IPv4/{ip_address}/malware"
        return self._get(endpoint)

    def get_url_list(self, ip_address: str) -> List[Dict[str, Any]]:
        """
        Get URLs associated with the IP address.

        Args:
            ip_address: IP address to query

        Returns:
            list: List of URLs associated with this IP
        """
        endpoint = f"indicators/IPv4/{ip_address}/url_list"
        response = self._get(endpoint)
        return response.get('url_list', [])

    def get_passive_dns(self, ip_address: str) -> Dict[str, Any]:
        """
        Get passive DNS data for IP.

        Args:
            ip_address: IP address to query

        Returns:
            dict: Passive DNS information
        """
        endpoint = f"indicators/IPv4/{ip_address}/passive_dns"
        return self._get(endpoint)

    def search_pulses(self, query: str, page: int = 1) -> Dict[str, Any]:
        """
        Search OTX pulses (threat intelligence reports).

        Args:
            query: Search query
            page: Page number for pagination

        Returns:
            dict: Search results
        """
        logger.info(f"Searching OTX pulses for: {query}")

        endpoint = "search/pulses"
        params = {
            'q': query,
            'page': page
        }

        return self._get(endpoint, params=params)

    def get_service_name(self) -> str:
        """
        Get the service name.

        Returns:
            str: Service name
        """
        return "AlienVault OTX"

    def get_subscribed_pulses(self, modified_since: str = None) -> Dict[str, Any]:
        """
        Get pulses from subscribed users/feeds.

        Args:
            modified_since: ISO 8601 datetime string to filter recent pulses

        Returns:
            dict: Subscribed pulses
        """
        endpoint = "pulses/subscribed"
        params = {}

        if modified_since:
            params['modified_since'] = modified_since

        return self._get(endpoint, params=params)
