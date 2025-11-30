"""
AbuseIPDB API client implementation.

This module demonstrates:
- Inheritance from abstract base class
- API-specific implementation
- Method overriding
- Real-world API integration
"""

from typing import Dict, Any
import logging
from services.threat_intel_client import ThreatIntelClient, APIError
from config import Config

logger = logging.getLogger(__name__)


class AbuseIPDBClient(ThreatIntelClient):
    """
    Client for AbuseIPDB threat intelligence API.

    API Documentation: https://docs.abuseipdb.com/

    This class inherits from ThreatIntelClient and implements
    the abstract methods for AbuseIPDB-specific functionality.
    """

    # AbuseIPDB API base URL
    BASE_URL = 'https://api.abuseipdb.com/api/v2'

    def __init__(self, api_key: str = None):
        """
        Initialize AbuseIPDB client.

        Args:
            api_key: AbuseIPDB API key (defaults to config)
        """
        key = api_key or Config.ABUSEIPDB_API_KEY
        if not key:
            raise ValueError("AbuseIPDB API key is required")

        super().__init__(
            api_key=key,
            base_url=self.BASE_URL,
            timeout=Config.API_TIMEOUT_SECONDS
        )

        logger.info("AbuseIPDB client initialized")

    def _get_default_headers(self) -> Dict[str, str]:
        """
        Get AbuseIPDB-specific headers.

        AbuseIPDB requires the API key in the 'Key' header.

        Returns:
            dict: Headers including API key
        """
        headers = super()._get_default_headers()
        headers['Key'] = self.api_key
        return headers

    def get_ip_reputation(self, ip_address: str) -> Dict[str, Any]:
        """
        Get IP reputation data from AbuseIPDB.

        Args:
            ip_address: IP address to query

        Returns:
            dict: Raw API response with reputation data

        Raises:
            APIError: If the API request fails

        Example response structure:
        {
            "data": {
                "ipAddress": "8.8.8.8",
                "isPublic": true,
                "ipVersion": 4,
                "isWhitelisted": false,
                "abuseConfidenceScore": 0,
                "countryCode": "US",
                "usageType": "Data Center/Web Hosting/Transit",
                "isp": "Google LLC",
                "domain": "google.com",
                "totalReports": 0,
                "numDistinctUsers": 0,
                "lastReportedAt": null
            }
        }
        """
        logger.info(f"Querying AbuseIPDB for IP: {ip_address}")

        try:
            # AbuseIPDB check endpoint with maxAgeInDays parameter
            params = {
                'ipAddress': ip_address,
                'maxAgeInDays': 90,  # Check reports from last 90 days
                'verbose': True      # Include detailed information
            }

            response = self._get('check', params=params)

            logger.info(
                f"AbuseIPDB response for {ip_address}: "
                f"confidence={response.get('data', {}).get('abuseConfidenceScore', 'N/A')}"
            )

            return response

        except APIError as e:
            logger.error(f"AbuseIPDB API error for {ip_address}: {e}")
            raise

    def get_service_name(self) -> str:
        """
        Get the service name.

        Returns:
            str: Service name
        """
        return "AbuseIPDB"

    def check_bulk(self, ip_addresses: list) -> Dict[str, Any]:
        """
        Check multiple IP addresses at once (requires premium API key).

        Note: This is a premium feature and may not be available on free tier.

        Args:
            ip_addresses: List of IP addresses to check

        Returns:
            dict: Bulk check results
        """
        logger.info(f"Bulk checking {len(ip_addresses)} IPs on AbuseIPDB")

        try:
            # Join IPs with commas for bulk check
            params = {
                'ipAddresses': ','.join(ip_addresses),
                'maxAgeInDays': 90
            }

            response = self._get('check-bulk', params=params)
            return response

        except APIError as e:
            logger.error(f"AbuseIPDB bulk check error: {e}")
            raise

    def report_ip(self, ip_address: str, categories: list, comment: str = None) -> Dict[str, Any]:
        """
        Report an IP address for abusive behavior.

        Note: Use responsibly - false reports can affect the database quality.

        Args:
            ip_address: IP address to report
            categories: List of category IDs (see AbuseIPDB docs)
            comment: Optional comment describing the abuse

        Returns:
            dict: Report submission result

        Example categories:
        - 18: Brute-Force
        - 22: Web App Attack
        - 15: Hacking
        """
        logger.info(f"Reporting IP {ip_address} to AbuseIPDB")

        try:
            data = {
                'ip': ip_address,
                'categories': ','.join(map(str, categories)),
                'comment': comment or 'Automated report from Threat Intel Lookup'
            }

            response = self._post('report', data=data)
            logger.info(f"Successfully reported {ip_address} to AbuseIPDB")
            return response

        except APIError as e:
            logger.error(f"AbuseIPDB report error for {ip_address}: {e}")
            raise
