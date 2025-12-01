"""
GreyNoise API Client for internet scanner/benign activity detection.

This module demonstrates:
- API client implementation
- Context-aware risk adjustment
- Classification of benign vs malicious noise
- Error handling and graceful degradation

GreyNoise provides context about IPs that scan the internet:
- Identifies common business services (benign noise)
- Flags malicious activity
- Provides actor classification
"""

import requests
import logging
from typing import Dict, Any, Optional
from config import Config

logger = logging.getLogger(__name__)


class GreyNoiseClient:
    """
    Client for GreyNoise IP Context API.

    GreyNoise helps distinguish between:
    - Benign internet scanners (search engines, security researchers)
    - Malicious actors (opportunistic attacks, botnets)

    This is crucial for reducing false positives in threat intelligence.
    """

    BASE_URL = "https://api.greynoise.io/v3"
    COMMUNITY_URL = "https://api.greynoise.io/v3/community"

    def __init__(self, api_key: Optional[str] = None):
        """
        Initialize GreyNoise client.

        Args:
            api_key: GreyNoise API key (defaults to config)
                    If not provided, falls back to Community API (limited data)
        """
        self.api_key = api_key or Config.GREYNOISE_API_KEY
        self.timeout = Config.API_TIMEOUT_SECONDS
        self.session = requests.Session()

        # Community API doesn't require auth, but paid API does
        if self.api_key and self.api_key != "your_greynoise_api_key_here":
            self.session.headers.update({
                'key': self.api_key,
                'Accept': 'application/json'
            })
            self.use_community_api = False
        else:
            self.use_community_api = True
            logger.info("GreyNoise API key not configured, using Community API (limited data)")

    def check_ip(self, ip_address: str) -> Optional[Dict[str, Any]]:
        """
        Look up an IP address in GreyNoise.

        Args:
            ip_address: IP address to check

        Returns:
            dict: GreyNoise API response, or None if error

        Response fields (varies by API tier):
        - classification: benign, malicious, or unknown
        - noise: boolean indicating if IP is noisy
        - riot: boolean indicating if part of known benign service
        - actor: threat actor name (if known)
        - tags: list of observed behaviors
        """
        if self.use_community_api:
            return self._check_ip_community(ip_address)
        else:
            return self._check_ip_context(ip_address)

    def _check_ip_context(self, ip_address: str) -> Optional[Dict[str, Any]]:
        """
        Query GreyNoise Context API (paid tier).

        Provides full context including:
        - Classification (benign/malicious/unknown)
        - Actor information
        - Detailed tags and behaviors
        - CVEs targeted
        """
        try:
            url = f"{self.BASE_URL}/context/{ip_address}"
            logger.info(f"Querying GreyNoise Context API for {ip_address}")

            response = self.session.get(url, timeout=self.timeout)

            if response.status_code == 200:
                data = response.json()
                logger.info(f"GreyNoise response received for {ip_address}: classification={data.get('classification')}")
                return data

            elif response.status_code == 404:
                logger.info(f"IP {ip_address} not found in GreyNoise (not scanning internet)")
                # Not found = not noisy = likely legitimate
                return {
                    'ip': ip_address,
                    'noise': False,
                    'riot': False,
                    'classification': 'unknown',
                    'seen': False
                }

            elif response.status_code == 401:
                logger.error("GreyNoise API key invalid, falling back to Community API")
                self.use_community_api = True
                return self._check_ip_community(ip_address)

            elif response.status_code == 429:
                logger.warning("GreyNoise rate limit exceeded, skipping (graceful degradation)")
                return None

            else:
                logger.error(f"GreyNoise API error: {response.status_code} - {response.text}")
                return None

        except requests.exceptions.Timeout:
            logger.error(f"GreyNoise API timeout for {ip_address}")
            return None

        except requests.exceptions.RequestException as e:
            logger.error(f"GreyNoise API request failed for {ip_address}: {e}")
            return None

        except Exception as e:
            logger.error(f"Unexpected error querying GreyNoise for {ip_address}: {e}", exc_info=True)
            return None

    def _check_ip_community(self, ip_address: str) -> Optional[Dict[str, Any]]:
        """
        Query GreyNoise Community API (free tier).

        Provides basic context:
        - Whether IP is noisy or not
        - Classification (benign/malicious/unknown)
        - RIOT status (known benign service)
        - Basic metadata

        No authentication required.
        """
        try:
            url = f"{self.COMMUNITY_URL}/{ip_address}"
            logger.info(f"Querying GreyNoise Community API for {ip_address}")

            response = self.session.get(url, timeout=self.timeout)

            if response.status_code == 200:
                data = response.json()
                logger.info(f"GreyNoise Community response received for {ip_address}: classification={data.get('classification')}")
                return data

            elif response.status_code == 404:
                logger.info(f"IP {ip_address} not found in GreyNoise Community (not scanning internet)")
                return {
                    'ip': ip_address,
                    'noise': False,
                    'riot': False,
                    'classification': 'unknown'
                }

            elif response.status_code == 429:
                logger.warning("GreyNoise Community rate limit exceeded, skipping")
                return None

            else:
                logger.error(f"GreyNoise Community API error: {response.status_code} - {response.text}")
                return None

        except requests.exceptions.Timeout:
            logger.error(f"GreyNoise Community API timeout for {ip_address}")
            return None

        except requests.exceptions.RequestException as e:
            logger.error(f"GreyNoise Community API request failed for {ip_address}: {e}")
            return None

        except Exception as e:
            logger.error(f"Unexpected error querying GreyNoise Community for {ip_address}: {e}", exc_info=True)
            return None

    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit - close session."""
        self.session.close()
