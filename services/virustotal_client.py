"""
VirusTotal API Client with production-aware rate limiting.

This module demonstrates:
- API client implementation with rate limiting
- Context manager for quota tracking
- Graceful degradation when quota exceeded
- Production vs development rate limit handling
- Error handling for API failures

VirusTotal Free Tier Limits:
- 4 lookups per minute
- 500 lookups per day
"""

import requests
import logging
import time
from datetime import datetime, timedelta
from typing import Dict, Any, Optional
from config import Config

logger = logging.getLogger(__name__)


class VirusTotalRateLimiter:
    """
    Rate limiter for VirusTotal API (4 requests/minute, 500/day).

    This demonstrates a simple in-memory rate limiter.
    In production, use Redis for distributed rate limiting.
    """

    def __init__(self):
        self.requests_per_minute = []  # Timestamps of recent requests
        self.daily_requests = 0
        self.daily_reset_time = datetime.now() + timedelta(days=1)
        self.max_per_minute = 4
        self.max_per_day = 500

    def can_make_request(self) -> bool:
        """
        Check if we can make a request without exceeding rate limits.

        Returns:
            bool: True if request can be made, False otherwise
        """
        now = datetime.now()

        # Reset daily counter if needed
        if now >= self.daily_reset_time:
            self.daily_requests = 0
            self.daily_reset_time = now + timedelta(days=1)
            logger.info("VirusTotal daily quota reset")

        # Check daily limit
        if self.daily_requests >= self.max_per_day:
            logger.warning(f"VirusTotal daily quota exceeded: {self.daily_requests}/{self.max_per_day}")
            return False

        # Clean old requests (older than 1 minute)
        one_minute_ago = time.time() - 60
        self.requests_per_minute = [
            ts for ts in self.requests_per_minute
            if ts > one_minute_ago
        ]

        # Check per-minute limit
        if len(self.requests_per_minute) >= self.max_per_minute:
            logger.warning(f"VirusTotal per-minute quota exceeded: {len(self.requests_per_minute)}/{self.max_per_minute}")
            return False

        return True

    def record_request(self) -> None:
        """Record that a request was made."""
        self.requests_per_minute.append(time.time())
        self.daily_requests += 1
        logger.debug(f"VirusTotal request recorded: {self.daily_requests} daily, {len(self.requests_per_minute)} per minute")

    def get_quota_info(self) -> Dict[str, Any]:
        """
        Get current quota usage information.

        Returns:
            dict: Quota usage stats
        """
        return {
            'daily_used': self.daily_requests,
            'daily_limit': self.max_per_day,
            'daily_remaining': self.max_per_day - self.daily_requests,
            'minute_used': len(self.requests_per_minute),
            'minute_limit': self.max_per_minute,
            'minute_remaining': self.max_per_minute - len(self.requests_per_minute),
            'daily_reset_time': self.daily_reset_time.isoformat()
        }


# Global rate limiter instance
_rate_limiter = VirusTotalRateLimiter()


class VirusTotalClient:
    """
    Client for VirusTotal IP lookup API.

    This demonstrates:
    - RESTful API client implementation
    - Rate limiting integration
    - Graceful degradation
    - Error handling for various HTTP status codes
    """

    BASE_URL = "https://www.virustotal.com/api/v3"

    def __init__(self, api_key: Optional[str] = None):
        """
        Initialize VirusTotal client.

        Args:
            api_key: VirusTotal API key (defaults to config)
        """
        self.api_key = api_key or Config.VIRUSTOTAL_API_KEY
        self.timeout = Config.API_TIMEOUT_SECONDS
        self.session = requests.Session()
        self.session.headers.update({
            'x-apikey': self.api_key,
            'Accept': 'application/json'
        })

    def check_ip(self, ip_address: str, skip_rate_limit: bool = False) -> Optional[Dict[str, Any]]:
        """
        Look up an IP address in VirusTotal.

        Args:
            ip_address: IP address to check
            skip_rate_limit: Skip rate limit check (for testing)

        Returns:
            dict: VirusTotal API response, or None if quota exceeded or error

        Raises:
            None: All exceptions are caught and logged
        """
        if not self.api_key:
            logger.warning("VirusTotal API key not configured, skipping")
            return None

        # Check rate limit (production-aware)
        if not skip_rate_limit and not _rate_limiter.can_make_request():
            logger.warning(f"VirusTotal rate limit exceeded for {ip_address}, skipping (graceful degradation)")
            # Return None to allow other sources to continue
            return None

        try:
            url = f"{self.BASE_URL}/ip_addresses/{ip_address}"
            logger.info(f"Querying VirusTotal for {ip_address}")

            response = self.session.get(url, timeout=self.timeout)

            # Record request for rate limiting
            if not skip_rate_limit:
                _rate_limiter.record_request()

            # Handle different status codes
            if response.status_code == 200:
                data = response.json()
                logger.info(f"VirusTotal response received for {ip_address}")
                return data

            elif response.status_code == 404:
                logger.info(f"IP {ip_address} not found in VirusTotal")
                return {'data': {'attributes': {}}}  # Return empty structure

            elif response.status_code == 429:
                logger.warning(f"VirusTotal rate limit hit (429), quota info: {_rate_limiter.get_quota_info()}")
                return None

            elif response.status_code == 401:
                logger.error("VirusTotal API key invalid or expired")
                return None

            else:
                logger.error(f"VirusTotal API error: {response.status_code} - {response.text}")
                return None

        except requests.exceptions.Timeout:
            logger.error(f"VirusTotal API timeout for {ip_address}")
            return None

        except requests.exceptions.RequestException as e:
            logger.error(f"VirusTotal API request failed for {ip_address}: {e}")
            return None

        except Exception as e:
            logger.error(f"Unexpected error querying VirusTotal for {ip_address}: {e}", exc_info=True)
            return None

    def get_quota_info(self) -> Dict[str, Any]:
        """
        Get current VirusTotal quota usage.

        Returns:
            dict: Quota information
        """
        return _rate_limiter.get_quota_info()

    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit - close session."""
        self.session.close()
