"""
Cache model for storing threat intelligence data.

This module demonstrates:
- OOP with dataclass for data modeling
- JSON serialization/deserialization
- Database operations with context managers
- Property decorators
- Class methods for CRUD operations
- Type checking with isinstance
"""

import json
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List, Union
from dataclasses import dataclass, asdict
import logging
from models.database import get_db_connection
from config import Config

logger = logging.getLogger(__name__)

# Forward declaration - will be imported at runtime to avoid circular imports
ThreatIntelResult = None


@dataclass
class ThreatIntelCache:
    """
    Data class representing a cached threat intelligence entry.

    This demonstrates the use of dataclasses for clean data modeling.

    Attributes:
        ip_address: The IP address being cached
        threat_data: JSON data containing threat intelligence
        created_at: When the cache entry was created
        expires_at: When the cache entry expires
        id: Database primary key (optional)
    """
    ip_address: str
    threat_data: Dict[str, Any]
    created_at: datetime
    expires_at: datetime
    id: Optional[int] = None

    @classmethod
    def from_db_row(cls, row: Dict[str, Any]) -> 'ThreatIntelCache':
        """
        Create a ThreatIntelCache instance from a database row.

        Args:
            row: Dictionary from database query result

        Returns:
            ThreatIntelCache: Cache instance
        """
        return cls(
            id=row['id'],
            ip_address=row['ip_address'],
            threat_data=json.loads(row['threat_data']),
            created_at=row['created_at'],
            expires_at=row['expires_at']
        )

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert cache entry to dictionary.

        Returns:
            dict: Dictionary representation
        """
        data = asdict(self)
        # Convert datetime to string for JSON serialization
        data['created_at'] = self.created_at.isoformat()
        data['expires_at'] = self.expires_at.isoformat()
        return data

    @property
    def is_expired(self) -> bool:
        """
        Check if cache entry has expired.

        Returns:
            bool: True if expired, False otherwise
        """
        return datetime.now() > self.expires_at

    @property
    def time_remaining(self) -> timedelta:
        """
        Get remaining time before expiration.

        Returns:
            timedelta: Time remaining
        """
        return self.expires_at - datetime.now()


class CacheManager:
    """
    Manager class for cache operations.

    This demonstrates:
    - Class methods for database operations
    - Use of context managers for database connections
    - CRUD operations
    """

    @staticmethod
    def get_cache(ip_address: str) -> Optional[ThreatIntelCache]:
        """
        Retrieve cached threat intelligence for an IP address.

        Args:
            ip_address: IP address to look up

        Returns:
            ThreatIntelCache if found and not expired, None otherwise
        """
        try:
            with get_db_connection() as conn:
                cursor = conn.cursor()
                query = """
                    SELECT id, ip_address, threat_data, created_at, expires_at
                    FROM threat_intel_cache
                    WHERE ip_address = %s
                    AND expires_at > NOW()
                    ORDER BY created_at DESC
                    LIMIT 1
                """
                cursor.execute(query, (ip_address,))
                row = cursor.fetchone()

                if row:
                    cache = ThreatIntelCache.from_db_row(row)
                    logger.info(f"Cache hit for IP: {ip_address}")
                    return cache

                logger.info(f"Cache miss for IP: {ip_address}")
                return None

        except Exception as e:
            logger.error(f"Error retrieving cache for {ip_address}: {e}")
            return None

    @staticmethod
    def set_cache(ip_address: str, threat_data: Union[Dict[str, Any], Any],
                  ttl_seconds: Optional[int] = None) -> bool:
        """
        Store threat intelligence data in cache.

        Now handles both dict and ThreatIntelResult dataclass objects.
        If ThreatIntelResult is provided, it's automatically serialized to dict.

        Args:
            ip_address: IP address to cache
            threat_data: Threat intelligence data (dict or ThreatIntelResult dataclass)
            ttl_seconds: Time to live in seconds (default from config)

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            # Import here to avoid circular dependency
            global ThreatIntelResult
            if ThreatIntelResult is None:
                from models.threat_intel_result import ThreatIntelResult as TIR
                ThreatIntelResult = TIR

            ttl = ttl_seconds or Config.CACHE_TTL_SECONDS
            created_at = datetime.now()
            expires_at = created_at + timedelta(seconds=ttl)

            # Handle both dict and ThreatIntelResult dataclass
            if hasattr(threat_data, 'to_dict'):
                # It's a ThreatIntelResult dataclass
                data_dict = threat_data.to_dict()
                logger.debug(f"Serializing ThreatIntelResult dataclass for {ip_address}")
            else:
                # It's already a dict (backward compatibility)
                data_dict = threat_data

            with get_db_connection() as conn:
                cursor = conn.cursor()
                query = """
                    INSERT INTO threat_intel_cache
                    (ip_address, threat_data, created_at, expires_at)
                    VALUES (%s, %s, %s, %s)
                """
                cursor.execute(query, (
                    ip_address,
                    json.dumps(data_dict),
                    created_at,
                    expires_at
                ))

                logger.info(f"Cached threat intel for IP: {ip_address}, expires in {ttl}s")
                return True

        except Exception as e:
            logger.error(f"Error setting cache for {ip_address}: {e}")
            return False

    @staticmethod
    def invalidate_cache(ip_address: str) -> bool:
        """
        Invalidate (delete) cache entry for an IP address.

        Args:
            ip_address: IP address to invalidate

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            with get_db_connection() as conn:
                cursor = conn.cursor()
                query = "DELETE FROM threat_intel_cache WHERE ip_address = %s"
                cursor.execute(query, (ip_address,))
                logger.info(f"Invalidated cache for IP: {ip_address}")
                return True

        except Exception as e:
            logger.error(f"Error invalidating cache for {ip_address}: {e}")
            return False

    @staticmethod
    def cleanup_expired() -> int:
        """
        Remove all expired cache entries.

        Returns:
            int: Number of entries removed
        """
        try:
            with get_db_connection() as conn:
                cursor = conn.cursor()
                query = "DELETE FROM threat_intel_cache WHERE expires_at < NOW()"
                cursor.execute(query)
                count = cursor.rowcount
                logger.info(f"Cleaned up {count} expired cache entries")
                return count

        except Exception as e:
            logger.error(f"Error cleaning up expired cache: {e}")
            return 0

    @staticmethod
    def get_all_cached_ips() -> List[str]:
        """
        Get list of all currently cached IP addresses.

        Demonstrates list comprehension for data transformation.

        Returns:
            List[str]: List of cached IP addresses
        """
        try:
            with get_db_connection() as conn:
                cursor = conn.cursor()
                query = """
                    SELECT DISTINCT ip_address
                    FROM threat_intel_cache
                    WHERE expires_at > NOW()
                """
                cursor.execute(query)
                results = cursor.fetchall()

                # Use list comprehension (Pythonic!)
                ips = [row['ip_address'] for row in results]
                logger.info(f"Found {len(ips)} cached IPs")
                return ips

        except Exception as e:
            logger.error(f"Error retrieving cached IPs: {e}")
            return []

    @staticmethod
    def get_cache_stats() -> Dict[str, Any]:
        """
        Get statistics about the cache.

        Returns:
            dict: Cache statistics
        """
        try:
            with get_db_connection() as conn:
                cursor = conn.cursor()
                query = """
                    SELECT
                        COUNT(*) as total_entries,
                        COUNT(CASE WHEN expires_at > NOW() THEN 1 END) as valid_entries,
                        COUNT(CASE WHEN expires_at <= NOW() THEN 1 END) as expired_entries
                    FROM threat_intel_cache
                """
                cursor.execute(query)
                stats = cursor.fetchone()
                logger.debug(f"Cache stats: {stats}")
                return stats or {}

        except Exception as e:
            logger.error(f"Error retrieving cache stats: {e}")
            return {}
