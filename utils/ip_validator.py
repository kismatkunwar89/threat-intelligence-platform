"""
IP Address validation and normalization utilities.

This module demonstrates:
- Using the ipaddress module from Python standard library
- Custom exception classes
- Type hints with Union types
- Comprehensions for batch operations
- Functional programming patterns
"""

import ipaddress
from typing import Union, List, Tuple
import logging

logger = logging.getLogger(__name__)


class IPValidationError(Exception):
    """Custom exception for IP validation errors."""
    pass


class IPValidator:
    """
    Validator class for IP addresses (IPv4 and IPv6).

    This class provides methods to validate and normalize IP addresses
    using Python's built-in ipaddress module.
    """

    @staticmethod
    def validate_ip(ip_string: str) -> Union[ipaddress.IPv4Address, ipaddress.IPv6Address]:
        """
        Validate and parse an IP address string.

        Args:
            ip_string: String representation of an IP address

        Returns:
            IPv4Address or IPv6Address object

        Raises:
            IPValidationError: If the IP address is invalid

        Examples:
            >>> validator = IPValidator()
            >>> validator.validate_ip('192.168.1.1')
            IPv4Address('192.168.1.1')
            >>> validator.validate_ip('2001:0db8:85a3::8a2e:0370:7334')
            IPv6Address('2001:db8:85a3::8a2e:370:7334')
        """
        try:
            # ipaddress.ip_address() automatically detects IPv4 or IPv6
            ip_obj = ipaddress.ip_address(ip_string)
            logger.debug(f"Valid IP address: {ip_obj} (version {ip_obj.version})")
            return ip_obj

        except ValueError as e:
            logger.warning(f"Invalid IP address '{ip_string}': {e}")
            raise IPValidationError(f"Invalid IP address: {ip_string}") from e

    @staticmethod
    def normalize_ip(ip_string: str) -> str:
        """
        Normalize an IP address (strip whitespace, validate format).

        Args:
            ip_string: Raw IP address string

        Returns:
            str: Normalized IP address string

        Raises:
            IPValidationError: If the IP address is invalid

        Examples:
            >>> IPValidator.normalize_ip('  192.168.1.1  ')
            '192.168.1.1'
            >>> IPValidator.normalize_ip('2001:0db8:85a3:0000:0000:8a2e:0370:7334')
            '2001:db8:85a3::8a2e:370:7334'
        """
        # Strip whitespace
        cleaned = ip_string.strip()

        # Validate and get normalized form
        ip_obj = IPValidator.validate_ip(cleaned)

        # Return compressed (normalized) string representation
        return str(ip_obj)

    @staticmethod
    def is_ipv4(ip_string: str) -> bool:
        """
        Check if an IP address is IPv4.

        Args:
            ip_string: IP address string

        Returns:
            bool: True if IPv4, False otherwise
        """
        try:
            ip_obj = ipaddress.ip_address(ip_string.strip())
            return isinstance(ip_obj, ipaddress.IPv4Address)
        except ValueError:
            return False

    @staticmethod
    def is_ipv6(ip_string: str) -> bool:
        """
        Check if an IP address is IPv6.

        Args:
            ip_string: IP address string

        Returns:
            bool: True if IPv6, False otherwise
        """
        try:
            ip_obj = ipaddress.ip_address(ip_string.strip())
            return isinstance(ip_obj, ipaddress.IPv6Address)
        except ValueError:
            return False

    @staticmethod
    def is_private(ip_string: str) -> bool:
        """
        Check if an IP address is private (RFC 1918 for IPv4).

        Args:
            ip_string: IP address string

        Returns:
            bool: True if private, False otherwise

        Examples:
            >>> IPValidator.is_private('192.168.1.1')
            True
            >>> IPValidator.is_private('8.8.8.8')
            False
        """
        try:
            ip_obj = ipaddress.ip_address(ip_string.strip())
            return ip_obj.is_private
        except ValueError:
            return False

    @staticmethod
    def is_public(ip_string: str) -> bool:
        """
        Check if an IP address is public (globally routable).

        Args:
            ip_string: IP address string

        Returns:
            bool: True if public, False otherwise
        """
        try:
            ip_obj = ipaddress.ip_address(ip_string.strip())
            return not (ip_obj.is_private or ip_obj.is_loopback or
                       ip_obj.is_reserved or ip_obj.is_multicast)
        except ValueError:
            return False

    @staticmethod
    def get_ip_info(ip_string: str) -> dict:
        """
        Get detailed information about an IP address.

        Args:
            ip_string: IP address string

        Returns:
            dict: Dictionary with IP information

        Raises:
            IPValidationError: If the IP address is invalid
        """
        ip_obj = IPValidator.validate_ip(ip_string.strip())

        return {
            'address': str(ip_obj),
            'version': ip_obj.version,
            'is_private': ip_obj.is_private,
            'is_global': ip_obj.is_global,
            'is_loopback': ip_obj.is_loopback,
            'is_multicast': ip_obj.is_multicast,
            'is_reserved': ip_obj.is_reserved,
            'is_link_local': ip_obj.is_link_local,
        }


def validate_ip_batch(ip_list: List[str]) -> Tuple[List[str], List[str]]:
    """
    Validate a batch of IP addresses.

    This function demonstrates list comprehensions for filtering and transforming data.

    Args:
        ip_list: List of IP address strings

    Returns:
        Tuple of (valid_ips, invalid_ips)

    Example:
        >>> ips = ['192.168.1.1', 'invalid', '8.8.8.8', 'bad_ip']
        >>> valid, invalid = validate_ip_batch(ips)
        >>> print(valid)
        ['192.168.1.1', '8.8.8.8']
    """
    validator = IPValidator()

    # Use list comprehensions (Pythonic!)
    valid_ips = [
        ip for ip in ip_list
        if _is_valid_ip(ip, validator)
    ]

    invalid_ips = [
        ip for ip in ip_list
        if not _is_valid_ip(ip, validator)
    ]

    logger.info(f"Batch validation: {len(valid_ips)} valid, {len(invalid_ips)} invalid")
    return valid_ips, invalid_ips


def _is_valid_ip(ip_string: str, validator: IPValidator) -> bool:
    """
    Helper function to check if an IP is valid.

    Args:
        ip_string: IP address string
        validator: IPValidator instance

    Returns:
        bool: True if valid, False otherwise
    """
    try:
        validator.validate_ip(ip_string.strip())
        return True
    except IPValidationError:
        return False


def filter_public_ips(ip_list: List[str]) -> List[str]:
    """
    Filter a list to only include public IP addresses.

    Demonstrates comprehensions with method calls.

    Args:
        ip_list: List of IP address strings

    Returns:
        List of public IP addresses
    """
    validator = IPValidator()

    # List comprehension with filter condition
    public_ips = [
        ip for ip in ip_list
        if _is_valid_ip(ip, validator) and validator.is_public(ip)
    ]

    logger.info(f"Filtered {len(public_ips)} public IPs from {len(ip_list)} total")
    return public_ips


# Convenience functions
def is_valid_ip(ip_string: str) -> bool:
    """
    Quick check if a string is a valid IP address.

    Args:
        ip_string: IP address string

    Returns:
        bool: True if valid, False otherwise
    """
    try:
        IPValidator.validate_ip(ip_string)
        return True
    except IPValidationError:
        return False
