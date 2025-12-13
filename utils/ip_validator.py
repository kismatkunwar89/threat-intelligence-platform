"""
IP Address validation and normalization utilities.

This module demonstrates:
- Using the ipaddress module from Python standard library
- Custom exception classes
- Type hints with Union types
- Comprehensions for batch operations
- Functional programming patterns (map, filter, lambda)
- Generator functions for memory-efficient processing
- Iterator pattern for custom IP range generation
"""

import ipaddress
from typing import Union, List, Tuple, Iterator, Generator
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


# ==============================================================================
# Advanced Python Features: Generators, Iterators, and Functional Programming
# ==============================================================================

def validate_ip_batch_functional(ip_list: List[str]) -> Tuple[List[str], List[str]]:
    """
    Validate a batch of IP addresses using functional programming approach.

    This demonstrates the use of filter() and lambda functions as an alternative
    to list comprehensions. While list comprehensions are more Pythonic,
    functional programming with filter/map can be useful for complex transformations.

    Args:
        ip_list: List of IP address strings

    Returns:
        Tuple of (valid_ips, invalid_ips)

    Example:
        >>> ips = ['192.168.1.1', 'invalid', '8.8.8.8', 'bad_ip']
        >>> valid, invalid = validate_ip_batch_functional(ips)
        >>> print(valid)
        ['192.168.1.1', '8.8.8.8']
    """
    validator = IPValidator()

    # Functional programming approach using filter() and lambda
    # filter() returns items where lambda returns True
    valid_ips = list(filter(lambda ip: _is_valid_ip(ip, validator), ip_list))
    invalid_ips = list(filter(lambda ip: not _is_valid_ip(ip, validator), ip_list))

    logger.info(f"Functional batch validation: {len(valid_ips)} valid, {len(invalid_ips)} invalid")
    return valid_ips, invalid_ips


def validate_ip_stream(ip_list: List[str]) -> Generator[str, None, None]:
    """
    Generator function that yields validated IPs one at a time.

    Generators are memory-efficient for processing large datasets because they
    produce values lazily (on-demand) instead of creating the entire list in memory.

    This is useful when:
    - Processing large IP lists from files
    - Streaming validation results
    - Reducing memory footprint

    Args:
        ip_list: List of IP address strings

    Yields:
        str: Valid IP addresses one at a time

    Example:
        >>> ips = ['192.168.1.1', 'invalid', '8.8.8.8', 'bad_ip']
        >>> for valid_ip in validate_ip_stream(ips):
        ...     print(f"Valid: {valid_ip}")
        Valid: 192.168.1.1
        Valid: 8.8.8.8
    """
    validator = IPValidator()

    for ip in ip_list:
        if _is_valid_ip(ip, validator):
            logger.debug(f"Generator yielding valid IP: {ip}")
            yield ip  # Generator yields values one at a time


def normalize_ip_stream(ip_list: List[str]) -> Generator[str, None, None]:
    """
    Generator that normalizes and yields valid IPs.

    Combines validation and normalization in a memory-efficient generator.

    Args:
        ip_list: List of IP address strings

    Yields:
        str: Normalized IP addresses

    Example:
        >>> ips = ['  192.168.1.1  ', '8.8.8.8', 'invalid']
        >>> normalized = list(normalize_ip_stream(ips))
        >>> print(normalized)
        ['192.168.1.1', '8.8.8.8']
    """
    validator = IPValidator()

    for ip in ip_list:
        try:
            normalized = validator.normalize_ip(ip)
            logger.debug(f"Generator yielding normalized IP: {normalized}")
            yield normalized
        except IPValidationError:
            # Skip invalid IPs silently
            continue


class IPRangeIterator:
    """
    Custom iterator for generating sequential IP addresses.

    This demonstrates the Iterator pattern by implementing __iter__() and __next__().
    Iterators are useful for creating custom iteration behavior over sequences.

    Use case: Generate sequential IPs for testing or scanning purposes.

    Example:
        >>> ip_range = IPRangeIterator('192.168.1.1', 5)
        >>> for ip in ip_range:
        ...     print(ip)
        192.168.1.1
        192.168.1.2
        192.168.1.3
        192.168.1.4
        192.168.1.5
    """

    def __init__(self, start_ip: str, count: int):
        """
        Initialize IP range iterator.

        Args:
            start_ip: Starting IP address
            count: Number of IPs to generate

        Raises:
            IPValidationError: If start_ip is invalid
        """
        self.start = ipaddress.ip_address(start_ip)
        self.count = count
        self.current_index = 0

    def __iter__(self) -> 'IPRangeIterator':
        """Return the iterator object itself."""
        return self

    def __next__(self) -> str:
        """
        Return the next IP address in the sequence.

        Raises:
            StopIteration: When all IPs have been generated
        """
        if self.current_index >= self.count:
            raise StopIteration

        # Calculate current IP by adding index to start IP
        current_ip = str(self.start + self.current_index)
        self.current_index += 1

        logger.debug(f"Iterator producing IP: {current_ip}")
        return current_ip


def filter_ips_by_type(ip_list: List[str], ip_type: str = 'public') -> List[str]:
    """
    Filter IPs using functional programming with lambda and filter.

    This demonstrates functional programming by combining filter(), lambda,
    and method references for flexible IP filtering.

    Args:
        ip_list: List of IP addresses
        ip_type: Type to filter ('public', 'private', 'ipv4', 'ipv6')

    Returns:
        List of filtered IP addresses

    Example:
        >>> ips = ['192.168.1.1', '8.8.8.8', '10.0.0.1']
        >>> public_ips = filter_ips_by_type(ips, 'public')
        >>> print(public_ips)
        ['8.8.8.8']
    """
    validator = IPValidator()

    # Define filter functions using lambda
    filters = {
        'public': lambda ip: _is_valid_ip(ip, validator) and validator.is_public(ip),
        'private': lambda ip: _is_valid_ip(ip, validator) and validator.is_private(ip),
        'ipv4': lambda ip: _is_valid_ip(ip, validator) and validator.is_ipv4(ip),
        'ipv6': lambda ip: _is_valid_ip(ip, validator) and validator.is_ipv6(ip),
    }

    # Apply filter using functional programming
    filter_func = filters.get(ip_type, filters['public'])
    filtered_ips = list(filter(filter_func, ip_list))

    logger.info(f"Filtered {len(filtered_ips)} {ip_type} IPs from {len(ip_list)} total")
    return filtered_ips


def map_ip_to_info(ip_list: List[str]) -> List[dict]:
    """
    Map IP addresses to their information using functional programming.

    This demonstrates the map() function for transforming data.
    map() applies a function to every item in an iterable.

    Args:
        ip_list: List of IP address strings

    Returns:
        List of IP information dictionaries

    Example:
        >>> ips = ['8.8.8.8', '1.1.1.1']
        >>> info_list = map_ip_to_info(ips)
        >>> print(info_list[0]['address'])
        8.8.8.8
    """
    validator = IPValidator()

    # Helper function to safely get IP info
    def safe_get_info(ip: str) -> dict:
        try:
            return validator.get_ip_info(ip)
        except IPValidationError:
            return {
                'address': ip,
                'error': 'Invalid IP address'
            }

    # Use map() to transform IP strings to info dictionaries
    # map() is a functional programming approach to transformations
    info_list = list(map(safe_get_info, ip_list))

    logger.info(f"Mapped {len(info_list)} IPs to information dictionaries")
    return info_list
