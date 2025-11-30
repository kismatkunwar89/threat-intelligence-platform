"""
Test script for verifying application components.

This script tests:
- Database connectivity
- IP validation
- Configuration loading
- Logging setup
"""

import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from utils.logger import setup_logging, get_logger
from config import Config
from models.database import test_connection, get_db_connection
from models.cache import CacheManager
from utils.ip_validator import IPValidator, validate_ip_batch
from services.abuseipdb_client import AbuseIPDBClient
from services.otx_client import OTXClient

# Setup logging
setup_logging(log_level="DEBUG")
logger = get_logger(__name__)


def test_config():
    """Test configuration loading."""
    logger.info("=" * 60)
    logger.info("Testing Configuration")
    logger.info("=" * 60)

    try:
        config_summary = Config.display_config_summary()
        logger.info(f"Configuration loaded successfully:")
        for key, value in config_summary.items():
            logger.info(f"  {key}: {value}")
        return True
    except Exception as e:
        logger.error(f"Configuration test failed: {e}")
        return False


def test_database():
    """Test database connectivity."""
    logger.info("=" * 60)
    logger.info("Testing Database Connection")
    logger.info("=" * 60)

    try:
        if test_connection():
            logger.info("✓ Database connection successful")

            # Test cache manager
            stats = CacheManager.get_cache_stats()
            logger.info(f"✓ Cache stats: {stats}")
            return True
        else:
            logger.error("✗ Database connection failed")
            return False
    except Exception as e:
        logger.error(f"Database test failed: {e}")
        return False


def test_ip_validation():
    """Test IP validation utilities."""
    logger.info("=" * 60)
    logger.info("Testing IP Validation")
    logger.info("=" * 60)

    test_ips = [
        "192.168.1.1",
        "8.8.8.8",
        "2001:0db8:85a3::8a2e:0370:7334",
        "invalid_ip",
        "999.999.999.999",
        "  10.0.0.1  ",  # With whitespace
    ]

    validator = IPValidator()

    for ip in test_ips:
        try:
            normalized = validator.normalize_ip(ip)
            info = validator.get_ip_info(normalized)
            logger.info(f"✓ Valid IP: {ip.strip()} -> {normalized}")
            logger.info(f"  Version: IPv{info['version']}, Private: {info['is_private']}")
        except Exception as e:
            logger.warning(f"✗ Invalid IP: {ip.strip()} - {e}")

    # Test batch validation
    valid, invalid = validate_ip_batch(test_ips)
    logger.info(f"\nBatch validation: {len(valid)} valid, {len(invalid)} invalid")

    return True


def test_api_clients():
    """Test API client initialization."""
    logger.info("=" * 60)
    logger.info("Testing API Clients")
    logger.info("=" * 60)

    try:
        # Note: These will fail if API keys are not configured
        # But we can test initialization

        if Config.ABUSEIPDB_API_KEY and Config.ABUSEIPDB_API_KEY != "your_abuseipdb_api_key_here":
            logger.info("Testing AbuseIPDB client...")
            abuse_client = AbuseIPDBClient()
            logger.info(f"✓ {abuse_client} initialized")
        else:
            logger.warning("⚠ AbuseIPDB API key not configured - skipping")

        if Config.OTX_API_KEY and Config.OTX_API_KEY != "your_otx_api_key_here":
            logger.info("Testing OTX client...")
            otx_client = OTXClient()
            logger.info(f"✓ {otx_client} initialized")
        else:
            logger.warning("⚠ OTX API key not configured - skipping")

        return True

    except Exception as e:
        logger.error(f"API client test failed: {e}")
        return False


def test_cache_operations():
    """Test cache read/write operations."""
    logger.info("=" * 60)
    logger.info("Testing Cache Operations")
    logger.info("=" * 60)

    test_ip = "8.8.8.8"
    test_data = {
        "ip": test_ip,
        "reputation": "good",
        "source": "test"
    }

    try:
        # Test write
        logger.info(f"Writing test data to cache for {test_ip}...")
        success = CacheManager.set_cache(test_ip, test_data, ttl_seconds=60)

        if success:
            logger.info("✓ Cache write successful")

            # Test read
            logger.info(f"Reading cache for {test_ip}...")
            cached = CacheManager.get_cache(test_ip)

            if cached:
                logger.info(f"✓ Cache read successful")
                logger.info(f"  Cached data: {cached.threat_data}")
                logger.info(f"  Expires in: {cached.time_remaining}")

                # Test invalidation
                logger.info(f"Invalidating cache for {test_ip}...")
                CacheManager.invalidate_cache(test_ip)
                logger.info("✓ Cache invalidated")

                return True
            else:
                logger.error("✗ Cache read failed")
                return False
        else:
            logger.error("✗ Cache write failed")
            return False

    except Exception as e:
        logger.error(f"Cache operation test failed: {e}")
        return False


def run_all_tests():
    """Run all component tests."""
    logger.info("\n" + "=" * 60)
    logger.info("THREAT INTEL APP - COMPONENT TESTS")
    logger.info("=" * 60 + "\n")

    results = {
        "Configuration": test_config(),
        "Database": test_database(),
        "IP Validation": test_ip_validation(),
        "API Clients": test_api_clients(),
        "Cache Operations": test_cache_operations()
    }

    # Summary
    logger.info("\n" + "=" * 60)
    logger.info("TEST SUMMARY")
    logger.info("=" * 60)

    passed = sum(1 for result in results.values() if result)
    total = len(results)

    for test_name, result in results.items():
        status = "✓ PASSED" if result else "✗ FAILED"
        logger.info(f"{test_name:.<40} {status}")

    logger.info("=" * 60)
    logger.info(f"Total: {passed}/{total} tests passed")
    logger.info("=" * 60 + "\n")

    return passed == total


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
