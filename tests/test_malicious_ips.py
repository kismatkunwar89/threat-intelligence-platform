"""
Test script for querying known malicious IP addresses.

This script demonstrates:
- Testing with real-world malicious IPs
- API integration validation
- Risk scoring verification
"""

import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from utils.logger import setup_logging, get_logger
from utils.ip_validator import IPValidator
from models.cache import CacheManager
from services.abuseipdb_client import AbuseIPDBClient
from services.otx_client import OTXClient
from utils.normalizer import normalize_abuseipdb, normalize_otx, aggregate_threat_intel
from config import Config

# Setup logging
setup_logging(log_level="INFO")
logger = get_logger(__name__)


# Known malicious IPs from IPsum "Wall of Shame"
# These IPs appear across multiple public blacklists
MALICIOUS_IPS_WALL_OF_SHAME = [
    "93.174.95.106",
    "80.82.77.33",
    "80.94.93.233",
    "101.250.60.4",
    "193.46.255.7",
    "3.130.96.91",
    "80.82.77.139",
    "80.82.77.202",
    "89.97.218.142",
    "91.224.92.108",
    "92.118.39.62",
    "119.18.55.217"
]

TEST_IPS = {
    "malicious": MALICIOUS_IPS_WALL_OF_SHAME,
    "clean": [
        "8.8.8.8",            # Google DNS
        "1.1.1.1",            # Cloudflare DNS
    ]
}


def test_ip_lookup(ip_address: str, category: str):
    """
    Test threat intel lookup for a single IP.

    Args:
        ip_address: IP to test
        category: Expected category (malicious/clean/suspicious)
    """
    logger.info("=" * 80)
    logger.info(f"Testing IP: {ip_address} (Expected: {category.upper()})")
    logger.info("=" * 80)

    # Validate IP
    validator = IPValidator()
    try:
        normalized_ip = validator.normalize_ip(ip_address)
        logger.info(f"✓ IP validated: {normalized_ip}")
    except Exception as e:
        logger.error(f"✗ IP validation failed: {e}")
        return

    # Check cache first
    cached = CacheManager.get_cache(normalized_ip)
    if cached and not cached.is_expired:
        logger.info(f"📦 Using cached data (expires in {cached.time_remaining})")
        display_results(cached.threat_data, from_cache=True)
        return

    # Fetch from APIs
    normalized_responses = []

    # AbuseIPDB
    try:
        if Config.ABUSEIPDB_API_KEY and Config.ABUSEIPDB_API_KEY != "your_abuseipdb_api_key_here":
            logger.info("📡 Querying AbuseIPDB...")
            abuse_client = AbuseIPDBClient()
            abuse_response = abuse_client.get_ip_reputation(normalized_ip)
            normalized_abuse = normalize_abuseipdb(abuse_response)
            normalized_responses.append(normalized_abuse)
            logger.info(f"✓ AbuseIPDB: Risk Score = {normalized_abuse.get('risk_score', 'N/A')}")
        else:
            logger.warning("⚠ AbuseIPDB API key not configured")
    except Exception as e:
        logger.error(f"✗ AbuseIPDB error: {e}")

    # AlienVault OTX
    try:
        if Config.OTX_API_KEY and Config.OTX_API_KEY != "your_otx_api_key_here":
            logger.info("📡 Querying AlienVault OTX...")
            otx_client = OTXClient()
            otx_response = otx_client.get_ip_reputation(normalized_ip)
            normalized_otx = normalize_otx(otx_response)
            normalized_responses.append(normalized_otx)
            logger.info(f"✓ OTX: Pulse Count = {normalized_otx.get('pulse_count', 'N/A')}")
        else:
            logger.warning("⚠ OTX API key not configured")
    except Exception as e:
        logger.error(f"✗ OTX error: {e}")

    if not normalized_responses:
        logger.error("✗ No data available - please configure API keys")
        return

    # Aggregate results
    logger.info(f"🔄 Aggregating {len(normalized_responses)} sources...")
    aggregated = aggregate_threat_intel(normalized_responses)

    # Cache the results
    CacheManager.set_cache(normalized_ip, aggregated)

    # Display results
    display_results(aggregated, from_cache=False)


def display_results(data: dict, from_cache: bool = False):
    """
    Display threat intelligence results in a formatted way.

    Args:
        data: Aggregated threat intel data
        from_cache: Whether data came from cache
    """
    cache_indicator = "📦 [CACHED]" if from_cache else "🆕 [FRESH]"

    logger.info("")
    logger.info("🔍 THREAT INTELLIGENCE RESULTS " + cache_indicator)
    logger.info("-" * 80)

    # Risk assessment
    risk_score = data.get('aggregate_risk_score', 0)
    is_malicious = data.get('is_malicious', False)

    if risk_score >= 75:
        risk_level = "🔴 HIGH RISK"
    elif risk_score >= 50:
        risk_level = "🟠 MEDIUM RISK"
    elif risk_score >= 25:
        risk_level = "🟡 LOW RISK"
    else:
        risk_level = "🟢 CLEAN"

    logger.info(f"Risk Score:      {risk_score}/100")
    logger.info(f"Risk Level:      {risk_level}")
    logger.info(f"Is Malicious:    {'YES ⚠️' if is_malicious else 'NO ✓'}")
    logger.info("")

    # Location info
    if data.get('country'):
        logger.info(f"Country:         {data.get('country', 'Unknown')}")

    if data.get('isp'):
        logger.info(f"ISP:             {data.get('isp', 'Unknown')}")

    logger.info("")

    # Reports and activity
    logger.info(f"Total Reports:   {data.get('total_reports', 0)}")
    logger.info(f"Pulse Count:     {data.get('pulse_count', 0)}")
    logger.info(f"Last Reported:   {data.get('last_reported', 'Unknown')}")
    logger.info("")

    # Threat categories
    categories = data.get('threat_categories', [])
    if categories:
        logger.info(f"Categories:      {', '.join(categories[:5])}")

    threat_types = data.get('threat_types', [])
    if threat_types:
        logger.info(f"Threat Types:    {', '.join(threat_types[:5])}")

    logger.info("")

    # Data sources
    sources = data.get('sources', [])
    logger.info(f"Data Sources:    {', '.join(sources)}")
    logger.info("-" * 80)
    logger.info("")


def run_malicious_ip_tests():
    """Run tests with known malicious IPs."""
    logger.info("\n" + "=" * 80)
    logger.info("🔬 THREAT INTEL APP - MALICIOUS IP TESTING")
    logger.info("=" * 80 + "\n")

    # Check if API keys are configured
    has_abuse = Config.ABUSEIPDB_API_KEY and Config.ABUSEIPDB_API_KEY != "your_abuseipdb_api_key_here"
    has_otx = Config.OTX_API_KEY and Config.OTX_API_KEY != "your_otx_api_key_here"

    if not has_abuse and not has_otx:
        logger.error("❌ No API keys configured!")
        logger.error("Please configure ABUSEIPDB_API_KEY or OTX_API_KEY in .env file")
        return

    logger.info("API Configuration:")
    logger.info(f"  AbuseIPDB: {'✓ Configured' if has_abuse else '✗ Not configured'}")
    logger.info(f"  OTX:       {'✓ Configured' if has_otx else '✗ Not configured'}")
    logger.info("")

    # Test each category
    all_results = []

    for category, ip_list in TEST_IPS.items():
        logger.info(f"\n{'#' * 80}")
        logger.info(f"# Testing {category.upper()} IPs")
        logger.info(f"{'#' * 80}\n")

        for ip in ip_list:
            try:
                test_ip_lookup(ip, category)
                all_results.append((ip, category, "✓ Success"))
            except Exception as e:
                logger.error(f"Test failed for {ip}: {e}")
                all_results.append((ip, category, f"✗ Failed: {e}"))

            # Small delay between requests to respect rate limits
            import time
            time.sleep(2)

    # Summary
    logger.info("\n" + "=" * 80)
    logger.info("📊 TEST SUMMARY")
    logger.info("=" * 80)

    for ip, category, status in all_results:
        logger.info(f"{ip:20s} ({category:12s}) - {status}")

    logger.info("=" * 80)
    logger.info(f"Total tests: {len(all_results)}")
    logger.info(f"Successful:  {sum(1 for _, _, s in all_results if s.startswith('✓'))}")
    logger.info("=" * 80 + "\n")


if __name__ == "__main__":
    try:
        run_malicious_ip_tests()
    except KeyboardInterrupt:
        logger.info("\n\n⚠️  Test interrupted by user")
    except Exception as e:
        logger.error(f"Test script error: {e}", exc_info=True)
        sys.exit(1)
