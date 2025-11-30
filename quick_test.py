"""
Quick test script for a single malicious IP.
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))

from utils.logger import setup_logging, get_logger
from utils.ip_validator import IPValidator
from services.abuseipdb_client import AbuseIPDBClient
from services.otx_client import OTXClient
from utils.normalizer import normalize_abuseipdb, normalize_otx, aggregate_threat_intel
from models.cache import CacheManager

setup_logging(log_level="INFO")
logger = get_logger(__name__)

# Test with a known malicious IP
TEST_IP = "185.220.101.1"  # Known Tor exit node with abuse reports

logger.info("=" * 80)
logger.info(f"🔍 Testing IP: {TEST_IP}")
logger.info("=" * 80)

# Validate
validator = IPValidator()
normalized_ip = validator.normalize_ip(TEST_IP)
logger.info(f"✓ IP validated: {normalized_ip}")

# Check cache
cached = CacheManager.get_cache(normalized_ip)
if cached and not cached.is_expired:
    logger.info(f"📦 Cache hit! Using cached data")
    data = cached.threat_data
else:
    logger.info("🆕 Cache miss - querying APIs...")

    responses = []

    # AbuseIPDB
    try:
        logger.info("📡 Querying AbuseIPDB...")
        abuse_client = AbuseIPDBClient()
        abuse_response = abuse_client.get_ip_reputation(normalized_ip)
        normalized_abuse = normalize_abuseipdb(abuse_response)
        responses.append(normalized_abuse)
        logger.info(f"✓ AbuseIPDB: Risk Score = {normalized_abuse['risk_score']}")
    except Exception as e:
        logger.error(f"✗ AbuseIPDB error: {e}")

    # OTX
    try:
        logger.info("📡 Querying AlienVault OTX...")
        otx_client = OTXClient()
        otx_response = otx_client.get_ip_reputation(normalized_ip)
        normalized_otx = normalize_otx(otx_response)
        responses.append(normalized_otx)
        logger.info(f"✓ OTX: Pulse Count = {normalized_otx.get('pulse_count', 0)}")
    except Exception as e:
        logger.error(f"✗ OTX error: {e}")

    if responses:
        logger.info(f"🔄 Aggregating {len(responses)} sources...")
        data = aggregate_threat_intel(responses)
        CacheManager.set_cache(normalized_ip, data)
    else:
        logger.error("No data received from any source")
        sys.exit(1)

# Display results
logger.info("")
logger.info("🔍 THREAT INTELLIGENCE RESULTS")
logger.info("=" * 80)

risk_score = data.get('aggregate_risk_score', 0)
if risk_score >= 75:
    risk_level = "🔴 HIGH RISK"
elif risk_score >= 50:
    risk_level = "🟠 MEDIUM RISK"
elif risk_score >= 25:
    risk_level = "🟡 LOW RISK"
else:
    risk_level = "🟢 CLEAN"

logger.info(f"IP Address:      {normalized_ip}")
logger.info(f"Risk Score:      {risk_score}/100")
logger.info(f"Risk Level:      {risk_level}")
logger.info(f"Is Malicious:    {'YES ⚠️' if data.get('is_malicious') else 'NO ✓'}")
logger.info(f"Country:         {data.get('country', 'Unknown')}")
logger.info(f"ISP:             {data.get('isp', 'Unknown')}")
logger.info(f"Total Reports:   {data.get('total_reports', 0)}")
logger.info(f"Pulse Count:     {data.get('pulse_count', 0)}")

categories = data.get('threat_categories', [])
if categories:
    logger.info(f"Categories:      {', '.join(categories[:5])}")

logger.info(f"Sources:         {', '.join(data.get('sources', []))}")
logger.info("=" * 80)

logger.info("\n✅ Test completed successfully!")
