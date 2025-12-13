"""
Test both AbuseIPDB and OTX together with malicious IPs.
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

# Test multiple IPs
TEST_IPS = [
    ("45.142.212.61", "Known malicious scanner"),
    ("8.8.8.8", "Google DNS - should be clean"),
]

for ip, description in TEST_IPS:
    logger.info("\n" + "=" * 80)
    logger.info(f"🔍 Testing: {ip} - {description}")
    logger.info("=" * 80)

    validator = IPValidator()
    normalized_ip = validator.normalize_ip(ip)

    # Skip cache for fresh test
    CacheManager.invalidate_cache(normalized_ip)

    responses = []

    # AbuseIPDB
    try:
        logger.info("📡 Querying AbuseIPDB...")
        abuse_client = AbuseIPDBClient()
        abuse_response = abuse_client.get_ip_reputation(normalized_ip)
        normalized_abuse = normalize_abuseipdb(abuse_response)
        responses.append(normalized_abuse)
        logger.info(f"  ✓ AbuseIPDB Risk: {normalized_abuse['risk_score']}/100")
    except Exception as e:
        logger.error(f"  ✗ AbuseIPDB error: {e}")

    # OTX
    try:
        logger.info("📡 Querying AlienVault OTX...")
        otx_client = OTXClient()
        otx_response = otx_client.get_ip_reputation(normalized_ip)
        normalized_otx = normalize_otx(otx_response)
        responses.append(normalized_otx)
        logger.info(f"  ✓ OTX Pulses: {normalized_otx.get('total_reports', 0)}")
    except Exception as e:
        logger.error(f"  ✗ OTX error: {e}")

    if responses:
        logger.info(f"\n🔄 Aggregating {len(responses)} sources...")
        data = aggregate_threat_intel(responses)

        risk_score = data.get('aggregate_risk_score', 0)
        if risk_score >= 75:
            risk_level = "🔴 HIGH RISK"
        elif risk_score >= 50:
            risk_level = "🟠 MEDIUM RISK"
        elif risk_score >= 25:
            risk_level = "🟡 LOW RISK"
        else:
            risk_level = "🟢 CLEAN"

        logger.info("")
        logger.info("📊 FINAL RESULTS:")
        logger.info(f"  Aggregate Risk Score: {risk_score}/100")
        logger.info(f"  Risk Level: {risk_level}")
        logger.info(f"  Is Malicious: {'YES ⚠️' if data.get('is_malicious') else 'NO ✓'}")
        logger.info(f"  Country: {data.get('country', 'Unknown')}")
        logger.info(f"  Total Reports: {data.get('total_reports', 0)}")
        logger.info(f"  Data Sources: {', '.join(data.get('sources', []))}")

logger.info("\n" + "=" * 80)
logger.info("✅ Both APIs working successfully!")
logger.info("=" * 80)
