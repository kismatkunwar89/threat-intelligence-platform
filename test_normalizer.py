"""
Test script for data normalization.

Tests the normalizer with sample API responses.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from utils.logger import setup_logging, get_logger
from utils.normalizer import (
    AbuseIPDBNormalizer,
    OTXNormalizer,
    ThreatIntelAggregator,
    aggregate_threat_intel
)

setup_logging(log_level="INFO")
logger = get_logger(__name__)


def test_abuseipdb_normalization():
    """Test AbuseIPDB response normalization."""
    logger.info("=" * 60)
    logger.info("Testing AbuseIPDB Normalization")
    logger.info("=" * 60)

    # Sample AbuseIPDB response
    sample_response = {
        "data": {
            "ipAddress": "8.8.8.8",
            "isPublic": True,
            "ipVersion": 4,
            "isWhitelisted": False,
            "abuseConfidenceScore": 0,
            "countryCode": "US",
            "countryName": "United States",
            "usageType": "Data Center/Web Hosting/Transit",
            "isp": "Google LLC",
            "domain": "google.com",
            "totalReports": 0,
            "numDistinctUsers": 0,
            "lastReportedAt": None
        }
    }

    normalized = AbuseIPDBNormalizer.normalize(sample_response)

    logger.info("Normalized data:")
    logger.info(f"  IP: {normalized['ip_address']}")
    logger.info(f"  Risk Score: {normalized['risk_score']}")
    logger.info(f"  Is Malicious: {normalized['is_malicious']}")
    logger.info(f"  Country: {normalized['country']} ({normalized['country_code']})")
    logger.info(f"  ISP: {normalized['isp']}")
    logger.info(f"  Total Reports: {normalized['total_reports']}")
    logger.info(f"  Sources: {normalized['sources']}")

    assert normalized['ip_address'] == "8.8.8.8"
    assert normalized['risk_score'] == 0
    assert normalized['is_malicious'] == False
    assert 'AbuseIPDB' in normalized['sources']

    logger.info("✓ AbuseIPDB normalization test passed\n")
    return True


def test_otx_normalization():
    """Test OTX response normalization."""
    logger.info("=" * 60)
    logger.info("Testing OTX Normalization")
    logger.info("=" * 60)

    # Sample OTX response (combined)
    sample_response = {
        "ip_address": "1.2.3.4",
        "general": {
            "pulse_info": {
                "count": 5,
                "pulses": [
                    {
                        "name": "Test Pulse",
                        "tags": ["malware", "botnet"]
                    },
                    {
                        "name": "Another Pulse",
                        "tags": ["phishing"]
                    }
                ]
            }
        },
        "reputation": {
            "reputation": 3
        },
        "geo": {
            "country_name": "United States",
            "country_code": "US",
            "asn": "AS15169 Google LLC"
        },
        "malware": {},
        "pulse_count": 5
    }

    normalized = OTXNormalizer.normalize(sample_response)

    logger.info("Normalized data:")
    logger.info(f"  IP: {normalized['ip_address']}")
    logger.info(f"  Risk Score: {normalized['risk_score']}")
    logger.info(f"  Is Malicious: {normalized['is_malicious']}")
    logger.info(f"  Country: {normalized['country']} ({normalized['country_code']})")
    logger.info(f"  Threat Types: {normalized['threat_types']}")
    logger.info(f"  Total Reports: {normalized['total_reports']}")
    logger.info(f"  Sources: {normalized['sources']}")

    assert normalized['ip_address'] == "1.2.3.4"
    assert normalized['risk_score'] > 0
    assert 'AlienVault OTX' in normalized['sources']
    assert len(normalized['threat_types']) > 0

    logger.info("✓ OTX normalization test passed\n")
    return True


def test_aggregation():
    """Test aggregating multiple sources."""
    logger.info("=" * 60)
    logger.info("Testing Threat Intel Aggregation")
    logger.info("=" * 60)

    # Create two normalized responses
    abuseipdb_data = {
        'ip_address': '8.8.8.8',
        'risk_score': 20,
        'is_malicious': False,
        'country': 'United States',
        'country_code': 'US',
        'isp': 'Google LLC',
        'domain': 'google.com',
        'total_reports': 5,
        'last_reported': None,
        'categories': ['spam', 'scanning'],
        'threat_types': ['abuse'],
        'sources': ['AbuseIPDB'],
        'raw_data': {'abuseipdb': {}}
    }

    otx_data = {
        'ip_address': '8.8.8.8',
        'risk_score': 60,
        'is_malicious': True,
        'country': 'United States',
        'country_code': 'US',
        'isp': None,
        'domain': None,
        'total_reports': 10,
        'last_reported': None,
        'categories': ['malware'],
        'threat_types': ['botnet', 'malware'],
        'sources': ['AlienVault OTX'],
        'raw_data': {'otx': {}}
    }

    aggregated = aggregate_threat_intel([abuseipdb_data, otx_data])

    logger.info("Aggregated data:")
    logger.info(f"  IP: {aggregated['ip_address']}")
    logger.info(f"  Aggregate Risk Score: {aggregated['risk_score']}")
    logger.info(f"  Is Malicious: {aggregated['is_malicious']}")
    logger.info(f"  Total Reports: {aggregated['total_reports']}")
    logger.info(f"  Categories: {aggregated['categories']}")
    logger.info(f"  Threat Types: {aggregated['threat_types']}")
    logger.info(f"  Sources: {aggregated['sources']}")

    assert aggregated['ip_address'] == '8.8.8.8'
    assert len(aggregated['sources']) == 2
    assert 'AbuseIPDB' in aggregated['sources']
    assert 'AlienVault OTX' in aggregated['sources']
    assert aggregated['total_reports'] == 15  # 5 + 10
    assert len(aggregated['categories']) >= 3  # Merged unique categories
    assert aggregated['risk_score'] > abuseipdb_data['risk_score']  # Should be weighted

    logger.info("✓ Aggregation test passed\n")
    return True


def run_all_tests():
    """Run all normalization tests."""
    logger.info("\n" + "=" * 60)
    logger.info("DATA NORMALIZATION TESTS")
    logger.info("=" * 60 + "\n")

    results = {
        "AbuseIPDB Normalization": test_abuseipdb_normalization(),
        "OTX Normalization": test_otx_normalization(),
        "Aggregation": test_aggregation()
    }

    # Summary
    logger.info("=" * 60)
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
