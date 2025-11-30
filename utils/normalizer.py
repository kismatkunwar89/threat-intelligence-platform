"""
Data normalization utilities for threat intelligence APIs.

This module demonstrates:
- Dictionary comprehensions
- List comprehensions
- Data transformation and normalization
- Functional programming patterns
- Type hints with TypedDict
"""

from typing import Dict, Any, List, Optional
from datetime import datetime
import logging

logger = logging.getLogger(__name__)


class ThreatIntelSchema:
    """
    Standardized schema for threat intelligence data.

    This defines the common format that all API responses
    will be normalized to.
    """

    @staticmethod
    def get_empty_schema() -> Dict[str, Any]:
        """
        Get an empty threat intel schema with default values.

        Returns:
            dict: Empty schema structure
        """
        return {
            'ip_address': None,
            'risk_score': 0,  # 0-100
            'is_malicious': False,
            'country': None,
            'country_code': None,
            'isp': None,
            'domain': None,
            'total_reports': 0,
            'last_reported': None,
            'categories': [],
            'threat_types': [],
            'sources': [],
            'raw_data': {}
        }


class AbuseIPDBNormalizer:
    """
    Normalizer for AbuseIPDB API responses.

    Demonstrates comprehensions and data transformation.
    """

    @staticmethod
    def normalize(response: Dict[str, Any]) -> Dict[str, Any]:
        """
        Normalize AbuseIPDB response to standard schema.

        Args:
            response: Raw AbuseIPDB API response

        Returns:
            dict: Normalized threat intel data

        Example input:
        {
            "data": {
                "ipAddress": "8.8.8.8",
                "abuseConfidenceScore": 0,
                "countryCode": "US",
                "usageType": "Data Center/Web Hosting/Transit",
                "isp": "Google LLC",
                "domain": "google.com",
                "totalReports": 0,
                "lastReportedAt": null
            }
        }
        """
        logger.debug("Normalizing AbuseIPDB response")

        data = response.get('data', {})

        # Use dictionary comprehension to extract and rename fields
        normalized = {
            'ip_address': data.get('ipAddress'),
            'risk_score': data.get('abuseConfidenceScore', 0),
            'is_malicious': data.get('abuseConfidenceScore', 0) > 50,
            'country': data.get('countryName'),
            'country_code': data.get('countryCode'),
            'isp': data.get('isp'),
            'domain': data.get('domain'),
            'total_reports': data.get('totalReports', 0),
            'last_reported': data.get('lastReportedAt'),
            'categories': AbuseIPDBNormalizer._extract_categories(data),
            'threat_types': ['abuse'] if data.get('totalReports', 0) > 0 else [],
            'sources': ['AbuseIPDB'],
            'raw_data': {
                'abuseipdb': data
            }
        }

        logger.info(
            f"AbuseIPDB normalized: IP={normalized['ip_address']}, "
            f"Score={normalized['risk_score']}, Reports={normalized['total_reports']}"
        )

        return normalized

    @staticmethod
    def _extract_categories(data: Dict[str, Any]) -> List[str]:
        """
        Extract abuse categories from AbuseIPDB data.

        Uses list comprehension to transform category IDs to names.

        Args:
            data: AbuseIPDB data dict

        Returns:
            list: Category names
        """
        # AbuseIPDB category mapping
        category_map = {
            1: "DNS Compromise",
            2: "DNS Poisoning",
            3: "Fraud Orders",
            4: "DDoS Attack",
            5: "FTP Brute-Force",
            6: "Ping of Death",
            7: "Phishing",
            8: "Fraud VoIP",
            9: "Open Proxy",
            10: "Web Spam",
            11: "Email Spam",
            12: "Blog Spam",
            13: "VPN IP",
            14: "Port Scan",
            15: "Hacking",
            16: "SQL Injection",
            17: "Spoofing",
            18: "Brute-Force",
            19: "Bad Web Bot",
            20: "Exploited Host",
            21: "Web App Attack",
            22: "SSH",
            23: "IoT Targeted"
        }

        reports = data.get('reports', [])
        if not reports:
            return []

        # Use set comprehension to get unique categories
        category_ids = {
            cat_id
            for report in reports
            for cat_id in report.get('categories', [])
        }

        # Map IDs to names using list comprehension
        return [
            category_map.get(cat_id, f"Unknown({cat_id})")
            for cat_id in sorted(category_ids)
        ]


class OTXNormalizer:
    """
    Normalizer for AlienVault OTX API responses.

    Demonstrates working with nested data structures.
    """

    @staticmethod
    def normalize(response: Dict[str, Any]) -> Dict[str, Any]:
        """
        Normalize OTX response to standard schema.

        Args:
            response: Raw OTX API response (combined data)

        Returns:
            dict: Normalized threat intel data
        """
        logger.debug("Normalizing OTX response")

        general = response.get('general', {})
        # Reputation can be int or dict from OTX
        reputation = response.get('reputation', 0)
        if isinstance(reputation, dict):
            reputation = reputation.get('reputation', 0)

        # Calculate risk score from multiple indicators
        risk_score = OTXNormalizer._calculate_risk_score(
            response.get('pulse_count', 0),
            reputation
        )

        # Extract geo data from general if not separate
        country = general.get('country_name')
        country_code = general.get('country_code2')
        isp = general.get('asn', '').split(' ', 1)[-1] if general.get('asn') else None

        normalized = {
            'ip_address': response.get('ip_address'),
            'risk_score': risk_score,
            'is_malicious': risk_score > 50,
            'country': country,
            'country_code': country_code,
            'isp': isp,
            'domain': None,  # OTX doesn't provide this directly
            'total_reports': response.get('pulse_count', 0),
            'last_reported': None,
            'categories': OTXNormalizer._extract_threat_types(general),
            'threat_types': OTXNormalizer._extract_threat_types(general),
            'sources': ['AlienVault OTX'],
            'raw_data': {
                'otx': response
            }
        }

        logger.info(
            f"OTX normalized: IP={normalized['ip_address']}, "
            f"Score={normalized['risk_score']}, Pulses={response.get('pulse_count', 0)}"
        )

        return normalized

    @staticmethod
    def _calculate_risk_score(pulse_count: int, reputation: int) -> int:
        """
        Calculate risk score from OTX data.

        Args:
            pulse_count: Number of pulses mentioning this IP
            reputation: Reputation score (0-5)

        Returns:
            int: Risk score (0-100)
        """
        # Base score on pulse count
        score = min(pulse_count * 10, 80)

        # Adjust based on reputation (0-5 scale from OTX)
        if reputation > 0:
            score = max(score, min(reputation * 20, 100))

        return min(score, 100)

    @staticmethod
    def _extract_threat_types(general: Dict[str, Any]) -> List[str]:
        """
        Extract threat types from OTX pulse data.

        Uses nested comprehensions to flatten pulse data.

        Args:
            general: OTX general data

        Returns:
            list: Unique threat types
        """
        pulse_info = general.get('pulse_info', {})
        pulses = pulse_info.get('pulses', [])

        if not pulses:
            return []

        # Use set comprehension with nested iteration
        threat_tags = {
            tag
            for pulse in pulses
            for tag in pulse.get('tags', [])
        }

        return sorted(list(threat_tags))


class ThreatIntelAggregator:
    """
    Aggregates and merges normalized data from multiple sources.

    Demonstrates advanced comprehensions and data merging.
    """

    @staticmethod
    def aggregate(normalized_responses: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Aggregate multiple normalized threat intel responses.

        Args:
            normalized_responses: List of normalized responses

        Returns:
            dict: Merged threat intelligence data
        """
        logger.info(f"Aggregating {len(normalized_responses)} threat intel sources")

        if not normalized_responses:
            return ThreatIntelSchema.get_empty_schema()

        # Start with first response as base
        aggregated = normalized_responses[0].copy()

        # Merge data from other sources
        for response in normalized_responses[1:]:
            aggregated = ThreatIntelAggregator._merge_responses(
                aggregated,
                response
            )

        # Calculate final aggregated metrics
        aggregated['risk_score'] = ThreatIntelAggregator._calculate_aggregate_risk(
            normalized_responses
        )
        aggregated['is_malicious'] = aggregated['risk_score'] > 50

        logger.info(
            f"Aggregation complete: Final risk score={aggregated['risk_score']}"
        )

        return aggregated

    @staticmethod
    def _merge_responses(base: Dict[str, Any],
                        new: Dict[str, Any]) -> Dict[str, Any]:
        """
        Merge two normalized responses.

        Args:
            base: Base response
            new: New response to merge

        Returns:
            dict: Merged response
        """
        merged = base.copy()

        # Merge lists using set to avoid duplicates, then convert back to list
        merged['categories'] = list(set(base.get('categories', []) + new.get('categories', [])))
        merged['threat_types'] = list(set(base.get('threat_types', []) + new.get('threat_types', [])))
        merged['sources'] = list(set(base.get('sources', []) + new.get('sources', [])))

        # Sum total reports
        merged['total_reports'] = base.get('total_reports', 0) + new.get('total_reports', 0)

        # Merge raw data
        merged['raw_data'].update(new.get('raw_data', {}))

        # Use non-null values from new response for other fields
        for key in ['country', 'country_code', 'isp', 'domain']:
            if not merged.get(key) and new.get(key):
                merged[key] = new[key]

        return merged

    @staticmethod
    def _calculate_aggregate_risk(responses: List[Dict[str, Any]]) -> int:
        """
        Calculate aggregate risk score from multiple sources.

        Uses comprehension to extract scores and calculate average.

        Args:
            responses: List of normalized responses

        Returns:
            int: Aggregate risk score (0-100)
        """
        # Extract all risk scores using list comprehension
        scores = [r.get('risk_score', 0) for r in responses]

        if not scores:
            return 0

        # Calculate weighted average (give more weight to higher scores)
        max_score = max(scores)
        avg_score = sum(scores) / len(scores)

        # 70% weight to max, 30% to average
        aggregate = int(max_score * 0.7 + avg_score * 0.3)

        return min(aggregate, 100)


def normalize_abuseipdb(response: Dict[str, Any]) -> Dict[str, Any]:
    """Convenience function for normalizing AbuseIPDB responses."""
    return AbuseIPDBNormalizer.normalize(response)


def normalize_otx(response: Dict[str, Any]) -> Dict[str, Any]:
    """Convenience function for normalizing OTX responses."""
    return OTXNormalizer.normalize(response)


def aggregate_threat_intel(responses: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Convenience function for aggregating normalized responses."""
    return ThreatIntelAggregator.aggregate(responses)
