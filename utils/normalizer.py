"""
Data normalization utilities for threat intelligence APIs.

This module demonstrates:
- Dictionary comprehensions
- List comprehensions
- Data transformation and normalization
- Functional programming patterns
- Type hints with TypedDict
- Dataclass integration
"""

from typing import Dict, Any, List, Optional
from datetime import datetime
import logging
from models.threat_intel_result import ThreatIntelResult
from utils.recommendation_engine import generate_recommendation

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
        isp = general.get('asn', '').split(
            ' ', 1)[-1] if general.get('asn') else None

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


class VirusTotalNormalizer:
    """
    Normalizer for VirusTotal API responses.

    VirusTotal provides comprehensive threat data from multiple antivirus engines
    and community submissions.
    """

    @staticmethod
    def normalize(response: Dict[str, Any]) -> Dict[str, Any]:
        """
        Normalize VirusTotal response to standard schema.

        Args:
            response: Raw VirusTotal API response

        Returns:
            dict: Normalized threat intel data

        Example input:
        {
            "data": {
                "id": "8.8.8.8",
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 0,
                        "suspicious": 0,
                        "harmless": 80,
                        "undetected": 10
                    },
                    "country": "US",
                    "as_owner": "Google LLC",
                    "network": "8.8.8.0/24"
                }
            }
        }
        """
        logger.debug("Normalizing VirusTotal response")

        data = response.get('data', {})
        attributes = data.get('attributes', {})

        # Extract analysis stats
        stats = attributes.get('last_analysis_stats', {})
        malicious_count = stats.get('malicious', 0)
        suspicious_count = stats.get('suspicious', 0)
        total_engines = sum(stats.values()) if stats else 0

        # Calculate risk score based on detection ratio
        risk_score = VirusTotalNormalizer._calculate_risk_score(
            malicious_count, suspicious_count, total_engines
        )

        # Extract categories from analysis results
        categories = VirusTotalNormalizer._extract_categories(attributes)

        normalized = {
            'ip_address': data.get('id'),
            'risk_score': risk_score,
            'is_malicious': malicious_count > 0 or suspicious_count > 2,
            'country': attributes.get('country'),
            'country_code': attributes.get('country'),
            'isp': attributes.get('as_owner'),
            'domain': None,
            'total_reports': malicious_count + suspicious_count,
            'last_reported': attributes.get('last_modification_date'),
            'categories': categories,
            'threat_types': VirusTotalNormalizer._extract_threat_types(attributes),
            'sources': ['VirusTotal'],
            'raw_data': {
                'virustotal': response
            }
        }

        logger.info(
            f"VirusTotal normalized: IP={normalized['ip_address']}, "
            f"Score={normalized['risk_score']}, Malicious={malicious_count}/{total_engines}"
        )

        return normalized

    @staticmethod
    def _calculate_risk_score(malicious: int, suspicious: int, total: int) -> int:
        """
        Calculate risk score from VirusTotal detection stats.

        Args:
            malicious: Number of engines flagging as malicious
            suspicious: Number of engines flagging as suspicious
            total: Total number of engines

        Returns:
            int: Risk score (0-100)
        """
        if total == 0:
            return 0

        # Weight: malicious = 1.0, suspicious = 0.5
        weighted_score = malicious + (suspicious * 0.5)

        # Scale to percentage of total engines, with a boost for any malicious
        base_score = (weighted_score / total) * 100

        # Boost score if any malicious detections
        if malicious > 0:
            base_score = max(base_score, 30 + (malicious * 5))

        return min(int(base_score), 100)

    @staticmethod
    def _extract_categories(attributes: Dict[str, Any]) -> List[str]:
        """
        Extract threat categories from VirusTotal analysis results.

        Args:
            attributes: VirusTotal attributes dict

        Returns:
            list: Unique categories
        """
        categories = []

        # Check last_analysis_results for category info
        results = attributes.get('last_analysis_results', {})
        for engine_name, result in results.items():
            category = result.get('category')
            if category and category not in ['harmless', 'undetected', 'timeout']:
                categories.append(category)

        return list(set(categories))

    @staticmethod
    def _extract_threat_types(attributes: Dict[str, Any]) -> List[str]:
        """
        Extract threat types from VirusTotal data.

        Args:
            attributes: VirusTotal attributes dict

        Returns:
            list: Unique threat types
        """
        threat_types = []

        # Extract from tags if available
        tags = attributes.get('tags', [])
        threat_types.extend(tags)

        # Extract from analysis results
        results = attributes.get('last_analysis_results', {})
        for engine_name, result in results.items():
            result_type = result.get('result')
            if result_type and result_type not in ['clean', 'unrated']:
                threat_types.append(result_type)

        return list(set(threat_types))[:10]  # Limit to top 10


class GreyNoiseNormalizer:
    """
    Normalizer for GreyNoise API responses.

    GreyNoise identifies internet-wide scanners and provides context
    about whether an IP is benign (e.g., security researcher) or malicious.

    Key insight: GreyNoise can REDUCE risk scores by identifying benign noise.
    """

    # Classification to risk adjustment mapping
    CLASSIFICATION_RISK = {
        'benign': -30,      # Significantly reduce risk (known good actor)
        'malicious': 40,    # Significantly increase risk
        'unknown': 0        # No adjustment
    }

    @staticmethod
    def normalize(response: Dict[str, Any]) -> Dict[str, Any]:
        """
        Normalize GreyNoise response to standard schema.

        Args:
            response: Raw GreyNoise API response

        Returns:
            dict: Normalized threat intel data

        Example input (Community API):
        {
            "ip": "8.8.8.8",
            "noise": false,
            "riot": true,
            "classification": "benign",
            "name": "Google Public DNS",
            "link": "https://viz.greynoise.io/ip/8.8.8.8"
        }
        """
        logger.debug("Normalizing GreyNoise response")

        ip_address = response.get('ip') or response.get('ip_address')
        classification = response.get('classification', 'unknown')
        is_noise = response.get('noise', False)
        # RIOT = Rule It Out - known benign
        is_riot = response.get('riot', False)

        # Calculate risk score with GreyNoise context
        risk_score = GreyNoiseNormalizer._calculate_risk_score(
            classification, is_noise, is_riot
        )

        # Determine malicious status
        is_malicious = classification == 'malicious'

        # Extract threat types and categories
        categories, threat_types = GreyNoiseNormalizer._extract_classifications(
            response)

        normalized = {
            'ip_address': ip_address,
            'risk_score': risk_score,
            'is_malicious': is_malicious,
            'country': None,  # Not provided in Community API
            'country_code': None,
            'isp': response.get('name'),  # Actor name if known
            'domain': None,
            'total_reports': 1 if is_noise else 0,
            'last_reported': response.get('last_seen'),
            'categories': categories,
            'threat_types': threat_types,
            'sources': ['GreyNoise'],
            'raw_data': {
                'greynoise': response
            },
            # GreyNoise-specific fields for risk adjustment
            'greynoise_classification': classification,
            'greynoise_riot': is_riot,
            'greynoise_noise': is_noise
        }

        logger.info(
            f"GreyNoise normalized: IP={ip_address}, "
            f"Classification={classification}, RIOT={is_riot}, Noise={is_noise}, "
            f"Score={risk_score}"
        )

        return normalized

    @staticmethod
    def _calculate_risk_score(classification: str, is_noise: bool, is_riot: bool) -> int:
        """
        Calculate risk score from GreyNoise classification.

        GreyNoise provides unique context that can REDUCE risk:
        - RIOT IPs are known good (Google, Microsoft, etc.)
        - Benign classification indicates security researchers, etc.

        Args:
            classification: benign, malicious, or unknown
            is_noise: Whether IP is seen scanning the internet
            is_riot: Whether IP is in the RIOT dataset (known benign)

        Returns:
            int: Risk score (0-100), can be negative adjustment indicator
        """
        base_score = 50  # Neutral starting point

        # RIOT dataset = known good services (Google, AWS, etc.)
        if is_riot:
            return 5  # Very low risk - known benign service

        # Apply classification adjustment
        adjustment = GreyNoiseNormalizer.CLASSIFICATION_RISK.get(
            classification, 0)
        score = base_score + adjustment

        # If it's noisy but not classified, slight increase
        if is_noise and classification == 'unknown':
            score += 10

        return max(0, min(score, 100))

    @staticmethod
    def _extract_classifications(response: Dict[str, Any]) -> tuple:
        """
        Extract categories and threat types from GreyNoise data.

        Args:
            response: GreyNoise API response

        Returns:
            tuple: (categories, threat_types)
        """
        categories = []
        threat_types = []

        classification = response.get('classification', 'unknown')
        is_riot = response.get('riot', False)

        # Add classification as category
        if classification != 'unknown':
            categories.append(f"greynoise_{classification}")

        if is_riot:
            categories.append('known_benign_service')
            threat_types.append('RIOT')

        # Extract tags if available (Context API)
        tags = response.get('tags', [])
        threat_types.extend(tags)

        # Extract actor info
        actor = response.get('actor')
        if actor:
            threat_types.append(f"actor:{actor}")

        # Extract CVEs if available (Context API)
        cves = response.get('cve', [])
        threat_types.extend(cves)

        return categories, threat_types

    @staticmethod
    def get_risk_adjustment(response: Dict[str, Any]) -> int:
        """
        Get risk adjustment value for aggregation.

        This is used by the aggregator to adjust the final risk score
        based on GreyNoise intelligence.

        Args:
            response: Normalized GreyNoise data

        Returns:
            int: Adjustment to apply to final risk score
                 Negative = reduce risk (benign)
                 Positive = increase risk (malicious)
                 Zero = no change
        """
        classification = response.get('greynoise_classification', 'unknown')
        is_riot = response.get('greynoise_riot', False)

        # RIOT = known benign, significant reduction
        if is_riot:
            return -40

        return GreyNoiseNormalizer.CLASSIFICATION_RISK.get(classification, 0)


class ConfidenceScorer:
    """
    Calculates confidence scores for threat intelligence assessments.

    Confidence score (0-100) indicates how reliable the risk assessment is,
    based on factors like:
    - Number of sources that provided data
    - Volume of reports/detections
    - Data recency
    - Source agreement (do sources agree on the assessment?)

    This addresses PRD FR5: Transparent and deterministic scoring model.
    """

    # Weight factors for confidence calculation
    WEIGHTS = {
        'source_count': 0.30,      # More sources = higher confidence
        'report_volume': 0.25,     # More reports = higher confidence
        'data_recency': 0.20,      # Recent data = higher confidence
        'source_agreement': 0.25   # Sources agreeing = higher confidence
    }

    # Source count scoring (max 4 sources in our system)
    SOURCE_SCORES = {
        1: 25,   # Single source - low confidence
        2: 50,   # Two sources - moderate confidence
        3: 75,   # Three sources - good confidence
        4: 100   # All four sources - high confidence
    }

    @staticmethod
    def calculate(normalized_responses: List[Dict[str, Any]]) -> int:
        """
        Calculate confidence score from aggregated threat intel responses.

        The confidence score is deterministic and transparent, based on:
        1. Source count (30%): How many sources provided data
        2. Report volume (25%): Total number of reports across sources
        3. Data recency (20%): How recent is the most recent report
        4. Source agreement (25%): Do sources agree on malicious status

        Args:
            normalized_responses: List of normalized responses from APIs

        Returns:
            int: Confidence score (0-100)

        Example:
            >>> responses = [{'sources': ['AbuseIPDB'], 'total_reports': 10, ...}]
            >>> ConfidenceScorer.calculate(responses)
            65
        """
        if not normalized_responses:
            return 0

        # Factor 1: Source count (30%)
        source_count = len(normalized_responses)
        source_score = ConfidenceScorer.SOURCE_SCORES.get(source_count, 100)

        # Factor 2: Report volume (25%)
        total_reports = sum(r.get('total_reports', 0)
                            for r in normalized_responses)
        report_score = ConfidenceScorer._calculate_report_score(total_reports)

        # Factor 3: Data recency (20%)
        recency_score = ConfidenceScorer._calculate_recency_score(
            normalized_responses)

        # Factor 4: Source agreement (25%)
        agreement_score = ConfidenceScorer._calculate_agreement_score(
            normalized_responses)

        # Calculate weighted confidence score
        confidence = int(
            source_score * ConfidenceScorer.WEIGHTS['source_count'] +
            report_score * ConfidenceScorer.WEIGHTS['report_volume'] +
            recency_score * ConfidenceScorer.WEIGHTS['data_recency'] +
            agreement_score * ConfidenceScorer.WEIGHTS['source_agreement']
        )

        logger.info(
            f"Confidence score calculated: {confidence} "
            f"(sources={source_score}, reports={report_score}, "
            f"recency={recency_score}, agreement={agreement_score})"
        )

        return max(0, min(confidence, 100))

    @staticmethod
    def _calculate_report_score(total_reports: int) -> int:
        """
        Calculate score based on report volume.

        More reports generally mean more confidence in the assessment.

        Args:
            total_reports: Total number of reports across all sources

        Returns:
            int: Report volume score (0-100)
        """
        if total_reports == 0:
            return 30  # No reports - baseline confidence
        elif total_reports < 5:
            return 50  # Few reports
        elif total_reports < 20:
            return 70  # Moderate reports
        elif total_reports < 50:
            return 85  # Many reports
        else:
            return 100  # Extensive reports

    @staticmethod
    def _calculate_recency_score(responses: List[Dict[str, Any]]) -> int:
        """
        Calculate score based on data recency.

        Recent data is more reliable than old data.

        Args:
            responses: List of normalized responses

        Returns:
            int: Recency score (0-100)
        """
        # Collect all last_reported timestamps
        timestamps = []
        for r in responses:
            last_reported = r.get('last_reported')
            if last_reported:
                timestamps.append(last_reported)

        if not timestamps:
            return 50  # No timestamp data - neutral score

        # Try to parse the most recent timestamp
        try:
            # Handle various timestamp formats
            most_recent = None
            for ts in timestamps:
                if isinstance(ts, str):
                    # Try ISO format first
                    try:
                        parsed = datetime.fromisoformat(
                            ts.replace('Z', '+00:00'))
                    except ValueError:
                        # Try other common formats
                        try:
                            parsed = datetime.strptime(ts[:10], '%Y-%m-%d')
                        except ValueError:
                            continue

                    if most_recent is None or parsed > most_recent:
                        most_recent = parsed
                elif isinstance(ts, (int, float)):
                    # Unix timestamp
                    parsed = datetime.fromtimestamp(ts)
                    if most_recent is None or parsed > most_recent:
                        most_recent = parsed

            if most_recent is None:
                return 50

            # Calculate days since most recent report
            now = datetime.now()
            if most_recent.tzinfo:
                now = datetime.now(most_recent.tzinfo)

            days_old = (now - most_recent).days

            if days_old < 1:
                return 100  # Today
            elif days_old < 7:
                return 90   # Within a week
            elif days_old < 30:
                return 75   # Within a month
            elif days_old < 90:
                return 60   # Within 3 months
            elif days_old < 365:
                return 40   # Within a year
            else:
                return 20   # Over a year old

        except Exception as e:
            logger.debug(f"Error calculating recency score: {e}")
            return 50  # Default on error

    @staticmethod
    def _calculate_agreement_score(responses: List[Dict[str, Any]]) -> int:
        """
        Calculate score based on source agreement.

        If multiple sources agree on malicious/benign status,
        confidence is higher.

        Args:
            responses: List of normalized responses

        Returns:
            int: Agreement score (0-100)
        """
        if len(responses) < 2:
            return 50  # Single source - neutral agreement

        # Count how many sources flag as malicious
        malicious_votes = sum(
            1 for r in responses if r.get('is_malicious', False))
        total_sources = len(responses)

        # Calculate agreement percentage
        # Full agreement (all malicious or all benign) = 100
        # Split decision = lower score
        if malicious_votes == 0 or malicious_votes == total_sources:
            return 100  # Full agreement

        # Partial agreement
        agreement_ratio = max(
            malicious_votes, total_sources - malicious_votes) / total_sources
        return int(agreement_ratio * 100)

    @staticmethod
    def get_confidence_level(score: int) -> str:
        """
        Get human-readable confidence level.

        Args:
            score: Confidence score (0-100)

        Returns:
            str: Confidence level (LOW, MEDIUM, HIGH, VERY HIGH)
        """
        if score >= 80:
            return "VERY HIGH"
        elif score >= 60:
            return "HIGH"
        elif score >= 40:
            return "MEDIUM"
        else:
            return "LOW"

    @staticmethod
    def get_confidence_explanation(score: int, source_count: int, total_reports: int) -> str:
        """
        Generate explanation for confidence score.

        Args:
            score: Confidence score
            source_count: Number of sources
            total_reports: Total reports

        Returns:
            str: Human-readable explanation
        """
        level = ConfidenceScorer.get_confidence_level(score)

        parts = [f"{level} confidence ({score}%)"]
        parts.append(f"based on {source_count} source(s)")

        if total_reports > 0:
            parts.append(f"and {total_reports} report(s)")

        return " ".join(parts)


class ThreatIntelAggregator:
    """
    Aggregates and merges normalized data from multiple sources.

    Demonstrates advanced comprehensions and data merging.
    """

    @staticmethod
    def aggregate(normalized_responses: List[Dict[str, Any]]) -> ThreatIntelResult:
        """
        Aggregate multiple normalized threat intel responses.

        This method now returns a ThreatIntelResult dataclass instead of dict,
        establishing the canonical schema as the single source of truth.

        Args:
            normalized_responses: List of normalized responses from APIs

        Returns:
            ThreatIntelResult: Canonical dataclass with aggregated data
        """
        logger.info(
            f"Aggregating {len(normalized_responses)} threat intel sources")

        if not normalized_responses:
            # Return empty ThreatIntelResult with IP address unknown
            return ThreatIntelResult(ip_address="unknown")

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

        # Calculate confidence score (Session 2 implementation)
        confidence_score = ConfidenceScorer.calculate(normalized_responses)

        logger.info(
            f"Aggregation complete: Final risk score={aggregated['risk_score']}, "
            f"Confidence={confidence_score}"
        )

        # Generate recommendation (addresses PRD Success Metric #1)
        recommendation = generate_recommendation(
            risk_score=aggregated['risk_score'],
            confidence_score=confidence_score,
            total_reports=aggregated['total_reports'],
            is_malicious=aggregated['is_malicious']
        )

        # Convert aggregated dict to canonical ThreatIntelResult dataclass
        result = ThreatIntelResult(
            ip_address=aggregated['ip_address'],
            risk_score=aggregated['risk_score'],
            confidence_score=confidence_score,
            is_malicious=aggregated['is_malicious'],
            country=aggregated.get('country'),
            country_code=aggregated.get('country_code'),
            isp=aggregated.get('isp'),
            domain=aggregated.get('domain'),
            total_reports=aggregated['total_reports'],
            last_reported=aggregated.get('last_reported'),
            categories=aggregated['categories'],
            threat_types=aggregated['threat_types'],
            sources=aggregated['sources'],
            recommendation=recommendation,
            raw_data=aggregated['raw_data']
        )

        logger.info(
            f"Converted to ThreatIntelResult dataclass: "
            f"IP={result.ip_address}, Recommendation={result.recommendation_action}"
        )

        return result

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
        merged['categories'] = list(
            set(base.get('categories', []) + new.get('categories', [])))
        merged['threat_types'] = list(
            set(base.get('threat_types', []) + new.get('threat_types', [])))
        merged['sources'] = list(
            set(base.get('sources', []) + new.get('sources', [])))

        # Sum total reports
        merged['total_reports'] = base.get(
            'total_reports', 0) + new.get('total_reports', 0)

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
        Applies GreyNoise risk adjustment for benign/malicious classification.

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

        # Apply GreyNoise risk adjustment if present
        # GreyNoise can reduce risk for known benign IPs (RIOT, benign classification)
        greynoise_adjustment = 0
        for response in responses:
            if 'greynoise_classification' in response:
                greynoise_adjustment = GreyNoiseNormalizer.get_risk_adjustment(
                    response)
                logger.info(
                    f"Applying GreyNoise risk adjustment: {greynoise_adjustment}")
                break  # Only apply once

        aggregate += greynoise_adjustment

        return max(0, min(aggregate, 100))


def normalize_abuseipdb(response: Dict[str, Any]) -> Dict[str, Any]:
    """Convenience function for normalizing AbuseIPDB responses."""
    return AbuseIPDBNormalizer.normalize(response)


def normalize_otx(response: Dict[str, Any]) -> Dict[str, Any]:
    """Convenience function for normalizing OTX responses."""
    return OTXNormalizer.normalize(response)


def normalize_virustotal(response: Dict[str, Any]) -> Dict[str, Any]:
    """Convenience function for normalizing VirusTotal responses."""
    return VirusTotalNormalizer.normalize(response)


def normalize_greynoise(response: Dict[str, Any]) -> Dict[str, Any]:
    """Convenience function for normalizing GreyNoise responses."""
    return GreyNoiseNormalizer.normalize(response)


def calculate_confidence(responses: List[Dict[str, Any]]) -> int:
    """
    Convenience function for calculating confidence score.

    Args:
        responses: List of normalized threat intel responses

    Returns:
        int: Confidence score (0-100)
    """
    return ConfidenceScorer.calculate(responses)


def aggregate_threat_intel(responses: List[Dict[str, Any]]) -> ThreatIntelResult:
    """
    Convenience function for aggregating normalized responses.

    Returns:
        ThreatIntelResult: Canonical dataclass (changed from dict in this session)
    """
    return ThreatIntelAggregator.aggregate(responses)
