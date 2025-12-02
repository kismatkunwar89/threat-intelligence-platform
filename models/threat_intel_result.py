"""
Canonical Threat Intelligence Result Schema.

This module defines the single source of truth for all threat intelligence data.
All API responses are normalized to this format, ensuring consistency across
exports, UI display, and caching.

Demonstrates:
- Dataclasses for clean data modeling
- Type hints with Optional and List
- Factory pattern for mutable defaults
- Method for JSON serialization
"""

from dataclasses import dataclass, field, asdict
from typing import Dict, List, Any, Optional
from datetime import datetime


@dataclass
class ThreatIntelResult:
    """
    Canonical threat intelligence result schema - single source of truth.

    This dataclass represents the normalized, aggregated result from multiple
    threat intelligence sources. It serves as the foundation for all exports
    (JSON, CSV, PDF) and UI displays.

    Design Philosophy:
    - Single Canonical Schema: One structure for all outputs
    - Extensible: New fields can be added without breaking existing code
    - Transparent: All raw data preserved for audit trail
    - Actionable: Includes recommendation for SOC operations
    """

    # Core Indicator
    ip_address: str

    # Assessment
    risk_score: int = 0  # 0-100 scale
    is_malicious: bool = False
    confidence_score: int = 0  # 0-100 (to be implemented in Session 2)

    # Geographic Context
    country: Optional[str] = None
    country_code: Optional[str] = None

    # Network Context
    isp: Optional[str] = None
    domain: Optional[str] = None
    usage_type: Optional[str] = None  # Data Center, ISP, Residential, etc. (AbuseIPDB)
    asn: Optional[str] = None  # Autonomous System Number
    asn_name: Optional[str] = None  # ASN owner name

    # Intelligence Metrics
    total_reports: int = 0
    last_reported: Optional[str] = None
    num_distinct_reporters: int = 0  # Number of unique reporters (AbuseIPDB)
    categories: List[str] = field(default_factory=list)
    threat_types: List[str] = field(default_factory=list)
    sources: List[str] = field(default_factory=list)

    # Temporal Intelligence
    first_seen: Optional[str] = None  # First observed (OTX/GreyNoise)
    last_seen: Optional[str] = None  # Last observed (OTX/GreyNoise)

    # Attribution & Malware
    malware_families: List[str] = field(default_factory=list)  # Associated malware (OTX)
    threat_actor: Optional[str] = None  # Known threat actor (GreyNoise)

    # Community Intelligence
    community_votes: Dict[str, int] = field(default_factory=dict)  # VirusTotal votes
    tags: List[str] = field(default_factory=list)  # Community tags (OTX/GreyNoise)

    # Privacy/Anonymization Services
    is_vpn: bool = False  # VPN detection (GreyNoise)
    is_tor: bool = False  # Tor exit node (GreyNoise)
    is_proxy: bool = False  # Proxy detection (GreyNoise)
    is_bot: bool = False  # Bot detection (GreyNoise)

    # CTIA Framework (Certified Threat Intelligence Analyst)
    # To be implemented in Session 2
    mitre_attack: List[Dict[str, str]] = field(default_factory=list)
    kill_chain_stages: List[str] = field(default_factory=list)

    # Recommendation (Addresses PRD Success Metric: 100% actionable recommendations)
    recommendation: Dict[str, str] = field(default_factory=dict)
    # Format: {
    #     "action": "BLOCK|MONITOR|INVESTIGATE|ALLOW",
    #     "priority": "CRITICAL|HIGH|MEDIUM|LOW",
    #     "justification": "text explaining the recommendation"
    # }

    # Raw API Responses (preserved for transparency and audit)
    raw_data: Dict[str, Any] = field(default_factory=dict)

    # Metadata
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert dataclass to dictionary for JSON serialization and template access.

        Returns:
            dict: Dictionary representation of the threat intelligence result

        Note:
            This method enables:
            - JSON export: json.dumps(result.to_dict())
            - Template access: {{ threat_data.risk_score }} works with both dict and dataclass
            - Cache storage: Stored as JSON blob in MySQL
        """
        return asdict(self)

    @property
    def risk_level(self) -> str:
        """
        Get human-readable risk level based on risk score.

        Returns:
            str: Risk level (LOW, MEDIUM, HIGH)
        """
        if self.risk_score < 25:
            return "LOW"
        elif self.risk_score < 75:
            return "MEDIUM"
        else:
            return "HIGH"

    @property
    def recommendation_action(self) -> str:
        """
        Get the recommended action (BLOCK, MONITOR, INVESTIGATE, ALLOW).

        Returns:
            str: Recommended action, or 'UNKNOWN' if not set
        """
        return self.recommendation.get('action', 'UNKNOWN')

    @property
    def recommendation_priority(self) -> str:
        """
        Get the recommendation priority (CRITICAL, HIGH, MEDIUM, LOW).

        Returns:
            str: Priority level, or 'UNKNOWN' if not set
        """
        return self.recommendation.get('priority', 'UNKNOWN')
