"""
Threat Intelligence Recommendation Engine.

This module generates actionable security recommendations based on threat
intelligence data, addressing PRD Success Metric #1:
"100% of lookups provide actionable recommendations"

The recommendation engine provides:
- Clear action: BLOCK, MONITOR, INVESTIGATE, or ALLOW
- Priority level: CRITICAL, HIGH, MEDIUM, or LOW
- Justification: Transparent explanation of the decision

Demonstrates:
- Deterministic decision logic (no randomness, reproducible)
- Threshold-based classification
- String formatting and concatenation
- Type hints for function parameters and return values
"""

from typing import Dict


def generate_recommendation(
    risk_score: int,
    confidence_score: int,
    total_reports: int,
    is_malicious: bool
) -> Dict[str, str]:
    """
    Generate actionable security recommendation based on threat intel data.

    The recommendation logic is deterministic and transparent, using clear
    thresholds that security analysts can understand and trust.

    Decision Logic:
    ---------------
    Action (based on risk_score):
    - BLOCK:        risk_score >= 75  (High threat, immediate action required)
    - MONITOR:      50 <= risk_score < 75  (Medium threat, watch closely)
    - INVESTIGATE:  25 <= risk_score < 50  (Low-medium threat, review)
    - ALLOW:        risk_score < 25  (Low threat, likely safe)

    Priority (based on risk_score):
    - CRITICAL:     risk_score >= 85  (Urgent response needed)
    - HIGH:         70 <= risk_score < 85  (Prompt action required)
    - MEDIUM:       40 <= risk_score < 70  (Normal priority)
    - LOW:          risk_score < 40  (Low priority, routine check)

    Args:
        risk_score: Aggregated risk score from 0-100
                   (calculated by weighted average of all sources)
        confidence_score: Confidence in the assessment from 0-100
                         (to be implemented in Session 2, currently unused)
        total_reports: Total number of abuse reports across all sources
        is_malicious: Whether the IP is flagged as malicious by any source

    Returns:
        dict: Recommendation with three keys:
            - "action": str (BLOCK|MONITOR|INVESTIGATE|ALLOW)
            - "priority": str (CRITICAL|HIGH|MEDIUM|LOW)
            - "justification": str (human-readable explanation)

    Example:
        >>> generate_recommendation(risk_score=68, confidence_score=85,
        ...                         total_reports=15, is_malicious=True)
        {
            "action": "MONITOR",
            "priority": "MEDIUM",
            "justification": "Risk score: 68/100 | 15 report(s) from threat intelligence sources | Flagged as malicious by multiple sources | Confidence: 85%"
        }
    """
    # Determine recommended action based on risk score
    if risk_score >= 75:
        action = "BLOCK"
    elif risk_score >= 50:
        action = "MONITOR"
    elif risk_score >= 25:
        action = "INVESTIGATE"
    else:
        action = "ALLOW"

    # Determine priority level based on risk score
    if risk_score >= 85:
        priority = "CRITICAL"
    elif risk_score >= 70:
        priority = "HIGH"
    elif risk_score >= 40:
        priority = "MEDIUM"
    else:
        priority = "LOW"

    # Build transparent justification
    justification_parts = [f"Risk score: {risk_score}/100"]

    if total_reports > 0:
        justification_parts.append(
            f"{total_reports} report(s) from threat intelligence sources"
        )

    if is_malicious:
        justification_parts.append(
            "Flagged as malicious by multiple sources"
        )

    if confidence_score > 0:
        justification_parts.append(f"Confidence: {confidence_score}%")

    # Join all parts with pipe separator for readability
    justification = " | ".join(justification_parts)

    return {
        "action": action,
        "priority": priority,
        "justification": justification
    }


def get_action_description(action: str) -> str:
    """
    Get human-readable description of a recommendation action.

    Args:
        action: Action code (BLOCK, MONITOR, INVESTIGATE, ALLOW)

    Returns:
        str: Description of what the action means

    Example:
        >>> get_action_description("BLOCK")
        "Immediately block this IP address in firewall/security controls"
    """
    descriptions = {
        "BLOCK": "Immediately block this IP address in firewall/security controls",
        "MONITOR": "Add to watchlist and monitor for suspicious activity",
        "INVESTIGATE": "Conduct further investigation before taking action",
        "ALLOW": "No action required - appears to be legitimate traffic",
    }
    return descriptions.get(action, "Unknown action")


def get_priority_color(priority: str) -> str:
    """
    Get CSS color code for priority level visualization.

    Args:
        priority: Priority level (CRITICAL, HIGH, MEDIUM, LOW)

    Returns:
        str: CSS color variable name

    Example:
        >>> get_priority_color("CRITICAL")
        "var(--danger-red)"
    """
    colors = {
        "CRITICAL": "var(--danger-red)",
        "HIGH": "var(--warning-orange)",
        "MEDIUM": "var(--accent-cyan)",
        "LOW": "var(--safe-green)",
    }
    return colors.get(priority, "var(--text-primary)")
