"""
Threat Intelligence Recommendation Engine.

This module generates actionable security recommendations based on threat
intelligence data, addressing PRD Success Metric #1:
"100% of lookups provide actionable recommendations"

The recommendation engine provides:
- Clear action: BLOCK, MONITOR, INVESTIGATE, or ALLOW
- Priority level: CRITICAL, HIGH, MEDIUM, or LOW
- Justification: Transparent explanation of the decision
- Confidence-adjusted recommendations

Demonstrates:
- Deterministic decision logic (no randomness, reproducible)
- Threshold-based classification
- Confidence-weighted decision making
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
    Action (based on risk_score, adjusted by confidence):
    - BLOCK:        risk_score >= 75 AND confidence >= 50  (High threat, confident)
    - MONITOR:      50 <= risk_score < 75 OR (risk_score >= 75 AND confidence < 50)
    - INVESTIGATE:  25 <= risk_score < 50  (Low-medium threat, review)
    - ALLOW:        risk_score < 25  (Low threat, likely safe)

    Priority (based on combined risk and confidence):
    - CRITICAL:     risk_score >= 85 AND confidence >= 60  (Urgent, confident)
    - HIGH:         70 <= risk_score < 85 OR (risk >= 85 AND confidence < 60)
    - MEDIUM:       40 <= risk_score < 70  (Normal priority)
    - LOW:          risk_score < 40  (Low priority, routine check)

    Confidence Impact:
    - High confidence (>= 70): Trust the risk score fully
    - Medium confidence (40-69): Consider with caution
    - Low confidence (< 40): Recommend investigation regardless

    Args:
        risk_score: Aggregated risk score from 0-100
                   (calculated by weighted average of all sources)
        confidence_score: Confidence in the assessment from 0-100
                         (based on source count, report volume, recency, agreement)
        total_reports: Total number of abuse reports across all sources
        is_malicious: Whether the IP is flagged as malicious by any source

    Returns:
        dict: Recommendation with keys:
            - "action": str (BLOCK|MONITOR|INVESTIGATE|ALLOW)
            - "priority": str (CRITICAL|HIGH|MEDIUM|LOW)
            - "justification": str (human-readable explanation)
            - "confidence_level": str (VERY HIGH|HIGH|MEDIUM|LOW)
            - "confidence_note": str (additional context about confidence)

    Example:
        >>> generate_recommendation(risk_score=68, confidence_score=85,
        ...                         total_reports=15, is_malicious=True)
        {
            "action": "MONITOR",
            "priority": "MEDIUM",
            "justification": "Risk score: 68/100 | Confidence: 85% (VERY HIGH) | ...",
            "confidence_level": "VERY HIGH",
            "confidence_note": "High confidence assessment from multiple sources"
        }
    """
    # Get confidence level
    confidence_level = get_confidence_level(confidence_score)

    # Determine recommended action based on risk score AND confidence
    action = _determine_action(risk_score, confidence_score, is_malicious)

    # Determine priority level based on risk score AND confidence
    priority = _determine_priority(risk_score, confidence_score)

    # Build transparent justification
    justification_parts = [f"Risk score: {risk_score}/100"]

    # Add confidence info
    justification_parts.append(
        f"Confidence: {confidence_score}% ({confidence_level})")

    if total_reports > 0:
        justification_parts.append(
            f"{total_reports} report(s) from threat intelligence sources"
        )

    if is_malicious:
        justification_parts.append(
            "Flagged as malicious by one or more sources"
        )

    # Add confidence-specific notes
    confidence_note = _get_confidence_note(confidence_score, risk_score)
    if confidence_note:
        justification_parts.append(confidence_note)

    # Join all parts with pipe separator for readability
    justification = " | ".join(justification_parts)

    return {
        "action": action,
        "priority": priority,
        "justification": justification,
        "confidence_level": confidence_level,
        "confidence_note": confidence_note or "Assessment based on available data"
    }


def _determine_action(risk_score: int, confidence_score: int, is_malicious: bool) -> str:
    """
    Determine recommended action based on risk and confidence.

    High risk + High confidence = BLOCK
    High risk + Low confidence = MONITOR (need more data)
    Medium risk = MONITOR
    Low-medium risk = INVESTIGATE
    Low risk = ALLOW

    Args:
        risk_score: Risk score 0-100
        confidence_score: Confidence score 0-100
        is_malicious: Whether flagged as malicious

    Returns:
        str: Recommended action
    """
    # Very low confidence - always recommend investigation
    if confidence_score < 30 and risk_score >= 25:
        return "INVESTIGATE"

    # High risk scenarios
    if risk_score >= 75:
        # Only BLOCK if we're confident
        if confidence_score >= 50:
            return "BLOCK"
        else:
            # High risk but low confidence - monitor and gather more data
            return "MONITOR"

    # Medium risk
    elif risk_score >= 50:
        return "MONITOR"

    # Low-medium risk
    elif risk_score >= 25:
        return "INVESTIGATE"

    # Low risk
    else:
        return "ALLOW"


def _determine_priority(risk_score: int, confidence_score: int) -> str:
    """
    Determine priority level based on risk and confidence.

    Critical requires both high risk AND reasonable confidence.

    Args:
        risk_score: Risk score 0-100
        confidence_score: Confidence score 0-100

    Returns:
        str: Priority level
    """
    # Calculate effective priority score (weighted combination)
    # Risk is primary (70%), confidence adjusts (30%)
    effective_score = (risk_score * 0.7) + (min(confidence_score, 100) * 0.3)

    # Critical: High risk AND confident
    if risk_score >= 85 and confidence_score >= 60:
        return "CRITICAL"

    # High: Either high risk or high effective score
    elif risk_score >= 70 or effective_score >= 70:
        return "HIGH"

    # Medium
    elif risk_score >= 40 or effective_score >= 45:
        return "MEDIUM"

    # Low
    else:
        return "LOW"


def _get_confidence_note(confidence_score: int, risk_score: int) -> str:
    """
    Generate contextual note about confidence level.

    Args:
        confidence_score: Confidence score 0-100
        risk_score: Risk score 0-100

    Returns:
        str: Contextual note or empty string
    """
    if confidence_score >= 80:
        return "High confidence assessment from multiple agreeing sources"
    elif confidence_score >= 60:
        return "Good confidence based on substantial evidence"
    elif confidence_score >= 40:
        if risk_score >= 50:
            return "Moderate confidence - consider additional investigation"
        return "Moderate confidence in assessment"
    else:
        if risk_score >= 50:
            return "Low confidence - recommend manual review before action"
        return "Limited data available for assessment"


def get_confidence_level(confidence_score: int) -> str:
    """
    Get human-readable confidence level.

    Args:
        confidence_score: Confidence score (0-100)

    Returns:
        str: Confidence level (VERY HIGH, HIGH, MEDIUM, LOW)
    """
    if confidence_score >= 80:
        return "VERY HIGH"
    elif confidence_score >= 60:
        return "HIGH"
    elif confidence_score >= 40:
        return "MEDIUM"
    else:
        return "LOW"


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
