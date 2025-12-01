"""
Lockheed Martin Cyber Kill Chain Mapping Utility.

This module maps threat intelligence categories and indicators to the
Lockheed Martin Cyber Kill Chain stages, providing context about where
in the attack lifecycle a threat actor may be operating.

The Cyber Kill Chain is a framework developed by Lockheed Martin that
describes the stages of a cyber attack, from reconnaissance to actions
on objectives.

Kill Chain Stages:
1. Reconnaissance - Harvesting information (email addresses, conference info, etc.)
2. Weaponization - Coupling exploit with backdoor into deliverable payload
3. Delivery - Delivering weaponized bundle to victim (email, USB, web)
4. Exploitation - Exploiting vulnerability to execute code on victim's system
5. Installation - Installing malware on the asset
6. Command & Control (C2) - Command channel for remote manipulation
7. Actions on Objectives - Accomplishing original goals (data exfiltration, etc.)

Reference: https://www.lockheedmartin.com/en-us/capabilities/cyber/cyber-kill-chain.html

Demonstrates:
- Dictionary-based mapping
- Pattern matching for threat classification
- Ordered stage progression
- Type hints and documentation
"""

from typing import Dict, List, Any, Optional
from enum import Enum
import logging

logger = logging.getLogger(__name__)


class KillChainStage(Enum):
    """
    Enumeration of Cyber Kill Chain stages in order of attack progression.
    """
    RECONNAISSANCE = ("1. Reconnaissance",
                      "Information gathering and target identification")
    WEAPONIZATION = ("2. Weaponization", "Creating attack tools and payloads")
    DELIVERY = ("3. Delivery", "Transmitting the weapon to the target")
    EXPLOITATION = ("4. Exploitation",
                    "Exploiting vulnerabilities to gain access")
    INSTALLATION = ("5. Installation", "Installing malware or backdoors")
    COMMAND_AND_CONTROL = ("6. Command & Control",
                           "Establishing remote control channel")
    ACTIONS_ON_OBJECTIVES = ("7. Actions on Objectives",
                             "Achieving attack goals")

    def __init__(self, display_name: str, description: str):
        self.display_name = display_name
        self.description = description


# Mapping of threat categories/indicators to Kill Chain stages
# Format: { 'category_keyword': [KillChainStage, ...] }
CATEGORY_TO_KILL_CHAIN = {
    # Stage 1: Reconnaissance
    'port scan': [KillChainStage.RECONNAISSANCE],
    'scan': [KillChainStage.RECONNAISSANCE],
    'scanning': [KillChainStage.RECONNAISSANCE],
    'reconnaissance': [KillChainStage.RECONNAISSANCE],
    'crawler': [KillChainStage.RECONNAISSANCE],
    'scraper': [KillChainStage.RECONNAISSANCE],
    'enumeration': [KillChainStage.RECONNAISSANCE],
    'information gathering': [KillChainStage.RECONNAISSANCE],
    'osint': [KillChainStage.RECONNAISSANCE],
    'bad web bot': [KillChainStage.RECONNAISSANCE],

    # Stage 2: Weaponization (typically not observed in network traffic)
    'exploit kit': [KillChainStage.WEAPONIZATION, KillChainStage.DELIVERY],
    'weaponization': [KillChainStage.WEAPONIZATION],

    # Stage 3: Delivery
    'phishing': [KillChainStage.DELIVERY],
    'spear phishing': [KillChainStage.DELIVERY],
    'spam': [KillChainStage.DELIVERY],
    'email spam': [KillChainStage.DELIVERY],
    'web spam': [KillChainStage.DELIVERY],
    'malspam': [KillChainStage.DELIVERY],
    'drive-by': [KillChainStage.DELIVERY],
    'watering hole': [KillChainStage.DELIVERY],

    # Stage 4: Exploitation
    'exploit': [KillChainStage.EXPLOITATION],
    'exploited host': [KillChainStage.EXPLOITATION, KillChainStage.INSTALLATION],
    'sql injection': [KillChainStage.EXPLOITATION],
    'web app attack': [KillChainStage.EXPLOITATION],
    'rce': [KillChainStage.EXPLOITATION],
    'remote code execution': [KillChainStage.EXPLOITATION],
    'vulnerability': [KillChainStage.EXPLOITATION],
    'cve': [KillChainStage.EXPLOITATION],
    'zero-day': [KillChainStage.EXPLOITATION],
    '0day': [KillChainStage.EXPLOITATION],

    # Stage 5: Installation
    'malware': [KillChainStage.INSTALLATION, KillChainStage.COMMAND_AND_CONTROL],
    'trojan': [KillChainStage.INSTALLATION, KillChainStage.COMMAND_AND_CONTROL],
    'backdoor': [KillChainStage.INSTALLATION],
    'rootkit': [KillChainStage.INSTALLATION],
    'dropper': [KillChainStage.INSTALLATION],
    'rat': [KillChainStage.INSTALLATION, KillChainStage.COMMAND_AND_CONTROL],
    'worm': [KillChainStage.INSTALLATION],
    'virus': [KillChainStage.INSTALLATION],

    # Stage 6: Command & Control
    'c2': [KillChainStage.COMMAND_AND_CONTROL],
    'c&c': [KillChainStage.COMMAND_AND_CONTROL],
    'command and control': [KillChainStage.COMMAND_AND_CONTROL],
    'botnet': [KillChainStage.COMMAND_AND_CONTROL],
    'bot': [KillChainStage.COMMAND_AND_CONTROL],
    'proxy': [KillChainStage.COMMAND_AND_CONTROL],
    'open proxy': [KillChainStage.COMMAND_AND_CONTROL],
    'tor': [KillChainStage.COMMAND_AND_CONTROL],
    'vpn': [KillChainStage.COMMAND_AND_CONTROL],
    'anonymizer': [KillChainStage.COMMAND_AND_CONTROL],
    'beacon': [KillChainStage.COMMAND_AND_CONTROL],

    # Stage 7: Actions on Objectives
    'ransomware': [KillChainStage.ACTIONS_ON_OBJECTIVES],
    'cryptominer': [KillChainStage.ACTIONS_ON_OBJECTIVES],
    'miner': [KillChainStage.ACTIONS_ON_OBJECTIVES],
    'data exfiltration': [KillChainStage.ACTIONS_ON_OBJECTIVES],
    'exfiltration': [KillChainStage.ACTIONS_ON_OBJECTIVES],
    'ddos': [KillChainStage.ACTIONS_ON_OBJECTIVES],
    'ddos attack': [KillChainStage.ACTIONS_ON_OBJECTIVES],
    'dos': [KillChainStage.ACTIONS_ON_OBJECTIVES],
    'ping of death': [KillChainStage.ACTIONS_ON_OBJECTIVES],
    'fraud': [KillChainStage.ACTIONS_ON_OBJECTIVES],
    'fraud orders': [KillChainStage.ACTIONS_ON_OBJECTIVES],

    # Multi-stage indicators
    'brute-force': [KillChainStage.RECONNAISSANCE, KillChainStage.EXPLOITATION],
    'brute force': [KillChainStage.RECONNAISSANCE, KillChainStage.EXPLOITATION],
    'ssh': [KillChainStage.RECONNAISSANCE, KillChainStage.EXPLOITATION],
    'ftp brute-force': [KillChainStage.RECONNAISSANCE, KillChainStage.EXPLOITATION],
    'credential': [KillChainStage.RECONNAISSANCE, KillChainStage.EXPLOITATION],
    'password': [KillChainStage.RECONNAISSANCE, KillChainStage.EXPLOITATION],
    'hacking': [KillChainStage.EXPLOITATION, KillChainStage.INSTALLATION],
    'abuse': [KillChainStage.ACTIONS_ON_OBJECTIVES],

    # DNS-related (can span multiple stages)
    'dns compromise': [KillChainStage.COMMAND_AND_CONTROL],
    'dns poisoning': [KillChainStage.DELIVERY, KillChainStage.COMMAND_AND_CONTROL],

    # IoT-related
    'iot': [KillChainStage.RECONNAISSANCE, KillChainStage.EXPLOITATION],
    'iot targeted': [KillChainStage.EXPLOITATION],

    # GreyNoise classifications
    'malicious': [KillChainStage.RECONNAISSANCE, KillChainStage.EXPLOITATION],
    'greynoise_malicious': [KillChainStage.RECONNAISSANCE],
    'suspicious': [KillChainStage.RECONNAISSANCE],
    'greynoise_suspicious': [KillChainStage.RECONNAISSANCE],
}


class KillChainMapper:
    """
    Maps threat intelligence data to Cyber Kill Chain stages.

    This class provides methods to analyze threat categories and indicators,
    returning relevant Kill Chain stages that help analysts understand where
    in the attack lifecycle the threat is operating.
    """

    @staticmethod
    def map_categories(categories: List[str]) -> List[KillChainStage]:
        """
        Map threat categories to Cyber Kill Chain stages.

        Args:
            categories: List of threat category strings

        Returns:
            List of unique KillChainStage enums, ordered by stage progression

        Example:
            >>> KillChainMapper.map_categories(['port scan', 'malware'])
            [KillChainStage.RECONNAISSANCE, KillChainStage.INSTALLATION, KillChainStage.COMMAND_AND_CONTROL]
        """
        stages = set()

        for category in categories:
            # Normalize category to lowercase for matching
            category_lower = category.lower().strip()

            # Direct match
            if category_lower in CATEGORY_TO_KILL_CHAIN:
                stages.update(CATEGORY_TO_KILL_CHAIN[category_lower])
            else:
                # Partial match - check if any key is contained in category
                for key, mapped_stages in CATEGORY_TO_KILL_CHAIN.items():
                    if key in category_lower or category_lower in key:
                        stages.update(mapped_stages)

        # Sort by stage order (using enum value position)
        stage_order = list(KillChainStage)
        sorted_stages = sorted(stages, key=lambda s: stage_order.index(s))

        logger.debug(
            f"Mapped {len(categories)} categories to {len(sorted_stages)} Kill Chain stages")
        return sorted_stages

    @staticmethod
    def map_threat_intel(threat_data: Dict[str, Any]) -> List[KillChainStage]:
        """
        Map complete threat intelligence data to Cyber Kill Chain stages.

        Analyzes categories, threat_types, and other fields to provide
        comprehensive Kill Chain mapping.

        Args:
            threat_data: Normalized threat intelligence dictionary or ThreatIntelResult

        Returns:
            List of unique KillChainStage enums, ordered by stage progression
        """
        all_indicators = []

        # Collect from categories
        categories = threat_data.get('categories', [])
        if categories:
            all_indicators.extend(categories)

        # Collect from threat_types
        threat_types = threat_data.get('threat_types', [])
        if threat_types:
            all_indicators.extend(threat_types)

        # Check GreyNoise classification
        gn_classification = threat_data.get('greynoise_classification')
        if gn_classification and gn_classification != 'unknown':
            all_indicators.append(f"greynoise_{gn_classification}")
            all_indicators.append(gn_classification)

        # Map all collected indicators
        stages = KillChainMapper.map_categories(all_indicators)

        logger.info(f"Mapped threat intel to {len(stages)} Kill Chain stages")
        return stages

    @staticmethod
    def get_stage_names(stages: List[KillChainStage]) -> List[str]:
        """
        Get display names for a list of Kill Chain stages.

        Args:
            stages: List of KillChainStage enums

        Returns:
            List of stage display names

        Example:
            >>> KillChainMapper.get_stage_names([KillChainStage.RECONNAISSANCE])
            ['1. Reconnaissance']
        """
        return [stage.display_name for stage in stages]

    @staticmethod
    def get_stages_with_descriptions(stages: List[KillChainStage]) -> List[Dict[str, str]]:
        """
        Get stages with their descriptions for detailed display.

        Args:
            stages: List of KillChainStage enums

        Returns:
            List of dictionaries with 'name' and 'description' keys
        """
        return [
            {
                'name': stage.display_name,
                'description': stage.description,
                'stage_number': stage.display_name.split('.')[0]
            }
            for stage in stages
        ]

    @staticmethod
    def get_attack_progression_summary(stages: List[KillChainStage]) -> str:
        """
        Generate a human-readable summary of the attack progression.

        Args:
            stages: List of KillChainStage enums

        Returns:
            String describing the attack progression

        Example:
            >>> stages = [KillChainStage.RECONNAISSANCE, KillChainStage.EXPLOITATION]
            >>> KillChainMapper.get_attack_progression_summary(stages)
            "Attack spans from Reconnaissance to Exploitation (2 stages)"
        """
        if not stages:
            return "No Kill Chain stages identified"

        if len(stages) == 1:
            return f"Attack stage: {stages[0].display_name}"

        # Get first and last stage
        first_stage = stages[0].display_name.split('. ')[1]
        last_stage = stages[-1].display_name.split('. ')[1]

        return f"Attack spans from {first_stage} to {last_stage} ({len(stages)} stages)"

    @staticmethod
    def get_all_stages() -> List[Dict[str, str]]:
        """
        Get all Kill Chain stages with their descriptions.

        Useful for displaying the full Kill Chain with highlighting
        of identified stages.

        Returns:
            List of all stages with name and description
        """
        return [
            {
                'name': stage.display_name,
                'description': stage.description,
                'enum': stage.name
            }
            for stage in KillChainStage
        ]


def map_to_kill_chain(threat_data: Dict[str, Any]) -> List[str]:
    """
    Convenience function to map threat data to Kill Chain stage names.

    Args:
        threat_data: Normalized threat intelligence dictionary

    Returns:
        List of Kill Chain stage display names
    """
    stages = KillChainMapper.map_threat_intel(threat_data)
    return KillChainMapper.get_stage_names(stages)


def get_kill_chain_stages(threat_data: Dict[str, Any]) -> List[Dict[str, str]]:
    """
    Convenience function to get Kill Chain stages with descriptions.

    Args:
        threat_data: Normalized threat intelligence dictionary

    Returns:
        List of stage dictionaries with name and description
    """
    stages = KillChainMapper.map_threat_intel(threat_data)
    return KillChainMapper.get_stages_with_descriptions(stages)
