"""
MITRE ATT&CK Mapping Utility.

This module maps threat intelligence categories and indicators to MITRE ATT&CK
techniques, providing standardized threat context for security analysts.

MITRE ATT&CK is a globally-accessible knowledge base of adversary tactics and
techniques based on real-world observations.

Demonstrates:
- Dictionary-based mapping
- Pattern matching for threat classification
- Integration with threat intelligence data
- Type hints and documentation

Reference: https://attack.mitre.org/
"""

from typing import Dict, List, Any, Optional
import logging

logger = logging.getLogger(__name__)


# MITRE ATT&CK Technique Mappings
# Format: { 'category_keyword': [{'id': 'TXXXX', 'name': 'Technique Name', 'tactic': 'Tactic'}] }
CATEGORY_TO_ATTACK = {
    # Reconnaissance (TA0043)
    'port scan': [
        {'id': 'T1595.001', 'name': 'Scanning IP Blocks', 'tactic': 'Reconnaissance'},
        {'id': 'T1595.002', 'name': 'Vulnerability Scanning',
            'tactic': 'Reconnaissance'}
    ],
    'scan': [
        {'id': 'T1595', 'name': 'Active Scanning', 'tactic': 'Reconnaissance'}
    ],
    'reconnaissance': [
        {'id': 'T1595', 'name': 'Active Scanning', 'tactic': 'Reconnaissance'}
    ],

    # Initial Access (TA0001)
    'brute-force': [
        {'id': 'T1110', 'name': 'Brute Force', 'tactic': 'Credential Access'},
        {'id': 'T1078', 'name': 'Valid Accounts', 'tactic': 'Initial Access'}
    ],
    'brute force': [
        {'id': 'T1110', 'name': 'Brute Force', 'tactic': 'Credential Access'}
    ],
    'ssh': [
        {'id': 'T1110.001', 'name': 'Password Guessing',
            'tactic': 'Credential Access'},
        {'id': 'T1021.004', 'name': 'SSH', 'tactic': 'Lateral Movement'}
    ],
    'ftp brute-force': [
        {'id': 'T1110.001', 'name': 'Password Guessing',
            'tactic': 'Credential Access'}
    ],
    'phishing': [
        {'id': 'T1566', 'name': 'Phishing', 'tactic': 'Initial Access'},
        {'id': 'T1566.001', 'name': 'Spearphishing Attachment',
            'tactic': 'Initial Access'},
        {'id': 'T1566.002', 'name': 'Spearphishing Link', 'tactic': 'Initial Access'}
    ],
    'exploit': [
        {'id': 'T1190', 'name': 'Exploit Public-Facing Application',
            'tactic': 'Initial Access'}
    ],
    'exploited host': [
        {'id': 'T1190', 'name': 'Exploit Public-Facing Application',
            'tactic': 'Initial Access'},
        {'id': 'T1059', 'name': 'Command and Scripting Interpreter', 'tactic': 'Execution'}
    ],

    # Execution (TA0002)
    'web app attack': [
        {'id': 'T1190', 'name': 'Exploit Public-Facing Application',
            'tactic': 'Initial Access'},
        {'id': 'T1059', 'name': 'Command and Scripting Interpreter', 'tactic': 'Execution'}
    ],
    'sql injection': [
        {'id': 'T1190', 'name': 'Exploit Public-Facing Application',
            'tactic': 'Initial Access'},
        {'id': 'T1505.001', 'name': 'SQL Stored Procedures', 'tactic': 'Persistence'}
    ],
    'rce': [
        {'id': 'T1059', 'name': 'Command and Scripting Interpreter', 'tactic': 'Execution'}
    ],
    'remote code execution': [
        {'id': 'T1059', 'name': 'Command and Scripting Interpreter', 'tactic': 'Execution'}
    ],

    # Command and Control (TA0011)
    'c2': [
        {'id': 'T1071', 'name': 'Application Layer Protocol',
            'tactic': 'Command and Control'},
        {'id': 'T1573', 'name': 'Encrypted Channel', 'tactic': 'Command and Control'}
    ],
    'botnet': [
        {'id': 'T1071', 'name': 'Application Layer Protocol',
            'tactic': 'Command and Control'},
        {'id': 'T1568', 'name': 'Dynamic Resolution',
            'tactic': 'Command and Control'}
    ],
    'malware': [
        {'id': 'T1059', 'name': 'Command and Scripting Interpreter',
            'tactic': 'Execution'},
        {'id': 'T1071', 'name': 'Application Layer Protocol',
            'tactic': 'Command and Control'}
    ],
    'trojan': [
        {'id': 'T1059', 'name': 'Command and Scripting Interpreter',
            'tactic': 'Execution'},
        {'id': 'T1547', 'name': 'Boot or Logon Autostart Execution',
            'tactic': 'Persistence'}
    ],
    'rat': [
        {'id': 'T1219', 'name': 'Remote Access Software',
            'tactic': 'Command and Control'}
    ],

    # Impact (TA0040)
    'ddos': [
        {'id': 'T1498', 'name': 'Network Denial of Service', 'tactic': 'Impact'},
        {'id': 'T1499', 'name': 'Endpoint Denial of Service', 'tactic': 'Impact'}
    ],
    'ddos attack': [
        {'id': 'T1498', 'name': 'Network Denial of Service', 'tactic': 'Impact'}
    ],
    'dos': [
        {'id': 'T1499', 'name': 'Endpoint Denial of Service', 'tactic': 'Impact'}
    ],
    'ping of death': [
        {'id': 'T1499.001', 'name': 'OS Exhaustion Flood', 'tactic': 'Impact'}
    ],
    'ransomware': [
        {'id': 'T1486', 'name': 'Data Encrypted for Impact', 'tactic': 'Impact'},
        {'id': 'T1490', 'name': 'Inhibit System Recovery', 'tactic': 'Impact'}
    ],

    # Defense Evasion (TA0005)
    'proxy': [
        {'id': 'T1090', 'name': 'Proxy', 'tactic': 'Command and Control'}
    ],
    'open proxy': [
        {'id': 'T1090.002', 'name': 'External Proxy',
            'tactic': 'Command and Control'}
    ],
    'vpn': [
        {'id': 'T1133', 'name': 'External Remote Services',
            'tactic': 'Initial Access'},
        {'id': 'T1090', 'name': 'Proxy', 'tactic': 'Command and Control'}
    ],
    'tor': [
        {'id': 'T1090.003', 'name': 'Multi-hop Proxy',
            'tactic': 'Command and Control'}
    ],
    'anonymizer': [
        {'id': 'T1090', 'name': 'Proxy', 'tactic': 'Command and Control'}
    ],
    'spoofing': [
        {'id': 'T1036', 'name': 'Masquerading', 'tactic': 'Defense Evasion'}
    ],

    # Credential Access (TA0006)
    'credential': [
        {'id': 'T1110', 'name': 'Brute Force', 'tactic': 'Credential Access'},
        {'id': 'T1555', 'name': 'Credentials from Password Stores',
            'tactic': 'Credential Access'}
    ],
    'password': [
        {'id': 'T1110', 'name': 'Brute Force', 'tactic': 'Credential Access'}
    ],

    # Collection (TA0009)
    'spam': [
        {'id': 'T1566', 'name': 'Phishing', 'tactic': 'Initial Access'}
    ],
    'email spam': [
        {'id': 'T1566.001', 'name': 'Spearphishing Attachment',
            'tactic': 'Initial Access'}
    ],
    'web spam': [
        {'id': 'T1189', 'name': 'Drive-by Compromise', 'tactic': 'Initial Access'}
    ],

    # Resource Development (TA0042)
    'fraud': [
        {'id': 'T1583', 'name': 'Acquire Infrastructure',
            'tactic': 'Resource Development'}
    ],
    'fraud orders': [
        {'id': 'T1583.001', 'name': 'Domains', 'tactic': 'Resource Development'}
    ],

    # DNS-related
    'dns compromise': [
        {'id': 'T1584.002', 'name': 'DNS Server',
            'tactic': 'Resource Development'},
        {'id': 'T1071.004', 'name': 'DNS', 'tactic': 'Command and Control'}
    ],
    'dns poisoning': [
        {'id': 'T1557.001', 'name': 'LLMNR/NBT-NS Poisoning',
            'tactic': 'Credential Access'}
    ],

    # IoT-related
    'iot': [
        {'id': 'T1595.001', 'name': 'Scanning IP Blocks', 'tactic': 'Reconnaissance'},
        {'id': 'T1190', 'name': 'Exploit Public-Facing Application',
            'tactic': 'Initial Access'}
    ],
    'iot targeted': [
        {'id': 'T1190', 'name': 'Exploit Public-Facing Application',
            'tactic': 'Initial Access'}
    ],

    # Web-related
    'bad web bot': [
        {'id': 'T1595.002', 'name': 'Vulnerability Scanning',
            'tactic': 'Reconnaissance'},
        {'id': 'T1190', 'name': 'Exploit Public-Facing Application',
            'tactic': 'Initial Access'}
    ],
    'crawler': [
        {'id': 'T1595.003', 'name': 'Wordlist Scanning', 'tactic': 'Reconnaissance'}
    ],
    'scraper': [
        {'id': 'T1213', 'name': 'Data from Information Repositories',
            'tactic': 'Collection'}
    ],

    # Hacking general
    'hacking': [
        {'id': 'T1190', 'name': 'Exploit Public-Facing Application',
            'tactic': 'Initial Access'},
        {'id': 'T1059', 'name': 'Command and Scripting Interpreter', 'tactic': 'Execution'}
    ],
    'abuse': [
        {'id': 'T1498', 'name': 'Network Denial of Service', 'tactic': 'Impact'}
    ],

    # GreyNoise specific
    'malicious': [
        {'id': 'T1595', 'name': 'Active Scanning', 'tactic': 'Reconnaissance'},
        {'id': 'T1190', 'name': 'Exploit Public-Facing Application',
            'tactic': 'Initial Access'}
    ],
    'greynoise_malicious': [
        {'id': 'T1595', 'name': 'Active Scanning', 'tactic': 'Reconnaissance'}
    ]
}


class MitreAttackMapper:
    """
    Maps threat intelligence data to MITRE ATT&CK techniques.

    This class provides methods to analyze threat categories and indicators,
    returning relevant ATT&CK techniques that help analysts understand the
    potential attack methods being used.
    """

    @staticmethod
    def map_categories(categories: List[str]) -> List[Dict[str, str]]:
        """
        Map threat categories to MITRE ATT&CK techniques.

        Args:
            categories: List of threat category strings

        Returns:
            List of ATT&CK technique dictionaries with id, name, and tactic

        Example:
            >>> MitreAttackMapper.map_categories(['port scan', 'brute-force'])
            [
                {'id': 'T1595.001', 'name': 'Scanning IP Blocks', 'tactic': 'Reconnaissance'},
                {'id': 'T1110', 'name': 'Brute Force', 'tactic': 'Credential Access'}
            ]
        """
        techniques = []
        seen_ids = set()

        for category in categories:
            # Normalize category to lowercase for matching
            category_lower = category.lower().strip()

            # Direct match
            if category_lower in CATEGORY_TO_ATTACK:
                for technique in CATEGORY_TO_ATTACK[category_lower]:
                    if technique['id'] not in seen_ids:
                        techniques.append(technique)
                        seen_ids.add(technique['id'])
            else:
                # Partial match - check if any key is contained in category
                for key, mapped_techniques in CATEGORY_TO_ATTACK.items():
                    if key in category_lower or category_lower in key:
                        for technique in mapped_techniques:
                            if technique['id'] not in seen_ids:
                                techniques.append(technique)
                                seen_ids.add(technique['id'])

        logger.debug(
            f"Mapped {len(categories)} categories to {len(techniques)} ATT&CK techniques")
        return techniques

    @staticmethod
    def map_threat_types(threat_types: List[str]) -> List[Dict[str, str]]:
        """
        Map threat types to MITRE ATT&CK techniques.

        Similar to map_categories but for threat_types field.

        Args:
            threat_types: List of threat type strings

        Returns:
            List of ATT&CK technique dictionaries
        """
        return MitreAttackMapper.map_categories(threat_types)

    @staticmethod
    def map_threat_intel(threat_data: Dict[str, Any]) -> List[Dict[str, str]]:
        """
        Map complete threat intelligence data to MITRE ATT&CK techniques.

        Analyzes categories, threat_types, and other fields to provide
        comprehensive ATT&CK mapping.

        Args:
            threat_data: Normalized threat intelligence dictionary or ThreatIntelResult

        Returns:
            List of unique ATT&CK technique dictionaries
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

        # Map all collected indicators
        techniques = MitreAttackMapper.map_categories(all_indicators)

        logger.info(
            f"Mapped threat intel to {len(techniques)} ATT&CK techniques")
        return techniques

    @staticmethod
    def get_tactics_summary(techniques: List[Dict[str, str]]) -> Dict[str, List[str]]:
        """
        Group techniques by their tactics for summary display.

        Args:
            techniques: List of ATT&CK technique dictionaries

        Returns:
            Dictionary with tactics as keys and lists of technique names as values

        Example:
            >>> techniques = [{'id': 'T1595', 'name': 'Active Scanning', 'tactic': 'Reconnaissance'}]
            >>> MitreAttackMapper.get_tactics_summary(techniques)
            {'Reconnaissance': ['Active Scanning (T1595)']}
        """
        summary = {}

        for technique in techniques:
            tactic = technique.get('tactic', 'Unknown')
            technique_str = f"{technique['name']} ({technique['id']})"

            if tactic not in summary:
                summary[tactic] = []

            if technique_str not in summary[tactic]:
                summary[tactic].append(technique_str)

        return summary

    @staticmethod
    def get_attack_url(technique_id: str) -> str:
        """
        Generate MITRE ATT&CK URL for a technique.

        Args:
            technique_id: ATT&CK technique ID (e.g., 'T1595.001')

        Returns:
            URL to the technique page on attack.mitre.org
        """
        # Handle sub-techniques (e.g., T1595.001 -> T1595/001)
        if '.' in technique_id:
            base_id, sub_id = technique_id.split('.')
            return f"https://attack.mitre.org/techniques/{base_id}/{sub_id}/"
        else:
            return f"https://attack.mitre.org/techniques/{technique_id}/"


def map_to_mitre_attack(threat_data: Dict[str, Any]) -> List[Dict[str, str]]:
    """
    Convenience function to map threat data to MITRE ATT&CK.

    Args:
        threat_data: Normalized threat intelligence dictionary

    Returns:
        List of ATT&CK technique dictionaries
    """
    return MitreAttackMapper.map_threat_intel(threat_data)
