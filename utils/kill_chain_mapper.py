"""
Lockheed Martin Cyber Kill Chain Mapping Utility (Data-Driven Version).

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
- File I/O (YAML configuration loading)
- Dictionary-based mapping (externalized to config)
- Pattern matching for threat classification
- Ordered stage progression
- Type hints and documentation
- Exception handling (config loading errors)
- MITRE ATT&CK integration (augmented mapping)
"""

from typing import Dict, List, Any, Optional
from enum import Enum
import logging
import os
import yaml

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


class KillChainMapper:
    """
    Maps threat intelligence data to Cyber Kill Chain stages.

    This class provides methods to analyze threat categories and indicators,
    returning relevant Kill Chain stages that help analysts understand where
    in the attack lifecycle the threat is operating.

    The mapper loads configuration from YAML files and can augment mappings
    using MITRE ATT&CK tactic translations.
    """

    # Class-level cache for loaded configurations
    _category_mapping: Optional[Dict[str, List[KillChainStage]]] = None
    _mitre_translation: Optional[Dict[str, List[str]]] = None

    @classmethod
    def _load_category_mapping(cls) -> Dict[str, List[KillChainStage]]:
        """
        Load category-to-stage mapping from YAML configuration file.

        Demonstrates:
        - File I/O operations
        - YAML parsing
        - Exception handling
        - Dictionary comprehension

        Returns:
            Dictionary mapping category keywords to Kill Chain stages
        """
        if cls._category_mapping is not None:
            return cls._category_mapping

        try:
            # Get path to config file
            config_path = os.path.join(
                os.path.dirname(__file__),
                '..',
                'config',
                'kill_chain_map.yaml'
            )

            # Load YAML configuration
            with open(config_path, 'r', encoding='utf-8') as f:
                config = yaml.safe_load(f)

            # Convert stage name strings to KillChainStage enums
            mapping = {}
            for category, stage_names in config.items():
                if isinstance(stage_names, list):
                    # Map stage name strings to enum instances
                    stages = [
                        KillChainStage[stage_name.upper()]
                        for stage_name in stage_names
                        if stage_name.upper() in KillChainStage.__members__
                    ]
                    mapping[category.lower()] = stages

            cls._category_mapping = mapping
            logger.info(f"Loaded {len(mapping)} category mappings from YAML config")
            return mapping

        except FileNotFoundError:
            logger.error(f"Kill Chain mapping config not found at {config_path}")
            # Return empty dict as fallback
            cls._category_mapping = {}
            return {}
        except yaml.YAMLError as e:
            logger.error(f"Failed to parse YAML config: {e}")
            cls._category_mapping = {}
            return {}
        except Exception as e:
            logger.error(f"Unexpected error loading config: {e}", exc_info=True)
            cls._category_mapping = {}
            return {}

    @classmethod
    def _load_mitre_translation(cls) -> Dict[str, List[str]]:
        """
        Load MITRE ATT&CK tactic to Kill Chain stage translation from YAML.

        Demonstrates:
        - File I/O operations
        - YAML parsing with nested structures
        - Exception handling

        Returns:
            Dictionary mapping MITRE tactics to Kill Chain stage names
        """
        if cls._mitre_translation is not None:
            return cls._mitre_translation

        try:
            # Get path to translation file
            config_path = os.path.join(
                os.path.dirname(__file__),
                '..',
                'config',
                'mitre_to_kill_chain.yaml'
            )

            # Load YAML configuration
            with open(config_path, 'r', encoding='utf-8') as f:
                config = yaml.safe_load(f)

            # Extract the translation mapping
            translation = config.get('mitre_to_kill_chain', {})
            cls._mitre_translation = translation
            logger.info(f"Loaded MITRE-to-Kill Chain translation for {len(translation)} tactics")
            return translation

        except FileNotFoundError:
            logger.warning(f"MITRE translation config not found at {config_path}")
            cls._mitre_translation = {}
            return {}
        except Exception as e:
            logger.error(f"Error loading MITRE translation: {e}", exc_info=True)
            cls._mitre_translation = {}
            return {}

    @classmethod
    def augment_with_mitre_techniques(
        cls,
        stages: set,
        threat_data: Dict[str, Any]
    ) -> None:
        """
        Augment Kill Chain stages using MITRE ATT&CK technique tactics.

        When threat data contains MITRE ATT&CK techniques, extract their
        tactics and translate them to Kill Chain stages for more comprehensive
        coverage.

        Demonstrates:
        - Integration of multiple frameworks (MITRE + Kill Chain)
        - Data transformation
        - Set operations

        Args:
            stages: Set of KillChainStage enums to augment (modified in place)
            threat_data: Threat intelligence dictionary potentially containing MITRE data
        """
        # Load translation mapping
        translation = cls._load_mitre_translation()
        if not translation:
            return

        # Check if threat data has MITRE techniques
        mitre_techniques = threat_data.get('mitre_attack_techniques', [])
        if not mitre_techniques:
            return

        # Extract tactics from techniques and translate to Kill Chain stages
        for technique in mitre_techniques:
            # Technique format: {'id': 'T1595', 'name': '...', 'tactic': 'Reconnaissance'}
            if isinstance(technique, dict):
                tactic = technique.get('tactic', '')
            else:
                continue

            # Look up Kill Chain stages for this tactic
            kill_chain_stages = translation.get(tactic, [])

            # Convert stage names to enums and add to set
            for stage_name in kill_chain_stages:
                try:
                    stage_enum = KillChainStage[stage_name.upper()]
                    stages.add(stage_enum)
                except KeyError:
                    logger.debug(f"Unknown stage name from MITRE: {stage_name}")

        logger.debug(f"Augmented Kill Chain with {len(mitre_techniques)} MITRE techniques")

    @classmethod
    def map_categories(cls, categories: List[str]) -> List[KillChainStage]:
        """
        Map threat categories to Cyber Kill Chain stages.

        Uses externalized YAML configuration for category-to-stage mappings.

        Demonstrates:
        - Dictionary lookups
        - Set operations (deduplication)
        - List sorting with custom key
        - Partial string matching

        Args:
            categories: List of threat category strings

        Returns:
            List of unique KillChainStage enums, ordered by stage progression

        Example:
            >>> KillChainMapper.map_categories(['port scan', 'malware'])
            [KillChainStage.RECONNAISSANCE, KillChainStage.INSTALLATION, KillChainStage.COMMAND_AND_CONTROL]
        """
        # Load mapping from YAML
        category_mapping = cls._load_category_mapping()
        stages = set()

        for category in categories:
            # Normalize category to lowercase for matching
            category_lower = category.lower().strip()

            # Direct match
            if category_lower in category_mapping:
                stages.update(category_mapping[category_lower])
            else:
                # Partial match - check if any key is contained in category
                for key, mapped_stages in category_mapping.items():
                    if key in category_lower or category_lower in key:
                        stages.update(mapped_stages)

        # Sort by stage order (using enum value position)
        stage_order = list(KillChainStage)
        sorted_stages = sorted(stages, key=lambda s: stage_order.index(s))

        logger.debug(
            f"Mapped {len(categories)} categories to {len(sorted_stages)} Kill Chain stages")
        return sorted_stages

    @classmethod
    def map_threat_intel(cls, threat_data: Dict[str, Any]) -> List[KillChainStage]:
        """
        Map complete threat intelligence data to Cyber Kill Chain stages.

        Analyzes categories, threat_types, and other fields to provide
        comprehensive Kill Chain mapping. Can optionally augment with
        MITRE ATT&CK technique tactics.

        Demonstrates:
        - Dictionary access with .get() for safe key retrieval
        - List concatenation
        - Function composition (calling other methods)

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

        # Map all collected indicators using configuration
        stages_list = cls.map_categories(all_indicators)
        stages_set = set(stages_list)

        # Augment with MITRE ATT&CK tactics if available
        cls.augment_with_mitre_techniques(stages_set, threat_data)

        # Sort by stage order
        stage_order = list(KillChainStage)
        sorted_stages = sorted(stages_set, key=lambda s: stage_order.index(s))

        logger.info(f"Mapped threat intel to {len(sorted_stages)} Kill Chain stages")
        return sorted_stages

    @staticmethod
    def get_stage_names(stages: List[KillChainStage]) -> List[str]:
        """
        Get display names for a list of Kill Chain stages.

        Demonstrates:
        - List comprehension
        - Accessing enum attributes

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

        Demonstrates:
        - List comprehension with dictionaries
        - String manipulation (split)

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

        Demonstrates:
        - Conditional logic
        - String formatting
        - List indexing

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

        Demonstrates:
        - Iterating over enum members
        - List comprehension

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

    Demonstrates:
    - Function composition
    - Clean API design

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

    Demonstrates:
    - Function composition
    - Returning structured data

    Args:
        threat_data: Normalized threat intelligence dictionary

    Returns:
        List of stage dictionaries with name and description
    """
    stages = KillChainMapper.map_threat_intel(threat_data)
    return KillChainMapper.get_stages_with_descriptions(stages)
