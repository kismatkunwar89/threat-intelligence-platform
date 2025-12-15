# Kill Chain Configuration Files

This directory contains YAML configuration files for the Cyber Kill Chain mapper, implementing a **data-driven architecture** instead of hardcoded mappings.

## Architecture Overview

The Kill Chain mapping system has been refactored to use **externalized configuration files**:

```
config/
├── kill_chain_map.yaml        # Category → Kill Chain stage mappings
├── mitre_to_kill_chain.yaml   # MITRE ATT&CK tactic → Kill Chain translations
└── README.md                  # This file
```

## Benefits of This Approach

1. **Separation of Concerns**: Business logic (mappings) separated from code
2. **Easy Maintenance**: Update mappings without touching Python code
3. **Version Control**: Track mapping changes over time
4. **Analyst-Friendly**: Security analysts can customize mappings directly
5. **MITRE Integration**: Automatic augmentation using MITRE ATT&CK data

## Configuration Files

### 1. `kill_chain_map.yaml`

Maps threat categories/indicators to Cyber Kill Chain stages.

**Format:**
```yaml
category_keyword:
  - STAGE_NAME
  - ANOTHER_STAGE  # For multi-stage indicators
```

**Valid Stage Names:**
- `RECONNAISSANCE` - Information gathering
- `WEAPONIZATION` - Creating attack tools (rarely observed)
- `DELIVERY` - Transmitting weapon to target
- `EXPLOITATION` - Exploiting vulnerabilities
- `INSTALLATION` - Installing malware
- `COMMAND_AND_CONTROL` - Remote control channel
- `ACTIONS_ON_OBJECTIVES` - Achieving attack goals

**Example:**
```yaml
port scan:
  - RECONNAISSANCE

malware:
  - INSTALLATION
  - COMMAND_AND_CONTROL

brute-force:
  - RECONNAISSANCE
  - EXPLOITATION
```

**Usage:** 76 category mappings loaded on application startup

### 2. `mitre_to_kill_chain.yaml`

Translates MITRE ATT&CK tactics to Kill Chain stages for automatic augmentation.

**Format:**
```yaml
mitre_to_kill_chain:
  MITRE_Tactic_Name:
    - KILL_CHAIN_STAGE
    - ANOTHER_STAGE
```

**Example:**
```yaml
mitre_to_kill_chain:
  Reconnaissance:
    - RECONNAISSANCE

  Initial Access:
    - DELIVERY
    - EXPLOITATION

  Command And Control:
    - COMMAND_AND_CONTROL
```

**Usage:** When MITRE ATT&CK techniques are present in threat data, their tactics are automatically translated to Kill Chain stages

## How the Mapper Works

### 1. Configuration Loading

```python
from utils.kill_chain_mapper import KillChainMapper

# Automatically loads YAML on first use
stages = KillChainMapper.map_categories(['port scan', 'malware'])
```

**Implementation:**
- Uses `yaml.safe_load()` for secure parsing
- Cached after first load for performance
- Graceful fallback if files are missing

### 2. Mapping Process

**Step 1:** Load category mappings from `kill_chain_map.yaml`

**Step 2:** Match threat categories:
- Direct match: `'port scan'` → `RECONNAISSANCE`
- Partial match: `'ssh brute-force'` contains `'ssh'` → stages for `'ssh'`

**Step 3:** Augment with MITRE (optional):
- If threat data contains MITRE ATT&CK techniques
- Extract tactic from each technique
- Translate tactic to Kill Chain stages using `mitre_to_kill_chain.yaml`

**Step 4:** Deduplicate and sort stages by progression order

### 3. Example Usage

```python
# Threat intelligence data
threat_data = {
    'categories': ['port scan', 'brute force', 'malware'],
    'threat_types': ['scanning', 'bot'],
    'greynoise_classification': 'malicious',
    'mitre_attack_techniques': [
        {'id': 'T1595', 'name': 'Active Scanning', 'tactic': 'Reconnaissance'}
    ]
}

# Map to Kill Chain
from utils.kill_chain_mapper import map_to_kill_chain, get_kill_chain_stages

# Get stage names
stages = map_to_kill_chain(threat_data)
# Result: ['1. Reconnaissance', '4. Exploitation', '5. Installation', '6. Command & Control']

# Get stages with descriptions
stages_detailed = get_kill_chain_stages(threat_data)
# Result: [
#   {'name': '1. Reconnaissance', 'description': 'Information gathering...', ...},
#   ...
# ]
```

## Customizing Mappings

### Adding New Categories

Edit `config/kill_chain_map.yaml`:

```yaml
# Add new category
my custom category:
  - RECONNAISSANCE
  - EXPLOITATION

# Add IoT-specific mapping
iot botnet:
  - INSTALLATION
  - COMMAND_AND_CONTROL
```

### Updating Existing Mappings

Simply edit the YAML file - changes take effect on next application restart or reload.

### Adding MITRE Translations

Edit `config/mitre_to_kill_chain.yaml`:

```yaml
mitre_to_kill_chain:
  # Add new MITRE tactic translation
  My Custom Tactic:
    - EXPLOITATION
    - INSTALLATION
```

## Testing Changes

After modifying configuration files:

```bash
# Test YAML loading
python -c "
from utils.kill_chain_mapper import KillChainMapper
mapping = KillChainMapper._load_category_mapping()
print(f'Loaded {len(mapping)} mappings')
"

# Test with threat data
python tests/test_malicious_ips.py
```

## Python Concepts Demonstrated

This configuration-based approach demonstrates several advanced Python concepts:

1. **File I/O**: Reading YAML files using `open()` with context managers
2. **YAML Parsing**: Using `yaml.safe_load()` for structured configuration
3. **Exception Handling**: Try-except blocks for graceful error handling
4. **Class Methods**: `@classmethod` for shared state management
5. **Caching**: Class-level variables to avoid repeated file I/O
6. **Dictionary Operations**: Mapping lookups, updates, and comprehensions
7. **Set Operations**: Deduplication using `set()`
8. **Enum Integration**: Converting strings to enum instances
9. **Type Hints**: `Optional[Dict[...]]` for type safety

## References

- **Lockheed Martin Cyber Kill Chain**: https://www.lockheedmartin.com/en-us/capabilities/cyber/cyber-kill-chain.html
- **MITRE ATT&CK Framework**: https://attack.mitre.org/
- **YAML Specification**: https://yaml.org/spec/

## Troubleshooting

### Config File Not Found

**Error:** `Kill Chain mapping config not found`

**Solution:** Ensure `config/kill_chain_map.yaml` exists in project root

### Invalid YAML Syntax

**Error:** `Failed to parse YAML config`

**Solution:** Validate YAML syntax using online tools or `yamllint`

### Unknown Stage Name

**Warning:** `Unknown stage name from MITRE: INVALID_STAGE`

**Solution:** Check stage names match enum members exactly (case-sensitive)

## Migration Notes

### Before (Hardcoded)

```python
CATEGORY_TO_KILL_CHAIN = {
    'port scan': [KillChainStage.RECONNAISSANCE],
    'malware': [KillChainStage.INSTALLATION],
    # 150+ more hardcoded entries...
}
```

### After (Data-Driven)

```yaml
# config/kill_chain_map.yaml
port scan:
  - RECONNAISSANCE

malware:
  - INSTALLATION
```

```python
# Loads automatically on first use
mapping = KillChainMapper._load_category_mapping()
```

**Result:**
- No code changes needed for new mappings
- Analysts can update configurations directly
- Version-controlled mapping evolution
- Easier testing and validation
