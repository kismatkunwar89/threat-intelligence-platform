#!/usr/bin/env python3
"""
Download MITRE ATT&CK Enterprise Data.

This script downloads the latest MITRE ATT&CK Enterprise framework data
from the official GitHub repository and saves it for offline use.

Run this script once during setup or periodically (every 6-12 months) to
update to the latest ATT&CK techniques.

Usage:
    python scripts/download_mitre_data.py

Requirements:
    - Internet connection
    - requests library (pip install requests)
"""

import requests
import json
import os
import sys
from pathlib import Path


def download_mitre_attack_data():
    """Download MITRE ATT&CK Enterprise data from official GitHub."""

    # URL to official MITRE CTI repository
    url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"

    # Determine output path (project root)
    script_dir = Path(__file__).parent
    project_root = script_dir.parent
    output_file = project_root / "enterprise-attack.json"

    print("="*70)
    print("MITRE ATT&CK Enterprise Data Downloader")
    print("="*70)
    print(f"\nSource: {url}")
    print(f"Destination: {output_file}")
    print("\nDownloading... (this may take 30-60 seconds)")

    try:
        # Download with timeout
        response = requests.get(url, timeout=120)
        response.raise_for_status()

        # Parse JSON to validate
        data = response.json()

        # Save to file
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2)

        # Display statistics
        file_size_mb = len(response.content) / 1024 / 1024
        object_count = len(data.get('objects', []))

        print(f"\n✅ Download successful!")
        print(f"   File size: {file_size_mb:.1f} MB")
        print(f"   Objects: {object_count:,}")
        print(f"   Saved to: {output_file}")

        # Count techniques
        techniques = [obj for obj in data.get('objects', [])
                     if obj.get('type') == 'attack-pattern']
        print(f"   Techniques: {len(techniques)}")

        print("\n" + "="*70)
        print("✅ MITRE ATT&CK data ready for use!")
        print("="*70)

        return 0

    except requests.exceptions.Timeout:
        print("\n❌ Error: Download timed out. Please check your internet connection.")
        return 1

    except requests.exceptions.RequestException as e:
        print(f"\n❌ Error downloading data: {e}")
        return 1

    except json.JSONDecodeError as e:
        print(f"\n❌ Error: Downloaded file is not valid JSON: {e}")
        return 1

    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(download_mitre_attack_data())
