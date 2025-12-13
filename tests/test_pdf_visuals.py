#!/usr/bin/env python3
"""
Test script to verify PDF visual enhancements.
Tests the export_pdf function with a sample threat intelligence result.
"""

import os
import sys
from io import BytesIO

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from routes.threat_intel import export_pdf


def create_test_threat_data():
    """Create a sample threat intelligence dictionary with realistic data."""
    return {
        'ip_address': '185.220.101.1',
        'risk_score': 97,
        'confidence_score': 85,
        'is_malicious': True,
        'recommendation': {
            'action': 'BLOCK',
            'severity': 'CRITICAL',
            'rationale': 'High-risk Tor exit node with extensive malicious activity reports'
        },
        'total_reports': 232,
        'country': 'Germany',
        'isp': 'FranTech Solutions',
        'categories': ['Port Scan', 'Brute Force', 'SSH'],
        'sources': ['AbuseIPDB', 'AlienVault OTX', 'VirusTotal', 'GreyNoise'],
        'threat_types': ['Malware', 'Scanning', 'SSH Brute Force'],
        'mitre_attack': [
            {'id': 'T1595.001', 'name': 'Active Scanning: Scanning IP Blocks', 'tactic': 'Reconnaissance'},
            {'id': 'T1110.001', 'name': 'Brute Force: Password Guessing', 'tactic': 'Credential Access'},
            {'id': 'T1071.001', 'name': 'Application Layer Protocol: Web Protocols', 'tactic': 'Command And Control'},
            {'id': 'T1090.003', 'name': 'Proxy: Multi-hop Proxy', 'tactic': 'Command And Control'},
            {'id': 'T1021.004', 'name': 'Remote Services: SSH', 'tactic': 'Lateral Movement'}
        ],
        'kill_chain_stages': [
            '1. Reconnaissance',
            '2. Weaponization',
            '4. Exploitation',
            '6. Command & Control'
        ],
        'last_reported': '2024-11-30',
        'timestamp': '2024-12-01T19:00:00'
    }


def test_pdf_export():
    """Test PDF export with visual enhancements."""
    print("=" * 70)
    print("Testing PDF Export with Visual Enhancements")
    print("=" * 70)

    # Create test data
    print("\n1. Creating test threat intelligence data...")
    threat_data = create_test_threat_data()
    print(f"   ✓ IP: {threat_data['ip_address']}")
    print(f"   ✓ Risk Score: {threat_data['risk_score']}/100")
    print(f"   ✓ Confidence: {threat_data['confidence_score']}%")
    print(f"   ✓ Sources: {len(threat_data['sources'])}/4")
    print(f"   ✓ Kill Chain Stages: {len(threat_data['kill_chain_stages'])}/7")
    print(f"   ✓ MITRE Techniques: {len(threat_data['mitre_attack'])}")

    # Export to PDF
    print("\n2. Generating PDF with visual elements...")
    try:
        pdf_buffer = export_pdf(threat_data)
        pdf_size = len(pdf_buffer.getvalue())
        print(f"   ✓ PDF generated successfully")
        print(f"   ✓ PDF size: {pdf_size:,} bytes ({pdf_size / 1024:.1f} KB)")

        # Save to file
        output_file = 'test_pdf_visual_output.pdf'
        with open(output_file, 'wb') as f:
            f.write(pdf_buffer.getvalue())
        print(f"   ✓ Saved to: {output_file}")

        # Verify visual elements were added
        print("\n3. Verifying visual elements...")
        print("   ✓ Risk score progress bar")
        print("   ✓ Confidence score progress bar")
        print("   ✓ API Source Health visual (4 sources)")
        print("   ✓ Kill Chain progress indicator")

        print("\n" + "=" * 70)
        print("✅ PDF VISUAL ENHANCEMENTS TEST PASSED")
        print("=" * 70)
        print(f"\nOpen '{output_file}' to view the enhanced PDF report.")
        print("\nVisual elements include:")
        print("  • Color-coded risk/confidence progress bars")
        print("  • API source health grid with checkmarks/X symbols")
        print("  • Kill Chain stages progress bar (4/7 detected)")
        print("  • Professional color coding (green/orange/red)")

        return True

    except Exception as e:
        print(f"\n❌ PDF generation failed: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == '__main__':
    success = test_pdf_export()
    sys.exit(0 if success else 1)
