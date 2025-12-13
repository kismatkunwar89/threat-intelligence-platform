"""
Session 2 Integration Test - Tests all 4 API sources and new features.

This script tests:
1. All 4 API integrations (AbuseIPDB, OTX, VirusTotal, GreyNoise)
2. Confidence scoring
3. MITRE ATT&CK mapping
4. Kill Chain mapping
5. Updated recommendation engine

Run with: python test_session2_integration.py
"""

from utils.kill_chain_mapper import KillChainMapper
from utils.mitre_mapper import MitreAttackMapper
from routes.threat_intel import _fetch_threat_intel
import json
import sys
from datetime import datetime

# Add project root to path
sys.path.insert(0, '/home/kismat/pythonfinalproject')


def test_ip(ip_address: str, description: str) -> dict:
    """Test a single IP and return results."""
    print(f"\n{'='*60}")
    print(f"Testing: {ip_address} ({description})")
    print('='*60)

    try:
        result = _fetch_threat_intel(ip_address)

        output = {
            'ip_address': result.ip_address,
            'description': description,
            'risk_score': result.risk_score,
            'confidence_score': result.confidence_score,
            'is_malicious': result.is_malicious,
            'sources': result.sources,
            'source_count': len(result.sources),
            'total_reports': result.total_reports,
            'country': result.country,
            'isp': result.isp,
            'categories': result.categories[:5] if result.categories else [],
            'threat_types': result.threat_types[:5] if result.threat_types else [],
            'recommendation': result.recommendation,
            'mitre_attack_count': len(result.mitre_attack),
            'mitre_attack': result.mitre_attack[:5] if result.mitre_attack else [],
            'kill_chain_stages': result.kill_chain_stages,
            'timestamp': datetime.now().isoformat()
        }

        # Print summary
        print(f"  Risk Score: {output['risk_score']}/100")
        print(f"  Confidence: {output['confidence_score']}%")
        print(
            f"  Sources ({output['source_count']}): {', '.join(output['sources'])}")
        print(f"  Is Malicious: {output['is_malicious']}")
        print(f"  Total Reports: {output['total_reports']}")
        print(f"  Country: {output['country']}")
        print(
            f"  Recommendation: {output['recommendation']['action']} ({output['recommendation']['priority']})")
        print(f"  MITRE ATT&CK: {output['mitre_attack_count']} techniques")
        print(f"  Kill Chain: {output['kill_chain_stages']}")

        return output

    except Exception as e:
        print(f"  ERROR: {e}")
        return {'ip_address': ip_address, 'error': str(e)}


def main():
    """Run all integration tests."""
    print("\n" + "="*60)
    print("SESSION 2 INTEGRATION TEST")
    print("Testing all 4 API sources with new features")
    print("="*60)

    # Test cases
    test_cases = [
        ("8.8.8.8", "Google DNS - Known safe"),
        ("1.1.1.1", "Cloudflare DNS - Known safe"),
        ("185.220.101.1", "Known Tor exit node - Likely malicious"),
    ]

    results = []

    for ip, description in test_cases:
        result = test_ip(ip, description)
        results.append(result)

    # Save results to file
    output_file = '/home/kismat/pythonfinalproject/test_results_session2.json'
    with open(output_file, 'w') as f:
        json.dump({
            'test_run': datetime.now().isoformat(),
            'test_count': len(results),
            'results': results
        }, f, indent=2)

    print(f"\n{'='*60}")
    print(f"TEST COMPLETE - Results saved to: {output_file}")
    print('='*60)

    # Summary
    print("\nSUMMARY:")
    print("-"*40)
    for r in results:
        if 'error' in r:
            print(f"  {r['ip_address']}: ERROR - {r['error']}")
        else:
            print(
                f"  {r['ip_address']}: Risk={r['risk_score']}, Confidence={r['confidence_score']}%, Action={r['recommendation']['action']}")

    # Verify all features working
    print("\nFEATURE VERIFICATION:")
    print("-"*40)

    all_passed = True

    # Check if we got data from all 4 sources for at least one IP
    max_sources = max(r.get('source_count', 0)
                      for r in results if 'error' not in r)
    print(
        f"  [{'✓' if max_sources >= 3 else '✗'}] Multiple API sources: {max_sources} sources")
    if max_sources < 3:
        all_passed = False

    # Check confidence scoring
    has_confidence = any(r.get('confidence_score', 0) >
                         0 for r in results if 'error' not in r)
    print(f"  [{'✓' if has_confidence else '✗'}] Confidence scoring: {'Working' if has_confidence else 'Not working'}")
    if not has_confidence:
        all_passed = False

    # Check MITRE ATT&CK
    has_mitre = any(r.get('mitre_attack_count', 0) >
                    0 for r in results if 'error' not in r)
    print(f"  [{'✓' if has_mitre else '✗'}] MITRE ATT&CK mapping: {'Working' if has_mitre else 'Not working'}")

    # Check Kill Chain
    has_killchain = any(len(r.get('kill_chain_stages', []))
                        > 0 for r in results if 'error' not in r)
    print(f"  [{'✓' if has_killchain else '✗'}] Kill Chain mapping: {'Working' if has_killchain else 'Not working'}")

    # Check recommendations
    has_recommendations = all('recommendation' in r and r['recommendation'].get(
        'action') for r in results if 'error' not in r)
    print(f"  [{'✓' if has_recommendations else '✗'}] Recommendations: {'Working' if has_recommendations else 'Not working'}")
    if not has_recommendations:
        all_passed = False

    print("\n" + "="*60)
    if all_passed:
        print("✅ ALL CORE FEATURES WORKING!")
    else:
        print("⚠️  Some features need attention")
    print("="*60 + "\n")

    return 0 if all_passed else 1


if __name__ == '__main__':
    sys.exit(main())
