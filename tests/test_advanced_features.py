"""
Test advanced Python features: Generators, Iterators, and Functional Programming.

This test file demonstrates the usage of advanced Python concepts implemented
in the utils/ip_validator.py module.
"""

import sys
sys.path.insert(0, '/home/kismat/pythonfinalproject')

from utils.ip_validator import (
    validate_ip_batch_functional,
    validate_ip_stream,
    normalize_ip_stream,
    IPRangeIterator,
    filter_ips_by_type,
    map_ip_to_info
)


def test_functional_programming():
    """Test functional programming with filter and lambda."""
    print("\n" + "="*70)
    print("Testing Functional Programming (filter + lambda)")
    print("="*70)

    test_ips = ['192.168.1.1', 'invalid_ip', '8.8.8.8', 'bad', '1.1.1.1']

    valid, invalid = validate_ip_batch_functional(test_ips)

    print(f"Input IPs: {test_ips}")
    print(f"Valid IPs (using filter + lambda): {valid}")
    print(f"Invalid IPs: {invalid}")
    print(f"Total: {len(valid)} valid, {len(invalid)} invalid")


def test_generator():
    """Test generator for memory-efficient IP validation."""
    print("\n" + "="*70)
    print("Testing Generator Functions (yield)")
    print("="*70)

    test_ips = ['192.168.1.1', 'invalid', '8.8.8.8', '10.0.0.1', 'bad_ip', '1.1.1.1']

    print(f"Input IPs: {test_ips}")
    print("\nGenerator yielding valid IPs one at a time:")

    for ip in validate_ip_stream(test_ips):
        print(f"  - Yielded: {ip}")

    print("\nNormalize IP stream (generator):")
    normalized = list(normalize_ip_stream(['  192.168.1.1  ', '8.8.8.8', 'invalid']))
    print(f"  Normalized IPs: {normalized}")


def test_iterator():
    """Test custom iterator for IP range generation."""
    print("\n" + "="*70)
    print("Testing Custom Iterator (__iter__ and __next__)")
    print("="*70)

    start_ip = '192.168.1.1'
    count = 10

    print(f"Generating {count} sequential IPs starting from {start_ip}:")

    ip_range = IPRangeIterator(start_ip, count)
    for ip in ip_range:
        print(f"  - {ip}")


def test_filter_with_lambda():
    """Test filtering IPs by type using lambda."""
    print("\n" + "="*70)
    print("Testing filter_ips_by_type (lambda + filter)")
    print("="*70)

    test_ips = ['192.168.1.1', '8.8.8.8', '10.0.0.1', '1.1.1.1', '172.16.0.1']

    print(f"Input IPs: {test_ips}")

    public_ips = filter_ips_by_type(test_ips, 'public')
    print(f"\nPublic IPs (using lambda filter): {public_ips}")

    private_ips = filter_ips_by_type(test_ips, 'private')
    print(f"Private IPs (using lambda filter): {private_ips}")


def test_map_function():
    """Test map() for transforming IP data."""
    print("\n" + "="*70)
    print("Testing map() Function for Data Transformation")
    print("="*70)

    test_ips = ['8.8.8.8', '1.1.1.1', '192.168.1.1']

    print(f"Input IPs: {test_ips}")
    print("\nMapping IPs to detailed information using map():")

    info_list = map_ip_to_info(test_ips)

    for info in info_list:
        print(f"\n  IP: {info.get('address')}")
        print(f"    Version: IPv{info.get('version', 'N/A')}")
        print(f"    Is Private: {info.get('is_private', 'N/A')}")
        print(f"    Is Global: {info.get('is_global', 'N/A')}")


def main():
    """Run all tests."""
    print("\n" + "="*70)
    print("ADVANCED PYTHON FEATURES DEMONSTRATION")
    print("Generators, Iterators, and Functional Programming")
    print("="*70)

    try:
        test_functional_programming()
        test_generator()
        test_iterator()
        test_filter_with_lambda()
        test_map_function()

        print("\n" + "="*70)
        print("ALL TESTS COMPLETED SUCCESSFULLY")
        print("="*70)
        print("\nSummary of Python Features Demonstrated:")
        print("  1. Functional Programming: filter() and lambda functions")
        print("  2. Generators: yield keyword for memory-efficient iteration")
        print("  3. Iterators: Custom __iter__() and __next__() implementation")
        print("  4. map(): Transforming data with functional programming")
        print("="*70 + "\n")

    except Exception as e:
        print(f"\nERROR: {e}")
        import traceback
        traceback.print_exc()


if __name__ == '__main__':
    main()
