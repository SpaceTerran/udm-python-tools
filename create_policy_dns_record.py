#!/usr/bin/env python3
"""
Create Static DNS Record

Create a new static DNS record. Can be created from JSON file
or via command-line arguments.
"""

import json
import sys
from dotenv import load_dotenv
from unifi_client import get_client_from_env

# Load environment variables
load_dotenv()


def main():
    """Create a static DNS record."""
    if len(sys.argv) < 2:
        print("Usage: python create_policy_dns_record.py <record_json_file>")
        print("   OR: python create_policy_dns_record.py --simple <domain> <value> [type] [ttl]")
        print("\nExamples:")
        print("  # Create simple A record (type defaults to A, TTL defaults to Auto)")
        print("  python create_policy_dns_record.py --simple myserver.example.com 192.168.1.100")
        print("\n  # Create with specific record type")
        print("  python create_policy_dns_record.py --simple myserver.example.com 192.168.1.100 A")
        print("\n  # Create with TTL")
        print("  python create_policy_dns_record.py --simple myserver.example.com 192.168.1.100 A 300")
        print("\n  # Create from JSON file")
        print("  python create_policy_dns_record.py record.json")
        print("\nJSON file format:")
        print('  {')
        print('    "key": "myserver.example.com",')
        print('    "value": "192.168.1.100",')
        print('    "record_type": "A",  # A, AAAA, CNAME, MX, SRV, TXT')
        print('    "ttl": 0,  # 0 = Auto')
        print('    "enabled": true,')
        print('    "priority": 0,  # for MX/SRV')
        print('    "weight": 0,  # for SRV')
        print('    "port": 0  # for SRV')
        print('  }')
        sys.exit(1)

    try:
        client = get_client_from_env()
    except ValueError as e:
        print(f"✗ Error: {e}")
        print("\nPlease create a .env file based on .env.example")
        sys.exit(1)

    # Authenticate
    if not client.login():
        sys.exit(1)

    # Handle command-line quick-create option
    if sys.argv[1] == "--simple":
        if len(sys.argv) < 4:
            print("✗ Error: --simple requires domain and value")
            print("Usage: python create_policy_dns_record.py --simple <domain> <value> [type] [ttl]")
            sys.exit(1)

        domain = sys.argv[2]
        value = sys.argv[3]
        record_type = sys.argv[4].upper() if len(sys.argv) > 4 else "A"
        ttl = int(sys.argv[5]) if len(sys.argv) > 5 else 0

        # Validate record type
        valid_types = ["A", "AAAA", "CNAME", "MX", "SRV", "TXT"]
        if record_type not in valid_types:
            print(f"✗ Invalid record type: {record_type}. Must be one of: {', '.join(valid_types)}")
            sys.exit(1)

        record_data = {
            "key": domain,
            "value": value,
            "record_type": record_type,
            "ttl": ttl,
            "enabled": True,
        }
    else:
        # Load from JSON file
        try:
            with open(sys.argv[1], "r") as f:
                record_data = json.load(f)
        except FileNotFoundError:
            print(f"✗ File not found: {sys.argv[1]}")
            sys.exit(1)
        except json.JSONDecodeError as e:
            print(f"✗ Invalid JSON: {e}")
            sys.exit(1)

    # Validate required fields
    required_fields = ["key", "value"]
    missing = [f for f in required_fields if f not in record_data]
    if missing:
        print(f"✗ Error: Missing required fields: {', '.join(missing)}")
        sys.exit(1)

    print(f"\nCreating DNS record: {record_data.get('key', 'Unnamed')}")
    print(f"  Type: {record_data.get('record_type', 'A')}")
    print(f"  Value: {record_data.get('value')}")
    print(f"  TTL: {'Auto' if record_data.get('ttl', 0) == 0 else record_data.get('ttl')}")

    # Create the record
    result = client.create_static_dns_record(record_data)

    if result:
        record_id = result.get("_id") if isinstance(result, dict) else None
        if record_id:
            print(f"\n✓ Successfully created DNS record with ID: {record_id}")
            print("\nRecord details:")
            print(f"  Domain: {record_data['key']}")
            print(f"  ID: {record_id}")
            print(f"  Type: {record_data.get('record_type', 'A')}")
            print(f"  Value: {record_data['value']}")
        else:
            print(f"\n✓ DNS record created (response: {result})")
    else:
        print("\n✗ Failed to create DNS record")
        sys.exit(1)


if __name__ == "__main__":
    main()
