#!/usr/bin/env python3
"""
Update Static DNS Record

Update a static DNS record with JSON data.
"""

import json
import sys
from dotenv import load_dotenv
from unifi_client import get_client_from_env

# Load environment variables
load_dotenv()


def main():
    """Update a static DNS record."""
    if len(sys.argv) < 3:
        print("Usage: python update_policy_dns_record.py <record_id> <json_file>")
        print("   OR: python update_policy_dns_record.py <record_id> '<json_string>'")
        print("\nExamples:")
        print("  # Update from JSON file")
        print("  python update_policy_dns_record.py 6831f9f5c8ac4702c97c5e1e updates.json")
        print("\n  # Update with inline JSON")
        print('  python update_policy_dns_record.py 6831f9f5c8ac4702c97c5e1e \'{"enabled": false}\'')
        print("\n  # Update value (IP address)")
        print('  python update_policy_dns_record.py 6831f9f5c8ac4702c97c5e1e \'{"value": "192.168.1.200"}\'')
        print("\n  # Update domain")
        print('  python update_policy_dns_record.py 6831f9f5c8ac4702c97c5e1e \'{"key": "newname.example.com"}\'')
        print("\nTo get record IDs, run: python list_policy_dns_records.py")
        sys.exit(1)

    record_id = sys.argv[1]
    json_input = sys.argv[2]

    try:
        client = get_client_from_env()
    except ValueError as e:
        print(f"✗ Error: {e}")
        print("\nPlease create a .env file based on .env.example")
        sys.exit(1)

    # Authenticate
    if not client.login():
        sys.exit(1)

    # Get current record to show what we're updating
    record = client.get_static_dns_record_by_id(record_id)
    if not record:
        print(f"✗ Record not found: {record_id}")
        sys.exit(1)

    print(f"\nCurrent record: {record.get('key', 'Unnamed')}")
    print(f"  Type: {record.get('record_type', 'A')}")
    print(f"  Value: {record.get('value', 'N/A')}")
    print(f"  TTL: {'Auto' if record.get('ttl', 0) == 0 else record.get('ttl')}")
    print(f"  Enabled: {record.get('enabled', True)}")

    # Parse JSON input
    try:
        if json_input.startswith("{") or json_input.startswith("["):
            # Inline JSON string
            update_data = json.loads(json_input)
        else:
            # JSON file
            with open(json_input, "r") as f:
                update_data = json.load(f)
    except FileNotFoundError:
        print(f"✗ File not found: {json_input}")
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"✗ Invalid JSON: {e}")
        sys.exit(1)

    print("\nUpdating with:")
    print(json.dumps(update_data, indent=2))

    # Update the record (with verification enabled by default)
    success = client.update_static_dns_record(record_id, update_data, verify=True)

    if success:
        print(f"\n✓ Successfully updated and verified DNS record: {record.get('key', record_id)}")
    else:
        print(f"\n✗ Failed to update DNS record: {record_id}")
        print("  The update may have been rejected by the API or verification failed.")
        sys.exit(1)


if __name__ == "__main__":
    main()
