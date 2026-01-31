#!/usr/bin/env python3
"""
View Static DNS Record

View a single DNS record by domain name or ID.
"""

import json
import sys
from dotenv import load_dotenv
from unifi_client import get_client_from_env

# Load environment variables
load_dotenv()


def main():
    """View a static DNS record by domain or ID."""
    if len(sys.argv) < 2:
        print("Usage: python view_policy_dns_record.py <domain_or_id>")
        print("\nExamples:")
        print("  python view_policy_dns_record.py scrypted.spaceterran.com")
        print("  python view_policy_dns_record.py spaceterran.com")
        print("  python view_policy_dns_record.py 6823f784c8ac4702c96adceb")
        print("\nTo list records, run: python list_policy_dns_records.py [filter]")
        sys.exit(1)

    key = sys.argv[1].strip()

    try:
        client = get_client_from_env()
    except ValueError as e:
        print(f"✗ Error: {e}")
        print("\nPlease create a .env file based on .env.example")
        sys.exit(1)

    if not client.login():
        sys.exit(1)

    print(f"\nLooking up DNS record: {key}...")

    # Try to find by ID first (24-char hex string), otherwise by domain
    if key.replace("-", "").isalnum() and len(key) == 24:
        record = client.get_static_dns_record_by_id(key)
    else:
        record = client.get_static_dns_record_by_domain(key)

    if not record:
        print(f"✗ No DNS record found for: {key}")
        print("\nTo list records, run: python list_policy_dns_records.py")
        sys.exit(1)

    print(f"\n{'='*70}")
    print("DNS RECORD")
    print(f"{'='*70}\n")
    print(f"  Domain:      {record.get('key', 'N/A')}")
    print(f"  ID:          {record.get('_id', 'N/A')}")
    print(f"  Type:        {record.get('record_type', 'A')}")
    print(f"  Value:       {record.get('value', 'N/A')}")
    print(f"  TTL:         {'Auto' if record.get('ttl', 0) == 0 else record.get('ttl')}")
    print(f"  Enabled:     {'Yes' if record.get('enabled', True) else 'No'}")
    if record.get("priority"):
        print(f"  Priority:    {record.get('priority')}")
    if record.get("weight"):
        print(f"  Weight:      {record.get('weight')}")
    if record.get("port"):
        print(f"  Port:        {record.get('port')}")
    print(f"\n{'='*70}")
    print("RAW (from API)")
    print(f"{'='*70}\n")
    print(json.dumps(record, indent=2, default=str))


if __name__ == "__main__":
    main()
