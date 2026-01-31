#!/usr/bin/env python3
"""
List Static DNS Records

Lists all static DNS records from UniFi controller.
"""

import sys
from dotenv import load_dotenv
from unifi_client import get_client_from_env

# Load environment variables
load_dotenv()


def main():
    """List all static DNS records."""
    # Check for optional name filter
    name_filter = None
    if len(sys.argv) > 1:
        name_filter = sys.argv[1].lower()

    try:
        client = get_client_from_env()
    except ValueError as e:
        print(f"✗ Error: {e}")
        print("\nPlease create a .env file based on .env.example")
        sys.exit(1)

    # Authenticate
    if not client.login():
        sys.exit(1)

    # List all DNS records
    print("\nFetching DNS records...")
    all_records = client.list_static_dns_records()

    if not all_records:
        print("  No DNS records found.")
        return

    # Filter by domain if specified
    if name_filter:
        all_records = [r for r in all_records if name_filter in r.get("key", "").lower()]
        if not all_records:
            print(f"  No records matching '{name_filter}' found.")
            return

    print(f"\n{'='*70}")
    print(f"DNS RECORDS: {len(all_records)} total")
    print(f"{'='*70}\n")

    for record in all_records:
        record_id = record.get("_id", "N/A")
        domain = record.get("key", "N/A")
        enabled = "✓ Enabled" if record.get("enabled", True) else "✗ Disabled"
        record_type = record.get("record_type", "A")
        value = record.get("value", "N/A")
        ttl = record.get("ttl", 0)
        ttl_display = "Auto" if ttl == 0 else f"{ttl}s"

        print(f"Domain: {domain}")
        print(f"  ID: {record_id}")
        print(f"  Status: {enabled}")
        print(f"  Type: {record_type}")
        print(f"  Value: {value}")
        print(f"  TTL: {ttl_display}")
        if record.get("priority"):
            print(f"  Priority: {record.get('priority')}")
        if record.get("weight"):
            print(f"  Weight: {record.get('weight')}")
        if record.get("port"):
            print(f"  Port: {record.get('port')}")
        print("-" * 70)

    print(f"\n{'='*70}")
    print(f"Total records: {len(all_records)}")
    print(f"{'='*70}")


if __name__ == "__main__":
    main()
