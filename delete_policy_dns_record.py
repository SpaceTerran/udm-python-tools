#!/usr/bin/env python3
"""
Delete Static DNS Record

Delete a static DNS record by ID.
"""

import sys
from dotenv import load_dotenv
from unifi_client import get_client_from_env

# Load environment variables
load_dotenv()


def main():
    """Delete a static DNS record."""
    if len(sys.argv) < 2:
        print("Usage: python delete_policy_dns_record.py <record_id>")
        print("\nTo get record IDs, run: python list_policy_dns_records.py")
        sys.exit(1)

    record_id = sys.argv[1]

    # Check for --force flag
    force = "--force" in sys.argv

    try:
        client = get_client_from_env()
    except ValueError as e:
        print(f"✗ Error: {e}")
        print("\nPlease create a .env file based on .env.example")
        sys.exit(1)

    # Authenticate
    if not client.login():
        sys.exit(1)

    # Get current record to show what we're deleting
    record = client.get_static_dns_record_by_id(record_id)
    if not record:
        print(f"✗ Record not found: {record_id}")
        sys.exit(1)

    domain = record.get("key", "Unnamed")
    record_type = record.get("record_type", "A")
    value = record.get("value", "N/A")

    print("\nDNS record to delete:")
    print(f"  Domain: {domain}")
    print(f"  ID: {record_id}")
    print(f"  Type: {record_type}")
    print(f"  Value: {value}")

    # Confirm deletion unless --force is used
    if not force:
        response = input("\nAre you sure you want to delete this DNS record? [y/N]: ")
        if response.lower() != "y":
            print("Aborted.")
            sys.exit(0)

    print(f"\nDeleting DNS record {record_id}...")

    # Delete the record
    success = client.delete_static_dns_record(record_id)

    if success:
        print(f"✓ Successfully deleted DNS record: {domain}")
    else:
        print(f"✗ Failed to delete DNS record: {record_id}")
        sys.exit(1)


if __name__ == "__main__":
    main()
