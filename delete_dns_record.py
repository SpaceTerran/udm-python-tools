#!/usr/bin/env python3
"""
Delete DNS Record

Delete a DNS record (disable local DNS) for a client device.
"""

import sys
from dotenv import load_dotenv
from unifi_client import get_client_from_env

# Load environment variables
load_dotenv()


def main():
    """Delete a DNS record."""
    if len(sys.argv) < 2:
        print("Usage: python delete_dns_record.py <mac_address>")
        print("\nTo get MAC addresses, run: python list_dns_records.py")
        sys.exit(1)

    mac_address = sys.argv[1]

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

    # Get current DNS record to show what we're deleting
    record = client.get_dns_record_by_mac(mac_address)
    if not record:
        print(f"✗ DNS record not found for MAC: {mac_address}")
        sys.exit(1)

    name = record.get("name", record.get("hostname", "Unnamed"))
    hostname = record.get("local_dns_record", "N/A")

    print("\nDNS record to delete:")
    print(f"  Name: {name}")
    print(f"  MAC: {mac_address}")
    print(f"  Hostname: {hostname}")

    # Confirm deletion unless --force is used
    if not force:
        response = input("\nAre you sure you want to delete this DNS record? [y/N]: ")
        if response.lower() != "y":
            print("Aborted.")
            sys.exit(0)

    print(f"\nDeleting DNS record for {mac_address}...")

    # Delete the DNS record
    success = client.delete_dns_record(mac_address)

    if success:
        print(f"✓ Successfully deleted DNS record: {hostname}")
    else:
        print(f"✗ Failed to delete DNS record: {mac_address}")
        sys.exit(1)


if __name__ == "__main__":
    main()
