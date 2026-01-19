#!/usr/bin/env python3
"""
View DNS Record

View detailed information about a specific DNS record by MAC address.
"""

import json
import sys
from dotenv import load_dotenv
from unifi_client import get_client_from_env

# Load environment variables
load_dotenv()


def main():
    """View a specific DNS record."""
    if len(sys.argv) < 2:
        print("Usage: python view_dns_record.py <mac_address>")
        print("\nTo list DNS records, run: python list_dns_records.py")
        sys.exit(1)

    mac_address = sys.argv[1]

    try:
        client = get_client_from_env()
    except ValueError as e:
        print(f"✗ Error: {e}")
        print("\nPlease create a .env file based on .env.example")
        sys.exit(1)

    # Authenticate
    if not client.login():
        sys.exit(1)

    # Get the DNS record
    print(f"\nFetching DNS record for MAC: {mac_address}...")
    record = client.get_dns_record_by_mac(mac_address)

    if not record:
        print(f"✗ DNS record not found for MAC: {mac_address}")
        print("\nTo list all DNS records, run: python list_dns_records.py")
        sys.exit(1)

    # Display formatted record
    print(f"\n{'='*70}")
    print("DNS RECORD DETAILS")
    print(f"{'='*70}\n")

    name = record.get("name", record.get("hostname", "Unnamed"))
    mac = record.get("mac", "N/A")
    hostname = record.get("local_dns_record", "N/A")
    ip = record.get("ip", "N/A")
    fixed_ip = record.get("fixed_ip", "")
    enabled = "✓ Enabled" if record.get("local_dns_record_enabled", False) else "✗ Disabled"

    print(f"  Name: {name}")
    print(f"  MAC: {mac}")
    print(f"  Hostname: {hostname}")
    print(f"  Status: {enabled}")
    print(f"  IP: {ip}")
    if fixed_ip:
        print(f"  Fixed IP: {fixed_ip}")

    # Display full JSON for reference
    print(f"\n{'='*70}")
    print("FULL JSON DATA")
    print(f"{'='*70}\n")
    print(json.dumps(record, indent=2, default=str))


if __name__ == "__main__":
    main()
