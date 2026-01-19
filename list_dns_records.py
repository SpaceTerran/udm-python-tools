#!/usr/bin/env python3
"""
List DNS Records

Lists all clients with DNS records (local DNS hostnames) from UniFi UDM Pro.
"""

import sys
from dotenv import load_dotenv
from unifi_client import get_client_from_env

# Load environment variables
load_dotenv()


def main():
    """List all DNS records."""
    # Check for optional hostname filter
    hostname_filter = None
    if len(sys.argv) > 1:
        hostname_filter = sys.argv[1].lower()

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
    all_records = client.list_dns_records()

    if not all_records:
        print("  No DNS records found.")
        return

    # Filter by hostname if specified
    if hostname_filter:
        all_records = [
            r
            for r in all_records
            if hostname_filter in r.get("local_dns_record", "").lower()
        ]
        if not all_records:
            print(f"  No DNS records matching '{hostname_filter}' found.")
            return

    print(f"\n{'='*70}")
    print(f"DNS RECORDS: {len(all_records)} total")
    print(f"{'='*70}\n")

    for record in all_records:
        mac = record.get("mac", "N/A")
        name = record.get("name", record.get("hostname", "Unnamed"))
        hostname = record.get("local_dns_record", "N/A")
        ip = record.get("ip", "N/A")
        fixed_ip = record.get("fixed_ip", "")

        print(f"Name: {name}")
        print(f"  MAC: {mac}")
        print(f"  Hostname: {hostname}")
        print(f"  IP: {ip}")
        if fixed_ip:
            print(f"  Fixed IP: {fixed_ip}")
        print("-" * 70)

    print(f"\n{'='*70}")
    print(f"Total DNS records: {len(all_records)}")
    print(f"{'='*70}")


if __name__ == "__main__":
    main()
