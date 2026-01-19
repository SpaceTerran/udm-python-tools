#!/usr/bin/env python3
"""
Create DNS Record

Create a DNS record (local DNS hostname) for a client device.
"""

import sys
from dotenv import load_dotenv
from unifi_client import get_client_from_env

# Load environment variables
load_dotenv()


def main():
    """Create a DNS record."""
    if len(sys.argv) < 3:
        print("Usage: python create_dns_record.py <mac_address> <hostname> [ip_address]")
        print("\nExamples:")
        print("  # Create DNS record only")
        print("  python create_dns_record.py aa:bb:cc:dd:ee:ff mydevice.local")
        print("\n  # Create DNS record with fixed IP")
        print("  python create_dns_record.py aa:bb:cc:dd:ee:ff mydevice.local 192.168.1.100")
        print("\nTo list clients, you may need to check the UniFi controller UI")
        sys.exit(1)

    mac_address = sys.argv[1]
    hostname = sys.argv[2]
    ip_address = sys.argv[3] if len(sys.argv) > 3 else None

    try:
        client = get_client_from_env()
    except ValueError as e:
        print(f"✗ Error: {e}")
        print("\nPlease create a .env file based on .env.example")
        sys.exit(1)

    # Authenticate
    if not client.login():
        sys.exit(1)

    print("\nCreating DNS record:")
    print(f"  MAC Address: {mac_address}")
    print(f"  Hostname: {hostname}")
    if ip_address:
        print(f"  Fixed IP: {ip_address}")

    # Create the DNS record
    success = client.create_dns_record(mac_address, hostname, ip_address)

    if success:
        print(f"\n✓ Successfully created DNS record: {hostname} for {mac_address}")
    else:
        print("\n✗ Failed to create DNS record")
        print("  Make sure the MAC address is correct and the client exists")
        sys.exit(1)


if __name__ == "__main__":
    main()
