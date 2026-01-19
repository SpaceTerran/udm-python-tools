#!/usr/bin/env python3
"""
Update DNS Record

Update a DNS record (local DNS hostname) for a client device.
"""

import sys
from dotenv import load_dotenv
from unifi_client import get_client_from_env

# Load environment variables
load_dotenv()


def main():
    """Update a DNS record."""
    if len(sys.argv) < 3:
        print("Usage: python update_dns_record.py <mac_address> <hostname>")
        print("   OR: python update_dns_record.py <mac_address> --disable")
        print("\nExamples:")
        print("  # Update hostname")
        print("  python update_dns_record.py aa:bb:cc:dd:ee:ff newhostname.local")
        print("\n  # Disable DNS record")
        print("  python update_dns_record.py aa:bb:cc:dd:ee:ff --disable")
        print("\nTo list DNS records, run: python list_dns_records.py")
        sys.exit(1)

    mac_address = sys.argv[1]
    hostname_or_flag = sys.argv[2]

    try:
        client = get_client_from_env()
    except ValueError as e:
        print(f"✗ Error: {e}")
        print("\nPlease create a .env file based on .env.example")
        sys.exit(1)

    # Authenticate
    if not client.login():
        sys.exit(1)

    # Get current DNS record to show what we're updating
    record = client.get_dns_record_by_mac(mac_address)
    if not record:
        print(f"✗ DNS record not found for MAC: {mac_address}")
        sys.exit(1)

    current_hostname = record.get("local_dns_record", "N/A")
    print("\nCurrent DNS record:")
    print(f"  MAC: {mac_address}")
    print(f"  Hostname: {current_hostname}")

    # Handle disable flag
    if hostname_or_flag == "--disable":
        print("\nDisabling DNS record...")
        success = client.update_dns_record(mac_address, enabled=False, verify=True)
        if success:
            print(f"✓ Successfully disabled and verified DNS record for {mac_address}")
        else:
            print("✗ Failed to disable DNS record")
            print("  The update may have been rejected by the API or verification failed.")
            sys.exit(1)
    else:
        # Update hostname
        new_hostname = hostname_or_flag
        print(f"\nUpdating hostname to: {new_hostname}")
        success = client.update_dns_record(mac_address, hostname=new_hostname, verify=True)

        if success:
            print(f"✓ Successfully updated and verified DNS record: {new_hostname} for {mac_address}")
        else:
            print("✗ Failed to update DNS record")
            print("  The update may have been rejected by the API or verification failed.")
            sys.exit(1)


if __name__ == "__main__":
    main()
