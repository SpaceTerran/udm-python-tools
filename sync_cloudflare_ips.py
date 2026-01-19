#!/usr/bin/env python3
"""
Sync Cloudflare IPs

Fetch the latest Cloudflare IP ranges and update the firewall group.
"""

import sys
import requests
from dotenv import load_dotenv
from unifi_client import get_client_from_env

# Load environment variables
load_dotenv()

# Cloudflare IP list URLs
CLOUDFLARE_IPV4_URL = "https://www.cloudflare.com/ips-v4"
CLOUDFLARE_IPV6_URL = "https://www.cloudflare.com/ips-v6"

# Default group ID for Cloudflare IPs
DEFAULT_CLOUDFLARE_GROUP_ID = "6831e974c8ac4702c97c400d"


def fetch_cloudflare_ips(include_ipv6: bool = False) -> list[str]:
    """
    Fetch the latest Cloudflare IP ranges from their official endpoint.

    Args:
        include_ipv6: Whether to include IPv6 ranges

    Returns:
        List of IP ranges (CIDR notation)
    """
    ips = []

    # Fetch IPv4
    try:
        response = requests.get(CLOUDFLARE_IPV4_URL, timeout=10)
        response.raise_for_status()
        ipv4_ranges = [line.strip() for line in response.text.strip().split('\n') if line.strip()]
        ips.extend(ipv4_ranges)
        print(f"✓ Fetched {len(ipv4_ranges)} IPv4 ranges from Cloudflare")
    except requests.exceptions.RequestException as e:
        print(f"✗ Failed to fetch IPv4 ranges: {e}")
        return []

    # Fetch IPv6 if requested
    if include_ipv6:
        try:
            response = requests.get(CLOUDFLARE_IPV6_URL, timeout=10)
            response.raise_for_status()
            ipv6_ranges = [line.strip() for line in response.text.strip().split('\n') if line.strip()]
            ips.extend(ipv6_ranges)
            print(f"✓ Fetched {len(ipv6_ranges)} IPv6 ranges from Cloudflare")
        except requests.exceptions.RequestException as e:
            print(f"✗ Failed to fetch IPv6 ranges: {e}")

    return ips


def main():
    """Sync Cloudflare IPs to firewall group."""
    # Parse arguments
    group_id = DEFAULT_CLOUDFLARE_GROUP_ID
    include_ipv6 = False
    dry_run = False

    for arg in sys.argv[1:]:
        if arg == "--ipv6":
            include_ipv6 = True
        elif arg == "--dry-run":
            dry_run = True
        elif arg.startswith("--group="):
            group_id = arg.split("=", 1)[1]
        elif arg in ["--help", "-h"]:
            print("Usage: python sync_cloudflare_ips.py [options]")
            print("\nOptions:")
            print("  --group=ID    Specify firewall group ID (default: cloudflare group)")
            print("  --ipv6        Include IPv6 ranges")
            print("  --dry-run     Show what would be done without making changes")
            print("  --help        Show this help message")
            sys.exit(0)

    # Fetch Cloudflare IPs
    print("\nFetching Cloudflare IP ranges...")
    cloudflare_ips = fetch_cloudflare_ips(include_ipv6)

    if not cloudflare_ips:
        print("✗ No IP ranges fetched, aborting")
        sys.exit(1)

    print(f"\nCloudflare IP ranges ({len(cloudflare_ips)}):")
    for ip in cloudflare_ips:
        print(f"  - {ip}")

    if dry_run:
        print(f"\n[DRY RUN] Would update group {group_id} with {len(cloudflare_ips)} IP ranges")
        sys.exit(0)

    # Connect to UniFi
    try:
        client = get_client_from_env()
    except ValueError as e:
        print(f"✗ Error: {e}")
        print("\nPlease create a .env file based on .env.example")
        sys.exit(1)

    if not client.login():
        sys.exit(1)

    # Get current group
    groups = client.list_firewall_groups()
    group = next((g for g in groups if g.get("_id") == group_id), None)

    if not group:
        print(f"✗ Group not found: {group_id}")
        sys.exit(1)

    current_members = set(group.get("group_members", []))
    new_members = set(cloudflare_ips)

    # Compare
    added = new_members - current_members
    removed = current_members - new_members

    if not added and not removed:
        print(f"\n✓ Group '{group.get('name')}' is already up to date")
        sys.exit(0)

    print(f"\nChanges to group '{group.get('name')}':")
    if added:
        print(f"  Added ({len(added)}):")
        for ip in sorted(added):
            print(f"    + {ip}")
    if removed:
        print(f"  Removed ({len(removed)}):")
        for ip in sorted(removed):
            print(f"    - {ip}")

    # Update the group
    print("\nUpdating group...")
    success = client.update_firewall_group(group_id, cloudflare_ips)

    if success:
        print(f"✓ Successfully synced Cloudflare IPs to group '{group.get('name')}'")
    else:
        print("✗ Failed to update group")
        sys.exit(1)


if __name__ == "__main__":
    main()
