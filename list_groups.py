#!/usr/bin/env python3
"""
List Firewall Groups

Lists all firewall groups (IP/port groups) from UniFi UDM Pro.
"""

import sys
from dotenv import load_dotenv
from unifi_client import get_client_from_env

# Load environment variables
load_dotenv()


def main():
    """List all firewall groups."""
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

    # List all groups
    print("\nFetching firewall groups...")
    all_groups = client.list_firewall_groups()

    if not all_groups:
        print("  No firewall groups found.")
        return

    # Filter by name if specified
    if name_filter:
        all_groups = [g for g in all_groups if name_filter in g.get("name", "").lower()]
        if not all_groups:
            print(f"  No groups matching '{name_filter}' found.")
            return

    print(f"\n{'='*70}")
    print(f"FIREWALL GROUPS: {len(all_groups)} total")
    print(f"{'='*70}\n")

    for group in all_groups:
        group_id = group.get("_id", "N/A")
        name = group.get("name", "Unnamed")
        group_type = group.get("group_type", "unknown")
        members = group.get("group_members", [])

        print(f"Name: {name}")
        print(f"  ID: {group_id}")
        print(f"  Type: {group_type}")
        print(f"  Members ({len(members)}):")
        for member in members:
            print(f"    - {member}")
        print("-" * 70)

    print(f"\n{'='*70}")
    print(f"Total groups: {len(all_groups)}")
    print(f"{'='*70}")


if __name__ == "__main__":
    main()
