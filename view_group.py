#!/usr/bin/env python3
"""
View Firewall Group

View detailed information about a specific firewall group by ID.
"""

import json
import sys
from dotenv import load_dotenv
from unifi_client import get_client_from_env

# Load environment variables
load_dotenv()


def main():
    """View a specific firewall group."""
    if len(sys.argv) < 2:
        print("Usage: python view_group.py <group_id>")
        print("\nTo list groups, run: python list_groups.py")
        sys.exit(1)

    group_id = sys.argv[1]

    try:
        client = get_client_from_env()
    except ValueError as e:
        print(f"✗ Error: {e}")
        print("\nPlease create a .env file based on .env.example")
        sys.exit(1)

    # Authenticate
    if not client.login():
        sys.exit(1)

    # Get the group
    print(f"\nFetching group: {group_id}...")
    groups = client.list_firewall_groups()
    group = next((g for g in groups if g.get("_id") == group_id), None)

    if not group:
        print(f"✗ Group not found: {group_id}")
        print("\nTo list all groups, run: python list_groups.py")
        sys.exit(1)

    # Display formatted group
    print(f"\n{'='*70}")
    print("GROUP DETAILS")
    print(f"{'='*70}\n")
    
    name = group.get("name", "Unnamed")
    group_type = group.get("group_type", "unknown")
    members = group.get("group_members", [])
    
    print(f"  Name: {name}")
    print(f"  ID: {group_id}")
    print(f"  Type: {group_type}")
    print(f"  Members ({len(members)}):")
    for member in members:
        print(f"    - {member}")

    # Display full JSON for reference
    print(f"\n{'='*70}")
    print("FULL JSON DATA")
    print(f"{'='*70}\n")
    print(json.dumps(group, indent=2, default=str))


if __name__ == "__main__":
    main()
