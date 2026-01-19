#!/usr/bin/env python3
"""
Delete Firewall Group

Delete a firewall group by ID.
"""

import sys
from dotenv import load_dotenv
from unifi_client import get_client_from_env

# Load environment variables
load_dotenv()


def main():
    """Delete a firewall group."""
    if len(sys.argv) < 2:
        print("Usage: python delete_group.py <group_id>")
        print("\nTo get group IDs, run: python list_groups.py")
        sys.exit(1)

    group_id = sys.argv[1]

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

    # Get current group to show what we're deleting
    groups = client.list_firewall_groups()
    group = next((g for g in groups if g.get("_id") == group_id), None)

    if not group:
        print(f"✗ Group not found: {group_id}")
        sys.exit(1)

    name = group.get("name", "Unnamed")
    group_type = group.get("group_type", "unknown")
    members = group.get("group_members", [])

    print("\nGroup to delete:")
    print(f"  Name: {name}")
    print(f"  ID: {group_id}")
    print(f"  Type: {group_type}")
    print(f"  Members ({len(members)}):")
    for member in members:
        print(f"    - {member}")

    # Confirm deletion unless --force is used
    if not force:
        response = input("\nAre you sure you want to delete this group? [y/N]: ")
        if response.lower() != "y":
            print("Aborted.")
            sys.exit(0)

    print(f"\nDeleting group {group_id}...")

    # Delete the group
    success = client.delete_firewall_group(group_id)

    if success:
        print(f"✓ Successfully deleted group: {name}")
    else:
        print(f"✗ Failed to delete group: {group_id}")
        sys.exit(1)


if __name__ == "__main__":
    main()
