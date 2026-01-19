#!/usr/bin/env python3
"""
Update Firewall Group

Update a firewall group's members (IP addresses or ports).
"""

import sys
from dotenv import load_dotenv
from unifi_client import get_client_from_env

# Load environment variables
load_dotenv()


def main():
    """Update a firewall group."""
    if len(sys.argv) < 3:
        print("Usage: python update_group.py <group_id> <action> [members...]")
        print("\nActions:")
        print("  set <members...>    - Replace all members with new list")
        print("  add <members...>    - Add members to existing list")
        print("  remove <members...> - Remove members from existing list")
        print("\nExamples:")
        print("  # Replace all members")
        print("  python update_group.py 6831e974c8ac4702c97c400d set 1.1.1.0/24 2.2.2.0/24")
        print("\n  # Add new members")
        print("  python update_group.py 6831e974c8ac4702c97c400d add 3.3.3.0/24")
        print("\n  # Remove members")
        print("  python update_group.py 6831e974c8ac4702c97c400d remove 1.1.1.0/24")
        print("\nTo list groups, run: python list_groups.py")
        sys.exit(1)

    group_id = sys.argv[1]
    action = sys.argv[2].lower()
    new_members = sys.argv[3:] if len(sys.argv) > 3 else []

    if action not in ["set", "add", "remove"]:
        print(f"✗ Invalid action: {action}")
        print("Valid actions: set, add, remove")
        sys.exit(1)

    if not new_members and action != "set":
        print(f"✗ No members specified for {action} action")
        sys.exit(1)

    try:
        client = get_client_from_env()
    except ValueError as e:
        print(f"✗ Error: {e}")
        print("\nPlease create a .env file based on .env.example")
        sys.exit(1)

    # Authenticate
    if not client.login():
        sys.exit(1)

    # Get current group
    groups = client.list_firewall_groups()
    group = next((g for g in groups if g.get("_id") == group_id), None)

    if not group:
        print(f"✗ Group not found: {group_id}")
        sys.exit(1)

    current_members = group.get("group_members", [])
    print(f"\nCurrent group: {group.get('name', 'Unnamed')}")
    print(f"Current members ({len(current_members)}):")
    for member in current_members:
        print(f"  - {member}")

    # Calculate new members based on action
    if action == "set":
        final_members = new_members
    elif action == "add":
        final_members = list(set(current_members + new_members))
    elif action == "remove":
        final_members = [m for m in current_members if m not in new_members]

    print(f"\nNew members ({len(final_members)}):")
    for member in final_members:
        print(f"  - {member}")

    print("\nUpdating group...")

    # Update the group (with verification enabled by default)
    success = client.update_firewall_group(group_id, final_members, verify=True)

    if success:
        print(f"✓ Successfully updated and verified group: {group.get('name', group_id)}")
    else:
        print(f"✗ Failed to update group: {group_id}")
        print("  The update may have been rejected by the API or verification failed.")
        sys.exit(1)


if __name__ == "__main__":
    main()
