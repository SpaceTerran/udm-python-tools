#!/usr/bin/env python3
"""
Delete Firewall Policy

Delete a firewall policy by ID.
"""

import sys
from dotenv import load_dotenv
from unifi_client import get_client_from_env

# Load environment variables
load_dotenv()


def main():
    """Delete a firewall policy."""
    if len(sys.argv) < 2:
        print("Usage: python delete_policy.py <policy_id>")
        print("\nTo get policy IDs, run: python list_policies.py")
        sys.exit(1)

    policy_id = sys.argv[1]

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

    # Get current policy to show what we're deleting
    policy = client.get_policy_by_id(policy_id)
    if not policy:
        print(f"✗ Policy not found: {policy_id}")
        sys.exit(1)

    print("\nPolicy to delete:")
    print(client.format_policy(policy))

    # Confirm deletion unless --force is used
    if not force:
        response = input("\nAre you sure you want to delete this policy? [y/N]: ")
        if response.lower() != 'y':
            print("Aborted.")
            sys.exit(0)

    print(f"\nDeleting policy {policy_id}...")

    # Delete the policy
    success = client.delete_policy(policy_id)

    if success:
        print(f"✓ Successfully deleted policy: {policy.get('name', policy_id)}")
    else:
        print(f"✗ Failed to delete policy: {policy_id}")
        sys.exit(1)


if __name__ == "__main__":
    main()
