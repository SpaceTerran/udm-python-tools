#!/usr/bin/env python3
"""
Enable Firewall Policy

Enable a firewall policy by ID.
"""

import sys
from dotenv import load_dotenv
from unifi_client import get_client_from_env

# Load environment variables
load_dotenv()


def main():
    """Enable a firewall policy."""
    if len(sys.argv) < 2:
        print("Usage: python enable_policy.py <policy_id>")
        print("\nTo get policy IDs, run: python list_policies.py")
        sys.exit(1)

    policy_id = sys.argv[1]

    try:
        client = get_client_from_env()
    except ValueError as e:
        print(f"✗ Error: {e}")
        print("\nPlease create a .env file based on .env.example")
        sys.exit(1)

    # Authenticate
    if not client.login():
        sys.exit(1)

    # Get current policy to show what we're enabling
    policy = client.get_policy_by_id(policy_id)
    if not policy:
        print(f"✗ Policy not found: {policy_id}")
        sys.exit(1)

    print("\nCurrent policy:")
    print(client.format_policy(policy))
    print(f"\nEnabling policy {policy_id}...")

    # Check if already enabled
    current_enabled = policy.get("enabled", False)
    if current_enabled:
        print("  Policy is already enabled.")
        return
    
    # Use batch update method (requires full policy object, with verification)
    success = client.update_policy(policy_id, {"enabled": True}, verify=True)

    if success:
        print(f"✓ Successfully enabled and verified policy: {policy.get('name', policy_id)}")
    else:
        print(f"✗ Failed to enable policy: {policy_id}")
        print("  The update may have been rejected by the API or verification failed.")
        sys.exit(1)


if __name__ == "__main__":
    main()
