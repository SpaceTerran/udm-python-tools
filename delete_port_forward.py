#!/usr/bin/env python3
"""
Delete Port Forwarding Rule

Delete a port forwarding rule by ID.
"""

import sys
from dotenv import load_dotenv
from unifi_client import get_client_from_env

# Load environment variables
load_dotenv()


def main():
    """Delete a port forwarding rule."""
    if len(sys.argv) < 2:
        print("Usage: python delete_port_forward.py <rule_id>")
        print("\nTo get rule IDs, run: python list_port_forwards.py")
        sys.exit(1)

    rule_id = sys.argv[1]

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

    # Get current rule to show what we're deleting
    rule = client.get_port_forward_by_id(rule_id)
    if not rule:
        print(f"✗ Rule not found: {rule_id}")
        sys.exit(1)

    name = rule.get("name", "Unnamed")
    dst_port = rule.get("dst_port", "N/A")
    fwd_ip = rule.get("fwd_ip", "N/A")
    fwd_port = rule.get("fwd_port", "N/A")

    print("\nPort forward to delete:")
    print(f"  Name: {name}")
    print(f"  ID: {rule_id}")
    print(f"  External Port: {dst_port}")
    print(f"  Forward To: {fwd_ip}:{fwd_port}")

    # Confirm deletion unless --force is used
    if not force:
        response = input("\nAre you sure you want to delete this port forward? [y/N]: ")
        if response.lower() != "y":
            print("Aborted.")
            sys.exit(0)

    print(f"\nDeleting port forward {rule_id}...")

    # Delete the rule
    success = client.delete_port_forward(rule_id)

    if success:
        print(f"✓ Successfully deleted port forward: {name}")
    else:
        print(f"✗ Failed to delete port forward: {rule_id}")
        sys.exit(1)


if __name__ == "__main__":
    main()
