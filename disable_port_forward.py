#!/usr/bin/env python3
"""
Disable Port Forwarding Rule

Disable a port forwarding rule.
"""

import sys
from dotenv import load_dotenv
from unifi_client import get_client_from_env

# Load environment variables
load_dotenv()


def main():
    """Disable a port forwarding rule."""
    if len(sys.argv) < 2:
        print("Usage: python disable_port_forward.py <rule_id>")
        print("\nTo get rule IDs, run: python list_port_forwards.py")
        sys.exit(1)

    rule_id = sys.argv[1]

    try:
        client = get_client_from_env()
    except ValueError as e:
        print(f"✗ Error: {e}")
        print("\nPlease create a .env file based on .env.example")
        sys.exit(1)

    # Authenticate
    if not client.login():
        sys.exit(1)

    # Get current rule
    rule = client.get_port_forward_by_id(rule_id)
    if not rule:
        print(f"✗ Rule not found: {rule_id}")
        sys.exit(1)

    if not rule.get("enabled", True):
        print(f"✓ Rule '{rule.get('name', rule_id)}' is already disabled")
        return

    print(f"\nDisabling port forward: {rule.get('name', rule_id)}...")

    # Disable the rule (with verification enabled by default)
    success = client.update_port_forward(rule_id, {"enabled": False}, verify=True)

    if success:
        print(f"✓ Successfully disabled and verified port forward: {rule.get('name', rule_id)}")
    else:
        print(f"✗ Failed to disable port forward: {rule_id}")
        print("  The update may have been rejected by the API or verification failed.")
        sys.exit(1)


if __name__ == "__main__":
    main()
