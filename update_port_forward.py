#!/usr/bin/env python3
"""
Update Port Forwarding Rule

Update a port forwarding rule with JSON data.
"""

import json
import sys
from dotenv import load_dotenv
from unifi_client import get_client_from_env

# Load environment variables
load_dotenv()


def main():
    """Update a port forwarding rule."""
    if len(sys.argv) < 3:
        print("Usage: python update_port_forward.py <rule_id> <json_file>")
        print("   OR: python update_port_forward.py <rule_id> '<json_string>'")
        print("\nExamples:")
        print("  # Update from JSON file")
        print("  python update_port_forward.py 6831f9f5c8ac4702c97c5e1e updates.json")
        print("\n  # Update with inline JSON")
        print('  python update_port_forward.py 6831f9f5c8ac4702c97c5e1e \'{"enabled": false}\'')
        print("\nTo get rule IDs, run: python list_port_forwards.py")
        sys.exit(1)

    rule_id = sys.argv[1]
    json_input = sys.argv[2]

    try:
        client = get_client_from_env()
    except ValueError as e:
        print(f"✗ Error: {e}")
        print("\nPlease create a .env file based on .env.example")
        sys.exit(1)

    # Authenticate
    if not client.login():
        sys.exit(1)

    # Get current rule to show what we're updating
    rule = client.get_port_forward_by_id(rule_id)
    if not rule:
        print(f"✗ Rule not found: {rule_id}")
        sys.exit(1)

    print(f"\nCurrent rule: {rule.get('name', 'Unnamed')}")
    print(f"  External Port: {rule.get('dst_port', 'N/A')}")
    print(f"  Forward To: {rule.get('fwd_ip', 'N/A')}:{rule.get('fwd_port', 'N/A')}")
    print(f"  Protocol: {rule.get('proto', 'N/A')}")
    print(f"  Enabled: {rule.get('enabled', True)}")

    # Parse JSON input
    try:
        if json_input.startswith("{") or json_input.startswith("["):
            # Inline JSON string
            update_data = json.loads(json_input)
        else:
            # JSON file
            with open(json_input, "r") as f:
                update_data = json.load(f)
    except FileNotFoundError:
        print(f"✗ File not found: {json_input}")
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"✗ Invalid JSON: {e}")
        sys.exit(1)

    print("\nUpdating with:")
    print(json.dumps(update_data, indent=2))

    # Update the rule (with verification enabled by default)
    success = client.update_port_forward(rule_id, update_data, verify=True)

    if success:
        print(f"\n✓ Successfully updated and verified port forward: {rule.get('name', rule_id)}")
    else:
        print(f"\n✗ Failed to update port forward: {rule_id}")
        print("  The update may have been rejected by the API or verification failed.")
        sys.exit(1)


if __name__ == "__main__":
    main()
